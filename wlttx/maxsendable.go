package wlttx

// Transaction:maxSendable — compute the largest amount of a given asset
// that can be safely sent from an account, accounting for network fees
// and (on Solana) the rent-exempt minimum the sender must retain plus
// the rent-exempt minimum a newly-created recipient must receive.
//
// The v1 implementation is native-only: native SOL / ETH / BTC. For
// token assets (ERC-20, SPL) the sendable amount equals the token
// balance — callers should use Asset:list to read token balances and
// call maxSendable separately to verify the account holds enough
// native currency to pay the fee.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterStatic("Transaction:maxSendable", apiMaxSendable)
}

// MaxSendableRequest is the input to Transaction:maxSendable.
type MaxSendableRequest struct {
	// From is the sender account address or ID. Empty means "current account".
	From string `json:"from,omitempty"`
	// To is optional. When set on Solana, the recipient's existence
	// is checked via getAccountInfo — if it doesn't exist, Max is
	// reduced by the rent-exempt minimum needed to fund the new
	// account. On Bitcoin the To field is unused (fee is computed
	// from the input count + a single output). On EVM it's ignored
	// for v1 (the 21000-gas assumption covers EOA destinations).
	To string `json:"to,omitempty"`
	// Asset is the asset key to compute max against. Empty or a key
	// ending in ".NATIVE" means the network's native currency.
	// Non-native (token) assets return an error in v1.
	Asset string `json:"asset,omitempty"`
	// Network overrides the current network.
	Network string `json:"network,omitempty"`
}

// ReservedAmt is one line item in MaxSendableResult.Reserved — an amount
// held back from the balance that the user cannot send.
type ReservedAmt struct {
	// Kind: "fee" | "sender_rent" | "recipient_rent".
	Kind string `json:"kind"`
	// Amount held back.
	Amount *wltobj.Amount `json:"amount"`
}

// MaxSendableResult is the response shape returned by Transaction:maxSendable.
type MaxSendableResult struct {
	// Chain: "evm" | "solana" | "bitcoin".
	Chain string `json:"chain"`
	// Max is the maximum amount safely sendable. Zero when the
	// balance cannot cover the fee + reservations; Reason explains
	// which reservation pushed it to zero.
	Max *wltobj.Amount `json:"max"`
	// Balance is the raw account balance before any deduction.
	Balance *wltobj.Amount `json:"balance"`
	// Fee is the amount reserved for the network fee.
	Fee *wltobj.Amount `json:"fee"`
	// Reserved breaks down what was held back beyond the fee
	// (rent-exempt minimums on Solana; nothing on EVM / Bitcoin v1).
	Reserved []ReservedAmt `json:"reserved,omitempty"`
	// Reason is a human-readable message populated when Max is zero.
	Reason string `json:"reason,omitempty"`
}

// apiMaxSendable is the Transaction:maxSendable endpoint.
func apiMaxSendable(ctx context.Context, req *MaxSendableRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	acct, err := resolveAccount(e, req.From)
	if err != nil {
		return nil, err
	}

	n, err := resolveNetwork(e, req.Network)
	if err != nil {
		return nil, err
	}

	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	if !isNativeAsset(req.Asset, n) {
		return nil, fmt.Errorf("maxSendable: v1 supports native assets only; for tokens use Asset:list (the full token balance is sendable, fees are paid in native currency)")
	}

	switch n.Type {
	case "solana":
		return maxSendableSolana(ctx, n, acct, req)
	case "evm":
		return maxSendableEVM(ctx, n, acct, req)
	case "bitcoin":
		return maxSendableBitcoin(ctx, n, acct, req)
	default:
		return nil, fmt.Errorf("unsupported network type %s", n.Type)
	}
}

func resolveAccount(e wltintf.Env, from string) (*wltacct.Account, error) {
	if from == "" {
		return wltacct.CurrentAccount(e)
	}
	return wltacct.FindAccount(e, from)
}

func resolveNetwork(e wltintf.Env, network string) (*wltnet.Network, error) {
	if network == "" {
		return wltnet.CurrentNetwork(e)
	}
	id, err := xuid.Parse(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network id %q: %w", network, err)
	}
	return wltnet.NetworkById(e, id)
}

// isNativeAsset reports whether the asset key refers to the network's
// native currency. An empty asset string defaults to native. Keys
// ending in ".NATIVE" are native; anything else is a token.
func isNativeAsset(asset string, _ *wltnet.Network) bool {
	if asset == "" {
		return true
	}
	return strings.HasSuffix(asset, ".NATIVE") || asset == "NATIVE"
}

// ── Solana ────────────────────────────────────────────────────────────────

// SolanaRentExemptMinimum returns the rent-exempt minimum (in lamports)
// for an account of the given data size on this network. data=0 is the
// basic system account used for plain SOL transfers.
//
// The result is NOT cached: the minimum is tied to the network's rent
// parameters (lamports per byte per year) which change on cluster
// upgrades. Callers that need to avoid the roundtrip should cache at
// their layer.
func SolanaRentExemptMinimum(ctx context.Context, n *wltnet.Network, dataBytes int) (uint64, error) {
	raw, err := n.DoRPCCtx(ctx, "getMinimumBalanceForRentExemption", dataBytes)
	if err != nil {
		return 0, err
	}
	var v uint64
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("parse getMinimumBalanceForRentExemption: %w", err)
	}
	return v, nil
}

// solanaAccountExists returns true when getAccountInfo(address) returns
// a non-null value. A missing account means the recipient will need to
// be created (and funded to its rent-exempt minimum) by the transfer.
func solanaAccountExists(ctx context.Context, n *wltnet.Network, address string) (bool, error) {
	raw, err := n.DoRPCCtx(ctx, "getAccountInfo", address, map[string]any{"encoding": "base64"})
	if err != nil {
		return false, err
	}
	var resp struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false, err
	}
	// getAccountInfo returns "value": null for missing accounts.
	return len(resp.Value) > 0 && string(resp.Value) != "null", nil
}

// solanaLamportsBalance returns the native balance (in lamports) for
// address on n.
func solanaLamportsBalance(ctx context.Context, n *wltnet.Network, address string) (uint64, error) {
	raw, err := n.DoRPCCtx(ctx, "getBalance", address)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parse getBalance: %w", err)
	}
	return resp.Value, nil
}

// computeSolanaMaxSendable is the RPC-free math extracted for unit tests.
//
// balance, fee, senderRent, recipientRent are all in lamports.
// recipientExists=true means we don't reserve recipientRent.
func computeSolanaMaxSendable(balance, fee, senderRent, recipientRent uint64, recipientExists bool) (max uint64, reserved uint64, reason string) {
	if !recipientExists {
		reserved = fee + senderRent + recipientRent
	} else {
		reserved = fee + senderRent
	}
	if balance <= reserved {
		reason = fmt.Sprintf("balance %d lamports is not enough to cover fee %d + sender rent %d", balance, fee, senderRent)
		if !recipientExists {
			reason = fmt.Sprintf("%s + new-recipient rent %d", reason, recipientRent)
		}
		return 0, reserved, reason
	}
	return balance - reserved, reserved, ""
}

func maxSendableSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *MaxSendableRequest) (*MaxSendableResult, error) {
	balLamports, err := solanaLamportsBalance(ctx, n, acct.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("getBalance: %w", err)
	}

	// Solana native transfers have a fixed 5000-lamport signature fee.
	// (ComputeBudget / priority fees are covered in a later pass.)
	const feeLamports uint64 = 5000

	senderRent, err := SolanaRentExemptMinimum(ctx, n, 0)
	if err != nil {
		// Fall back to the canonical value (0-byte system account,
		// mainnet rent parameters as of mid-2020 and unchanged since).
		senderRent = 890880
	}

	var recipientRent uint64
	recipientExists := true
	if req.To != "" {
		exists, err := solanaAccountExists(ctx, n, req.To)
		if err == nil && !exists {
			recipientExists = false
			recipientRent = senderRent
		}
	}

	res := &MaxSendableResult{
		Chain:   "solana",
		Balance: wltobj.NewAmountRaw(new(big.Int).SetUint64(balLamports), 9),
		Fee:     wltobj.NewAmountRaw(new(big.Int).SetUint64(feeLamports), 9),
		Reserved: []ReservedAmt{
			{Kind: "sender_rent", Amount: wltobj.NewAmountRaw(new(big.Int).SetUint64(senderRent), 9)},
		},
	}
	if !recipientExists {
		res.Reserved = append(res.Reserved, ReservedAmt{
			Kind:   "recipient_rent",
			Amount: wltobj.NewAmountRaw(new(big.Int).SetUint64(recipientRent), 9),
		})
	}

	maxLamports, _, reason := computeSolanaMaxSendable(balLamports, feeLamports, senderRent, recipientRent, recipientExists)
	res.Max = wltobj.NewAmountRaw(new(big.Int).SetUint64(maxLamports), 9)
	res.Reason = reason
	return res, nil
}

// ── EVM ───────────────────────────────────────────────────────────────────

// evmFeeForBasicTransfer returns the fee in wei for a single EOA-to-EOA
// transfer on n. Uses EIP-1559 (maxFee = 2 * baseFee + tip) when the
// chain supports it, else eth_gasPrice.
func evmFeeForBasicTransfer(ctx context.Context, n *wltnet.Network, gas uint64) (*big.Int, error) {
	info, err := n.GetChainInfo()
	if err != nil {
		return nil, err
	}

	if info.HasFeature("EIP1559") {
		tip, err := ethrpc.ReadBigInt(n.DoRPCCtx(ctx, "eth_maxPriorityFeePerGas"))
		if err != nil || tip == nil || tip.Sign() <= 0 {
			tip = big.NewInt(1_000_000_000) // 1 gwei fallback
		}
		raw, rerr := n.DoRPCCtx(ctx, "eth_getBlockByNumber", "latest", false)
		var block struct {
			BaseFeePerGas string `json:"baseFeePerGas"`
		}
		if rerr == nil {
			_ = json.Unmarshal(raw, &block)
		}
		var baseFee *big.Int
		if block.BaseFeePerGas != "" {
			baseFee, _ = new(big.Int).SetString(strings.TrimPrefix(block.BaseFeePerGas, "0x"), 16)
		}
		if baseFee == nil {
			// No baseFee — use gasPrice as a conservative ceiling.
			baseFee, err = ethrpc.ReadBigInt(n.DoRPCCtx(ctx, "eth_gasPrice"))
			if err != nil || baseFee == nil {
				baseFee = big.NewInt(0)
			}
		}
		maxFee := new(big.Int).Mul(baseFee, big.NewInt(2))
		maxFee.Add(maxFee, tip)
		return new(big.Int).Mul(maxFee, new(big.Int).SetUint64(gas)), nil
	}

	gp, err := ethrpc.ReadBigInt(n.DoRPCCtx(ctx, "eth_gasPrice"))
	if err != nil {
		return nil, err
	}
	return new(big.Int).Mul(gp, new(big.Int).SetUint64(gas)), nil
}

func maxSendableEVM(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, _ *MaxSendableRequest) (*MaxSendableResult, error) {
	info, err := n.GetChainInfo()
	if err != nil {
		return nil, err
	}
	decimals := n.CurrencyDecimals
	if decimals == 0 {
		decimals = info.NativeCurrency.Decimals
	}

	balHex, err := ethrpc.ReadString(n.DoRPCCtx(ctx, "eth_getBalance", acct.GetAddress(), "latest"))
	if err != nil {
		return nil, err
	}
	balI, ok := new(big.Int).SetString(balHex, 0)
	if !ok {
		return nil, fmt.Errorf("invalid balance from rpc: %q", balHex)
	}

	// Basic EOA-to-EOA transfer is 21000 gas; contract destinations
	// cost more, but we can't know that here without a To. Callers
	// sending to a contract should call Transaction:validate which
	// runs eth_estimateGas and will refuse if the fee exceeds balance.
	const gas uint64 = 21000
	feeI, err := evmFeeForBasicTransfer(ctx, n, gas)
	if err != nil {
		return nil, err
	}

	res := &MaxSendableResult{
		Chain:   "evm",
		Balance: wltobj.NewAmountRaw(balI, decimals),
		Fee:     wltobj.NewAmountRaw(feeI, decimals),
	}

	if balI.Cmp(feeI) <= 0 {
		res.Max = wltobj.NewAmountRaw(big.NewInt(0), decimals)
		res.Reason = fmt.Sprintf("balance %s wei does not cover fee %s wei", balI.String(), feeI.String())
		return res, nil
	}
	res.Max = wltobj.NewAmountRaw(new(big.Int).Sub(balI, feeI), decimals)
	return res, nil
}

// ── Bitcoin ───────────────────────────────────────────────────────────────

// computeBitcoinMaxSendable is the RPC-free math extracted for unit tests.
// totalSats is the sum of available UTXOs; nInputs is how many of them
// would be spent; feeRate is sat/vB; the output count is fixed at 1
// (sending max = no change output).
func computeBitcoinMaxSendable(totalSats int64, nInputs int, feeRate int64) (max int64, fee int64, reason string) {
	vsize := int64(estimateTxVSize(nInputs, 1))
	fee = vsize * feeRate
	if totalSats <= fee {
		return 0, fee, fmt.Sprintf("total UTXO %d sats does not cover fee %d sats", totalSats, fee)
	}
	return totalSats - fee, fee, ""
}

func maxSendableBitcoin(_ context.Context, n *wltnet.Network, acct *wltacct.Account, _ *MaxSendableRequest) (*MaxSendableResult, error) {
	xpub, err := acct.Xpub()
	if err != nil {
		return nil, fmt.Errorf("xpub: %w", err)
	}
	utxos, err := fetchBitcoinUTXOs(n, xpub, "m/0")
	if err != nil {
		return nil, err
	}

	var totalSats int64
	for _, u := range utxos.Txo {
		totalSats += int64(u.Amt)
	}
	nInputs := len(utxos.Txo)

	res := &MaxSendableResult{
		Chain:   "bitcoin",
		Balance: wltobj.NewAmountRaw(big.NewInt(totalSats), 8),
	}

	if nInputs == 0 {
		res.Max = wltobj.NewAmountRaw(big.NewInt(0), 8)
		res.Fee = wltobj.NewAmountRaw(big.NewInt(0), 8)
		res.Reason = "no spendable UTXOs"
		return res, nil
	}

	feeRate, err := bitcoinFeeRate(n)
	if err != nil {
		feeRate = 10
	}
	maxSats, feeSats, reason := computeBitcoinMaxSendable(totalSats, nInputs, feeRate)
	res.Max = wltobj.NewAmountRaw(big.NewInt(maxSats), 8)
	res.Fee = wltobj.NewAmountRaw(big.NewInt(feeSats), 8)
	res.Reason = reason
	return res, nil
}
