package wlttx

// Transaction:maxSendable — compute the largest amount of a given asset
// that can be safely sent from an account, accounting for network fees
// and (on Solana) the rent-exempt minimum the sender must retain plus
// the rent-exempt minimum a newly-created recipient must receive.
//
// Native assets (SOL / ETH / BTC) reserve fees + rents from the
// returned Max so the value is immediately usable as the input
// amount of a transfer or swap.
//
// Token assets (SPL on Solana, ERC-20 on EVM) report the full
// on-chain balance as Max — fees are paid in the chain's native
// currency and don't reduce the spendable token amount. The Fee
// field reports the *native-currency* fee a transfer would cost so
// the frontend can warn when the user lacks enough native to pay
// it; the units there are intentionally different from Max.
//
// Bitcoin-family chains have no token model; passing a non-native
// Asset on a Bitcoin network errors.

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
	// Asset is the asset key to compute max against. Canonical
	// form is "<type>.<chainId>.<suffix>" (e.g. "evm.1.NATIVE",
	// "solana.mainnet.<mint>") — identical to the keys
	// Asset:list returns. The network is inferred from the
	// "<type>.<chainId>." prefix; empty or bare "NATIVE" falls
	// back to the current network's native currency. Non-native
	// (token) assets return an error in v1.
	Asset string `json:"asset,omitempty"`
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
//
// For bitcoin-family chains, BitcoinUTXOs and BitcoinFeeRate carry
// the exact selection + fee rate maxSendable used to compute Max.
// Threading them back into the build call (Transaction.UTXOs +
// Transaction.BitcoinFeeRate) eliminates the two ways "send max"
// can fail with insufficient-funds:
//
//  1. The fee-rate RPC (estimatesmartfee) returning a different
//     value between maxSendable and build.
//  2. Coin selection picking a different UTXO subset than max
//     accounted for.
//
// Pinning both pins the fee math end-to-end. EVM / Solana paths
// leave these fields empty.
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

	// BitcoinUTXOs is the list of "<txid>:<vout>" inputs the
	// max calculation accounted for. Pass back via
	// Transaction.UTXOs to make build use the same selection.
	// Empty on non-bitcoin chains.
	BitcoinUTXOs []string `json:"bitcoinUtxos,omitempty"`
	// BitcoinFeeRate is the sat/vB rate the max calculation
	// used. Pass back via Transaction.BitcoinFeeRate to make
	// build use the same rate (no second estimatesmartfee call,
	// no drift). Zero on non-bitcoin chains.
	BitcoinFeeRate uint64 `json:"bitcoinFeeRate,omitempty"`
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

	n, err := resolveNetwork(e, req.Asset)
	if err != nil {
		return nil, err
	}

	if err := acct.UpdateAddressForNetwork(n); err != nil {
		return nil, err
	}

	return MaxSendable(ctx, n, acct, req)
}

// MaxSendable is the RPC-driven core of Transaction:maxSendable, exposed
// so other endpoints (Swap:maxSpendable, asset-aware UIs) can ask the
// same question without going through pobj. The caller is responsible
// for resolving acct + n + UpdateAddressForNetwork beforehand.
func MaxSendable(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, req *MaxSendableRequest) (*MaxSendableResult, error) {
	if isNativeAsset(req.Asset, n) {
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
	addr := assetSuffix(req.Asset)
	if addr == "" {
		return nil, fmt.Errorf("maxSendable: cannot derive token address from asset %q", req.Asset)
	}
	switch n.Type {
	case "solana":
		return maxSendableSolanaSPL(ctx, n, acct, addr)
	case "evm":
		return maxSendableEVMERC20(ctx, n, acct, addr)
	case "bitcoin":
		return nil, fmt.Errorf("maxSendable: Bitcoin-family chains have no token model")
	default:
		return nil, fmt.Errorf("unsupported network type %s", n.Type)
	}
}

// assetSuffix returns the third dotted segment of a canonical asset
// key — the on-chain mint or contract address. Returns "" when the
// suffix is missing, "NATIVE", or the key isn't well-formed.
func assetSuffix(asset string) string {
	parts := strings.SplitN(asset, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	if parts[2] == "" || parts[2] == "NATIVE" {
		return ""
	}
	return parts[2]
}

func resolveAccount(e wltintf.Env, from string) (*wltacct.Account, error) {
	if from == "" {
		return wltacct.CurrentAccount(e)
	}
	return wltacct.FindAccount(e, from)
}

// resolveNetwork picks the network the maxSendable call applies to.
// Derives from asset's "<type>.<chainId>." prefix; falls back to the
// current network when asset is empty or a bare "NATIVE".
func resolveNetwork(e wltintf.Env, asset string) (*wltnet.Network, error) {
	prefix := networkFromAssetPrefix(asset)
	if prefix == "" {
		return wltnet.CurrentNetwork(e)
	}
	id := wltnet.NetworkIdForTypeAndChainId(derivedType(prefix), derivedChain(prefix))
	return wltnet.NetworkById(e, id)
}

// networkFromAssetPrefix returns the "<type>.<chainId>" prefix of an
// asset key or "" when the key isn't in canonical form. Handles the
// special "NATIVE" / "" cases as "" (no prefix).
func networkFromAssetPrefix(asset string) string {
	if asset == "" || asset == "NATIVE" {
		return ""
	}
	parts := strings.SplitN(asset, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// derivedType / derivedChain split the "<type>.<chainId>" string
// produced by networkFromAssetPrefix. Both return "" on malformed
// input.
func derivedType(prefix string) string {
	i := strings.IndexByte(prefix, '.')
	if i < 0 {
		return ""
	}
	return prefix[:i]
}
func derivedChain(prefix string) string {
	i := strings.IndexByte(prefix, '.')
	if i < 0 {
		return ""
	}
	return prefix[i+1:]
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

// maxSendableSolanaSPL returns the full SPL-token balance for (acct,
// mint) on n. Fees are paid in SOL and don't reduce the spendable
// token amount, so Max == Balance == sum of token-account balances
// for that mint (almost always exactly one account; we sum to be
// safe). Fee reports the *native-currency* fee a transfer costs so
// the frontend can warn when SOL is insufficient — its decimals
// (9, lamports) intentionally don't match Max's (the token's own).
func maxSendableSolanaSPL(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, mint string) (*MaxSendableResult, error) {
	raw, err := n.DoRPCCtx(ctx, "getTokenAccountsByOwner",
		acct.GetAddress(),
		map[string]any{"mint": mint},
		map[string]any{"encoding": "jsonParsed"},
	)
	if err != nil {
		return nil, fmt.Errorf("getTokenAccountsByOwner: %w", err)
	}
	var resp struct {
		Value []struct {
			Account struct {
				Data struct {
					Parsed struct {
						Info struct {
							TokenAmount struct {
								Amount   string `json:"amount"`
								Decimals int    `json:"decimals"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse getTokenAccountsByOwner: %w", err)
	}

	total := new(big.Int)
	decimals := 0
	for _, ta := range resp.Value {
		amt, ok := new(big.Int).SetString(ta.Account.Data.Parsed.Info.TokenAmount.Amount, 10)
		if !ok {
			continue
		}
		total.Add(total, amt)
		decimals = ta.Account.Data.Parsed.Info.TokenAmount.Decimals
	}

	res := &MaxSendableResult{
		Chain:   "solana",
		Balance: wltobj.NewAmountRaw(total, decimals),
		Max:     wltobj.NewAmountRaw(total, decimals),
		// Native fee for an SPL transfer (no extra ATA creation).
		// Same 5000-lamport sig fee as a native transfer; a real
		// transfer may add ATA-rent (~2_039_280) when the recipient
		// has no ATA, but we don't know the recipient here.
		Fee: wltobj.NewAmountRaw(big.NewInt(5000), 9),
	}
	if total.Sign() == 0 {
		res.Reason = fmt.Sprintf("no SPL balance for mint %s", mint)
	}
	return res, nil
}

// ── EVM ERC-20 ────────────────────────────────────────────────────────────

// erc20BalanceOfSelector / erc20DecimalsSelector are the ERC-20
// function selectors we hit for token max-sendable. Same constants
// the discovery path uses (wlttoken/discover.go); duplicated here to
// avoid an import cycle (wlttoken depends on wlttx via the asset key).
const (
	erc20BalanceOfSelector = "0x70a08231" // balanceOf(address)
	erc20DecimalsSelector  = "0x313ce567" // decimals()
)

// maxSendableEVMERC20 returns the ERC-20 balance for (acct, contract)
// on n. Same semantics as the SPL helper — Max equals Balance because
// gas is paid in the chain's native currency. Fee here is the
// estimated gas cost of a typical ERC-20 transfer (~65k gas, twice
// the basic 21k since the contract write touches storage), in native
// units.
func maxSendableEVMERC20(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, contract string) (*MaxSendableResult, error) {
	balI, err := evmERC20BalanceOf(ctx, n, contract, acct.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("balanceOf: %w", err)
	}
	dec, err := evmERC20Decimals(ctx, n, contract)
	if err != nil {
		return nil, fmt.Errorf("decimals: %w", err)
	}

	// Native gas estimate for a typical ERC-20 transfer. 65000 is the
	// conservative ceiling: the canonical openzeppelin transfer is
	// ~50k for warm storage, ~65k for cold. We err high so the
	// reported Fee never under-warns.
	const gas uint64 = 65000
	feeI, err := evmFeeForBasicTransfer(ctx, n, gas)
	if err != nil {
		return nil, err
	}
	nativeDecimals := n.CurrencyDecimals
	if nativeDecimals == 0 {
		if info, ierr := n.GetChainInfo(); ierr == nil {
			nativeDecimals = info.NativeCurrency.Decimals
		}
	}
	if nativeDecimals == 0 {
		nativeDecimals = 18
	}

	res := &MaxSendableResult{
		Chain:   "evm",
		Balance: wltobj.NewAmountRaw(balI, dec),
		Max:     wltobj.NewAmountRaw(new(big.Int).Set(balI), dec),
		Fee:     wltobj.NewAmountRaw(feeI, nativeDecimals),
	}
	if balI.Sign() == 0 {
		res.Reason = fmt.Sprintf("no ERC-20 balance for %s", contract)
	}
	return res, nil
}

// evmERC20BalanceOf reads balanceOf(owner) from contract on n. ABI:
// the call data is the 4-byte selector followed by the owner address
// padded to 32 bytes. Result is a single uint256.
func evmERC20BalanceOf(ctx context.Context, n *wltnet.Network, contract, owner string) (*big.Int, error) {
	addr := strings.TrimPrefix(strings.ToLower(owner), "0x")
	data := erc20BalanceOfSelector + strings.Repeat("0", 64-len(addr)) + addr
	hexResult, err := ethrpc.ReadString(n.DoRPCCtx(ctx, "eth_call", map[string]string{
		"to":   contract,
		"data": data,
	}, "latest"))
	if err != nil {
		return nil, err
	}
	hexResult = strings.TrimPrefix(hexResult, "0x")
	if hexResult == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(hexResult, 16)
	if !ok {
		return nil, fmt.Errorf("invalid balanceOf response %q", hexResult)
	}
	return v, nil
}

// evmERC20Decimals reads decimals() from contract on n.
func evmERC20Decimals(ctx context.Context, n *wltnet.Network, contract string) (int, error) {
	hexResult, err := ethrpc.ReadString(n.DoRPCCtx(ctx, "eth_call", map[string]string{
		"to":   contract,
		"data": erc20DecimalsSelector,
	}, "latest"))
	if err != nil {
		return 0, err
	}
	hexResult = strings.TrimPrefix(hexResult, "0x")
	if hexResult == "" {
		return 0, fmt.Errorf("decimals() returned empty response")
	}
	v, ok := new(big.Int).SetString(hexResult, 16)
	if !ok {
		return 0, fmt.Errorf("invalid decimals response %q", hexResult)
	}
	return int(v.Int64()), nil
}

// ── EVM native ────────────────────────────────────────────────────────────

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
// totalSats is the sum of available UTXOs; vsize is the precomputed
// transaction vsize in vbytes (use estimateMixedTxVSize from the
// caller so per-input shapes are honoured); feeRate is sat/vB.
func computeBitcoinMaxSendable(totalSats int64, vsize int, feeRate int64) (max int64, fee int64, reason string) {
	fee = int64(vsize) * feeRate
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
	// Pull EVERY spendable UTXO across receive (m/0) AND change
	// (m/1) — the same source buildBitcoinTx uses. m/0-only made
	// maxSendable return 0 immediately after a send because the
	// change went to m/1 and was invisible here. fetchBitcoinUTXOs
	// also runs through the in-memory tracker, so a just-broadcast
	// change UTXO is visible before modchain reindexes.
	utxos, err := fetchBitcoinUTXOs(n, xpub)
	if err != nil {
		return nil, err
	}

	var totalSats int64
	for _, u := range utxos {
		totalSats += int64(u.Amt)
	}
	nInputs := len(utxos)

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
	// Per-input vsize math (reads bitcoinTxo.Script for each
	// candidate) so a wallet whose change is p2wpkh but whose
	// historical receives include p2pkh entries doesn't under-
	// pay.
	//
	// Output count = 2 (recipient + change) on purpose, even
	// though a max-send produces no change output. We need to
	// match buildBitcoinTx's coin-selection check, which uses
	// the 2-output assumption — otherwise build computes a
	// strictly larger fee than maxSendable did, sees
	// `change < 0`, and bounces with insufficient-funds. The
	// caller can still send the max amount; build will detect
	// that change rounds to zero and emit a 1-output tx, paying
	// the small (~31 vbyte × feeRate) overestimate to the
	// miner. That overpayment is the cost of having a stable
	// "send the entire balance" UX without per-build special-
	// casing.
	vsize := estimateMixedTxVSize(utxos, 2)
	maxSats, feeSats, reason := computeBitcoinMaxSendable(totalSats, vsize, feeRate)
	res.Max = wltobj.NewAmountRaw(big.NewInt(maxSats), 8)
	res.Fee = wltobj.NewAmountRaw(big.NewInt(feeSats), 8)
	res.Reason = reason

	// Pin the inputs + fee rate so the caller can pass them
	// back via Transaction.UTXOs + Transaction.BitcoinFeeRate
	// to keep build's math identical to ours.
	res.BitcoinFeeRate = uint64(feeRate)
	res.BitcoinUTXOs = make([]string, 0, len(utxos))
	for _, u := range utxos {
		res.BitcoinUTXOs = append(res.BitcoinUTXOs, u.Txo)
	}
	return res, nil
}
