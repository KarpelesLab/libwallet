package wlttx

// Transaction simulation + decoding.
//
// Given an unsigned Transaction the wallet is about to sign, return a
// structured view the host app can render as "this sends X to Y" /
// "this approves Z to spend up to N" / "this call will revert". Covers
// EVM (via eth_call + calldata ABI decoding), Solana (via
// simulateTransaction RPC), and Bitcoin-family (decode-only — UTXO
// model doesn't have "simulation" per se, but the parsed inputs /
// outputs are what a user actually needs to see).
//
// Result is a flat SimulationResult struct so Dart can parse it without
// a sealed hierarchy; per-chain-specific fields are optional.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("Transaction:simulate", apiSimulateTransaction)
}

// SimulationResult is a flat per-tx summary surfaced to the Dart client.
//
// The three "family" fields (EVM / Solana / Bitcoin) are mutually
// exclusive — whichever chain the tx targets, the matching block is
// populated and the others stay zero-valued.
type SimulationResult struct {
	// Cross-chain basics
	Chain         string `json:"chain"`            // "evm" | "solana" | "bitcoin"
	WillRevert    bool   `json:"willRevert"`       // true if the sim failed or eth_call reverted
	RevertReason  string `json:"revertReason,omitempty"`

	// Decoded high-level operation when we can recognize the tx shape.
	DecodedMethod string         `json:"decodedMethod,omitempty"` // "native_transfer" | "erc20_transfer" | "erc20_approve" | "unknown"
	DecodedArgs   map[string]any `json:"decodedArgs,omitempty"`

	// EVM-specific
	GasEstimate uint64 `json:"gasEstimate,omitempty"`

	// Solana-specific
	Logs           []string `json:"logs,omitempty"`
	UnitsConsumed  uint64   `json:"unitsConsumed,omitempty"`

	// Bitcoin-specific — decoded from Tx.Raw via outscript.BtcTx.
	BitcoinInputs  []BitcoinIO `json:"bitcoinInputs,omitempty"`
	BitcoinOutputs []BitcoinIO `json:"bitcoinOutputs,omitempty"`
	BitcoinFee     int64       `json:"bitcoinFee,omitempty"` // sats, only when inputs are resolved
}

// BitcoinIO is one input or output of a BTC-family tx after decoding.
type BitcoinIO struct {
	Address string `json:"address,omitempty"` // resolved address (if script was standard)
	Amount  int64  `json:"amount"`            // sats
	Script  string `json:"script,omitempty"`  // hex script if we couldn't map to an address
	TxID    string `json:"txid,omitempty"`    // inputs only: prev txid (big-endian hex)
	Vout    uint32 `json:"vout,omitempty"`    // inputs only
}

// apiSimulateTransaction is the Transaction:simulate endpoint. Accepts
// the same Transaction shape as Transaction:validate, runs the per-chain
// simulator, returns a SimulationResult.
func apiSimulateTransaction(ctx context.Context, tx *Transaction) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	// Reuse Validate so gas/nonce/fees/amount normalization happens.
	// Skip its side effects on the DB by clearing Keys first.
	tx.Keys = nil
	if err := tx.Validate(e); err != nil {
		// Some types (bitcoin_transfer) may not be fully validatable
		// without keys; fall through so the simulator still runs on
		// raw data when available.
	}

	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, fmt.Errorf("no current network: %w", err)
	}

	switch n.Type {
	case "evm":
		return simulateEVM(ctx, e, n, tx)
	case "solana":
		return simulateSolana(ctx, e, n, tx)
	case "bitcoin":
		return simulateBitcoin(ctx, e, n, tx)
	default:
		return &SimulationResult{Chain: n.Type, DecodedMethod: "unknown"}, nil
	}
}

// ── EVM ───────────────────────────────────────────────────────────────────

// erc20ApproveSelector = keccak256("approve(address,uint256)")[:4]
const erc20ApproveSelector = "095ea7b3"

func simulateEVM(ctx context.Context, e wltintf.Env, n *wltnet.Network, tx *Transaction) (*SimulationResult, error) {
	res := &SimulationResult{Chain: "evm"}
	decodeEVMCall(tx, res)

	call := map[string]any{
		"to":   tx.To,
		"data": "0x" + stripHex(tx.Data),
	}
	if tx.From != "" {
		call["from"] = tx.From
	}
	if tx.Value != nil && tx.Value.Sign() > 0 {
		call["value"] = "0x" + tx.Value.Value().Text(16)
	}
	if tx.Gas > 0 {
		call["gas"] = fmt.Sprintf("0x%x", tx.Gas)
	}

	if raw, err := n.DoRPC("eth_call", call, "latest"); err == nil {
		// Success — try to pull a gas estimate too (cheap on erigon).
		if g, err := n.DoRPC("eth_estimateGas", call); err == nil {
			var gasHex string
			if json.Unmarshal(g, &gasHex) == nil {
				if v, ok := new(big.Int).SetString(strings.TrimPrefix(gasHex, "0x"), 16); ok {
					res.GasEstimate = v.Uint64()
				}
			}
		}
		_ = raw // return value not exposed in v1
		return res, nil
	} else {
		res.WillRevert = true
		res.RevertReason = decodeEVMRevert(err)
		return res, nil
	}
}

// decodeEVMCall recognizes the ERC-20 transfer / approve shape and a
// plain native transfer, and fills in DecodedMethod / DecodedArgs.
func decodeEVMCall(tx *Transaction, res *SimulationResult) {
	data := stripHex(tx.Data)
	if data == "" {
		if tx.Amount != nil && tx.Amount.Sign() > 0 {
			res.DecodedMethod = "native_transfer"
			res.DecodedArgs = map[string]any{
				"to":     tx.To,
				"amount": tx.Amount.String(),
			}
		}
		return
	}
	if len(data) < 8 {
		res.DecodedMethod = "unknown"
		res.DecodedArgs = map[string]any{"selector": "0x" + data}
		return
	}
	selector := data[:8]
	switch selector {
	case erc20TransferSelector:
		to, amount, ok := decodeERC20TransferArgs(data[8:])
		if !ok {
			break
		}
		res.DecodedMethod = "erc20_transfer"
		res.DecodedArgs = map[string]any{
			"token":  tx.To,
			"to":     to,
			"amount": amount.String(),
		}
		return
	case erc20ApproveSelector:
		spender, amount, ok := decodeERC20TransferArgs(data[8:])
		if !ok {
			break
		}
		res.DecodedMethod = "erc20_approve"
		res.DecodedArgs = map[string]any{
			"token":   tx.To,
			"spender": spender,
			"amount":  amount.String(),
		}
		return
	}
	res.DecodedMethod = "unknown"
	res.DecodedArgs = map[string]any{"selector": "0x" + selector, "data": "0x" + data}
}

// decodeERC20TransferArgs parses a 64-byte ABI-encoded (address, uint256).
func decodeERC20TransferArgs(hexArgs string) (addr string, amount *big.Int, ok bool) {
	if len(hexArgs) < 128 {
		return "", nil, false
	}
	// First 32 bytes: address (12 bytes zero-pad + 20 bytes).
	addrHex := hexArgs[24:64]
	if _, err := hex.DecodeString(addrHex); err != nil {
		return "", nil, false
	}
	amt, okAmt := new(big.Int).SetString(hexArgs[64:128], 16)
	if !okAmt {
		return "", nil, false
	}
	return "0x" + addrHex, amt, true
}

// decodeEVMRevert pulls a human-readable reason out of an eth_call error.
// Standard reverts come back as 0x08c379a0 (Error(string)) or 0x4e487b71
// (Panic(uint256)). The RPC client surfaces these as plain error strings;
// we look for the payload.
func decodeEVMRevert(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Look for a hex payload ("0x…") which is the revert data.
	idx := strings.Index(msg, "0x")
	if idx == -1 {
		return msg
	}
	hexPart := msg[idx:]
	// Cut at first non-hex char.
	end := len(hexPart)
	for i := 2; i < len(hexPart); i++ {
		c := hexPart[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			end = i
			break
		}
	}
	payload := hexPart[:end]
	raw, derr := hex.DecodeString(strings.TrimPrefix(payload, "0x"))
	if derr != nil || len(raw) < 4 {
		return msg
	}
	// Error(string): selector 0x08c379a0 + offset(32) + len(32) + string.
	if len(raw) >= 4+32+32 && hex.EncodeToString(raw[:4]) == "08c379a0" {
		length := new(big.Int).SetBytes(raw[4+32 : 4+32+32]).Int64()
		if length > 0 && int64(len(raw)) >= 4+64+length {
			return string(raw[4+64 : 4+64+length])
		}
	}
	return msg
}

func stripHex(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
}

// ── Solana ────────────────────────────────────────────────────────────────

func simulateSolana(ctx context.Context, e wltintf.Env, n *wltnet.Network, tx *Transaction) (*SimulationResult, error) {
	res := &SimulationResult{Chain: "solana"}
	if len(tx.Raw) == 0 {
		return res, errors.New("solana tx has no raw bytes; call validate first")
	}
	b64 := base64.StdEncoding.EncodeToString(tx.Raw)
	raw, err := n.DoRPCNamed("simulateTransaction", map[string]any{
		"transaction": b64,
		"encoding":    "base64",
		"commitment":  "processed",
		"sigVerify":   false,
	})
	if err != nil {
		res.WillRevert = true
		res.RevertReason = err.Error()
		return res, nil
	}
	var sim struct {
		Value struct {
			Err           any      `json:"err"`
			Logs          []string `json:"logs"`
			UnitsConsumed uint64   `json:"unitsConsumed"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &sim); err != nil {
		return res, fmt.Errorf("decode simulateTransaction response: %w", err)
	}
	res.Logs = sim.Value.Logs
	res.UnitsConsumed = sim.Value.UnitsConsumed
	if sim.Value.Err != nil {
		res.WillRevert = true
		if b, err := json.Marshal(sim.Value.Err); err == nil {
			res.RevertReason = string(b)
		}
	}
	if tx.Amount != nil && tx.Amount.Sign() > 0 {
		res.DecodedMethod = "native_transfer"
		res.DecodedArgs = map[string]any{"to": tx.To, "amount": tx.Amount.String()}
	}
	return res, nil
}

// ── Bitcoin ───────────────────────────────────────────────────────────────

func simulateBitcoin(ctx context.Context, e wltintf.Env, n *wltnet.Network, tx *Transaction) (*SimulationResult, error) {
	res := &SimulationResult{Chain: "bitcoin"}
	if len(tx.Raw) == 0 {
		// No raw tx yet — just reflect the intent.
		if tx.Amount != nil {
			res.DecodedMethod = "native_transfer"
			res.DecodedArgs = map[string]any{"to": tx.To, "amount": tx.Amount.String()}
		}
		return res, nil
	}
	btx := &outscript.BtcTx{}
	if err := btx.UnmarshalBinary(tx.Raw); err != nil {
		return res, fmt.Errorf("decode btc tx: %w", err)
	}
	_ = bitcoinNetworkName // hint to keep import
	for _, o := range btx.Out {
		io := BitcoinIO{
			Amount: int64(o.Amount),
			Script: hex.EncodeToString(o.Script),
		}
		res.BitcoinOutputs = append(res.BitcoinOutputs, io)
	}
	for _, in := range btx.In {
		var be [32]byte
		for j := 0; j < 32; j++ {
			be[j] = in.TXID[31-j]
		}
		res.BitcoinInputs = append(res.BitcoinInputs, BitcoinIO{
			TxID: hex.EncodeToString(be[:]),
			Vout: in.Vout,
		})
	}
	// We can't resolve input amounts without a separate RPC roundtrip per
	// prev txid; leave fee computation to when the caller has the utxo
	// context (buildBitcoinTx already records the fee on the Transaction).
	if tx.Fee != nil {
		res.BitcoinFee = tx.Fee.Value().Int64()
	}
	res.DecodedMethod = "native_transfer"
	if tx.To != "" && tx.Amount != nil {
		res.DecodedArgs = map[string]any{"to": tx.To, "amount": tx.Amount.String()}
	}
	return res, nil
}

