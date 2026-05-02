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
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
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

	// Warnings surfaced to the approval UI. Non-blocking at simulate
	// time (the tx can still be signed); apps choose whether to
	// confirm with the user. See the Warning.Code table in the
	// package docs for the stable code set.
	Warnings []Warning `json:"warnings,omitempty"`

	// Decoded high-level operation when we can recognize the TOP-LEVEL tx
	// shape. For a richer "all transfers that will fire at any depth"
	// view (the anti-drainer signal), use Effects.
	DecodedMethod string         `json:"decodedMethod,omitempty"` // "native_transfer" | "erc20_transfer" | "erc20_approve" | "unknown"
	DecodedArgs   map[string]any `json:"decodedArgs,omitempty"`

	// Effects lists every transfer the tx will cause, at any call depth.
	// Populated via erigon's debug_traceCall (callTracer). On chains
	// without debug_traceCall support, only the top-level decoded call
	// is returned (one effect matching DecodedMethod).
	Effects []Effect `json:"effects,omitempty"`

	// BalanceChanges lists every address whose native balance changes
	// in the simulated tx (including the sender paying gas). Populated
	// from the prestateTracer diff.
	BalanceChanges []BalanceChange `json:"balanceChanges,omitempty"`

	// EVM-specific
	GasEstimate uint64 `json:"gasEstimate,omitempty"`

	// Solana-specific
	Logs           []string `json:"logs,omitempty"`
	UnitsConsumed  uint64   `json:"unitsConsumed,omitempty"`

	// Bitcoin-specific — decoded from Tx.Raw via outscript.BtcTx, or
	// dry-run from the Transaction shape when Raw is empty.
	BitcoinInputs  []BitcoinIO `json:"bitcoinInputs,omitempty"`
	BitcoinOutputs []BitcoinIO `json:"bitcoinOutputs,omitempty"`
	BitcoinFee     int64       `json:"bitcoinFee,omitempty"` // sats, only when inputs are resolved
	// BitcoinChange is the change amount (sats) returned to the
	// account in a dry-run preview. Zero when there's no change
	// output (sending the exact amount, or change went to dust).
	// Only populated by the dry-run path; decode-only sims leave it
	// at zero because they can't separate the change output from
	// the recipient output without context.
	BitcoinChange int64 `json:"bitcoinChange,omitempty"`
	// BitcoinVSize is the estimated tx vsize in vbytes, surfaced so
	// the approval UI can show "X sat/vB × Y vbytes = fee" without
	// reverse-engineering the ratio from BitcoinFee alone. Set by
	// the dry-run path; decode-only sims compute it from len(Raw).
	BitcoinVSize int `json:"bitcoinVSize,omitempty"`
}

// Effect is one observable transfer the tx will cause.
type Effect struct {
	// Type: "native_transfer" | "erc20_transfer" | "erc20_approve".
	Type string `json:"type"`
	// Token contract address for ERC-20 effects. Empty for native.
	Token string `json:"token,omitempty"`
	// From / To addresses (0x-prefixed, lowercase).
	From string `json:"from"`
	To   string `json:"to"`
	// Amount as an unsigned decimal integer string (wei / token base units).
	Amount string `json:"amount"`
}

// BalanceChange is one address's native-balance delta across the simulation.
// Positive = net receive; negative = net spend (includes gas cost for the
// sender).
type BalanceChange struct {
	Address string `json:"address"`
	// Delta as a SIGNED decimal integer string (wei for EVM).
	Delta string `json:"delta"`
}

// BitcoinIO is one input or output of a BTC-family tx after decoding.
type BitcoinIO struct {
	Address string `json:"address,omitempty"` // resolved address (if script was standard)
	Amount  int64  `json:"amount"`            // sats
	Script  string `json:"script,omitempty"`  // hex script if we couldn't map to an address
	TxID    string `json:"txid,omitempty"`    // inputs only: prev txid (big-endian hex)
	Vout    uint32 `json:"vout,omitempty"`    // inputs only
	// Path is the BIP32 derivation the input belongs to (e.g.
	// "m/0/3"), populated by the dry-run preview so the UI can
	// flag when a change UTXO is being spent. Empty on decoded-
	// from-Raw sims because the prev-utxo-to-path mapping isn't
	// derivable from the wire bytes alone.
	Path string `json:"path,omitempty"`
}

// apiSimulateTransaction is the Transaction:simulate endpoint. Accepts
// the same Transaction shape as Transaction:validate, runs the per-chain
// simulator, returns a SimulationResult.
func apiSimulateTransaction(ctx context.Context, tx *Transaction) (any, error) {
	return Simulate(ctx, tx)
}

// Simulate exposes the per-chain simulation pipeline so callers
// other than the Transaction:simulate endpoint (notably the Web3
// sign-request emitter in wltbase) can attach decoded data to
// approval prompts without a separate RPC round-trip from Dart.
//
// Returns (*SimulationResult, error). The result may be nil when
// the chain type has no simulator.
func Simulate(ctx context.Context, tx *Transaction) (*SimulationResult, error) {
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

	var res *SimulationResult
	switch n.Type {
	case "evm":
		res, err = simulateEVM(ctx, e, n, tx)
	case "solana":
		res, err = simulateSolana(ctx, e, n, tx)
	case "bitcoin":
		res, err = simulateBitcoin(ctx, e, n, tx)
	default:
		return &SimulationResult{Chain: n.Type, DecodedMethod: "unknown"}, nil
	}
	if err != nil || res == nil {
		return res, err
	}
	// Collect non-blocking warnings. Bounded so a slow node can't
	// wedge simulate.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res.Warnings = append(res.Warnings, collectSimulationWarnings(wctx, n, tx)...)
	return res, nil
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

	// Bound every RPC call so a slow / hung upstream doesn't freeze the
	// simulate endpoint. 10 s is generous for eth_call / debug_traceCall
	// against a local erigon; production public RPCs are slower but
	// should still return within that window.
	rpcCtx, rpcCancel := context.WithTimeout(ctx, 10*time.Second)
	defer rpcCancel()

	// Prefer erigon's debug_traceCall (callTracer) — it gives us the
	// full call tree including nested CALLs and all LOGs, which is what
	// lets us surface "all transfers that will fire" (anti-drainer) even
	// when the top-level calldata looks benign. Fall back to plain
	// eth_call if the node doesn't expose debug_*.
	tracerCfg := map[string]any{
		"tracer": "callTracer",
		"tracerConfig": map[string]any{
			"withLog": true,
		},
	}
	if raw, err := n.DoRPCCtx(rpcCtx, "debug_traceCall", call, "latest", tracerCfg); err == nil {
		var frame callFrame
		if err := json.Unmarshal(raw, &frame); err == nil {
			if frame.Error != "" {
				res.WillRevert = true
				res.RevertReason = decodeRevertHex(frame.RevertReason)
				if res.RevertReason == "" {
					res.RevertReason = frame.Error
				}
			}
			res.Effects = extractEffects(&frame, tx)
			if frame.GasUsed != "" {
				if v, ok := new(big.Int).SetString(strings.TrimPrefix(frame.GasUsed, "0x"), 16); ok {
					res.GasEstimate = v.Uint64()
				}
			}
		}
	} else if raw, err := n.DoRPCCtx(rpcCtx, "eth_call", call, "latest"); err == nil {
		_ = raw
		if g, err := n.DoRPCCtx(rpcCtx, "eth_estimateGas", call); err == nil {
			var gasHex string
			if json.Unmarshal(g, &gasHex) == nil {
				if v, ok := new(big.Int).SetString(strings.TrimPrefix(gasHex, "0x"), 16); ok {
					res.GasEstimate = v.Uint64()
				}
			}
		}
		// No call tree available — synthesize a single effect from the
		// top-level decode (if any).
		if eff := effectFromDecoded(tx, res); eff != nil {
			res.Effects = append(res.Effects, *eff)
		}
	} else {
		res.WillRevert = true
		res.RevertReason = decodeEVMRevert(err)
		return res, nil
	}

	// Second pass: prestateTracer diff mode for native-balance changes.
	// Best-effort — if it fails we just don't populate BalanceChanges.
	preCfg := map[string]any{
		"tracer": "prestateTracer",
		"tracerConfig": map[string]any{
			"diffMode": true,
		},
	}
	if raw, err := n.DoRPCCtx(rpcCtx, "debug_traceCall", call, "latest", preCfg); err == nil {
		res.BalanceChanges = extractBalanceChanges(raw)
	}

	return res, nil
}

// callFrame mirrors erigon's callTracer output shape.
type callFrame struct {
	Type         string      `json:"type"`
	From         string      `json:"from"`
	To           string      `json:"to"`
	Value        string      `json:"value"`
	Gas          string      `json:"gas"`
	GasUsed      string      `json:"gasUsed"`
	Input        string      `json:"input"`
	Output       string      `json:"output"`
	Error        string      `json:"error"`
	RevertReason string      `json:"revertReason"`
	Logs         []callLog   `json:"logs"`
	Calls        []callFrame `json:"calls"`
}

type callLog struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// transferEventTopic = keccak256("Transfer(address,address,uint256)")
const transferEventTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

// approvalEventTopic = keccak256("Approval(address,address,uint256)")
const approvalEventTopic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

// extractEffects walks a callTracer frame tree and pulls out every ERC-20
// Transfer + Approval event and every value-carrying CALL / CREATE.
func extractEffects(root *callFrame, topTx *Transaction) []Effect {
	var out []Effect
	var walk func(f *callFrame)
	walk = func(f *callFrame) {
		if f == nil {
			return
		}
		// Native value transfer via CALL / STATICCALL / CALLCODE /
		// DELEGATECALL / CREATE with non-zero value. Only CALL and
		// CREATE actually transfer value; delegatecall/staticcall do not.
		if (f.Type == "CALL" || f.Type == "CREATE" || f.Type == "CREATE2") && f.Value != "" && f.Value != "0x" && f.Value != "0x0" {
			if v, ok := new(big.Int).SetString(strings.TrimPrefix(f.Value, "0x"), 16); ok && v.Sign() > 0 {
				out = append(out, Effect{
					Type:   "native_transfer",
					From:   strings.ToLower(f.From),
					To:     strings.ToLower(f.To),
					Amount: v.String(),
				})
			}
		}
		for _, lg := range f.Logs {
			if len(lg.Topics) < 1 {
				continue
			}
			switch lg.Topics[0] {
			case transferEventTopic:
				if eff := decodeTransferLog(lg); eff != nil {
					out = append(out, *eff)
				}
			case approvalEventTopic:
				if eff := decodeApprovalLog(lg); eff != nil {
					out = append(out, *eff)
				}
			}
		}
		for i := range f.Calls {
			walk(&f.Calls[i])
		}
	}
	walk(root)
	return out
}

// decodeTransferLog turns a Transfer(address,address,uint256) log into an
// Effect. Topics are zero-padded 32-byte values.
func decodeTransferLog(lg callLog) *Effect {
	if len(lg.Topics) < 3 {
		return nil
	}
	from := "0x" + strings.ToLower(stripTopicToAddress(lg.Topics[1]))
	to := "0x" + strings.ToLower(stripTopicToAddress(lg.Topics[2]))
	amt, ok := new(big.Int).SetString(strings.TrimPrefix(lg.Data, "0x"), 16)
	if !ok {
		return nil
	}
	return &Effect{
		Type:   "erc20_transfer",
		Token:  strings.ToLower(lg.Address),
		From:   from,
		To:     to,
		Amount: amt.String(),
	}
}

// decodeApprovalLog turns an Approval(address,address,uint256) log into an
// Effect (owner, spender, amount). We use From=owner, To=spender to keep
// the Effect shape uniform.
func decodeApprovalLog(lg callLog) *Effect {
	if len(lg.Topics) < 3 {
		return nil
	}
	owner := "0x" + strings.ToLower(stripTopicToAddress(lg.Topics[1]))
	spender := "0x" + strings.ToLower(stripTopicToAddress(lg.Topics[2]))
	amt, ok := new(big.Int).SetString(strings.TrimPrefix(lg.Data, "0x"), 16)
	if !ok {
		return nil
	}
	return &Effect{
		Type:   "erc20_approve",
		Token:  strings.ToLower(lg.Address),
		From:   owner,
		To:     spender,
		Amount: amt.String(),
	}
}

// stripTopicToAddress extracts the trailing 20-byte address from a
// 32-byte 0x-prefixed topic.
func stripTopicToAddress(topic string) string {
	t := strings.TrimPrefix(topic, "0x")
	if len(t) < 40 {
		return t
	}
	return t[len(t)-40:]
}

// effectFromDecoded converts res.DecodedMethod + DecodedArgs into a single
// Effect when the tracer isn't available. Returns nil for unknown calls.
func effectFromDecoded(tx *Transaction, res *SimulationResult) *Effect {
	from := strings.ToLower(tx.From)
	switch res.DecodedMethod {
	case "native_transfer":
		to, _ := res.DecodedArgs["to"].(string)
		amt, _ := res.DecodedArgs["amount"].(string)
		return &Effect{Type: "native_transfer", From: from, To: strings.ToLower(to), Amount: amt}
	case "erc20_transfer":
		token, _ := res.DecodedArgs["token"].(string)
		to, _ := res.DecodedArgs["to"].(string)
		amt, _ := res.DecodedArgs["amount"].(string)
		return &Effect{Type: "erc20_transfer", Token: strings.ToLower(token), From: from, To: strings.ToLower(to), Amount: amt}
	case "erc20_approve":
		token, _ := res.DecodedArgs["token"].(string)
		spender, _ := res.DecodedArgs["spender"].(string)
		amt, _ := res.DecodedArgs["amount"].(string)
		return &Effect{Type: "erc20_approve", Token: strings.ToLower(token), From: from, To: strings.ToLower(spender), Amount: amt}
	}
	return nil
}

// decodeRevertHex decodes a 0x-prefixed revert-data blob (as surfaced by
// callTracer's revertReason field) into a human string.
func decodeRevertHex(s string) string {
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) < 4+64 {
		return s
	}
	if hex.EncodeToString(raw[:4]) != "08c379a0" {
		return s
	}
	length := new(big.Int).SetBytes(raw[4+32 : 4+64]).Int64()
	if length <= 0 || int64(len(raw)) < 4+64+length {
		return s
	}
	return string(raw[4+64 : 4+64+length])
}

// prestateTracer diff-mode output shape:
//
//	{
//	  "pre":  { "<addr>": { "balance": "0x...", "nonce": 1, ... }, ... },
//	  "post": { "<addr>": { "balance": "0x...", ... },            ... }
//	}
//
// Only addresses whose state actually changed appear in either map.
func extractBalanceChanges(raw json.RawMessage) []BalanceChange {
	var diff struct {
		Pre  map[string]map[string]any `json:"pre"`
		Post map[string]map[string]any `json:"post"`
	}
	if err := json.Unmarshal(raw, &diff); err != nil {
		return nil
	}
	out := make([]BalanceChange, 0, len(diff.Pre))
	seen := make(map[string]bool)
	// Iterate pre first so we see every address that had state.
	for addr, pre := range diff.Pre {
		seen[addr] = true
		preBal := hexBigInt(pre["balance"])
		var postBal *big.Int
		if post, ok := diff.Post[addr]; ok {
			postBal = hexBigInt(post["balance"])
		}
		if preBal == nil && postBal == nil {
			continue
		}
		if preBal == nil {
			preBal = big.NewInt(0)
		}
		if postBal == nil {
			postBal = big.NewInt(0)
		}
		delta := new(big.Int).Sub(postBal, preBal)
		if delta.Sign() == 0 {
			continue
		}
		out = append(out, BalanceChange{Address: strings.ToLower(addr), Delta: delta.String()})
	}
	// Addresses that only appear in post (newly created accounts).
	for addr, post := range diff.Post {
		if seen[addr] {
			continue
		}
		postBal := hexBigInt(post["balance"])
		if postBal == nil || postBal.Sign() == 0 {
			continue
		}
		out = append(out, BalanceChange{Address: strings.ToLower(addr), Delta: postBal.String()})
	}
	return out
}

func hexBigInt(v any) *big.Int {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return nil
	}
	return n
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
	rpcCtx, rpcCancel := context.WithTimeout(ctx, 10*time.Second)
	defer rpcCancel()
	b64 := base64.StdEncoding.EncodeToString(tx.Raw)
	raw, err := n.DoRPCNamedCtx(rpcCtx, "simulateTransaction", map[string]any{
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
	if tx.To != "" && tx.Amount != nil {
		res.DecodedMethod = "native_transfer"
		res.DecodedArgs = map[string]any{"to": tx.To, "amount": tx.Amount.String()}
	}

	// Dry-run preview path: no Raw bytes built yet, but enough
	// intent to plan the spend. Run the same coin-selection +
	// fee math buildBitcoinTx would, but stop before signing —
	// gives the approval UI a "you would spend these inputs,
	// pay this fee, get this change back" view without a wallet
	// commit.
	if len(tx.Raw) == 0 {
		if tx.Type == "bitcoin_transfer" && tx.From != "" && tx.To != "" && tx.Amount != nil {
			if err := simulateBitcoinDryRun(e, n, tx, res); err != nil {
				res.Warnings = append(res.Warnings, Warning{
					Code:    "bitcoin_dryrun_failed",
					Message: err.Error(),
				})
			}
		}
		return res, nil
	}

	// Decode-from-Raw path: tx is already built (post-validate /
	// post-buildBitcoinTx), surface its actual on-wire shape.
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
	res.BitcoinVSize = len(tx.Raw)
	return res, nil
}

// simulateBitcoinDryRun mirrors buildBitcoinTx's selection + fee math
// without signing, so the approval UI can show what the user is about
// to commit to before any wallet keys are touched. Reads the same
// fetchBitcoinAllUTXOs source the build path uses, honours
// tx.UTXOs (manual selection), and produces resolved input
// addresses + amounts so the preview reads like "spend ltc1...XX,
// L...YY → ltc1<recipient> + change to ltc1<change>, fee 1234 sats".
func simulateBitcoinDryRun(e wltintf.Env, n *wltnet.Network, tx *Transaction, res *SimulationResult) error {
	wantSats := tx.Amount.Value().Int64()
	if wantSats <= 0 {
		return errors.New("invalid amount")
	}

	// Resolve the spending account from tx.From — we need the
	// xpub + DerivePublic to render input addresses for the
	// preview. Validate already set tx.From if it was empty, so
	// FindAccount has a concrete value to look up.
	acct, err := wltacct.FindAccount(e, tx.From)
	if err != nil {
		return fmt.Errorf("find account %q: %w", tx.From, err)
	}
	xpub, err := acct.Xpub()
	if err != nil {
		return fmt.Errorf("xpub: %w", err)
	}
	allUTXOs, err := fetchBitcoinAllUTXOs(n, xpub)
	if err != nil {
		return err
	}
	if len(allUTXOs) == 0 {
		return errors.New("no spendable UTXOs")
	}

	feeRate, err := bitcoinFeeRate(n)
	if err != nil {
		feeRate = 10
	}

	var selected []bitcoinTxo
	var totalIn int64
	if len(tx.UTXOs) > 0 {
		owned := make(map[string]bitcoinTxo, len(allUTXOs))
		for _, u := range allUTXOs {
			owned[u.Txo] = u
		}
		for _, ref := range tx.UTXOs {
			u, ok := owned[ref]
			if !ok {
				return fmt.Errorf("UTXO %q not owned", ref)
			}
			selected = append(selected, u)
			totalIn += int64(u.Amt)
		}
	} else {
		selected, totalIn, err = selectUTXOs(allUTXOs, wantSats, feeRate)
		if err != nil {
			return err
		}
	}

	estVSize := estimateMixedTxVSize(selected, 2)
	fee := int64(estVSize) * feeRate
	change := totalIn - wantSats - fee
	if change < 0 {
		return fmt.Errorf("insufficient funds: have %d, need %d + fee %d", totalIn, wantSats, fee)
	}

	tag := outscriptAddressTag(n.ChainId)
	for _, u := range selected {
		entry := BitcoinIO{
			Amount: int64(u.Amt),
			Path:   u.Path,
		}
		if txid, vout, perr := parseTxoRef(u.Txo); perr == nil {
			entry.TxID = hex.EncodeToString(txid)
			entry.Vout = vout
		}
		if addr, derr := deriveAddressForTxo(acct, u, tag); derr == nil {
			entry.Address = addr
		}
		res.BitcoinInputs = append(res.BitcoinInputs, entry)
	}

	res.BitcoinOutputs = append(res.BitcoinOutputs, BitcoinIO{
		Address: tx.To,
		Amount:  wantSats,
	})
	if change > 546 {
		// Next clean change index — same source the build path uses.
		changeIndex := 0
		if changeUtxos, cerr := fetchBitcoinUTXOs(n, xpub, "m/1"); cerr == nil {
			changeIndex = changeUtxos.LastI + 1
		}
		if changeAddr, cerr := acct.ChangeAddress(n.ChainId, changeIndex); cerr == nil {
			res.BitcoinOutputs = append(res.BitcoinOutputs, BitcoinIO{
				Address: changeAddr,
				Amount:  change,
			})
			res.BitcoinChange = change
		}
	} else {
		// Change goes to fee (dust threshold) — match buildBitcoinTx.
		fee += change
		change = 0
	}
	res.BitcoinFee = fee
	res.BitcoinVSize = estVSize
	return nil
}

