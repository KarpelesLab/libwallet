package wltswap

// EVM approval helpers.
//
// ERC-20 allowance checks and approve-tx building for the 1inch
// adapter. Solana providers don't need this — SPL transfers
// operate on token accounts, there's no "approve spender" concept.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wlttx"
)

// erc20ApproveSelector is keccak256("approve(address,uint256)")[:4].
// Hardcoded to avoid pulling a keccak dependency.
const erc20ApproveSelector = "095ea7b3"

// erc20AllowanceSelector is keccak256("allowance(address,address)")[:4].
const erc20AllowanceSelector = "dd62ed3e"

// approvalMaxSentinel is the string the caller passes to
// Swap:buildApproval's ApprovalAmount to request an unlimited
// approval (encodes to 2^256 - 1). Same sentinel used in logs /
// error messages so apps can pattern-match.
const approvalMaxSentinel = "max"

// approvalMax is the uint256 value used when the caller opts into
// an unlimited approval. Equal to (2^256 - 1).
var approvalMax = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// encodeERC20Approve builds the call data for ERC-20
// approve(address spender, uint256 amount). Returns a 0x-prefixed
// hex string.
func encodeERC20Approve(spender string, amount *big.Int) (string, error) {
	addr, ok := strings.CutPrefix(strings.ToLower(spender), "0x")
	if !ok {
		return "", errors.New("erc20 approve spender must be a 0x-prefixed address")
	}
	if len(addr) != 40 {
		return "", fmt.Errorf("erc20 approve spender must be 20 bytes (40 hex chars), got %d", len(addr))
	}
	addrBytes, err := hex.DecodeString(addr)
	if err != nil {
		return "", fmt.Errorf("erc20 approve spender: %w", err)
	}
	if amount == nil || amount.Sign() < 0 {
		return "", errors.New("erc20 approve amount must be non-negative")
	}
	if amount.BitLen() > 256 {
		return "", errors.New("erc20 approve amount overflows uint256")
	}

	addrPadded := make([]byte, 32)
	copy(addrPadded[12:], addrBytes)

	amountBytes := amount.Bytes()
	amountPadded := make([]byte, 32)
	copy(amountPadded[32-len(amountBytes):], amountBytes)

	return "0x" + erc20ApproveSelector + hex.EncodeToString(addrPadded) + hex.EncodeToString(amountPadded), nil
}

// readERC20Allowance does an eth_call of allowance(owner, spender)
// on the token contract. Returns the current allowance as a
// *big.Int in token base units. Any RPC failure returns 0 + the
// error — callers that want a best-effort value can check the error
// and treat it as "unknown".
func readERC20Allowance(ctx context.Context, n *wltnet.Network, token, owner, spender string) (*big.Int, error) {
	ownerAddr, err := hexAddressBytes(owner)
	if err != nil {
		return nil, fmt.Errorf("owner: %w", err)
	}
	spenderAddr, err := hexAddressBytes(spender)
	if err != nil {
		return nil, fmt.Errorf("spender: %w", err)
	}

	ownerPadded := make([]byte, 32)
	copy(ownerPadded[12:], ownerAddr)
	spenderPadded := make([]byte, 32)
	copy(spenderPadded[12:], spenderAddr)

	data := "0x" + erc20AllowanceSelector + hex.EncodeToString(ownerPadded) + hex.EncodeToString(spenderPadded)

	call := map[string]any{
		"to":   token,
		"data": data,
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hexOut, err := ethrpc.ReadString(n.DoRPCCtx(rpcCtx, "eth_call", call, "latest"))
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(hexOut, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode eth_call result: %w", err)
	}
	return new(big.Int).SetBytes(raw), nil
}

// hexAddressBytes validates and decodes a 0x-prefixed EVM address.
func hexAddressBytes(addr string) ([]byte, error) {
	lower := strings.ToLower(addr)
	if !strings.HasPrefix(lower, "0x") {
		return nil, errors.New("not a 0x-prefixed address")
	}
	b, err := hex.DecodeString(lower[2:])
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("address must be 20 bytes, got %d", len(b))
	}
	return b, nil
}

// ApprovalPreview is returned by Swap:buildApproval. It carries
// every field a UI approval sheet typically renders — spender
// address + human label, decoded amount, unlimited-flag, network
// fee estimate — plus the underlying Transaction the caller feeds
// into Transaction:signAndSend.
//
// The UI pattern:
//
//	"Approve <preview.token.symbol>"
//	"to <preview.spenderLabel> (<preview.spender>)"
//	"amount: <preview.amount> (<'Unlimited' if preview.isUnlimited>)"
//	"network fee ~ <preview.networkFee>"
//	[Approve] [Cancel]
type ApprovalPreview struct {
	// Token being approved.
	Token TokenRef `json:"token"`
	// Spender is the address receiving the allowance.
	Spender string `json:"spender"`
	// SpenderLabel is the aggregator's friendly name (e.g.
	// "1inch Aggregation Router"). Derived from the quote's
	// ProviderLabel. UIs can map / override as they see fit.
	SpenderLabel string `json:"spenderLabel,omitempty"`
	// Amount is the approval amount in token base units.
	Amount *wltobj.Amount `json:"amount"`
	// IsUnlimited flags approvals at or near uint256.max — same
	// threshold used by the erc20_approve_unlimited simulate
	// warning (top bit set).
	IsUnlimited bool `json:"isUnlimited"`
	// CurrentAllowance is what's already approved — zero for
	// first-time approvals. Helps the UI say "current 0 → 1.0".
	CurrentAllowance *wltobj.Amount `json:"currentAllowance,omitempty"`
	// NetworkFee is the estimated chain gas cost for the approval
	// tx itself (distinct from the swap's gas).
	NetworkFee *wltobj.Amount `json:"networkFee,omitempty"`
	// Tx is the validated Transaction the app feeds into
	// Transaction:signAndSend. Already has Nonce / Gas / GasPrice
	// / Fee populated.
	Tx *wlttx.Transaction `json:"tx"`
}

// BuildApprovalRequest is the input to Swap:buildApproval.
type BuildApprovalRequest struct {
	QuoteId string `json:"quoteId"`
	// ApprovalAmount overrides the default approval. Empty means
	// "exactly the quote's amountIn" — the safest value: even if
	// the spender contract is compromised later, it can only drain
	// what the user already agreed to swap right now.
	//
	// Accepted forms:
	//   - "" (omitted): exact amountIn
	//   - "max" or "unlimited": 2^256-1 (OpenZeppelin convention)
	//   - any decimal string: approve that many base units
	//
	// Raising the amount above amountIn is a user-driven choice —
	// convenient for batching multiple swaps against a router but
	// widens the blast radius if that router is ever exploited.
	ApprovalAmount string `json:"approvalAmount,omitempty"`
	// From optionally overrides the account; defaults to the one
	// the quote was issued to.
	From string `json:"from,omitempty"`
}

// resolveApprovalAmount converts the caller-supplied sentinel
// or decimal string into a concrete *big.Int. Defaults to the
// quote's AmountIn when the request field is empty.
func resolveApprovalAmount(req *BuildApprovalRequest, q *Quote) (*big.Int, error) {
	if req.ApprovalAmount == "" {
		// Default: exactly what the swap needs.
		return new(big.Int).Set(q.AmountIn.Value()), nil
	}
	if lc := strings.ToLower(req.ApprovalAmount); lc == approvalMaxSentinel || lc == "unlimited" {
		return new(big.Int).Set(approvalMax), nil
	}
	v, ok := new(big.Int).SetString(req.ApprovalAmount, 10)
	if !ok || v.Sign() < 0 {
		return nil, newErr(ErrCodeInvalidRequest, fmt.Sprintf("approvalAmount %q is not a non-negative decimal or the %q sentinel", req.ApprovalAmount, approvalMaxSentinel))
	}
	return v, nil
}

// swapBuildApproval is the Swap:buildApproval endpoint. Returns an
// unsigned wlttx.Transaction (Type=evm) the caller feeds into
// Transaction:signAndSend.
func swapBuildApproval(ctx context.Context, req *BuildApprovalRequest) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if req == nil || req.QuoteId == "" {
		return nil, newErr(ErrCodeInvalidRequest, "quoteId is required")
	}
	q, ok := quoteCache.get(req.QuoteId)
	if !ok {
		return nil, newErr(ErrCodeQuoteNotFound, "quote not found or expired")
	}
	if q.Chain != "evm" {
		return nil, newErr(ErrCodeInvalidRequest, "approvals are only relevant for EVM swaps — Solana has no allowance model")
	}
	if !q.RequiresApproval {
		return nil, newErr(ErrCodeInvalidRequest, "quote does not require an approval (native-in swap or existing allowance already covers amountIn)")
	}
	amount, err := resolveApprovalAmount(req, q)
	if err != nil {
		return nil, err
	}
	data, err := encodeERC20Approve(q.ApprovalSpender, amount)
	if err != nil {
		return nil, err
	}

	from := req.From
	if from == "" {
		from = q.from
	}
	tx := &wlttx.Transaction{
		Type:   "evm",
		From:   from,
		To:     q.TokenIn.Address, // the token contract
		Value:  wltobj.NewAmountRaw(big.NewInt(0), q.TokenIn.Decimals),
		Amount: wltobj.NewAmountRaw(new(big.Int).Set(amount), q.TokenIn.Decimals),
		Data:   data,
	}
	// Validate fills in Nonce / Gas / fee fields so the caller can
	// immediately pass the tx to Transaction:signAndSend without a
	// second round-trip.
	if err := tx.Validate(e); err != nil {
		return nil, fmt.Errorf("validate approval tx: %w", err)
	}

	return &ApprovalPreview{
		Token:            q.TokenIn,
		Spender:          q.ApprovalSpender,
		SpenderLabel:     approvalSpenderLabel(q),
		Amount:           wltobj.NewAmountRaw(new(big.Int).Set(amount), q.TokenIn.Decimals),
		IsUnlimited:      isUnlimitedApprovalAmount(amount),
		CurrentAllowance: q.CurrentAllowance,
		NetworkFee:       tx.Fee,
		Tx:               tx,
	}, nil
}

// isUnlimitedApprovalAmount reports whether amount is at or above
// the 2^255 threshold also used by the erc20_approve_unlimited
// simulate warning. Kept in sync with wlttx.unlimitedApprovalThreshold.
func isUnlimitedApprovalAmount(amount *big.Int) bool {
	if amount == nil {
		return false
	}
	threshold := new(big.Int).Lsh(big.NewInt(1), 255)
	return amount.Cmp(threshold) >= 0
}

// approvalSpenderLabel maps the quote's provider to a user-facing
// label for the spender contract. For 1inch the router is their
// "Aggregation Router V6" on every chain; future adapters with
// multiple possible spenders would extend the switch.
func approvalSpenderLabel(q *Quote) string {
	switch q.Provider {
	case "1inch":
		return "1inch Aggregation Router"
	}
	if q.ProviderLabel != "" {
		return q.ProviderLabel + " Router"
	}
	return q.Provider
}
