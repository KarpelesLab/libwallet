package wltbase

// Unified sign-request payloads.
//
// libwallet deliberately collapses the chain-specific sign events
// into two shapes — TransactionSignValue (anything that lands
// on-chain) and MessageSignValue (anything that doesn't) —  so host
// UIs render one approval sheet per category with typed decoded
// data, not three near-duplicates per category.
//
// Every field populated here comes from libwallet's own decoders
// so the host doesn't need a follow-up Transaction:simulate round-
// trip: by the time the PendingRequest hits the Dart stream, the
// sheet has everything it needs to say "Send 0.01 ETH to 0x…" /
// "Approve unlimited USDC to 1inch Router" / "Sign in to
// uniswap.org".

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/KarpelesLab/libwallet/wltcontract"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttx"
)

// SignEffect is one observable transfer or approval triggered by a
// transaction at any call depth. Mirrors wlttx.Effect but is
// flattened into the request so the host doesn't need a second
// types package.
type SignEffect struct {
	// Type: "native_transfer" | "erc20_transfer" | "erc20_approve"
	// | "spl_transfer" | "bitcoin_output".
	Type string `json:"type"`
	// Token contract/mint address. Empty for native transfers and
	// Bitcoin outputs.
	Token string `json:"token,omitempty"`
	// From / To addresses in the chain's native format
	// (0x-prefixed hex on EVM, base58 on Solana, base58 on Bitcoin).
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Amount in the token's base units, as an unsigned decimal
	// integer string. Apps convert to display using token
	// decimals (included in DecodedArgs or a separate lookup).
	Amount string `json:"amount,omitempty"`
}

// SignBalanceChange is one address's signed native-balance delta
// caused by a tx. Negative = loss (includes fees on the sender),
// positive = gain. Apps compare to DecodedArgs / Effects to detect
// "drainer" patterns where the sender's delta is worse than what
// the tx purports to do.
type SignBalanceChange struct {
	Address string `json:"address"`
	// Signed decimal integer string in the chain's native base
	// units (wei / lamports / sats).
	Delta string `json:"delta"`
}

// SignWarning is an advisory the UI can surface in the approval
// sheet. Stable codes keep the UI copy table short:
//
//	insufficient_balance / below_sender_rent /
//	recipient_rent_not_funded / recipient_is_contract /
//	recipient_new_account / erc20_approve_unlimited /
//	net_loss_exceeds_amount / priority_fee_recommended
type SignWarning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // "info" | "warn" | "block"
	Message  string `json:"message"`
	Field    string `json:"field,omitempty"` // "to" | "amount" | "fee"
}

// SignBitcoinIO is one input or output of a Bitcoin-family tx after
// decoding. Duplicates wlttx.BitcoinIO so the host doesn't need the
// wlttx package just to read an approval sheet.
type SignBitcoinIO struct {
	Address string `json:"address,omitempty"`
	Amount  int64  `json:"amount,omitempty"` // sats
	Script  string `json:"script,omitempty"` // hex
	TxID    string `json:"txid,omitempty"`
	Vout    uint32 `json:"vout,omitempty"`
}

// TransactionSignValue is the unified payload for any on-chain
// transaction-signing approval request. The Chain and Method
// fields tell the host which UI section to render; everything
// else is decoded into chain-agnostic primitives where possible
// and falls back to chain-specific extras when the concept doesn't
// translate (SolanaLogs, BitcoinInputs, etc.).
type TransactionSignValue struct {
	Chain  string `json:"chain"`  // "evm" | "solana" | "bitcoin"
	Method string `json:"method"` // the original RPC method name

	// From: the signer's address in the chain's native format.
	From string `json:"from,omitempty"`

	// Network identifier ("<type>.<chainId>") for UI copy plus
	// the full Network struct for detail displays.
	NetworkId   string          `json:"networkId,omitempty"`
	Network     *wltnet.Network `json:"network,omitempty"`
	NetworkName string          `json:"networkName,omitempty"`

	// SizeBytes: the serialized raw tx size. Useful for the
	// "this transaction is X bytes" info line.
	SizeBytes int `json:"sizeBytes"`
	// Raw: hex (EVM/Bitcoin) or base64 (Solana) — the dev-mode
	// "see raw" view. Apps that don't need it can ignore.
	Raw string `json:"raw,omitempty"`

	// ── Decoded top-level view ────────────────────────────────

	// DecodedMethod: recognized operation — "native_transfer" |
	// "erc20_transfer" | "erc20_approve" | "spl_transfer" |
	// "bitcoin_transfer" | "unknown".
	DecodedMethod string         `json:"decodedMethod,omitempty"`
	DecodedArgs   map[string]any `json:"decodedArgs,omitempty"`

	// Effects: every transfer/approve this tx will cause, at any
	// call depth. Populated by debug_traceCall on EVM when the
	// node supports it; by the handcoded decoders on other
	// chains for the common cases.
	Effects []SignEffect `json:"effects,omitempty"`

	// BalanceChanges: signed native-balance deltas per address
	// across the simulation. Empty when the node or chain doesn't
	// expose a prestate-style trace.
	BalanceChanges []SignBalanceChange `json:"balanceChanges,omitempty"`

	// Warnings surfaced to the approval sheet. Stable codes —
	// see SignWarning.
	Warnings []SignWarning `json:"warnings,omitempty"`

	// ── Revert / fee ──────────────────────────────────────────

	WillRevert   bool   `json:"willRevert,omitempty"`
	RevertReason string `json:"revertReason,omitempty"`

	// Fee estimate in base units. FeeDecimals + FeeSymbol let the
	// UI render without a second network lookup.
	FeeAmount   string `json:"feeAmount,omitempty"`
	FeeDecimals int    `json:"feeDecimals,omitempty"`
	FeeSymbol   string `json:"feeSymbol,omitempty"`

	// ── Chain-specific extras ─────────────────────────────────

	// EvmTransaction: the full Transaction record (populated by
	// Validate). Includes gas, nonce, data, etc. for dev-mode.
	EvmTransaction *wlttx.Transaction `json:"evmTransaction,omitempty"`

	// Solana: compute-unit cost and program log lines from a
	// simulateTransaction roundtrip.
	SolanaUnitsConsumed uint64   `json:"solanaUnitsConsumed,omitempty"`
	SolanaLogs          []string `json:"solanaLogs,omitempty"`

	// Bitcoin: decoded inputs and outputs.
	BitcoinInputs  []SignBitcoinIO `json:"bitcoinInputs,omitempty"`
	BitcoinOutputs []SignBitcoinIO `json:"bitcoinOutputs,omitempty"`
	// Bitcoin fee in satoshi (sum(in) − sum(out) when inputs are
	// resolvable; zero otherwise).
	BitcoinFeeSats int64 `json:"bitcoinFeeSats,omitempty"`
}

// MessageSignValue is the unified payload for arbitrary-data /
// login signing — personal_sign, eth_signTypedData*,
// solana_signMessage, mpurse_signMessage. The pattern-recognition
// fields (IsSIWE / IsSIWS / SIWEFields) let hosts render "Sign in
// to example.com" instead of an opaque byte dump when the message
// matches a known standard.
type MessageSignValue struct {
	Chain  string `json:"chain"`  // "evm" | "solana" | "bitcoin"
	Method string `json:"method"` // RPC method that triggered the request

	// From: the signer's address in the chain's native format.
	From string `json:"from,omitempty"`

	// MessageBytes: raw bytes to sign, base64-encoded for JSON
	// transport. Always populated — even for EIP-712 where
	// StructuredData is the human-readable view.
	MessageBytes string `json:"messageBytes,omitempty"`
	// MessageText: UTF-8 decode of MessageBytes when valid,
	// empty otherwise. Host falls back to MessageBytes (hex or
	// base64) for display when this is empty.
	MessageText string `json:"messageText,omitempty"`

	// StructuredData: EIP-712 parsed object
	// {domain, types, primaryType, message}. Set only for
	// eth_signTypedData* methods.
	StructuredData map[string]any `json:"structuredData,omitempty"`

	// StructuredPrimaryType / StructuredDomain — pre-extracted
	// convenience getters so the UI doesn't drill into the raw
	// StructuredData map for common fields.
	StructuredPrimaryType string         `json:"structuredPrimaryType,omitempty"`
	StructuredDomain      map[string]any `json:"structuredDomain,omitempty"`

	// VerifyingContractLabel: curated display label for the EIP-712
	// domain's verifyingContract, when the address matches a known
	// entry in wltcontract — e.g. "Uniswap V3: SwapRouter02",
	// "OpenSea: Seaport 1.6". Empty when there's no curated match
	// (custom contract, chain not yet in the registry); the host
	// shows the raw address in that case.
	//
	// Backed by wltcontract.Lookup; the same registry is exposed
	// as a generic primitive via Contracts:lookup for hosts that
	// want to label addresses at other render sites.
	VerifyingContractLabel string `json:"verifyingContractLabel,omitempty"`

	// IsSIWE / IsSIWS: auto-detected Sign-In-With-Ethereum /
	// Sign-In-With-Solana pattern. Empty MessageText means the
	// detector didn't run.
	IsSIWE bool `json:"isSiwe,omitempty"`
	IsSIWS bool `json:"isSiws,omitempty"`
	// SIWEFields: parsed {domain, uri, version, chainId, nonce,
	// issuedAt, expirationTime, statement, address, …} when
	// IsSIWE. Empty for non-SIWE messages.
	SIWEFields map[string]string `json:"siweFields,omitempty"`

	// Warnings: advisories — e.g. "message contains a URL",
	// "message mentions private keys". Empty when nothing is
	// worth flagging.
	Warnings []SignWarning `json:"warnings,omitempty"`
}

// ── Decoded-data helpers ───────────────────────────────────────

// txSimResultAsSignValue copies the fields the Transaction:simulate
// SimulationResult exposes into the unified SignValue — effects,
// balance changes, warnings, decoded method, gas estimate. Called
// from the EVM sign path right after the tx is validated.
func txSimResultAsSignValue(sim any, dst *TransactionSignValue) {
	// sim is an *wlttx.SimulationResult but we avoid the import
	// coupling by going through JSON — SimulationResult's public
	// fields line up with our typed names.
	if sim == nil {
		return
	}
	buf, err := json.Marshal(sim)
	if err != nil {
		return
	}
	var r struct {
		WillRevert    bool                `json:"willRevert"`
		RevertReason  string              `json:"revertReason"`
		DecodedMethod string              `json:"decodedMethod"`
		DecodedArgs   map[string]any      `json:"decodedArgs"`
		Effects       []wlttxEffectShape  `json:"effects"`
		Balance       []wlttxBalanceShape `json:"balanceChanges"`
		Warnings      []wlttxWarningShape `json:"warnings"`
		GasEstimate   uint64              `json:"gasEstimate"`
		Logs          []string            `json:"logs"`
		UnitsConsumed uint64              `json:"unitsConsumed"`
		BitcoinFee    int64               `json:"bitcoinFee"`
		BitcoinIns    []wlttxBtcIO        `json:"bitcoinInputs"`
		BitcoinOuts   []wlttxBtcIO        `json:"bitcoinOutputs"`
	}
	if err := json.Unmarshal(buf, &r); err != nil {
		return
	}
	dst.WillRevert = r.WillRevert
	dst.RevertReason = r.RevertReason
	if dst.DecodedMethod == "" && r.DecodedMethod != "" {
		dst.DecodedMethod = r.DecodedMethod
	}
	if dst.DecodedArgs == nil {
		dst.DecodedArgs = r.DecodedArgs
	}
	for _, e := range r.Effects {
		dst.Effects = append(dst.Effects, SignEffect{Type: e.Type, Token: e.Token, From: e.From, To: e.To, Amount: e.Amount})
	}
	for _, b := range r.Balance {
		dst.BalanceChanges = append(dst.BalanceChanges, SignBalanceChange{Address: b.Address, Delta: b.Delta})
	}
	for _, w := range r.Warnings {
		dst.Warnings = append(dst.Warnings, SignWarning{Code: w.Code, Severity: w.Severity, Message: w.Message, Field: w.Field})
	}
	if r.UnitsConsumed > 0 {
		dst.SolanaUnitsConsumed = r.UnitsConsumed
	}
	if len(r.Logs) > 0 {
		dst.SolanaLogs = r.Logs
	}
	if r.BitcoinFee > 0 {
		dst.BitcoinFeeSats = r.BitcoinFee
	}
	for _, io := range r.BitcoinIns {
		dst.BitcoinInputs = append(dst.BitcoinInputs, SignBitcoinIO{Address: io.Address, Amount: io.Amount, Script: io.Script, TxID: io.TxID, Vout: io.Vout})
	}
	for _, io := range r.BitcoinOuts {
		dst.BitcoinOutputs = append(dst.BitcoinOutputs, SignBitcoinIO{Address: io.Address, Amount: io.Amount, Script: io.Script, TxID: io.TxID, Vout: io.Vout})
	}
}

// Shadow shapes for the JSON round-trip above.
type wlttxEffectShape struct {
	Type   string `json:"type"`
	Token  string `json:"token"`
	From   string `json:"from"`
	To     string `json:"to"`
	Amount string `json:"amount"`
}
type wlttxBalanceShape struct {
	Address string `json:"address"`
	Delta   string `json:"delta"`
}
type wlttxWarningShape struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Field    string `json:"field"`
}
type wlttxBtcIO struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
	Script  string `json:"script"`
	TxID    string `json:"txid"`
	Vout    uint32 `json:"vout"`
}

// ── Message decoder helpers ─────────────────────────────────────

// utf8Text returns s decoded as UTF-8 when valid and printable,
// empty string otherwise. Stricter than just "valid UTF-8" — rejects
// control characters so we don't surface raw binary as "text".
func utf8Text(b []byte) string {
	if !isPrintableUTF8(b) {
		return ""
	}
	return string(b)
}

func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range string(b) {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// siweRegex matches the canonical "…wants you to sign in…" phrase
// from EIP-4361. Detection is best-effort — a malformed SIWE
// message falls back to the plain-text view.
var siweRegex = regexp.MustCompile(`(?m)^(?P<domain>[^\s]+) wants you to sign in with your Ethereum account:`)

// siwsRegex — Sign-In With Solana (EIP-4361-inspired). Same shape,
// different family.
var siwsRegex = regexp.MustCompile(`(?m)^(?P<domain>[^\s]+) wants you to sign in with your Solana account:`)

// detectSIWE populates dst.IsSIWE and dst.SIWEFields when the
// plain-text message matches the SIWE pattern.
func detectSIWE(dst *MessageSignValue) {
	if dst.MessageText == "" {
		return
	}
	if m := siweRegex.FindStringSubmatch(dst.MessageText); m != nil {
		dst.IsSIWE = true
		dst.SIWEFields = parseSIWEFields(dst.MessageText, m[1])
		return
	}
	if m := siwsRegex.FindStringSubmatch(dst.MessageText); m != nil {
		dst.IsSIWS = true
		dst.SIWEFields = parseSIWEFields(dst.MessageText, m[1])
	}
}

// parseSIWEFields pulls the standard EIP-4361 keys out of a
// SIWE/SIWS message body. Best-effort — keys not found simply
// aren't in the returned map.
func parseSIWEFields(text, domain string) map[string]string {
	out := map[string]string{"domain": domain}
	// EIP-4361 keys that appear as "Key: value" lines.
	for _, key := range []string{"URI", "Version", "Chain ID", "Nonce", "Issued At", "Expiration Time", "Not Before", "Request ID", "Resources"} {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `: (.+)$`)
		if m := re.FindStringSubmatch(text); m != nil {
			out[strings.ToLower(strings.ReplaceAll(key, " ", ""))] = strings.TrimSpace(m[1])
		}
	}
	// Address shows up as the second line by convention.
	lines := strings.Split(text, "\n")
	if len(lines) >= 2 {
		addr := strings.TrimSpace(lines[1])
		if strings.HasPrefix(addr, "0x") && len(addr) == 42 {
			out["address"] = addr
		}
	}
	return out
}

// hasURL reports whether a message text contains an http(s) URL —
// worth warning on, since SIWE-style messages with unexpected URLs
// can be phishing vectors.
func hasURL(text string) bool {
	if text == "" {
		return false
	}
	for _, tok := range strings.Fields(text) {
		tok = strings.TrimRight(tok, ".,;)")
		if u, err := url.Parse(tok); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			return true
		}
	}
	return false
}

// extractPrimaryAndDomain pulls primaryType + domain out of an
// EIP-712 typed-data object (any shape).
func extractPrimaryAndDomain(td map[string]any) (primaryType string, domain map[string]any) {
	if v, ok := td["primaryType"].(string); ok {
		primaryType = v
	}
	if v, ok := td["domain"].(map[string]any); ok {
		domain = v
	}
	return
}

// lookupVerifyingContractLabel returns the curated label for the EIP-712
// domain's verifyingContract on chain, or "" when no curated entry exists
// (custom contract, chain not yet covered). chain is the wltnet.Network
// .Type ("evm" / "solana") — pulled from the signing-request context;
// the domain's chainId determines which chain registry to consult.
//
// Only fires for EVM. EIP-712 on Solana exists but the verifyingContract
// pattern doesn't apply the same way.
func lookupVerifyingContractLabel(chain string, domain map[string]any) string {
	if chain != "evm" || domain == nil {
		return ""
	}
	vc, _ := domain["verifyingContract"].(string)
	if vc == "" {
		return ""
	}
	// EIP-712 chainId can be a JSON number or a string. Normalise.
	var chainId string
	switch v := domain["chainId"].(type) {
	case string:
		// Some dApps send hex ("0x1"); normalise to decimal so the
		// chainId matches our registry's "evm.<decimalChainId>" key.
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			if b, ok := new(big.Int).SetString(v, 0); ok {
				chainId = b.Text(10)
			}
		} else {
			chainId = v
		}
	case float64:
		chainId = strconv.FormatInt(int64(v), 10)
	case int:
		chainId = strconv.Itoa(v)
	case int64:
		chainId = strconv.FormatInt(v, 10)
	case json.Number:
		chainId = string(v)
	}
	if chainId == "" {
		return ""
	}
	e := wltcontract.Lookup(chain, chainId, vc)
	if e == nil {
		return ""
	}
	return e.Label
}

// ── Base64 / hex helpers ─────────────────────────────────────

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hexEncode(b []byte) string { return hex.EncodeToString(b) }
func bigIntStr(i *big.Int) string {
	if i == nil {
		return ""
	}
	return i.String()
}

// ptrOfAddr returns a pointer to s when non-empty, nil otherwise.
// Handy for assigning request.Account which is a *string.
func ptrOfAddr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// newMessageSignValue builds a MessageSignValue for arbitrary-data
// signing. typedDataJSON is the EIP-712 JSON string for
// eth_signTypedData* and empty for everything else.
func newMessageSignValue(ctx context.Context, chain, method, from, origin string, msgBytes []byte, typedDataJSON string) *MessageSignValue {
	val := &MessageSignValue{
		Chain:        chain,
		Method:       method,
		From:         from,
		MessageBytes: b64Encode(msgBytes),
	}
	if t := utf8Text(msgBytes); t != "" {
		val.MessageText = t
	}
	if typedDataJSON != "" {
		var td map[string]any
		if err := json.Unmarshal([]byte(typedDataJSON), &td); err == nil {
			val.StructuredData = td
			val.StructuredPrimaryType, val.StructuredDomain = extractPrimaryAndDomain(td)
			// Curated label for verifyingContract — sign sheet shows
			// "Uniswap V3: SwapRouter02" above the raw 0x… instead of
			// just hex when the address matches a known entry. Empty
			// when no match; host renders the address alone.
			val.VerifyingContractLabel = lookupVerifyingContractLabel(chain, val.StructuredDomain)
		}
		// Anti-blind-signing: surface cross-chain replay risk and
		// dangerous approval primitives (Permit / Permit2 / approve /
		// Seaport). Additive — these never block signing, they just
		// give the host enough to render an informed prompt.
		if parsed, err := ParseEIP712TypedData(typedDataJSON); err == nil {
			val.Warnings = append(val.Warnings, parsed.SecurityWarnings(activeEVMChainID(ctx, chain))...)
		}
	}
	detectSIWE(val)
	if val.MessageText != "" && hasURL(val.MessageText) {
		val.Warnings = append(val.Warnings, SignWarning{
			Code:     "message_contains_url",
			Severity: "info",
			Message:  "message contains a URL — verify it before signing",
		})
	}
	// SIWE/SIWS origin check: the domain/uri the message asks you to
	// sign in to should match the site that requested the signature.
	// A mismatch is a classic phishing pattern (a malicious page
	// asking you to sign in to a bank/exchange).
	if (val.IsSIWE || val.IsSIWS) && val.SIWEFields != nil {
		if w := siweOriginWarning(val.SIWEFields, origin); w != nil {
			val.Warnings = append(val.Warnings, *w)
		}
	}
	return val
}

// siweOriginWarning compares the SIWE/SIWS message's declared domain
// and uri against the requesting site's origin and returns a warning
// when they don't line up. requestOrigin is the request Host (e.g.
// "https://example.com"); empty disables the check.
func siweOriginWarning(fields map[string]string, requestOrigin string) *SignWarning {
	if requestOrigin == "" {
		return nil
	}
	originHost := hostOf(requestOrigin)
	if originHost == "" {
		return nil
	}
	domain := strings.TrimSpace(fields["domain"])
	uri := strings.TrimSpace(fields["uri"])
	mismatch := false
	if domain != "" && !hostMatches(domain, originHost) {
		mismatch = true
	}
	if uri != "" && !hostMatches(hostOf(uri), originHost) {
		mismatch = true
	}
	if !mismatch {
		return nil
	}
	detail := domain
	if detail == "" {
		detail = uri
	}
	return &SignWarning{
		Code:     "siwe_domain_mismatch",
		Severity: "warn",
		Message:  fmt.Sprintf("This sign-in message is for %q but the request came from %q. This can be a phishing attempt — verify before signing.", detail, originHost),
		Field:    "domain",
	}
}

// hostOf extracts the host (no scheme/port) from a URL or a bare
// "host[:port]" / "host/path" string.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Bare authority — strip any path then any port.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// hostMatches reports whether candidate equals host or is a subdomain
// relationship of it (either direction), tolerating the common
// "www." prefix.
func hostMatches(candidate, host string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	host = strings.ToLower(strings.TrimSpace(host))
	if candidate == "" || host == "" {
		return false
	}
	candidate = strings.TrimPrefix(candidate, "www.")
	host = strings.TrimPrefix(host, "www.")
	if candidate == host {
		return true
	}
	return strings.HasSuffix(candidate, "."+host) || strings.HasSuffix(host, "."+candidate)
}

// activeEVMChainID returns the wallet's current EVM network chain id
// (decimal string) for the cross-chain EIP-712 check, or "" when the
// active network isn't EVM or can't be resolved.
func activeEVMChainID(ctx context.Context, chain string) string {
	if chain != "evm" {
		return ""
	}
	env := getEnvFromCtx(ctx)
	if env == nil {
		return ""
	}
	n, err := wltnet.CurrentNetwork(env)
	if err != nil || n == nil || n.Type != "evm" {
		return ""
	}
	return n.ChainId
}

// ── Chain-specific TransactionSignValue builders ─────────────

// newEVMTransactionSignValue runs Simulate on a validated EVM tx
// and copies the decoded fields into a TransactionSignValue so the
// approval sheet has effects / balance changes / warnings without a
// second round-trip from Dart.
func newEVMTransactionSignValue(ctx context.Context, e wltintf.Env, n *wltnet.Network, tx *wlttx.Transaction, method string) *TransactionSignValue {
	val := &TransactionSignValue{
		Chain:          "evm",
		Method:         method,
		From:           tx.From,
		EvmTransaction: tx,
	}
	if n != nil {
		val.Network = n
		val.NetworkId = n.String()
		val.NetworkName = n.Name
		if info, err := n.GetChainInfo(); err == nil {
			val.FeeSymbol = info.NativeCurrency.Symbol
			val.FeeDecimals = info.NativeCurrency.Decimals
		}
	}
	if tx.Fee != nil {
		val.FeeAmount = bigIntStr(tx.Fee.Value())
		if val.FeeDecimals == 0 {
			val.FeeDecimals = tx.Fee.Exp()
		}
	}
	// Ballpark size — actual signed tx size is close to the
	// marshalled length of gas + nonce + to + value + data + signature.
	// Use len(tx.Data) + fixed overhead as a cheap proxy for the UI.
	val.SizeBytes = approxEVMTxSize(tx)
	val.Raw = tx.Data
	// Run simulate to decorate the value. Bounded timeout lives
	// inside Simulate itself.
	if sim, _ := wlttx.Simulate(ctx, tx); sim != nil {
		txSimResultAsSignValue(sim, val)
	}
	// Fall back for the bare-send case when simulate didn't decode.
	if val.DecodedMethod == "" {
		if tx.Data == "" || tx.Data == "0x" {
			val.DecodedMethod = "native_transfer"
			val.DecodedArgs = map[string]any{
				"to":     tx.To,
				"amount": bigIntStr(amountIntFor(tx)),
			}
		}
	}
	return val
}

// amountIntFor returns the effective value a tx is moving on-chain
// (Value field, falling back to Amount). Used only for the fallback
// decode path when simulate didn't run.
func amountIntFor(tx *wlttx.Transaction) *big.Int {
	if tx.Value != nil && tx.Value.Sign() > 0 {
		return tx.Value.Value()
	}
	if tx.Amount != nil {
		return tx.Amount.Value()
	}
	return big.NewInt(0)
}

// approxEVMTxSize returns a rough byte-size estimate for an EVM tx
// suitable for the "this transaction is X bytes" UI line. Not
// signature-accurate; real wire size depends on the sig's RLP
// encoding which we don't have yet at emit time.
func approxEVMTxSize(tx *wlttx.Transaction) int {
	size := 21 + 32 + 20 // fixed: sig (~65) + nonce + to
	if tx.Data != "" {
		if s, ok := strings.CutPrefix(tx.Data, "0x"); ok {
			size += len(s) / 2
		}
	}
	return size
}

// newSolanaTransactionSignValue builds a TransactionSignValue for a
// Solana sign or signAndSend request.
func newSolanaTransactionSignValue(ctx context.Context, e wltintf.Env, n *wltnet.Network, from, rawBase64, method string) *TransactionSignValue {
	val := &TransactionSignValue{
		Chain:  "solana",
		Method: method,
		From:   from,
		Raw:    rawBase64,
	}
	if n != nil {
		val.Network = n
		val.NetworkId = n.String()
		val.NetworkName = n.Name
		val.FeeSymbol = "SOL"
		val.FeeDecimals = 9
	}
	if raw, err := base64.StdEncoding.DecodeString(rawBase64); err == nil {
		val.SizeBytes = len(raw)
		// Best-effort local decode of a plain System Program
		// transfer — covers the common "send SOL to address"
		// case without round-tripping simulate.
		if from, to, amount, ok := decodeSolanaSystemTransfer(raw); ok {
			val.DecodedMethod = "native_transfer"
			val.DecodedArgs = map[string]any{
				"to":     to,
				"amount": amount,
			}
			val.Effects = append(val.Effects, SignEffect{
				Type:   "native_transfer",
				From:   from,
				To:     to,
				Amount: amount,
			})
		}
	}
	// Tiny Solana fee model: 5000 lamports base + priority.
	// Without a full tx object we can only guess; leave FeeAmount
	// empty for now — UI surfaces the fixed base when nothing
	// else is known.
	if val.FeeAmount == "" {
		val.FeeAmount = "5000"
	}
	// Optional: kick off simulateTransaction on the RPC to get
	// units + logs + a sanity check for revert. Skipped for now
	// since wltbase doesn't import wlttx's Solana simulate helper
	// and keeping this off the hot path is fine for v1. Hosts
	// that want richer decoded data can call Transaction:simulate
	// with the raw tx themselves.
	_ = ctx
	_ = e
	return val
}

// newBitcoinTransactionSignValue parses a raw hex Bitcoin tx and
// builds a TransactionSignValue with inputs + outputs. Input amounts
// and therefore the fee are populated only when libwallet also knows
// the prev-txo amounts (typically set by buildBitcoinTx at send
// time — external rawTxHex sent via mpurse_signRawTransaction leaves
// inputs amount-less).
func newBitcoinTransactionSignValue(ctx context.Context, e wltintf.Env, n *wltnet.Network, from, rawHex, method string) *TransactionSignValue {
	val := &TransactionSignValue{
		Chain:  "bitcoin",
		Method: method,
		From:   from,
		Raw:    rawHex,
	}
	if n != nil {
		val.Network = n
		val.NetworkId = n.String()
		val.NetworkName = n.Name
		if sym, err := n.NativeSymbol(); err == nil {
			val.FeeSymbol = sym
		}
		val.FeeDecimals = 8
	}
	if raw, err := hex.DecodeString(strings.TrimPrefix(rawHex, "0x")); err == nil {
		val.SizeBytes = len(raw)
	}
	// Reuse wlttx's BTC decoder by running the chain's simulate
	// path on a synthetic Transaction shell. The shell carries
	// tx.Raw + the bitcoin_transfer type so simulateBitcoin can
	// parse inputs/outputs without needing the full sign pipeline.
	rawBytes, err := hex.DecodeString(strings.TrimPrefix(rawHex, "0x"))
	if err == nil && len(rawBytes) > 0 {
		shell := &wlttx.Transaction{Type: "bitcoin_transfer", From: from, Raw: rawBytes}
		if sim, _ := wlttx.Simulate(ctx, shell); sim != nil {
			txSimResultAsSignValue(sim, val)
		}
	}
	val.DecodedMethod = "bitcoin_transfer"
	_ = e
	return val
}

// decodeSolanaSystemTransfer looks for a single System Program
// transfer instruction at the end of a legacy Solana tx message
// (the shape wlttx.buildSOLTransferMessage produces). Returns
// (fromBase58, toBase58, lamportsDecimalString, true) on match,
// zeroes otherwise. Good enough for the common "user sends SOL"
// case; anything else falls through to DecodedMethod="unknown".
func decodeSolanaSystemTransfer(raw []byte) (string, string, string, bool) {
	// Skip signatures block: compact-u16 numSigs + numSigs*64.
	if len(raw) < 1 {
		return "", "", "", false
	}
	numSigs, n, err := readCompactU16(raw, 0)
	if err != nil {
		return "", "", "", false
	}
	pos := n + int(numSigs)*64
	if pos+3 > len(raw) {
		return "", "", "", false
	}
	// Header (3 bytes) then compact-u16 numAccountKeys then
	// numKeys*32 account keys then 32 blockhash then compact-u16
	// numInstructions.
	pos += 3
	numKeys, n, err := readCompactU16(raw, pos)
	if err != nil {
		return "", "", "", false
	}
	pos += n
	if len(raw) < pos+int(numKeys)*32+32 {
		return "", "", "", false
	}
	accounts := make([][]byte, numKeys)
	for i := 0; i < int(numKeys); i++ {
		accounts[i] = raw[pos : pos+32]
		pos += 32
	}
	pos += 32 // blockhash
	numInstr, n, err := readCompactU16(raw, pos)
	if err != nil {
		return "", "", "", false
	}
	pos += n
	for i := 0; i < int(numInstr); i++ {
		if pos >= len(raw) {
			return "", "", "", false
		}
		progIdx := raw[pos]
		pos++
		numAccts, n, err := readCompactU16(raw, pos)
		if err != nil {
			return "", "", "", false
		}
		pos += n
		if pos+int(numAccts) > len(raw) {
			return "", "", "", false
		}
		acctRefs := raw[pos : pos+int(numAccts)]
		pos += int(numAccts)
		dataLen, n, err := readCompactU16(raw, pos)
		if err != nil {
			return "", "", "", false
		}
		pos += n
		if pos+int(dataLen) > len(raw) {
			return "", "", "", false
		}
		data := raw[pos : pos+int(dataLen)]
		pos += int(dataLen)

		// System Program = all-zero 32-byte pubkey. Transfer
		// instruction discriminator = uint32 LE == 2, followed
		// by u64 LE lamports.
		if int(progIdx) < len(accounts) && isAllZero(accounts[progIdx]) && len(data) == 12 && data[0] == 2 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
			if len(acctRefs) < 2 {
				continue
			}
			fromIdx := int(acctRefs[0])
			toIdx := int(acctRefs[1])
			if fromIdx >= len(accounts) || toIdx >= len(accounts) {
				continue
			}
			lamports := uint64(data[4]) |
				uint64(data[5])<<8 |
				uint64(data[6])<<16 |
				uint64(data[7])<<24 |
				uint64(data[8])<<32 |
				uint64(data[9])<<40 |
				uint64(data[10])<<48 |
				uint64(data[11])<<56
			from58 := solanaBase58(accounts[fromIdx])
			to58 := solanaBase58(accounts[toIdx])
			return from58, to58, new(big.Int).SetUint64(lamports).String(), true
		}
	}
	return "", "", "", false
}

func readCompactU16(b []byte, pos int) (uint16, int, error) {
	if pos >= len(b) {
		return 0, 0, errShortBuf
	}
	var v uint16
	n := 0
	for shift := uint(0); shift <= 14; shift += 7 {
		if pos+n >= len(b) {
			return 0, 0, errShortBuf
		}
		byteVal := b[pos+n]
		n++
		v |= uint16(byteVal&0x7f) << shift
		if byteVal&0x80 == 0 {
			return v, n, nil
		}
	}
	return 0, 0, errShortBuf
}

var errShortBuf = &genericErr{msg: "short buffer"}

type genericErr struct{ msg string }

func (e *genericErr) Error() string { return e.msg }

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// solanaBase58 minimal base58 encoder for 32-byte account keys.
// Duplicated from wltacct helper space to avoid a cross-package
// hop on the sign-request emit path.
func solanaBase58(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	if len(b) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	size := (len(b)-zeros)*138/100 + 1
	encoded := make([]byte, size)
	high := size - 1
	for i := zeros; i < len(b); i++ {
		carry := int(b[i])
		j := size - 1
		for ; j > high || carry != 0; j-- {
			carry += 256 * int(encoded[j])
			encoded[j] = byte(carry % 58)
			carry /= 58
		}
		high = j
	}
	// Skip leading zeroes in encoded buffer.
	it := 0
	for ; it < size && encoded[it] == 0; it++ {
	}
	out := make([]byte, zeros+(size-it))
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for j := zeros; it < size; j++ {
		out[j] = alphabet[encoded[it]]
		it++
	}
	return string(out)
}
