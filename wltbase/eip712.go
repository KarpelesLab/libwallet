package wltbase

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"
)

var (
	// maxUint256 is type(uint256).max — the canonical "unlimited"
	// ERC-20 allowance value.
	maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	// maxUint160 is type(uint160).max — Permit2 amounts are uint160,
	// so this is its "unlimited" sentinel.
	maxUint160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
)

// DomainChainID returns the EIP-712 domain's chainId normalised to a
// decimal string. ok is false when the domain omits chainId (it is an
// optional field) or the value can't be parsed.
func (td *EIP712TypedData) DomainChainID() (string, bool) {
	if td.Domain == nil {
		return "", false
	}
	switch v := td.Domain["chainId"].(type) {
	case string:
		if v == "" {
			return "", false
		}
		s, base := v, 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s, base = s[2:], 16
		}
		if b, ok := new(big.Int).SetString(s, base); ok {
			return b.Text(10), true
		}
	case float64:
		return strconv.FormatInt(int64(v), 10), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case json.Number:
		if b, ok := new(big.Int).SetString(string(v), 10); ok {
			return b.Text(10), true
		}
	}
	return "", false
}

// SecurityWarnings inspects parsed typed data for cross-chain replay
// and dangerous-approval risks (ERC-2612 Permit, Permit2
// PermitSingle/PermitBatch, token approve/increaseAllowance, Seaport
// orders) and returns additive advisories for the approval sheet.
// activeChainID is the wallet's current EVM network chain id (decimal
// string); pass "" to skip the cross-chain check. These warnings never
// block signing — they exist purely to defeat blind signing by
// surfacing spender / amount / deadline, explicitly flagging unlimited
// (type(uint256).max) allowances.
func (td *EIP712TypedData) SecurityWarnings(activeChainID string) []SignWarning {
	var out []SignWarning

	// (a) Cross-chain: a signature whose domain targets a different
	// chain than the wallet is on can be replayed on that chain.
	if activeChainID != "" {
		if dom, ok := td.DomainChainID(); ok && dom != activeChainID {
			out = append(out, SignWarning{
				Code:     "eip712_chain_mismatch",
				Severity: "warn",
				Message:  fmt.Sprintf("This typed-data signature targets chain %s but your wallet is on chain %s. It may be replayable on the other chain.", dom, activeChainID),
				Field:    "chainId",
			})
		}
	}

	// (b) Dangerous primitives.
	msg := td.Message
	ptl := strings.ToLower(td.PrimaryType)

	appendAllowance := func(code, spender string, amount *big.Int, deadline string) {
		unlimited := amount != nil && (amount.Cmp(maxUint256) == 0 || amount.Cmp(maxUint160) == 0)
		var b strings.Builder
		b.WriteString("Signing this authorises a token spending approval")
		if spender != "" {
			b.WriteString(" to spender " + spender)
		}
		if amount != nil {
			if unlimited {
				b.WriteString(" for an UNLIMITED amount")
			} else {
				b.WriteString(" for amount " + amount.String())
			}
		}
		if deadline != "" {
			b.WriteString(" (deadline " + deadline + ")")
		}
		b.WriteString(". Only sign if you trust this site.")
		if unlimited {
			code += "_unlimited"
		}
		out = append(out, SignWarning{Code: code, Severity: "warn", Message: b.String(), Field: "spender"})
	}

	switch {
	case ptl == "permit":
		// ERC-2612: { owner, spender, value, nonce, deadline }.
		appendAllowance("eip712_permit", eip712Str(msg, "spender"),
			eip712Big(msg, "value"), eip712Display(msg, "deadline"))
	case ptl == "permitsingle":
		// Permit2 PermitSingle: { details:{token,amount,...}, spender, sigDeadline }.
		var amount *big.Int
		if d, ok := msg["details"].(map[string]any); ok {
			amount = eip712Big(d, "amount")
		}
		appendAllowance("permit2_approve", eip712Str(msg, "spender"), amount,
			eip712Display(msg, "sigDeadline"))
	case ptl == "permitbatch":
		// Permit2 PermitBatch: { details:[{token,amount,...}], spender, sigDeadline }.
		spender := eip712Str(msg, "spender")
		deadline := eip712Display(msg, "sigDeadline")
		if arr, ok := msg["details"].([]any); ok && len(arr) > 0 {
			for _, it := range arr {
				if d, ok := it.(map[string]any); ok {
					appendAllowance("permit2_approve", spender, eip712Big(d, "amount"), deadline)
				}
			}
		} else {
			appendAllowance("permit2_approve", spender, nil, deadline)
		}
	case strings.Contains(ptl, "increaseallowance"):
		amount := eip712Big(msg, "value")
		if amount == nil {
			amount = eip712Big(msg, "amount")
		}
		appendAllowance("eip712_increase_allowance", eip712Str(msg, "spender"), amount, "")
	case strings.Contains(ptl, "approve"):
		amount := eip712Big(msg, "value")
		if amount == nil {
			amount = eip712Big(msg, "amount")
		}
		appendAllowance("eip712_token_approval", eip712Str(msg, "spender"), amount, "")
	case strings.Contains(ptl, "order"):
		// Seaport (OpenSea) OrderComponents and similar marketplace
		// orders — signing can list or transfer your NFTs/tokens.
		out = append(out, SignWarning{
			Code:     "seaport_order",
			Severity: "warn",
			Message:  "This signs a marketplace order (Seaport-style) that can list or transfer your NFTs/tokens. Verify the collection, price, and recipient before signing.",
		})
	default:
		// Message-level match: a custom primaryType wrapping an
		// approval still exposes a spender + amount the user should
		// see.
		if msg != nil {
			if _, ok := msg["spender"]; ok {
				amount := eip712Big(msg, "value")
				if amount == nil {
					amount = eip712Big(msg, "amount")
				}
				appendAllowance("eip712_token_approval", eip712Str(msg, "spender"), amount,
					eip712Display(msg, "deadline"))
			}
		}
	}

	return out
}

// eip712Str returns m[key] as a string, or "" when absent / not a string.
func eip712Str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// eip712Big parses m[key] (string decimal/hex, JSON number, or float)
// into a big.Int. Returns nil when absent or unparsable.
func eip712Big(m map[string]any, key string) *big.Int {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case string:
		s, base := v, 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s, base = s[2:], 16
		}
		if b, ok := new(big.Int).SetString(s, base); ok {
			return b
		}
	case float64:
		return new(big.Int).SetInt64(int64(v))
	case json.Number:
		if b, ok := new(big.Int).SetString(string(v), 10); ok {
			return b
		}
	}
	return nil
}

// eip712Display renders m[key] for human-readable warning text.
func eip712Display(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case json.Number:
		return string(v)
	}
	return ""
}

// EIP712TypedData represents the full EIP-712 typed data structure.
type EIP712TypedData struct {
	Types       map[string][]EIP712Field `json:"types"`
	PrimaryType string                   `json:"primaryType"`
	Domain      map[string]any           `json:"domain"`
	Message     map[string]any           `json:"message"`
}

// EIP712Field represents a single field in an EIP-712 type definition.
type EIP712Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// HashEIP712 computes the EIP-712 digest: keccak256("\x19\x01" || domainSeparator || hashStruct(message))
func (td *EIP712TypedData) HashEIP712() ([]byte, error) {
	domainSep, err := td.hashStruct("EIP712Domain", td.Domain)
	if err != nil {
		return nil, fmt.Errorf("domain separator: %w", err)
	}

	msgHash, err := td.hashStruct(td.PrimaryType, td.Message)
	if err != nil {
		return nil, fmt.Errorf("message hash: %w", err)
	}

	// "\x19\x01" || domainSeparator || hashStruct(message)
	raw := []byte{0x19, 0x01}
	raw = append(raw, domainSep...)
	raw = append(raw, msgHash...)
	return keccak256(raw), nil
}

// hashStruct computes keccak256(typeHash || encodeData(value))
func (td *EIP712TypedData) hashStruct(typeName string, data map[string]any) ([]byte, error) {
	typeHash, err := td.typeHash(typeName)
	if err != nil {
		return nil, err
	}

	encoded, err := td.encodeData(typeName, data)
	if err != nil {
		return nil, err
	}

	raw := make([]byte, 0, 32+len(encoded))
	raw = append(raw, typeHash...)
	raw = append(raw, encoded...)
	return keccak256(raw), nil
}

// typeHash returns keccak256(encodeType(typeName))
func (td *EIP712TypedData) typeHash(typeName string) ([]byte, error) {
	enc, err := td.encodeType(typeName)
	if err != nil {
		return nil, err
	}
	return keccak256([]byte(enc)), nil
}

// encodeType returns the type encoding string per EIP-712.
// e.g. "Mail(address from,address to,string contents)"
// Referenced types are appended in sorted order.
func (td *EIP712TypedData) encodeType(typeName string) (string, error) {
	fields, ok := td.Types[typeName]
	if !ok {
		return "", fmt.Errorf("type %s not found", typeName)
	}

	// Collect referenced struct types
	deps := make(map[string]bool)
	td.findDeps(typeName, deps)
	delete(deps, typeName) // primary type comes first

	sortedDeps := make([]string, 0, len(deps))
	for d := range deps {
		sortedDeps = append(sortedDeps, d)
	}
	sort.Strings(sortedDeps)

	result := formatType(typeName, fields)
	for _, dep := range sortedDeps {
		result += formatType(dep, td.Types[dep])
	}
	return result, nil
}

func formatType(name string, fields []EIP712Field) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = f.Type + " " + f.Name
	}
	return name + "(" + strings.Join(parts, ",") + ")"
}

// findDeps recursively finds all struct type dependencies.
func (td *EIP712TypedData) findDeps(typeName string, deps map[string]bool) {
	if deps[typeName] {
		return
	}
	fields, ok := td.Types[typeName]
	if !ok {
		return
	}
	deps[typeName] = true
	for _, f := range fields {
		baseType := stripArraySuffix(f.Type)
		if _, isStruct := td.Types[baseType]; isStruct {
			td.findDeps(baseType, deps)
		}
	}
}

// encodeData encodes the values of a struct according to EIP-712.
func (td *EIP712TypedData) encodeData(typeName string, data map[string]any) ([]byte, error) {
	fields, ok := td.Types[typeName]
	if !ok {
		return nil, fmt.Errorf("type %s not found", typeName)
	}

	var encoded []byte
	for _, field := range fields {
		val := data[field.Name]
		enc, err := td.encodeValue(field.Type, val)
		if err != nil {
			return nil, fmt.Errorf("field %s.%s: %w", typeName, field.Name, err)
		}
		encoded = append(encoded, enc...)
	}
	return encoded, nil
}

// encodeValue encodes a single value per EIP-712 rules.
func (td *EIP712TypedData) encodeValue(typ string, val any) ([]byte, error) {
	// Array types — both dynamic (T[]) and fixed-size (T[N]). EIP-712
	// encodes either as keccak256 of the concatenated member encodings.
	if elemType, fixedLen, isArray := arrayElemType(typ); isArray {
		arr, ok := val.([]any)
		if !ok {
			return nil, fmt.Errorf("expected array for %s", typ)
		}
		if fixedLen >= 0 && len(arr) != fixedLen {
			return nil, fmt.Errorf("%s expects %d elements, got %d", typ, fixedLen, len(arr))
		}
		var inner []byte
		for _, item := range arr {
			enc, err := td.encodeValue(elemType, item)
			if err != nil {
				return nil, err
			}
			inner = append(inner, enc...)
		}
		return keccak256(inner), nil
	}

	// Struct types (referenced types)
	if _, isStruct := td.Types[typ]; isStruct {
		m, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected object for struct type %s", typ)
		}
		h, err := td.hashStruct(typ, m)
		if err != nil {
			return nil, err
		}
		return h, nil
	}

	// Atomic types
	switch {
	case typ == "string":
		s, _ := val.(string)
		return keccak256([]byte(s)), nil
	case typ == "bytes":
		s, ok := val.(string)
		if !ok {
			return nil, errors.New("bytes value must be hex string")
		}
		b, err := hexDecode(s)
		if err != nil {
			return nil, fmt.Errorf("bytes: %w", err)
		}
		return keccak256(b), nil
	case typ == "bool":
		return padLeft32(boolToBytes(val)), nil
	case typ == "address":
		s, _ := val.(string)
		b, err := hexDecode(s)
		if err != nil {
			return nil, fmt.Errorf("address: %w", err)
		}
		return padLeft32(b), nil
	case strings.HasPrefix(typ, "uint"):
		n, ok := bigIntFromVal(val)
		if !ok {
			return nil, fmt.Errorf("invalid value for %s", typ)
		}
		if n.Sign() < 0 {
			return nil, fmt.Errorf("negative value for unsigned %s", typ)
		}
		return encodeUint256(n), nil
	case strings.HasPrefix(typ, "int"):
		n, ok := bigIntFromVal(val)
		if !ok {
			return nil, fmt.Errorf("invalid value for %s", typ)
		}
		return encodeInt256(n), nil
	case strings.HasPrefix(typ, "bytes"):
		// Fixed-size bytesN
		s, _ := val.(string)
		b, err := hexDecode(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", typ, err)
		}
		return padRight32(b), nil
	default:
		return nil, fmt.Errorf("unsupported EIP-712 type: %s", typ)
	}
}

func stripArraySuffix(t string) string {
	if idx := strings.Index(t, "["); idx != -1 {
		return t[:idx]
	}
	return t
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func padLeft32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func padRight32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded, b)
	return padded
}

// arrayElemType reports whether typ is an array type and, if so,
// returns its element type and fixed length. fixedLen is -1 for a
// dynamic array (T[]) and >= 0 for a fixed-size array (T[N]).
func arrayElemType(typ string) (elem string, fixedLen int, ok bool) {
	if !strings.HasSuffix(typ, "]") {
		return "", 0, false
	}
	open := strings.LastIndex(typ, "[")
	if open < 0 {
		return "", 0, false
	}
	inner := typ[open+1 : len(typ)-1]
	base := typ[:open]
	if inner == "" {
		return base, -1, true
	}
	n, err := strconv.Atoi(inner)
	if err != nil || n < 0 {
		return "", 0, false
	}
	return base, n, true
}

// hexDecode decodes a 0x-prefixed (or bare) hex string, returning an
// error on invalid input instead of silently zero-filling — so a
// malformed value aborts signing rather than producing an attacker-
// chosen (zero) digest input.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return []byte{}, nil
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// bigIntFromVal parses an EIP-712 numeric value (decimal/hex string,
// JSON number, or float) into a big.Int, preserving sign.
func bigIntFromVal(val any) (*big.Int, bool) {
	switch v := val.(type) {
	case string:
		v = strings.TrimSpace(v)
		neg := strings.HasPrefix(v, "-")
		if neg {
			v = v[1:]
		}
		n := new(big.Int)
		var ok bool
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			_, ok = n.SetString(v[2:], 16)
		} else {
			_, ok = n.SetString(v, 10)
		}
		if !ok {
			return nil, false
		}
		if neg {
			n.Neg(n)
		}
		return n, true
	case json.Number:
		n := new(big.Int)
		if _, ok := n.SetString(string(v), 10); ok {
			return n, true
		}
		return nil, false
	case float64:
		return new(big.Int).SetInt64(int64(v)), true
	default:
		return nil, false
	}
}

// encodeUint256 renders the low 256 bits of n as big-endian 32 bytes.
func encodeUint256(n *big.Int) []byte {
	b := make([]byte, 32)
	new(big.Int).And(n, maxUint256).FillBytes(b)
	return b
}

// encodeInt256 renders n as a 32-byte two's-complement big-endian
// integer — correct for negatives and for positive magnitudes whose
// top bit is set (which the previous magnitude+sign-extend code got
// wrong).
func encodeInt256(n *big.Int) []byte {
	b := make([]byte, 32)
	m := new(big.Int)
	if n.Sign() >= 0 {
		m.And(n, maxUint256)
	} else {
		// 2^256 + n, masked to 256 bits.
		m.Add(new(big.Int).Lsh(big.NewInt(1), 256), n)
		m.And(m, maxUint256)
	}
	m.FillBytes(b)
	return b
}

func boolToBytes(val any) []byte {
	switch v := val.(type) {
	case bool:
		if v {
			return []byte{1}
		}
		return []byte{0}
	default:
		return []byte{0}
	}
}

// ParseEIP712TypedData parses a JSON string into EIP712TypedData.
func ParseEIP712TypedData(data string) (*EIP712TypedData, error) {
	var td EIP712TypedData
	if err := json.Unmarshal([]byte(data), &td); err != nil {
		return nil, fmt.Errorf("failed to parse typed data: %w", err)
	}
	if td.PrimaryType == "" {
		return nil, errors.New("primaryType is required")
	}
	if td.Types == nil {
		return nil, errors.New("types is required")
	}
	if _, ok := td.Types[td.PrimaryType]; !ok {
		return nil, fmt.Errorf("primaryType %s not found in types", td.PrimaryType)
	}
	return &td, nil
}
