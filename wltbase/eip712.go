package wltbase

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

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
	// Array types
	if strings.HasSuffix(typ, "[]") {
		elemType := typ[:len(typ)-2]
		arr, ok := val.([]any)
		if !ok {
			return nil, fmt.Errorf("expected array for %s", typ)
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
		b := hexDecode(s)
		return keccak256(b), nil
	case typ == "bool":
		return padLeft32(boolToBytes(val)), nil
	case typ == "address":
		s, _ := val.(string)
		b := hexDecode(s)
		return padLeft32(b), nil
	case strings.HasPrefix(typ, "uint"):
		return padLeft32(bigIntBytes(val)), nil
	case strings.HasPrefix(typ, "int"):
		return padLeft32Signed(bigIntBytes(val)), nil
	case strings.HasPrefix(typ, "bytes"):
		// Fixed-size bytesN
		s, _ := val.(string)
		b := hexDecode(s)
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

func padLeft32Signed(b []byte) []byte {
	if len(b) == 0 {
		return make([]byte, 32)
	}
	padded := make([]byte, 32)
	// Sign-extend: if high bit set, fill with 0xff
	if b[0]&0x80 != 0 {
		for i := range padded {
			padded[i] = 0xff
		}
	}
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

func hexDecode(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, _ := fmt.Sscanf(s, "%x", new([]byte))
	_ = b
	// Use hex.DecodeString for reliable decoding
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		fmt.Sscanf(s[i:i+2], "%02x", &result[i/2])
	}
	return result
}

func bigIntBytes(val any) []byte {
	switch v := val.(type) {
	case string:
		n := new(big.Int)
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			n.SetString(v[2:], 16)
		} else {
			n.SetString(v, 10)
		}
		return n.Bytes()
	case json.Number:
		n := new(big.Int)
		n.SetString(string(v), 10)
		return n.Bytes()
	case float64:
		n := new(big.Int)
		n.SetInt64(int64(v))
		return n.Bytes()
	default:
		return nil
	}
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
