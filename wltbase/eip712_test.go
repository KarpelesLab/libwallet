package wltbase

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestEIP712EncodeInt256TwosComplement(t *testing.T) {
	// -1 must encode as all 0xff (two's complement), not 0x00..01.
	got := hex.EncodeToString(encodeInt256(big.NewInt(-1)))
	want := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if got != want {
		t.Errorf("encodeInt256(-1) = %s, want %s", got, want)
	}
	// A positive magnitude with the top bit set must NOT be sign-
	// extended to 0xff (the old bug). 2^255 fits in uint256.
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	got = hex.EncodeToString(encodeInt256(p))
	want = "8000000000000000000000000000000000000000000000000000000000000000"
	if got != want {
		t.Errorf("encodeInt256(2^255) = %s, want %s", got, want)
	}
}

func TestEIP712FixedArray(t *testing.T) {
	typedData := `{
		"types": {
			"EIP712Domain": [{"name": "name", "type": "string"}],
			"Pair": [{"name": "vals", "type": "uint256[2]"}]
		},
		"primaryType": "Pair",
		"domain": {"name": "Test"},
		"message": {"vals": ["1", "2"]}
	}`
	td, err := ParseEIP712TypedData(typedData)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if _, err := td.HashEIP712(); err != nil {
		t.Fatalf("HashEIP712 error: %v", err)
	}
	// Wrong element count must be rejected, not silently mis-encoded.
	td.Message["vals"] = []any{"1"}
	if _, err := td.HashEIP712(); err == nil {
		t.Error("expected error for fixed array with wrong length")
	}
}

func TestEIP712HexDecodeError(t *testing.T) {
	if _, err := hexDecode("0xZZ"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if b, err := hexDecode("0x1234"); err != nil || hex.EncodeToString(b) != "1234" {
		t.Errorf("hexDecode(0x1234) = %x, %v", b, err)
	}
}

func TestEIP712SecurityWarnings(t *testing.T) {
	// Unlimited ERC-2612 permit + chain mismatch.
	typedData := `{
		"types": {
			"EIP712Domain": [{"name": "chainId", "type": "uint256"}],
			"Permit": [
				{"name": "owner", "type": "address"},
				{"name": "spender", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "nonce", "type": "uint256"},
				{"name": "deadline", "type": "uint256"}
			]
		},
		"primaryType": "Permit",
		"domain": {"chainId": "1"},
		"message": {
			"owner": "0x0000000000000000000000000000000000000001",
			"spender": "0x000000000000000000000000000000000000dEaD",
			"value": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
			"nonce": "0",
			"deadline": "1700000000"
		}
	}`
	td, err := ParseEIP712TypedData(typedData)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	ws := td.SecurityWarnings("137") // wallet on Polygon, domain says chain 1
	var sawMismatch, sawUnlimited bool
	for _, w := range ws {
		if w.Code == "eip712_chain_mismatch" {
			sawMismatch = true
		}
		if w.Code == "eip712_permit_unlimited" {
			sawUnlimited = true
		}
	}
	if !sawMismatch {
		t.Error("expected eip712_chain_mismatch warning")
	}
	if !sawUnlimited {
		t.Error("expected eip712_permit_unlimited warning")
	}
	// Same chain → no mismatch warning.
	for _, w := range td.SecurityWarnings("1") {
		if w.Code == "eip712_chain_mismatch" {
			t.Error("unexpected chain mismatch warning when chains match")
		}
	}
}

// Test vector from EIP-712 specification
// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct
func TestEIP712Hash(t *testing.T) {
	typedData := `{
		"types": {
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"Person": [
				{"name": "name", "type": "string"},
				{"name": "wallet", "type": "address"}
			],
			"Mail": [
				{"name": "from", "type": "Person"},
				{"name": "to", "type": "Person"},
				{"name": "contents", "type": "string"}
			]
		},
		"primaryType": "Mail",
		"domain": {
			"name": "Ether Mail",
			"version": "1",
			"chainId": "1",
			"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
		},
		"message": {
			"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
			"to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
			"contents": "Hello, Bob!"
		}
	}`

	td, err := ParseEIP712TypedData(typedData)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	// Test encodeType for Mail
	mailType, err := td.encodeType("Mail")
	if err != nil {
		t.Fatalf("encodeType error: %v", err)
	}
	expectedType := "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
	if mailType != expectedType {
		t.Errorf("encodeType(Mail) = %q, want %q", mailType, expectedType)
	}

	// Test typeHash for Mail
	// keccak256("Mail(Person from,Person to,string contents)Person(string name,address wallet)")
	typeHash, err := td.typeHash("Mail")
	if err != nil {
		t.Fatalf("typeHash error: %v", err)
	}
	expectedTypeHash := "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
	if hex.EncodeToString(typeHash) != expectedTypeHash {
		t.Errorf("typeHash(Mail) = %x, want %s", typeHash, expectedTypeHash)
	}

	// Test full EIP-712 hash
	digest, err := td.HashEIP712()
	if err != nil {
		t.Fatalf("HashEIP712 error: %v", err)
	}
	// Known hash from EIP-712 spec
	expectedDigest := "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
	if hex.EncodeToString(digest) != expectedDigest {
		t.Errorf("HashEIP712 = %x, want %s", digest, expectedDigest)
	}
}

func TestEIP712ParseErrors(t *testing.T) {
	// Invalid JSON
	_, err := ParseEIP712TypedData("{bad")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}

	// Missing primaryType
	_, err = ParseEIP712TypedData(`{"types":{"X":[]},"domain":{},"message":{}}`)
	if err == nil {
		t.Error("expected error for missing primaryType")
	}

	// primaryType not in types
	_, err = ParseEIP712TypedData(`{"types":{"X":[]},"primaryType":"Y","domain":{},"message":{}}`)
	if err == nil {
		t.Error("expected error for primaryType not in types")
	}
}

func TestEIP712ArrayType(t *testing.T) {
	typedData := `{
		"types": {
			"EIP712Domain": [
				{"name": "name", "type": "string"}
			],
			"Batch": [
				{"name": "amounts", "type": "uint256[]"}
			]
		},
		"primaryType": "Batch",
		"domain": {"name": "Test"},
		"message": {"amounts": ["100", "200"]}
	}`

	td, err := ParseEIP712TypedData(typedData)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	digest, err := td.HashEIP712()
	if err != nil {
		t.Fatalf("HashEIP712 error: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}
}
