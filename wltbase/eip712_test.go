package wltbase

import (
	"encoding/hex"
	"testing"
)

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
