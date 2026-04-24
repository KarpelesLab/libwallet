package wltacct

import (
	"encoding/base64"
	"testing"

	"github.com/KarpelesLab/libwallet/wltnet"
)

// TestUpdateAddressForNetwork_SolanaWithSecp256k1 guards against the
// "Invalid param: WrongSize" error Solana RPC returns when the Asset
// listing path blindly base58-encodes a secp256k1 account's 33-byte
// compressed pubkey as if it were a 32-byte ed25519 point. Addresses
// on Solana for non-ed25519 accounts must be "N/A" so currentAssets
// skips them instead of calling getBalance with a malformed pubkey.
func TestUpdateAddressForNetwork_SolanaWithSecp256k1(t *testing.T) {
	// 33-byte compressed secp256k1 pubkey (example — 0x02 prefix + x).
	raw := make([]byte, 33)
	raw[0] = 0x02
	for i := 1; i < 33; i++ {
		raw[i] = byte(i)
	}
	a := &Account{
		Curve:  "secp256k1",
		Pubkey: base64.RawURLEncoding.EncodeToString(raw),
	}
	net := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
	if err := a.UpdateAddressForNetwork(net); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Address != "N/A" {
		t.Fatalf("want Address=N/A for secp256k1 on Solana, got %q", a.Address)
	}
	if a.URI != "" {
		t.Fatalf("want empty URI, got %q", a.URI)
	}
}

// A properly-sized ed25519 pubkey must still produce a valid base58
// Solana address — sanity check the happy path didn't regress.
func TestUpdateAddressForNetwork_SolanaWithEd25519(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	a := &Account{
		Curve:  "ed25519",
		Pubkey: base64.RawURLEncoding.EncodeToString(raw),
	}
	net := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
	if err := a.UpdateAddressForNetwork(net); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Address == "N/A" || a.Address == "" {
		t.Fatalf("want a real base58 address for ed25519 on Solana, got %q", a.Address)
	}
	if a.URI != "solana:"+a.Address {
		t.Fatalf("unexpected URI: %q", a.URI)
	}
}

// Guard the length check independently — a pubkey that somehow
// decodes to the wrong number of bytes (truncated storage, junk
// input) must still resolve to N/A rather than produce a malformed
// Solana address.
func TestUpdateAddressForNetwork_SolanaWrongPubkeyLength(t *testing.T) {
	// 16 bytes — too short for either curve.
	raw := make([]byte, 16)
	a := &Account{
		Curve:  "ed25519",
		Pubkey: base64.RawURLEncoding.EncodeToString(raw),
	}
	net := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
	if err := a.UpdateAddressForNetwork(net); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Address != "N/A" {
		t.Fatalf("want Address=N/A for wrong-size pubkey, got %q", a.Address)
	}
}
