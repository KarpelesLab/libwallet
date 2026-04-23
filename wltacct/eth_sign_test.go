package wltacct

import (
	"crypto/sha256"
	"testing"

	"github.com/KarpelesLab/secp256k1"
)

// TestEthereumWireFormat checks the exact byte layout SignEthereumDigest
// produces against an independent ecrecover. Uses a throwaway secp256k1
// key (not TSS) and walks through the same DER → ParseDER → recovery →
// ExportCompact pipeline the production helper uses, since exercising
// the real Account.Sign requires TSS infrastructure.
//
// Three things have to hold for ecrecover, viem, ethers, etc. to accept
// the signature:
//
//  1. exactly 65 bytes
//  2. byte[64] (v) is 27 or 28 — NOT 0/1 and NOT chainId-adjusted
//  3. recovery from the (r, s, v) triple yields the original pubkey
func TestEthereumWireFormat(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %s", err)
	}
	pub := priv.PubKey()

	// Stand-in for an EIP-191 / EIP-712 keccak digest. The pipeline is
	// digest-shape-agnostic — sha256 here just gives us 32 bytes.
	digestArr := sha256.Sum256([]byte("verify libwallet eth signing"))
	digest := digestArr[:]

	sig := secp256k1.Sign(priv, digest)
	if !sig.BruteforceRecoveryCode(digest, pub) {
		t.Fatal("could not determine recovery code")
	}
	wire := sig.ExportCompact(false, 27)

	if len(wire) != 65 {
		t.Fatalf("want 65-byte wire signature, got %d", len(wire))
	}
	v := wire[64]
	if v != 27 && v != 28 {
		t.Fatalf("want v ∈ {27, 28}, got %d", v)
	}

	// Reconstruct the Bitcoin-layout compact signature
	// (header || R || S) so we can use the existing RecoverCompact.
	// Same bytes, different position for v.
	btcLayout := make([]byte, 65)
	btcLayout[0] = wire[64]
	copy(btcLayout[1:], wire[:64])

	recovered, _, err := secp256k1.RecoverCompact(btcLayout, digest)
	if err != nil {
		t.Fatalf("ecrecover-equivalent: %s", err)
	}
	if !recovered.IsEqual(pub) {
		t.Fatal("recovered pubkey does not match signing key — wire format is wrong")
	}
}
