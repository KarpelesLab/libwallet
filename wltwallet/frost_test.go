package wltwallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/KarpelesLab/libwallet/wltsign"
)

// TestFrostWalletEndToEnd exercises FROST(Ed25519) keygen + sign
// against in-process Plain shares. The wallet is force-stamped with
// Protocol=frost so initializeEdDSAWallet dispatches into
// initializeFrostWallet; the resulting 64-byte signature must verify
// under the wallet's persisted Ed25519 pubkey via the stdlib
// verifier (this is the contract — any standard Ed25519 verifier).
//
// Threshold=1, 3 shares → sign with at least 2 (T+1). FROST allows
// more than T+1 signers, unlike DKLs23.
func TestFrostWalletEndToEnd(t *testing.T) {
	w := &Wallet{Protocol: ProtocolFROST}

	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.initializeEdDSAWallet(context.Background(), kd); err != nil {
		t.Fatalf("frost keygen failed: %s", err)
	}
	if w.Protocol != ProtocolFROST {
		t.Fatalf("Protocol = %q, want %q", w.Protocol, ProtocolFROST)
	}
	if w.Curve != "ed25519" {
		t.Fatalf("Curve = %q, want ed25519", w.Curve)
	}
	for i, k := range w.Keys {
		if k.Schema != "frost" {
			t.Errorf("Keys[%d].Schema = %q, want \"frost\"", i, k.Schema)
		}
	}

	opts := &wltsign.Opts{}
	for _, k := range w.Keys[:w.Threshold+1] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	msg := []byte("frost e2e signing")
	sig, err := w.Sign(rand.Reader, msg, opts)
	if err != nil {
		t.Fatalf("frost sign failed: %s", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("frost signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	// FROST signatures verify under any Ed25519 verifier — that's the
	// whole point of the protocol. Use the stdlib verifier rather than
	// the eddsatss-specific path.
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("failed to decode wallet pubkey: %s", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sig) {
		t.Fatalf("frost signature did not verify against wallet pubkey")
	}
}
