package wltwallet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
)

// TestDklsWalletEndToEnd exercises the dkls23 keygen + sign path
// against in-process Plain shares. The wallet is force-stamped with
// Protocol=dkls23 so initializeWallet dispatches into
// initializeDklsWallet; the resulting signature is parsed as DER and
// the recovered pubkey must match the wallet's persisted Pubkey.
//
// Threshold=1, 3 shares → sign with exactly 2 (T+1). This mirrors
// TestWalletCreate's shape but uses the modern DKLs23 path.
func TestDklsWalletEndToEnd(t *testing.T) {
	w := &Wallet{Protocol: ProtocolDKLS}

	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.initializeWallet(context.Background(), kd); err != nil {
		t.Fatalf("dkls23 keygen failed: %s", err)
	}
	if w.Protocol != ProtocolDKLS {
		t.Fatalf("Protocol = %q, want %q", w.Protocol, ProtocolDKLS)
	}
	if w.Curve != "secp256k1" {
		t.Fatalf("Curve = %q, want secp256k1", w.Curve)
	}
	for i, k := range w.Keys {
		if k.Schema != "dkls23" {
			t.Errorf("Keys[%d].Schema = %q, want \"dkls23\"", i, k.Schema)
		}
	}

	// Decrypt+sign with the first T+1 shares.
	opts := &wltsign.Opts{}
	for _, k := range w.Keys[:w.Threshold+1] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	msg := []byte("dkls23 e2e signing")
	digest := sha256.Sum256(msg)

	sig, err := w.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("dkls23 sign failed: %s", err)
	}
	if len(sig) == 0 {
		t.Fatal("dkls23 sign returned empty signature")
	}

	// Parse the DER signature and verify against the persisted pubkey.
	parsed, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Fatalf("failed to parse dkls23 DER signature: %s", err)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("failed to decode wallet pubkey: %s", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("failed to parse wallet pubkey: %s", err)
	}
	if !parsed.Verify(digest[:], pub) {
		t.Fatalf("dkls23 signature did not verify against wallet pubkey")
	}
}

// TestDklsSubsetSizeMismatch confirms the subset-size guard in the
// sign path surfaces as a clean error rather than letting NewSigning
// fail per-party. dklstss requires exactly T+1 signers; libwallet
// catches len(keys) != T+1 up-front.
func TestDklsSubsetSizeMismatch(t *testing.T) {
	w := &Wallet{Protocol: ProtocolDKLS}
	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.initializeWallet(context.Background(), kd); err != nil {
		t.Fatalf("dkls23 keygen failed: %s", err)
	}

	opts := &wltsign.Opts{}
	for _, k := range w.Keys {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	digest := sha256.Sum256([]byte("subset test"))
	if _, err := w.Sign(rand.Reader, digest[:], opts); err == nil {
		t.Fatal("expected error when signing with N keys instead of T+1, got nil")
	}
}
