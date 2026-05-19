package wltwallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
)

// TestReshareDklsEndToEnd creates a DKLs23 wallet, reshares it to a
// new committee of the same size + threshold, then signs under the new
// committee and verifies under the wallet's persisted public key. The
// pubkey MUST be preserved across reshare; if it isn't, every existing
// address derived from the wallet would silently break.
func TestReshareDklsEndToEnd(t *testing.T) {
	w := &Wallet{Protocol: ProtocolDKLS}
	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.initializeWallet(context.Background(), kd); err != nil {
		t.Fatalf("dkls23 keygen failed: %s", err)
	}
	origPubkey := w.Pubkey

	// Sign with the original committee to prove the pre-reshare wallet
	// is operational — guards against a reshare that "succeeds" against
	// an already-broken keygen.
	preOpts := &wltsign.Opts{}
	for _, k := range w.Keys[:w.Threshold+1] {
		preOpts.Keys = append(preOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	preDigest := sha256.Sum256([]byte("pre-reshare"))
	if _, err := w.Sign(rand.Reader, preDigest[:], preOpts); err != nil {
		t.Fatalf("pre-reshare sign failed: %s", err)
	}

	// dkls23 needs exactly T+1 old signers in the active subset.
	oldKeys := make([]*wltsign.KeyDescription, w.Threshold+1)
	for i, k := range w.Keys[:w.Threshold+1] {
		oldKeys[i] = &wltsign.KeyDescription{Id: k.Id.String()}
	}
	newKD := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.Reshare(context.Background(), oldKeys, newKD); err != nil {
		t.Fatalf("dkls23 reshare failed: %s", err)
	}

	// Public key preserved.
	if w.Pubkey != origPubkey {
		t.Fatalf("dkls23 reshare changed Pubkey: %q → %q", origPubkey, w.Pubkey)
	}
	if len(w.Keys) != len(newKD) {
		t.Fatalf("expected %d new keys, got %d", len(newKD), len(w.Keys))
	}
	for i, k := range w.Keys {
		if k.Schema != "dkls23" {
			t.Errorf("new Keys[%d].Schema = %q, want \"dkls23\"", i, k.Schema)
		}
	}

	// Sign with the new committee and verify under the persisted
	// pubkey. If the share rotation desynchronised the joint key, this
	// is where it surfaces.
	postOpts := &wltsign.Opts{}
	for _, k := range w.Keys[:w.Threshold+1] {
		postOpts.Keys = append(postOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	postMsg := []byte("post-reshare dkls23 verification")
	postDigest := sha256.Sum256(postMsg)
	sig, err := w.Sign(rand.Reader, postDigest[:], postOpts)
	if err != nil {
		t.Fatalf("post-reshare sign failed: %s", err)
	}
	parsed, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Fatalf("parse DER: %s", err)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("decode pubkey: %s", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("parse pubkey: %s", err)
	}
	if !parsed.Verify(postDigest[:], pub) {
		t.Fatalf("post-reshare signature did not verify against persisted pubkey")
	}
}

// TestReshareFrostEndToEnd is the FROST counterpart to
// TestReshareDklsEndToEnd. The reshare must preserve the GroupPublicKey
// (the wallet's Ed25519 public key) so downstream Solana / Sui addresses
// stay valid.
func TestReshareFrostEndToEnd(t *testing.T) {
	w := &Wallet{Protocol: ProtocolFROST}
	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.initializeEdDSAWallet(context.Background(), kd); err != nil {
		t.Fatalf("frost keygen failed: %s", err)
	}
	origPubkey := w.Pubkey

	// Pre-reshare sign sanity check.
	preOpts := &wltsign.Opts{Context: context.Background()}
	for _, k := range w.Keys[:w.Threshold+1] {
		preOpts.Keys = append(preOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	if _, err := w.Sign(nil, []byte("pre-reshare"), preOpts); err != nil {
		t.Fatalf("pre-reshare sign failed: %s", err)
	}

	// FROST resharing tolerates any T+1 oldSubset (subset of old
	// committee); use the first two for definiteness.
	oldKeys := make([]*wltsign.KeyDescription, w.Threshold+1)
	for i, k := range w.Keys[:w.Threshold+1] {
		oldKeys[i] = &wltsign.KeyDescription{Id: k.Id.String()}
	}
	newKD := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}
	if err := w.Reshare(context.Background(), oldKeys, newKD); err != nil {
		t.Fatalf("frost reshare failed: %s", err)
	}
	if w.Pubkey != origPubkey {
		t.Fatalf("frost reshare changed Pubkey: %q → %q", origPubkey, w.Pubkey)
	}
	if len(w.Keys) != len(newKD) {
		t.Fatalf("expected %d new keys, got %d", len(newKD), len(w.Keys))
	}
	for i, k := range w.Keys {
		if k.Schema != "frost" {
			t.Errorf("new Keys[%d].Schema = %q, want \"frost\"", i, k.Schema)
		}
	}

	postOpts := &wltsign.Opts{Context: context.Background()}
	for _, k := range w.Keys[:w.Threshold+1] {
		postOpts.Keys = append(postOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	postMsg := []byte("post-reshare frost verification")
	sig, err := w.Sign(nil, postMsg, postOpts)
	if err != nil {
		t.Fatalf("post-reshare sign failed: %s", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("post-reshare sig length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("decode pubkey: %s", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), postMsg, sig) {
		t.Fatalf("post-reshare signature did not verify against persisted pubkey")
	}
}
