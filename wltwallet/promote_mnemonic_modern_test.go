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
	"github.com/tyler-smith/go-bip39"
)

// TestMigrateOneChainBothCurves exercises the modern PromoteMnemonic
// fan-out: one BIP39 seed migrates to a secp256k1 chain (Ethereum
// default path) AND an ed25519 chain (Solana Sollet-style empty
// path), each producing its own modern TSS wallet. The dispatch on
// ChainMigration.Curve is the new surface area; previously
// migrateOneChain only knew BIP32-secp256k1.
func TestMigrateOneChainBothCurves(t *testing.T) {
	// Use a fixed mnemonic so the expected addresses are stable across
	// runs and any future test diff makes the divergence visible.
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := bip39.NewSeed(mnemonic, "")

	source := &Wallet{Name: "TestMnemonic", Curve: "secp256k1"}
	newKeys := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	// ── secp256k1 / DKLs23 chain ──────────────────────────────────
	secpChain := ChainMigration{
		Network:        "ethereum",
		DerivationPath: "m/44'/60'/0'/0/0",
		// Curve empty → defaults to secp256k1 (backwards-compat).
	}
	nwSecp, err := source.migrateOneChain(context.Background(), seed, secpChain, newKeys, 1)
	if err != nil {
		t.Fatalf("migrateOneChain secp256k1: %s", err)
	}
	if nwSecp.Curve != "secp256k1" || nwSecp.Protocol != ProtocolDKLS {
		t.Fatalf("expected secp256k1/dkls23, got %s/%s", nwSecp.Curve, nwSecp.Protocol)
	}
	wantSecpPriv, err := derivePrivkeyFromSeed(seed, "secp256k1", secpChain.DerivationPath)
	if err != nil {
		t.Fatalf("derive expected secp priv: %s", err)
	}
	wantSecpPub := secp256k1.PrivKeyFromBytes(wantSecpPriv).PubKey().SerializeCompressed()
	if base64.RawURLEncoding.EncodeToString(wantSecpPub) != nwSecp.Pubkey {
		t.Errorf("secp256k1 chain pubkey diverged from BIP32 derivation: got %s want %s",
			nwSecp.Pubkey, base64.RawURLEncoding.EncodeToString(wantSecpPub))
	}

	signOpts := &wltsign.Opts{}
	for _, k := range nwSecp.Keys[:nwSecp.Threshold+1] {
		signOpts.Keys = append(signOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	digest := sha256.Sum256([]byte("migrate secp256k1"))
	sig, err := nwSecp.Sign(rand.Reader, digest[:], signOpts)
	if err != nil {
		t.Fatalf("secp256k1 post-migrate sign: %s", err)
	}
	parsed, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Fatalf("parse DER: %s", err)
	}
	wantPub, err := secp256k1.ParsePubKey(wantSecpPub)
	if err != nil {
		t.Fatalf("parse pubkey: %s", err)
	}
	if !parsed.Verify(digest[:], wantPub) {
		t.Fatalf("secp256k1 post-migrate sig did not verify under BIP32-derived pubkey")
	}

	// ── ed25519 / FROST chain ─────────────────────────────────────
	// Empty DerivationPath on ed25519 = Sollet convention (seed[:32]
	// as the Ed25519 seed). Migrating produces a FROST wallet whose
	// GroupPublicKey must match the standard Ed25519 expansion of
	// that same seed[:32].
	edChain := ChainMigration{
		Network:        "solana",
		DerivationPath: "",
		Curve:          "ed25519",
	}
	nwEd, err := source.migrateOneChain(context.Background(), seed, edChain, newKeys, 1)
	if err != nil {
		t.Fatalf("migrateOneChain ed25519: %s", err)
	}
	if nwEd.Curve != "ed25519" || nwEd.Protocol != ProtocolFROST {
		t.Fatalf("expected ed25519/frost, got %s/%s", nwEd.Curve, nwEd.Protocol)
	}
	wantEdSeed, err := derivePrivkeyFromSeed(seed, "ed25519", edChain.DerivationPath)
	if err != nil {
		t.Fatalf("derive expected ed seed: %s", err)
	}
	wantEdPub := []byte(ed25519.NewKeyFromSeed(wantEdSeed).Public().(ed25519.PublicKey))
	if base64.RawURLEncoding.EncodeToString(wantEdPub) != nwEd.Pubkey {
		t.Errorf("ed25519 chain pubkey diverged from SLIP-0010 derivation: got %s want %s",
			nwEd.Pubkey, base64.RawURLEncoding.EncodeToString(wantEdPub))
	}

	edOpts := &wltsign.Opts{Context: context.Background()}
	for _, k := range nwEd.Keys[:nwEd.Threshold+1] {
		edOpts.Keys = append(edOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	edMsg := []byte("migrate ed25519")
	edSig, err := nwEd.Sign(nil, edMsg, edOpts)
	if err != nil {
		t.Fatalf("ed25519 post-migrate sign: %s", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(wantEdPub), edMsg, edSig) {
		t.Fatalf("ed25519 post-migrate sig did not verify under SLIP-0010-derived pubkey")
	}

	// Sanity: different curves → different pubkeys → different wallet IDs.
	if nwSecp.Pubkey == nwEd.Pubkey {
		t.Error("secp256k1 and ed25519 migrations from the same mnemonic landed on the same pubkey")
	}
	if nwSecp.Id.String() == nwEd.Id.String() {
		t.Error("two chain migrations share a wallet id")
	}
}
