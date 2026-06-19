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
	"github.com/KarpelesLab/xuid"
)

// TestPromoteToDkls23EndToEnd exercises the import-helper-driven
// promote path. A fresh 32-byte secp256k1 privkey is wrapped as a
// 1-of-1 dklstss.Key via the in-tss-lib ImportKey helper, then
// distributed to a 3-share committee with threshold 1 via
// dklstss.NewResharing. The new committee must sign DER signatures
// that verify under the importer's original public key — if the
// joint pubkey moved during the reshare, downstream addresses would
// silently break, which is what this test pins.
//
// Runs entirely in-process; no database, no Spot, no Paillier
// preparams.
func TestPromoteToDkls23EndToEnd(t *testing.T) {
	// 1) Fresh secp256k1 privkey.
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %s", err)
	}
	expectedPub := secp256k1.PrivKeyFromBytes(priv[:]).PubKey().SerializeCompressed()

	// 2) Allocate 3 new committee rows (thin, no Paillier).
	newWKeys := make([]*WalletKey, 3)
	walletID := xuid.New("wlt")
	for i := range newWKeys {
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: walletID,
			Type:   "Plain",
			Gen:    1,
		}
	}
	importerShell := &WalletKey{Id: xuid.New("wkey")}

	// 3) Run the import + reshare end-to-end.
	if err := promoteToDkls23(context.Background(), priv[:], importerShell, newWKeys, 1); err != nil {
		t.Fatalf("promoteToDkls23: %s", err)
	}

	// 4) Every new share holds dklsData stamped with the original pubkey.
	for i, p := range newWKeys {
		if p.dklsData == nil {
			t.Fatalf("new committee key %d missing dklsData", i)
		}
		gotPub := p.dklsData.ECDSAPub.ToSecp256k1PubKey().SerializeCompressed()
		if base64.RawURLEncoding.EncodeToString(gotPub) != base64.RawURLEncoding.EncodeToString(expectedPub) {
			t.Errorf("new key %d pubkey diverged from importer: got %x want %x", i, gotPub, expectedPub)
		}
	}

	// 5) Promote landed shares on the WalletKeys directly. Drive a
	//    full Sign() through a synthesized Wallet to confirm the
	//    committee can produce a signature that recovers back to the
	//    original pubkey.
	w := &Wallet{
		Id:        walletID,
		Curve:     "secp256k1",
		Protocol:  ProtocolDKLS,
		Threshold: 1,
		Pubkey:    base64.RawURLEncoding.EncodeToString(expectedPub),
		Keys:      newWKeys,
	}
	// encrypt now so subSign's decryptDkls round-trips through the same
	// Bottle pipeline production callers use; otherwise the test would
	// be relying on dklsData being in memory which production never is.
	for _, k := range w.Keys {
		if err := k.encrypt(&wltsign.KeyDescription{Type: "Plain"}); err != nil {
			t.Fatalf("encrypt key %s: %s", k.Id, err)
		}
	}

	opts := &wltsign.Opts{}
	for _, k := range w.Keys[:w.Threshold+1] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	msg := []byte("dkls23 promote verification")
	digest := sha256.Sum256(msg)
	sig, err := w.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		t.Fatalf("post-promote sign failed: %s", err)
	}
	parsed, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Fatalf("parse DER: %s", err)
	}
	pub, err := secp256k1.ParsePubKey(expectedPub)
	if err != nil {
		t.Fatalf("parse pub: %s", err)
	}
	if !parsed.Verify(digest[:], pub) {
		t.Fatalf("post-promote signature did not verify against importer pubkey — promote moved the joint key")
	}
}

// TestPromoteToFrostEndToEnd is the ed25519 counterpart of
// TestPromoteToDkls23EndToEnd. The most important guard: the
// post-promote GroupPublicKey MUST equal the public half of
// ed25519.NewKeyFromSeed(seed) — the wallet's Pubkey field was
// computed against that point at import time, so any divergence
// silently breaks every Solana / Sui / etc. address derived from
// the wallet.
func TestPromoteToFrostEndToEnd(t *testing.T) {
	// 1) Fresh 32-byte Ed25519 seed.
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand: %s", err)
	}
	expectedPub := []byte(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))

	// 2) 3-share committee.
	newWKeys := make([]*WalletKey, 3)
	walletID := xuid.New("wlt")
	for i := range newWKeys {
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: walletID,
			Type:   "Plain",
			Gen:    1,
		}
	}
	importerShell := &WalletKey{Id: xuid.New("wkey")}

	// 3) Import + reshare end-to-end.
	if err := promoteToFrost(context.Background(), seed[:], importerShell, newWKeys, 1); err != nil {
		t.Fatalf("promoteToFrost: %s", err)
	}

	// 4) Every new share's GroupPublicKey matches the seed's pubkey.
	for i, p := range newWKeys {
		if p.frostData == nil {
			t.Fatalf("new committee key %d missing frostData", i)
		}
		gotPub := p.frostData.GroupPublicKey.ToEd25519PubKey().Serialize()
		if base64.RawURLEncoding.EncodeToString(gotPub) != base64.RawURLEncoding.EncodeToString(expectedPub) {
			t.Errorf("new key %d pubkey diverged from seed import: got %x want %x", i, gotPub, expectedPub)
		}
	}

	// 5) Drive a sign through the synthesized wallet to confirm the
	//    promoted committee produces an Ed25519 signature that stdlib
	//    accepts under the seed-derived pubkey. If the FROST scalar
	//    diverged from the seed's clamped scalar, this is where it
	//    surfaces.
	w := &Wallet{
		Id:        walletID,
		Curve:     "ed25519",
		Protocol:  ProtocolFROST,
		Threshold: 1,
		Pubkey:    base64.RawURLEncoding.EncodeToString(expectedPub),
		Keys:      newWKeys,
	}
	for _, k := range w.Keys {
		if err := k.encrypt(&wltsign.KeyDescription{Type: "Plain"}); err != nil {
			t.Fatalf("encrypt key %s: %s", k.Id, err)
		}
	}
	opts := &wltsign.Opts{Context: context.Background()}
	for _, k := range w.Keys[:w.Threshold+1] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	msg := []byte("frost promote verification")
	sig, err := w.Sign(nil, msg, opts)
	if err != nil {
		t.Fatalf("post-promote frost sign failed: %s", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(expectedPub), msg, sig) {
		t.Fatalf("post-promote frost sig did not verify under seed-derived pubkey — scalar derivation diverged from RFC 8032")
	}
}
