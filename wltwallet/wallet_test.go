package wltwallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/xuid"
)

// testPhone is a known invalid phone number but just valid enough so it can be input in a phone number input field
const testPhone = "+14045551234" // code=000000

func TestWalletCreate(t *testing.T) {
	w := &Wallet{}

	log.Printf("storeKey = %+v", must(storekeyCreate()))

	remoteKey := must(remoteNew(context.Background(), testPhone))
	verify := must(remoteVerify(context.Background(), remoteKey.Session, "000000"))
	log.Printf("made session = %+v", verify)

	kd := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
	}

	err := w.initializeWallet(context.Background(), kd)
	if err != nil {
		t.Errorf("failed to init: %s", err)
		return
	}

	log.Printf("wallet ready")

	// test sig
	opts := &wltsign.Opts{}

	for _, k := range w.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	s := []byte("hello world")
	sHash := sha256.Sum256(s)

	sig, err := w.Sign(rand.Reader, sHash[:], opts)
	if err != nil {
		t.Errorf("failed to sign: %s", err)
		return
	}

	log.Printf("signature data (len %d) = %x", len(sig), sig)

	sigO, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Errorf("failed to parse sign: %s", err)
		return
	}

	// extract public key
	pubk := must(secp256k1.ParsePubKey(must(base64.RawURLEncoding.DecodeString(w.Pubkey))))

	sigO.BruteforceRecoveryCode(sHash[:], pubk)

	// transform signature into ethereum format
	sigC := sigO.ExportCompact(true, 27)

	// check if signature is valid
	//log.Printf("wallet pubkey = %v", pubk)
	pk, compressed, err := secp256k1.RecoverCompact(sigC, sHash[:])

	if err != nil {
		t.Errorf("failed to recover ECDSA key from signature: %s", err)
	} else if compressed {
		t.Errorf("invalid compressed flag, expected compressed=false")
	} else if !pk.IsEqual(pubk) {
		t.Errorf("invalid signature (public key did not match")
	}
	// all good

	// let's try reshare
	newKd := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
	}

	err = w.Reshare(context.Background(), opts.Keys, newKd)
	if err != nil {
		t.Errorf("failed to reshare wallet: %s", err)
		return
	}

	// let's try to sign again after reshare

	// first, fetch the new keys
	opts = &wltsign.Opts{}
	for _, k := range w.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	s = []byte("hello world2")
	sHash = sha256.Sum256(s)

	sig, err = w.Sign(rand.Reader, sHash[:], opts)
	if err != nil {
		t.Errorf("failed to sign: %s", err)
		return
	}

	log.Printf("signature data (len %d) = %x", len(sig), sig)

	sigO, err = secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Errorf("failed to parse sign: %s", err)
		return
	}

	// extract public key
	pubk = must(secp256k1.ParsePubKey(must(base64.RawURLEncoding.DecodeString(w.Pubkey))))

	sigO.BruteforceRecoveryCode(sHash[:], pubk)

	// transform signature into ethereum format
	sigC = sigO.ExportCompact(true, 27)

	// check if signature is valid
	//log.Printf("wallet pubkey = %v", pubk)
	pk, compressed, err = secp256k1.RecoverCompact(sigC, sHash[:])

	if err != nil {
		t.Errorf("failed to recover ECDSA key from signature: %s", err)
	} else if compressed {
		t.Errorf("invalid compressed flag, expected compressed=false")
	} else if !pk.IsEqual(pubk) {
		t.Errorf("invalid signature (public key did not match")
	}
	// all good
}

func TestEdDSAWalletCreate(t *testing.T) {
	w := &Wallet{}

	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	err := w.initializeEdDSAWallet(context.Background(), kd)
	if err != nil {
		t.Fatalf("failed to init eddsa wallet: %s", err)
	}

	if w.Curve != "ed25519" {
		t.Errorf("expected curve ed25519, got %s", w.Curve)
	}
	if w.Pubkey == "" {
		t.Fatal("expected non-empty pubkey")
	}
	if w.Chaincode == "" {
		t.Fatal("expected non-empty chaincode")
	}
	if len(w.Keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(w.Keys))
	}
	for i, k := range w.Keys {
		if k.Id == nil {
			t.Errorf("key %d has nil Id", i)
		}
		if k.Type != "Plain" {
			t.Errorf("key %d type = %s, want Plain", i, k.Type)
		}
	}

	log.Printf("eddsa wallet ready, pubkey=%s", w.Pubkey)
	origPubkey := w.Pubkey

	// The pubkey stored on the Wallet struct MUST be the
	// spec-compliant compressed Ed25519 encoding (32-byte little-
	// endian Y with X-sign bit in MSB of byte 31) — not a raw X
	// coordinate. Without this check the wallet produces valid TSS
	// signatures that Solana rejects because the displayed pubkey
	// doesn't match the signing key. Regression guard for the bug
	// fixed in 2c8b25d / 0c1e355.
	edPubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("wallet pubkey is not valid base64: %s", err)
	}
	if len(edPubBytes) != ed25519.PublicKeySize {
		t.Fatalf("wallet pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(edPubBytes))
	}
	// Cross-check against what stdlib would produce from the same
	// Edwards point: the TSS public key, serialized via the library's
	// canonical compressed form, must match byte-for-byte.
	canonical := w.Keys[0].eddata.EDDSAPub.ToEd25519PubKey().Serialize()
	if !bytes.Equal(edPubBytes, canonical) {
		t.Fatalf("wallet pubkey mismatch with canonical compressed form:\n  got:  %x\n  want: %x", edPubBytes, canonical)
	}

	// sign with keys 0+1
	opts := &wltsign.Opts{Context: context.Background()}
	for _, k := range w.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	msg1 := []byte("hello ed25519 world")
	sig1, err := w.Sign(nil, msg1, opts)
	if err != nil {
		t.Fatalf("failed to sign msg1: %s", err)
	}
	if len(sig1) != 64 {
		t.Errorf("expected 64-byte signature, got %d bytes", len(sig1))
	}
	log.Printf("eddsa sig1 (len %d) = %x", len(sig1), sig1)

	// End-to-end verification against stdlib: the signature the TSS
	// just produced MUST verify under the pubkey the wallet reports.
	// A mismatch here means Solana's signature-verification would
	// also reject the tx — catches the same class of bug the user
	// hit in production (Transaction did not pass signature
	// verification) regardless of which of the many encoding steps
	// is wrong.
	if !ed25519.Verify(ed25519.PublicKey(edPubBytes), msg1, sig1) {
		t.Fatalf("stdlib ed25519.Verify rejected the TSS signature under the wallet's own pubkey — Solana will do the same")
	}

	// sign a different message with same keys
	msg2 := []byte("second message")
	sig2, err := w.Sign(nil, msg2, opts)
	if err != nil {
		t.Fatalf("failed to sign msg2: %s", err)
	}
	if len(sig2) != 64 {
		t.Errorf("expected 64-byte signature, got %d bytes", len(sig2))
	}

	// signatures for different messages should differ
	if string(sig1) == string(sig2) {
		t.Error("signatures for different messages should not be identical")
	}

	// sign with keys 0+2 (different threshold subset)
	opts2 := &wltsign.Opts{Context: context.Background()}
	opts2.Keys = []*wltsign.KeyDescription{
		{Id: w.Keys[0].Id.String()},
		{Id: w.Keys[2].Id.String()},
	}

	sig3, err := w.Sign(nil, msg1, opts2)
	if err != nil {
		t.Fatalf("failed to sign with keys 0+2: %s", err)
	}
	if len(sig3) != 64 {
		t.Errorf("expected 64-byte signature, got %d bytes", len(sig3))
	}
	log.Printf("eddsa sig3 (keys 0+2, len %d) = %x", len(sig3), sig3)

	// sign with keys 1+2
	opts3 := &wltsign.Opts{Context: context.Background()}
	opts3.Keys = []*wltsign.KeyDescription{
		{Id: w.Keys[1].Id.String()},
		{Id: w.Keys[2].Id.String()},
	}

	sig4, err := w.Sign(nil, msg1, opts3)
	if err != nil {
		t.Fatalf("failed to sign with keys 1+2: %s", err)
	}
	if len(sig4) != 64 {
		t.Errorf("expected 64-byte signature, got %d bytes", len(sig4))
	}
	log.Printf("eddsa sig4 (keys 1+2, len %d) = %x", len(sig4), sig4)

	// pubkey should not have changed
	if w.Pubkey != origPubkey {
		t.Errorf("pubkey changed after signing: %s -> %s", origPubkey, w.Pubkey)
	}

	// decode and verify pubkey is valid 32-byte ed25519 key
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		t.Fatalf("failed to decode pubkey: %s", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("expected 32-byte ed25519 pubkey, got %d bytes", len(pubBytes))
	}

	// reshare to new keys
	log.Printf("starting eddsa reshare")
	newKd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	// use keys 0+1 as old keys for reshare
	oldKeyDescs := []*wltsign.KeyDescription{
		{Id: w.Keys[0].Id.String()},
		{Id: w.Keys[1].Id.String()},
		{Id: w.Keys[2].Id.String()},
	}

	err = w.Reshare(context.Background(), oldKeyDescs, newKd)
	if err != nil {
		t.Fatalf("failed to reshare eddsa wallet: %s", err)
	}
	log.Printf("eddsa reshare complete, new keys: %d", len(w.Keys))

	if len(w.Keys) != 3 {
		t.Fatalf("expected 3 new keys after reshare, got %d", len(w.Keys))
	}

	// sign with new keys after reshare
	opts4 := &wltsign.Opts{Context: context.Background()}
	for _, k := range w.Keys[:2] {
		opts4.Keys = append(opts4.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	msg5 := []byte("message after reshare")
	sig5, err := w.Sign(nil, msg5, opts4)
	if err != nil {
		t.Fatalf("failed to sign after reshare: %s", err)
	}
	if len(sig5) != 64 {
		t.Errorf("expected 64-byte signature after reshare, got %d bytes", len(sig5))
	}
	log.Printf("eddsa post-reshare signature (len %d) = %x", len(sig5), sig5)
}

func TestMultiCreateWallet(t *testing.T) {
	kd := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	now := time.Now()
	wSecp := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     "MultiTest",
		Created:  now,
		Modified: now,
	}
	wEd := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     "MultiTest",
		Created:  now,
		Modified: now,
	}

	var errSecp, errEd error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errSecp = wSecp.initializeWallet(context.Background(), kd)
	}()
	go func() {
		defer wg.Done()
		errEd = wEd.initializeEdDSAWallet(context.Background(), kd)
	}()
	wg.Wait()

	if errSecp != nil {
		t.Fatalf("secp256k1 init failed: %s", errSecp)
	}
	if errEd != nil {
		t.Fatalf("ed25519 init failed: %s", errEd)
	}

	// Verify secp256k1 wallet
	if wSecp.Curve != "secp256k1" {
		t.Errorf("expected secp256k1 curve, got %s", wSecp.Curve)
	}
	if wSecp.Pubkey == "" {
		t.Fatal("secp256k1 wallet has empty pubkey")
	}
	if len(wSecp.Keys) != 3 {
		t.Fatalf("expected 3 secp256k1 keys, got %d", len(wSecp.Keys))
	}

	// Verify ed25519 wallet
	if wEd.Curve != "ed25519" {
		t.Errorf("expected ed25519 curve, got %s", wEd.Curve)
	}
	if wEd.Pubkey == "" {
		t.Fatal("ed25519 wallet has empty pubkey")
	}
	if len(wEd.Keys) != 3 {
		t.Fatalf("expected 3 ed25519 keys, got %d", len(wEd.Keys))
	}

	// Pubkeys must differ (different curves)
	if wSecp.Pubkey == wEd.Pubkey {
		t.Error("secp256k1 and ed25519 wallets should have different pubkeys")
	}

	// Verify secp256k1 signing
	secpOpts := &wltsign.Opts{}
	for _, k := range wSecp.Keys[:2] {
		secpOpts.Keys = append(secpOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	msg := sha256.Sum256([]byte("multi-create test"))
	sigSecp, err := wSecp.Sign(rand.Reader, msg[:], secpOpts)
	if err != nil {
		t.Fatalf("secp256k1 sign failed: %s", err)
	}

	pubk := must(secp256k1.ParsePubKey(must(base64.RawURLEncoding.DecodeString(wSecp.Pubkey))))
	sigO := must(secp256k1.ParseDERSignature(sigSecp))
	sigO.BruteforceRecoveryCode(msg[:], pubk)
	sigC := sigO.ExportCompact(true, 27)
	pk, _, err := secp256k1.RecoverCompact(sigC, msg[:])
	if err != nil {
		t.Fatalf("secp256k1 recover failed: %s", err)
	}
	if !pk.IsEqual(pubk) {
		t.Error("secp256k1 signature pubkey mismatch")
	}

	// Verify ed25519 signing
	edOpts := &wltsign.Opts{Context: context.Background()}
	for _, k := range wEd.Keys[:2] {
		edOpts.Keys = append(edOpts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	edMsg := []byte("multi-create ed25519 test")
	sigEd, err := wEd.Sign(nil, edMsg, edOpts)
	if err != nil {
		t.Fatalf("ed25519 sign failed: %s", err)
	}
	if len(sigEd) != 64 {
		t.Errorf("expected 64-byte ed25519 sig, got %d", len(sigEd))
	}

	log.Printf("multi-create test passed: secp256k1 pubkey=%s ed25519 pubkey=%s", wSecp.Pubkey, wEd.Pubkey)
}

func must[T any](a T, err error) T {
	if err != nil {
		panic(err)
	}
	return a
}
