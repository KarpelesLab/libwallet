package wltwallet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"testing"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
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

func must[T any](a T, err error) T {
	if err != nil {
		panic(err)
	}
	return a
}
