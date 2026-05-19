package wltwallet

import (
	"context"
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
