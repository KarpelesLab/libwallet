package wltwallet

import (
	"context"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/xuid"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

func TestRemoteWallet(t *testing.T) {
	// Real-infra end-to-end: drives Crypto/WalletSign:new/verify/
	// reshare via the testPhone account ("+14045551234" / verify
	// code "000000"), authenticated as ClientID com.ellipx.walletapp
	// (registered by TestMain in testmain_test.go). On a backend
	// blip we skip via skipOnBackendInfra so the build doesn't fail
	// on documented infra flakes; on a healthy backend this fully
	// covers the dkls23 RemoteKey lifecycle + reshare.
	log.Printf("generating remote ID...")
	remote, err := remoteNew(context.Background(), testPhone)
	if err := skipOnBackendInfra(t, "remoteNew", err); err != nil {
		t.Fatalf("failed to initialize context: %s", err)
	}
	remoteV, err := remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify", err); err != nil {
		t.Fatalf("failed to verify remote context: %s", err)
	}

	log.Printf("created wallet key receiver with id: %s", remoteV.RemoteKey)

	keys := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{
			Type: "RemoteKey",
			Key:  remoteV.RemoteKey,
		},
	}

	wallet := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     "Test",
		Created:  time.Now(),
		Modified: time.Now(),
	}

	log.Printf("Generating wallet keys (can take a long time!)")

	err = wallet.initializeWallet(context.Background(), keys)
	if err := skipOnBackendInfra(t, "initializeWallet", err); err != nil {
		t.Fatalf("failed to initialize wallet: %s", err)
	}

	// wallet is *ready*

	// now let's try a reshare
	remote, err = remoteReshare(context.Background(), remoteV.RemoteKey)
	if err := skipOnBackendInfra(t, "remoteReshare", err); err != nil {
		t.Fatalf("failed to initialize reshare: %s", err)
	}
	remoteV, err = remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify (reshare)", err); err != nil {
		t.Fatalf("failed to verify reshare remote context: %s", err)
	}

	// dkls23 reshare requires exactly T+1 = 2 old signers in the
	// active subset (T=1 here); passing all 3 keys hits the explicit
	// "got 3" guard in ReshareDkls. Pick one Plain + the RemoteKey
	// so the reshare actually exercises the wdrone path.
	var oldKeys []*wltsign.KeyDescription
	plainIncluded := false
	for _, k := range wallet.Keys {
		switch k.Type {
		case "RemoteKey":
			oldKeys = append(oldKeys, &wltsign.KeyDescription{Id: k.Id.String(), Key: remoteV.RemoteKey})
		case "Plain":
			if !plainIncluded {
				oldKeys = append(oldKeys, &wltsign.KeyDescription{Id: k.Id.String()})
				plainIncluded = true
			}
		}
	}

	newKeys := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{
			Type: "RemoteKey",
			Key:  remoteV.RemoteKey, // using the same ID will allow updating the payload
		},
	}

	if err := wallet.Reshare(context.Background(), oldKeys, newKeys); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "failed to select peer") {
			t.Skipf("backend not reachable (selectPeer): %s", err)
		}
		if strings.Contains(errMsg, "failed to init remote") &&
			strings.Contains(errMsg, "context deadline exceeded") {
			t.Skipf("backend not reachable (init timeout): %s", err)
		}
		t.Fatalf("failed to reshare remote wallet: %s", err)
	}
}

func TestEdDSALocalToRemoteReshare(t *testing.T) {
	// Real-infra end-to-end: local FROST keygen → reshare to a real
	// RemoteKey share served by the live wdrone fleet. Authenticated
	// as ClientID com.ellipx.walletapp via TestMain. Skips on
	// documented backend infra flakes; otherwise runs the full path
	// the field-reported password-reset bug exercises.

	// Step 1: create ed25519 wallet with 3 local (Plain) shares
	wallet := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     "EdDSA-LocalToRemote",
		Created:  time.Now(),
		Modified: time.Now(),
	}

	localKeys := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	err := wallet.initializeEdDSAWallet(context.Background(), localKeys)
	if err != nil {
		t.Fatalf("failed to create local ed25519 wallet: %s", err)
	}
	log.Printf("ed25519 wallet created locally, pubkey=%s", wallet.Pubkey)
	origPubkey := wallet.Pubkey

	// verify signing works with local keys
	opts := &wltsign.Opts{Context: context.Background()}
	for _, k := range wallet.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	sig, err := wallet.Sign(nil, []byte("pre-reshare test"), opts)
	if err != nil {
		t.Fatalf("failed to sign before reshare: %s", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte sig, got %d", len(sig))
	}
	log.Printf("pre-reshare signing works")

	// Step 2: set up remote key via 2FA
	remote, err := remoteNew(context.Background(), testPhone)
	if err := skipOnBackendInfra(t, "remoteNew", err); err != nil {
		t.Fatalf("failed to create remote session: %s", err)
	}
	remoteV, err := remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify", err); err != nil {
		t.Fatalf("failed to verify remote session: %s", err)
	}
	log.Printf("remote key verified: %s", remoteV.RemoteKey)

	// Step 3: reshare from 3 Plain → 2 Plain + 1 RemoteKey
	oldKeys := make([]*wltsign.KeyDescription, len(wallet.Keys))
	for i, k := range wallet.Keys {
		oldKeys[i] = &wltsign.KeyDescription{Id: k.Id.String()}
	}

	newKeys := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "RemoteKey", Key: remoteV.RemoteKey},
	}

	if err := wallet.Reshare(context.Background(), oldKeys, newKeys); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "failed to select peer") {
			t.Skipf("backend not reachable (selectPeer): %s", err)
		}
		if strings.Contains(errMsg, "failed to init remote") &&
			strings.Contains(errMsg, "context deadline exceeded") {
			t.Skipf("backend not reachable (init timeout): %s", err)
		}
		t.Fatalf("failed to reshare ed25519 wallet to remote: %s", err)
	}
	log.Printf("ed25519 reshare to remote complete, %d new keys", len(wallet.Keys))

	// pubkey must be preserved after reshare
	if wallet.Pubkey != origPubkey {
		t.Errorf("pubkey changed after reshare: %s → %s", origPubkey, wallet.Pubkey)
	}

	if len(wallet.Keys) != 3 {
		t.Fatalf("expected 3 keys after reshare, got %d", len(wallet.Keys))
	}

	// verify one of the new keys is RemoteKey
	hasRemote := false
	for _, k := range wallet.Keys {
		if k.Type == "RemoteKey" {
			hasRemote = true
		}
	}
	if !hasRemote {
		t.Error("expected at least one RemoteKey after reshare")
	}
}
