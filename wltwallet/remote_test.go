package wltwallet

import (
	"context"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/xuid"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	// Temporary: surface the raw response body when rest.Do can't
	// parse it as JSON. Three back-to-back CI failures on
	// Crypto/WalletSign:setGeneratedKey returned HTML
	// ("invalid character '<' looking for beginning of value")
	// without telling us what the body actually said. Drop after
	// the cause is identified.
	rest.Debug = true
}

func TestRemoteWallet(t *testing.T) {
	// generate a new remote id
	log.Printf("generating remote ID...")
	remote, err := remoteNew(context.Background(), "+14045551234") // "unit_test"
	if err != nil {
		t.Errorf("failed to initialize context: %s", err)
		return
	}
	remoteV, err := remoteVerify(context.Background(), remote.Session, "000000") // test code
	if err != nil {
		t.Errorf("failed to verify remote context: %s", err)
		return
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
	if err != nil {
		t.Errorf("failed to initialize wallet: %s", err)
		return
	}

	// wallet is *ready*

	// now let's try a reshare
	remote, err = remoteReshare(context.Background(), remoteV.RemoteKey, "secp256k1")
	if err != nil {
		t.Errorf("failed to initialize reshare: %s", err)
	}
	remoteV, err = remoteVerify(context.Background(), remote.Session, "000000") // test code
	if err != nil {
		t.Errorf("failed to verify reshare remote context: %s", err)
		return
	}

	var oldKeys []*wltsign.KeyDescription
	for _, k := range wallet.Keys {
		if k.Type == "RemoteKey" {
			oldKeys = append(oldKeys, &wltsign.KeyDescription{Id: k.Id.String(), Key: remoteV.RemoteKey})
		} else {
			oldKeys = append(oldKeys, &wltsign.KeyDescription{Id: k.Id.String()})
		}
	}

	newKeys := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{
			Type: "RemoteKey",
			Key:  remoteV.RemoteKey, // using the same ID will allow updating the payload
		},
	}

	err = wallet.Reshare(context.Background(), oldKeys, newKeys)
	if err != nil {
		t.Errorf("failed to reshare remote wallet: %s", err)
	}
}

func TestEdDSALocalToRemoteReshare(t *testing.T) {
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
	if err != nil {
		t.Fatalf("failed to create remote session: %s", err)
	}
	remoteV, err := remoteVerify(context.Background(), remote.Session, "000000")
	if err != nil {
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

	err = wallet.Reshare(context.Background(), oldKeys, newKeys)
	if err != nil {
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
