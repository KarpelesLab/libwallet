package wltwallet

import (
	"context"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/xuid"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
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
