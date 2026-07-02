package wltwallet

// Real-infra end-to-end (live wdrone fleet): reproduce the field-reported
// RemoteKey share desync and validate Wallet:repairRemoteKey fixes it.
//
// The field incident: a change-password reshare's final setGeneratedKey
// upload timed out client-side (90s http2 header timeout) but still landed
// server-side, overwriting the crws record's share with one from the
// abandoned ceremony's polynomial while the wallet kept its old committee.
// Every later ceremony needing the RemoteKey's participation then stalled
// after peer init — and with the StoreKey also lost, the wallet dropped
// below T+1 recoverable shares. The repair relies on encrypt() keeping the
// byte-identical fleet-encrypted blob in WalletKey.Data (preserved by
// Wallet:backup): pushing it back restores the record.
//
// The corruption is simulated exactly: deep-copy the wallet (as backup
// does), run a completing reshare on the COPY (its upload lands, like the
// abandoned ceremony's did), then discard the copy — the original wallet
// now disagrees with the server-side share.
//
// The slow leg (verifying the corrupted state trips the 2-minute rounds
// deadline) runs only with LIBWALLET_SLOW_TESTS=1; the corrupt → repair →
// recover cycle always runs.

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
)

func freshRemoteSession(t *testing.T, key string) string {
	t.Helper()
	remote, err := remoteReshare(context.Background(), key)
	if err := skipOnBackendInfra(t, "remoteReshare", err); err != nil {
		t.Fatalf("remoteReshare: %s", err)
	}
	v, err := remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify", err); err != nil {
		t.Fatalf("remoteVerify: %s", err)
	}
	return v.RemoteKey
}

func TestRepairRemoteKeyShare(t *testing.T) {
	// Phase 1: legacy wallet with a live RemoteKey share (polynomial P0).
	wallet := legacyEdDSAKeygen(t)
	remote, err := remoteNew(context.Background(), testPhone)
	if err := skipOnBackendInfra(t, "remoteNew", err); err != nil {
		t.Fatalf("remoteNew: %s", err)
	}
	remoteV, err := remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify", err); err != nil {
		t.Fatalf("remoteVerify: %s", err)
	}
	var oldKeys []*wltsign.KeyDescription
	for _, k := range wallet.Keys {
		oldKeys = append(oldKeys, &wltsign.KeyDescription{Id: k.Id.String()})
	}
	if err := wallet.Reshare(context.Background(), oldKeys, []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "RemoteKey", Key: remoteV.RemoteKey}}); err != nil {
		t.Fatalf("phase-1 reshare to remote: %s", err)
	}
	var remoteWK *WalletKey
	for _, k := range wallet.Keys {
		if k.Type == "RemoteKey" {
			remoteWK = k
		}
	}
	if remoteWK == nil || len(remoteWK.Data) == 0 {
		t.Fatal("no RemoteKey share data after phase 1")
	}
	log.Printf("phase 1 done: record holds P0, wallet committee gen=%d", wallet.Gen)

	// Phase 2 — corrupt: the "abandoned ceremony". Reshare a DEEP COPY
	// (management-style: all-local authorizers, remote only on the new
	// side); its setGeneratedKey upload lands, moving the record to P1.
	// Discarding the copy leaves the original wallet on P0 — exactly the
	// field state after the timed-out change-password.
	buf, err := json.Marshal(wallet)
	if err != nil {
		t.Fatalf("marshal wallet: %s", err)
	}
	ghost := &Wallet{}
	if err := json.Unmarshal(buf, ghost); err != nil {
		t.Fatalf("unmarshal ghost wallet: %s", err)
	}
	ghostSession := freshRemoteSession(t, remoteV.RemoteKey)
	var ghostOld []*wltsign.KeyDescription
	for _, k := range ghost.Keys {
		if k.Type == "Plain" {
			ghostOld = append(ghostOld, &wltsign.KeyDescription{Id: k.Id.String()})
		}
	}
	if err := ghost.Reshare(context.Background(), ghostOld, []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "RemoteKey", Key: ghostSession}}); err != nil {
		t.Fatalf("ghost (abandoned) reshare: %s", err)
	}
	log.Printf("phase 2 done: record now holds P1 (abandoned ceremony's share); original wallet still on P0")

	// Phase 3 (slow, optional): the corrupted state must trip the rounds
	// deadline instead of completing.
	if os.Getenv("LIBWALLET_SLOW_TESTS") != "" {
		sess := freshRemoteSession(t, ghostSession)
		var old2 []*wltsign.KeyDescription
		plainDone := false
		for _, k := range wallet.Keys {
			switch k.Type {
			case "RemoteKey":
				old2 = append(old2, &wltsign.KeyDescription{Id: k.Id.String(), Key: sess, Type: "RemoteKey"})
			case "Plain":
				if !plainDone {
					old2 = append(old2, &wltsign.KeyDescription{Id: k.Id.String()})
					plainDone = true
				}
			}
		}
		start := time.Now()
		err := wallet.Reshare(context.Background(), old2, []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "RemoteKey", Key: sess}})
		if err == nil {
			t.Fatal("expected the desynced share to stall the reshare, but it completed")
		}
		if !strings.Contains(err.Error(), "stopped responding") {
			t.Fatalf("expected the rounds-deadline error, got after %s: %s", time.Since(start).Round(time.Second), err)
		}
		log.Printf("phase 3 done: desync reproduced the field hang → deadline error after %s", time.Since(start).Round(time.Second))
	}

	// Phase 4 — repair: push the wallet's local P0 blob back to the record.
	repairSession := freshRemoteSession(t, ghostSession)
	if err := remoteWK.pushRemoteShare(wallet, repairSession); err != nil {
		t.Fatalf("pushRemoteShare: %s", err)
	}
	log.Printf("phase 4 done: record restored to P0 from the wallet's local blob")

	// Phase 5 — recovery works again: old = [Plain, RemoteKey].
	recoverSession := freshRemoteSession(t, repairSession)
	var old3 []*wltsign.KeyDescription
	plainDone := false
	for _, k := range wallet.Keys {
		switch k.Type {
		case "RemoteKey":
			old3 = append(old3, &wltsign.KeyDescription{Id: k.Id.String(), Key: recoverSession, Type: "RemoteKey"})
		case "Plain":
			if !plainDone {
				old3 = append(old3, &wltsign.KeyDescription{Id: k.Id.String()})
				plainDone = true
			}
		}
	}
	start := time.Now()
	if err := wallet.Reshare(context.Background(), old3, []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "RemoteKey", Key: recoverSession}}); err != nil {
		t.Fatalf("post-repair recovery reshare failed after %s: %s", time.Since(start).Round(time.Second), err)
	}
	log.Printf("phase 5 done: post-repair recovery reshare COMPLETED in %s", time.Since(start).Round(time.Second))
}
