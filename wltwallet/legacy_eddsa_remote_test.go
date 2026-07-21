package wltwallet

// Real-infra end-to-end (live wdrone fleet), like TestRemoteWallet: LEGACY eddsatss (GG18-style Schnorr) reshare
// with the RemoteKey as an OLD-side active TSS participant — the exact
// field-reported device-recovery shape for wallets created before the FROST
// migration (their reshare logs say "producing eddsa reshare final", not
// "frost"). Legacy keygen was removed in b93ac5b with the promise that
// existing legacy wallets stay reshareable; this probe checks the wdrone
// side of that promise (runWalletReshareEddsa driving the rounds).
//
// Keygen body resurrected from b93ac5b^ (pre-removal initializeEdDSAWallet).

import (
	"context"
	"log"
	"math/big"
	"strings"
	"testing"
	"time"

	"encoding/base64"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/xuid"
)

// legacyEdDSAKeygen builds a 1-of-3 LEGACY eddsatss wallet with local Plain
// shares — what a pre-FROST libwallet produced.
func legacyEdDSAKeygen(t *testing.T) *Wallet {
	t.Helper()
	w := &Wallet{Id: xuid.New("wlt"), Name: "legacy-eddsa-probe", Created: time.Now(), Modified: time.Now()}
	w.Curve = "ed25519"
	w.Protocol = ProtocolLegacyEdDSA
	w.Threshold = 1
	kDesc := []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "Plain"}}
	nk := len(kDesc)
	w.Keys = make([]*WalletKey, nk)

	ctx := context.Background()
	root := newProgressScope(ctx)
	for i, kInfo := range kDesc {
		k, err := w.createWalletKey(ctx, kInfo.Type, root.sub(i, nk+1))
		if err != nil {
			t.Fatalf("createWalletKey: %s", err)
		}
		w.Keys[i] = k
	}

	var ids tss.UnSortedPartyIDs
	idmap := make(map[int]*tss.PartyID)
	for n, p := range w.Keys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		ids = append(ids, id)
		idmap[n] = id
	}
	sids := tss.SortPartyIDs(ids)
	curve := tss.Edwards()
	tssctx := tss.NewPeerContext(sids)

	hub := newTssHub()
	for n := range w.Keys {
		hub.addLocal(idmap[n])
	}
	done := make(chan struct{})
	for n, p := range w.Keys {
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		params.SetBroker(hub.local[idmap[n].Id])
		kg, err := eddsatss.NewKeygen(ctx, params)
		if err != nil {
			t.Fatalf("eddsa keygen start party %d: %s", n, err)
		}
		go func(p *WalletKey, kg *eddsatss.Keygen) {
			select {
			case key := <-kg.Done:
				p.eddata = key
			case err := <-kg.Err:
				log.Printf("eddsa keygen err = %s", err)
			}
			done <- struct{}{}
		}(p, kg)
	}
	for range w.Keys {
		<-done
	}
	for _, p := range w.Keys {
		if p.eddata == nil {
			t.Fatal("legacy eddsa keygen failed")
		}
	}
	pubBytes := w.Keys[0].eddata.EDDSAPub.ToEd25519PubKey().Serialize()
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pubBytes)
	for i, kInfo := range kDesc {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			t.Fatalf("encrypt key %d: %s", i, err)
		}
	}
	return w
}

func TestLegacyEdDSAOldSideRemoteReshare(t *testing.T) {
	wallet := legacyEdDSAKeygen(t)
	log.Printf("legacy eddsa wallet ready, pubkey=%s", wallet.Pubkey)

	// Phase 1: reshare 3 Plain → 2 Plain + RemoteKey (remote NEW-side only;
	// mirrors how field wallets acquired their 2FA share).
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
		t.Fatalf("phase-1 legacy reshare to remote: %s", err)
	}
	log.Printf("phase 1 done: legacy wallet has a live RemoteKey share")

	// Phase 2 — THE PROBE: old = [one Plain, RemoteKey]; wdrone must drive
	// LEGACY eddsatss reshare rounds (runWalletReshareEddsa).
	remote, err = remoteReshare(context.Background(), remoteV.RemoteKey)
	if err := skipOnBackendInfra(t, "remoteReshare", err); err != nil {
		t.Fatalf("remoteReshare: %s", err)
	}
	remoteV, err = remoteVerify(context.Background(), remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify(2)", err); err != nil {
		t.Fatalf("remoteVerify(2): %s", err)
	}
	var old2 []*wltsign.KeyDescription
	plainDone := false
	for _, k := range wallet.Keys {
		switch k.Type {
		case "RemoteKey":
			old2 = append(old2, &wltsign.KeyDescription{Id: k.Id.String(), Key: remoteV.RemoteKey, Type: "RemoteKey"})
		case "Plain":
			if !plainDone {
				old2 = append(old2, &wltsign.KeyDescription{Id: k.Id.String()})
				plainDone = true
			}
		}
	}
	new2 := []*wltsign.KeyDescription{{Type: "Plain"}, {Type: "Plain"}, {Type: "RemoteKey", Key: remoteV.RemoteKey}}

	start := time.Now()
	err = wallet.Reshare(context.Background(), old2, new2)
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "failed to select peer") || (strings.Contains(msg, "failed to init remote") && strings.Contains(msg, "context deadline exceeded")) {
			t.Skipf("backend not reachable: %s", err)
		}
		if strings.Contains(msg, "stopped responding") {
			t.Fatalf("REPRODUCED the field hang (rounds deadline fired after %s): %s", time.Since(start).Round(time.Second), err)
		}
		t.Fatalf("legacy old-side remote reshare failed after %s: %s", time.Since(start).Round(time.Second), err)
	}
	log.Printf("LEGACY eddsa old-side remote reshare COMPLETED in %s — fleet drives legacy rounds fine", time.Since(start).Round(time.Second))
}
