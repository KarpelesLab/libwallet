package wltwallet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// Reshare will produce new keys for the given wallet.
func (w *Wallet) Reshare(ctx context.Context, oldKeys []*wltsign.KeyDescription, newKeys []*wltsign.KeyDescription) error {
	if w.Curve == "ed25519" {
		return w.ReshareEdDSA(ctx, oldKeys, newKeys)
	}
	if w.Threshold == 0 {
		w.Threshold = 1
	}

	nk := len(newKeys)

	if nk == 0 {
		return errors.New("at least one key is required")
	}
	if w.Threshold >= nk {
		return errors.New("threshold too high")
	}
	if w.Threshold < 0 {
		return errors.New("threshold too low")
	}

	// prepare old ids
	var oldids tss.UnSortedPartyIDs
	oldidmap := make(map[int]*tss.PartyID)
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p == nil {
			return fmt.Errorf("could not find key id=%s", kd.Id)
		}
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		oldids = append(oldids, id)
		oldidmap[n] = id
	}
	oldsids := tss.SortPartyIDs(oldids)

	curve, ok := tss.GetCurveByName(tss.CurveName(w.Curve))
	if !ok {
		return fmt.Errorf("unknown curve %s", w.Curve)
	}
	oldtssctx := tss.NewPeerContext(oldsids)

	// Allocate new wallet keys (local only; remote peers carry no local key).
	newWKeys := make([]*WalletKey, nk)

	root := newProgressScope(ctx)
	root.report(0)

	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating key %d/%d", i, nk)

		k, err := w.createWalletKey(ctx, kInfo.Type, root.sub(i, nk+1))
		if err != nil {
			return err
		}
		newWKeys[i] = k
	}

	reshareFinalScope := root.sub(nk, nk+1)
	reshareFinalScope.report(0)

	var newids tss.UnSortedPartyIDs
	newidmap := make(map[int]*tss.PartyID)
	for n, p := range newWKeys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		newids = append(newids, id)
		newidmap[n] = id
	}
	newsids := tss.SortPartyIDs(newids)

	newtssctx := tss.NewPeerContext(newsids)

	log.Printf("producing final; oldids = %v newids = %v", oldsids, newsids)

	hub := newTssHub()

	// Register brokers for every local participant (old + new) up-front so
	// pre-handler inbound messages can queue safely.
	for n := range newWKeys {
		hub.addLocal(newidmap[n])
	}
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			continue
		}
		hub.addLocal(oldidmap[n])
	}

	// Initialize any remote peers (spot handshake) before any TSS round runs.
	var remotes []*spotPeer
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type != "RemoteKey" {
			continue
		}
		info := &walletSignReshareInit{
			OldPeers:      oldsids,
			NewPeers:      newsids,
			Name:          oldidmap[n],
			OldPartycount: len(oldKeys),
			NewPartycount: len(newKeys),
			OldThreshold:  w.Threshold,
			NewThreshold:  w.Threshold,
			Curve:         w.Curve,
		}
		spot, err := envSpot(ctx)
		if err != nil {
			return err
		}
		if err := waitOnlineSpot(spot); err != nil {
			return err
		}
		log.Printf("initializing remote peer %s with info=%+v", p.Id.String(), info)
		log.Printf("remote sid = %s", kd.Key)
		rp := &spotPeer{
			hub:     hub,
			partyId: oldidmap[n],
			info:    info,
			spot:    spot,
			sid:     kd.Key,
		}
		hub.addRemote(rp)
		remotes = append(remotes, rp)
	}

	for _, rp := range remotes {
		if err := rp.Start(); err != nil {
			return fmt.Errorf("failed to start remote peer %s: %w", rp.partyId.Id, err)
		}
	}

	var wg sync.WaitGroup
	var reshareErr error
	var reshareErrOnce sync.Once

	// New committee members
	for n, p := range newWKeys {
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, newidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		params.SetBroker(hub.local[newidmap[n].Id])
		rs, err := ecdsatss.NewResharing(ctx, params, nil, *p.pre)
		if err != nil {
			return fmt.Errorf("failed to start reshare for new party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rs *ecdsatss.Resharing) {
			defer wg.Done()
			select {
			case key := <-rs.Done:
				p.sdata = key
			case err := <-rs.Err:
				log.Printf("reshare new-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(p, rs)
	}

	// Old committee members (local only; remote peers are already running on
	// the other side of Spot).
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			continue
		}
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, oldidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		params.SetBroker(hub.local[oldidmap[n].Id])
		sdata, err := p.decrypt(kd, keyResharePurpose)
		if err != nil {
			return err
		}
		rs, err := ecdsatss.NewResharing(ctx, params, sdata)
		if err != nil {
			return fmt.Errorf("failed to start reshare for old party %d: %w", n, err)
		}
		wg.Add(1)
		go func(rs *ecdsatss.Resharing) {
			defer wg.Done()
			select {
			case <-rs.Done:
				// old committee members produce a key with Xi zeroed; discard
			case err := <-rs.Err:
				log.Printf("reshare old-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(rs)
	}

	wg.Wait()

	if reshareErr != nil {
		return reshareErr
	}
	for _, p := range newWKeys {
		if p.sdata == nil {
			return errors.New("reshare failed: missing new committee key data")
		}
	}

	w.Keys = newWKeys

	for i, kInfo := range newKeys {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			return err
		}
	}

	reshareFinalScope.report(1)
	return nil
}

// ReshareEdDSA will produce new keys for the given ed25519 wallet.
func (w *Wallet) ReshareEdDSA(ctx context.Context, oldKeys []*wltsign.KeyDescription, newKeys []*wltsign.KeyDescription) error {
	if w.Curve != "ed25519" {
		return errors.New("ReshareEdDSA requires an ed25519 wallet")
	}
	if w.Threshold == 0 {
		w.Threshold = 1
	}

	nk := len(newKeys)

	if nk == 0 {
		return errors.New("at least one key is required")
	}
	if w.Threshold >= nk {
		return errors.New("threshold too high")
	}
	if w.Threshold < 0 {
		return errors.New("threshold too low")
	}

	var oldids tss.UnSortedPartyIDs
	oldidmap := make(map[int]*tss.PartyID)
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p == nil {
			return fmt.Errorf("could not find key id=%s", kd.Id)
		}
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		oldids = append(oldids, id)
		oldidmap[n] = id
	}
	oldsids := tss.SortPartyIDs(oldids)

	curve := tss.Edwards()
	oldtssctx := tss.NewPeerContext(oldsids)

	newWKeys := make([]*WalletKey, nk)

	rootEd := newProgressScope(ctx)
	rootEd.report(0)

	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating eddsa reshare key %d/%d", i, nk)

		k, err := w.createWalletKey(ctx, kInfo.Type, rootEd.sub(i, nk+1))
		if err != nil {
			return err
		}
		newWKeys[i] = k
	}

	edReshareFinalScope := rootEd.sub(nk, nk+1)
	edReshareFinalScope.report(0)

	var newids tss.UnSortedPartyIDs
	newidmap := make(map[int]*tss.PartyID)
	for n, p := range newWKeys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		newids = append(newids, id)
		newidmap[n] = id
	}
	newsids := tss.SortPartyIDs(newids)

	newtssctx := tss.NewPeerContext(newsids)

	log.Printf("producing eddsa reshare final; oldids = %v newids = %v", oldsids, newsids)

	hub := newTssHub()

	for n := range newWKeys {
		hub.addLocal(newidmap[n])
	}
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			continue
		}
		hub.addLocal(oldidmap[n])
	}

	var remotes []*spotPeer
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type != "RemoteKey" {
			continue
		}
		info := &walletSignReshareInit{
			OldPeers:      oldsids,
			NewPeers:      newsids,
			Name:          oldidmap[n],
			OldPartycount: len(oldKeys),
			NewPartycount: len(newKeys),
			OldThreshold:  w.Threshold,
			NewThreshold:  w.Threshold,
			Curve:         w.Curve,
		}
		spot, err := envSpot(ctx)
		if err != nil {
			return err
		}
		if err := waitOnlineSpot(spot); err != nil {
			return err
		}
		log.Printf("initializing eddsa remote peer %s with info=%+v", p.Id.String(), info)
		rp := &spotPeer{
			hub:     hub,
			partyId: oldidmap[n],
			info:    info,
			spot:    spot,
			sid:     kd.Key,
		}
		hub.addRemote(rp)
		remotes = append(remotes, rp)
	}

	for _, rp := range remotes {
		if err := rp.Start(); err != nil {
			return fmt.Errorf("failed to start remote peer %s: %w", rp.partyId.Id, err)
		}
	}

	var wg sync.WaitGroup
	var reshareErr error
	var reshareErrOnce sync.Once

	for n, p := range newWKeys {
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, newidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		params.SetBroker(hub.local[newidmap[n].Id])
		rs, err := eddsatss.NewResharing(ctx, params, nil)
		if err != nil {
			return fmt.Errorf("failed to start eddsa reshare for new party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rs *eddsatss.Resharing) {
			defer wg.Done()
			select {
			case key := <-rs.Done:
				p.eddata = key
			case err := <-rs.Err:
				log.Printf("eddsa reshare new-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(p, rs)
	}

	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			continue
		}
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, oldidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		params.SetBroker(hub.local[oldidmap[n].Id])
		eddata, err := p.decryptEdDSA(kd, keyResharePurpose)
		if err != nil {
			return err
		}
		rs, err := eddsatss.NewResharing(ctx, params, eddata)
		if err != nil {
			return fmt.Errorf("failed to start eddsa reshare for old party %d: %w", n, err)
		}
		wg.Add(1)
		go func(rs *eddsatss.Resharing) {
			defer wg.Done()
			select {
			case <-rs.Done:
				// old committee: key is discarded
			case err := <-rs.Err:
				log.Printf("eddsa reshare old-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(rs)
	}

	wg.Wait()

	if reshareErr != nil {
		return reshareErr
	}
	for _, p := range newWKeys {
		if p.eddata == nil {
			return errors.New("eddsa reshare failed: missing new committee key data")
		}
	}

	w.Keys = newWKeys

	for i, kInfo := range newKeys {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			return err
		}
	}

	edReshareFinalScope.report(1)
	return nil
}

// envSpot returns the environment's Spot client, creating a fresh one if none
// is available. Used for the reshare path where remote parties are reached
// over Spot.
func envSpot(ctx context.Context) (*spotlib.Client, error) {
	if env := wltintf.GetEnv(ctx); env != nil {
		if spot := env.Spot(); spot != nil {
			return spot, nil
		}
	}
	return spotlib.New()
}

func waitOnlineSpot(spot *spotlib.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := spot.WaitOnline(ctx)
	if err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}
