package wltwallet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"encoding/base64"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/xuid"
)

// Reshare will produce new keys for the given wallet.
//
// Dispatches on Wallet.Protocol so each TSS family runs its own
// resharing primitive: dklstss.NewResharing for dkls23, frosttss
// resharing for frost, eddsatss for legacy ed25519, and ecdsatss
// (GG18) for legacy secp256k1. The dispatch keeps the public Reshare
// signature stable so callers don't need to know which protocol a
// wallet was generated under.
func (w *Wallet) Reshare(ctx context.Context, oldKeys []*wltsign.KeyDescription, newKeys []*wltsign.KeyDescription) error {
	switch w.resolveProtocol() {
	case ProtocolDKLS:
		return w.ReshareDkls(ctx, oldKeys, newKeys)
	case ProtocolFROST:
		return w.ReshareFrost(ctx, oldKeys, newKeys)
	}
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
		// Do not log kd.Key (the RemoteKey session id) — it is sensitive
		// routing material and was previously emitted at info level.
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

// ReshareFrost reshares a FROST(Ed25519) wallet. The orchestration is
// structurally identical to ReshareEdDSA — same combined-committee
// broker hub, same OLD/NEW party split — only the underlying TSS
// primitive changes from eddsatss.NewResharing to frosttss.NewResharing.
//
// FROST resharing preserves the GroupPublicKey, so wallet.Pubkey stays
// valid for any address derived from it. The new committee size and
// threshold can both differ from the old.
func (w *Wallet) ReshareFrost(ctx context.Context, oldKeys []*wltsign.KeyDescription, newKeys []*wltsign.KeyDescription) error {
	if w.Curve != "ed25519" {
		return errors.New("ReshareFrost requires an ed25519 wallet")
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
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		// frost shares are quick to materialise: no Paillier preparams.
		// Use a thin allocator rather than createWalletKey (which still
		// runs Paillier for secp256k1 share rows).
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: w.Id,
			Type:   kInfo.Type,
			Gen:    w.Gen + 1,
		}
		rootEd.sub(i, nk+1).report(1)
	}

	frostReshareFinalScope := rootEd.sub(nk, nk+1)
	frostReshareFinalScope.report(0)

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

	log.Printf("producing frost reshare; oldids=%v newids=%v", oldsids, newsids)

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

	remotes, err := w.startReshareRemotes(ctx, hub, oldKeys, oldidmap, oldsids, newsids, len(oldKeys), len(newKeys), ProtocolFROST)
	if err != nil {
		return err
	}
	_ = remotes

	var wg sync.WaitGroup
	var reshareErr error
	var reshareErrOnce sync.Once

	for n, p := range newWKeys {
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, newidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		params.SetBroker(hub.local[newidmap[n].Id])
		rs, err := frosttss.NewResharing(ctx, params, nil)
		if err != nil {
			return fmt.Errorf("failed to start frost reshare for new party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rs *frosttss.Resharing) {
			defer wg.Done()
			select {
			case key := <-rs.Done:
				p.frostData = key
			case err := <-rs.Err:
				log.Printf("frost reshare new-committee err: %s", err)
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
		frostKey, err := p.decryptFrost(kd, keyResharePurpose)
		if err != nil {
			return fmt.Errorf("ReshareFrost: failed to decrypt old share %s: %w", kd.Id, err)
		}
		rs, err := frosttss.NewResharing(ctx, params, frostKey)
		if err != nil {
			return fmt.Errorf("failed to start frost reshare for old party %d: %w", n, err)
		}
		wg.Add(1)
		go func(rs *frosttss.Resharing) {
			defer wg.Done()
			select {
			case <-rs.Done:
				// OLD committee: discard the returned key (it has no new share).
			case err := <-rs.Err:
				log.Printf("frost reshare old-committee err: %s", err)
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
		if p.frostData == nil {
			return errors.New("frost reshare failed: missing new committee key data")
		}
	}

	w.Keys = newWKeys
	for i, kInfo := range newKeys {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			return err
		}
	}
	frostReshareFinalScope.report(1)
	return nil
}

// ReshareDkls reshares a DKLs23 secp256k1 wallet. The dklstss primitive
// has a different shape from the legacy eddsatss / ecdsatss path:
//
//   - The committee is a single combined peer context (oldPIDs ++
//     newPIDs), not separate old / new contexts.
//   - oldECDSAPub binds the resharing to a specific public key — every
//     participant must agree on it. Pulled from wallet.Pubkey.
//   - oldSubset must be exactly T+1 of the old committee (the active
//     OLD signers); newSubset is the entire new committee.
//   - OLD-only parties produce no new share; their Done channel fires
//     with a nil sentinel after round 1.
func (w *Wallet) ReshareDkls(ctx context.Context, oldKeys []*wltsign.KeyDescription, newKeys []*wltsign.KeyDescription) error {
	if w.Curve != "secp256k1" {
		return errors.New("ReshareDkls requires a secp256k1 wallet")
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
	if len(oldKeys) != w.Threshold+1 {
		return fmt.Errorf("ReshareDkls: dkls23 requires exactly T+1=%d old signers in the active subset, got %d", w.Threshold+1, len(oldKeys))
	}

	// Decode the wallet's persisted compressed pubkey into an ECPoint
	// for NewResharing's security binding.
	pubBytes, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		return fmt.Errorf("ReshareDkls: invalid wallet pubkey: %w", err)
	}
	secpPub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return fmt.Errorf("ReshareDkls: parse wallet pubkey: %w", err)
	}
	xb, yb := secpPub.X(), secpPub.Y()
	oldECDSAPub, err := crypto.NewECPoint(tss.S256(), xb, yb)
	if err != nil {
		return fmt.Errorf("ReshareDkls: build oldECDSAPub: %w", err)
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

	curve := tss.S256()

	newWKeys := make([]*WalletKey, nk)
	root := newProgressScope(ctx)
	root.report(0)

	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: w.Id,
			Type:   kInfo.Type,
			Gen:    w.Gen + 1,
		}
		root.sub(i, nk+1).report(1)
	}

	dklsReshareFinalScope := root.sub(nk, nk+1)
	dklsReshareFinalScope.report(0)

	var newids tss.UnSortedPartyIDs
	newidmap := make(map[int]*tss.PartyID)
	for n, p := range newWKeys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		newids = append(newids, id)
		newidmap[n] = id
	}
	newsids := tss.SortPartyIDs(newids)

	// dkls23 uses a single combined peer context for params.
	combined := make(tss.UnSortedPartyIDs, 0, len(oldids)+len(newids))
	combined = append(combined, oldids...)
	combined = append(combined, newids...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	log.Printf("producing dkls23 reshare; oldids=%v newids=%v", oldsids, newsids)

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

	remotes, err := w.startReshareRemotes(ctx, hub, oldKeys, oldidmap, oldsids, newsids, len(oldKeys), len(newKeys), ProtocolDKLS)
	if err != nil {
		return err
	}
	_ = remotes

	var wg sync.WaitGroup
	var reshareErr error
	var reshareErrOnce sync.Once

	// NEW-side parties (no oldKey).
	for n, p := range newWKeys {
		params := tss.NewParameters(curve, combinedCtx, newidmap[n], len(combinedSorted), w.Threshold)
		params.SetBroker(hub.local[newidmap[n].Id])
		rp, err := dklstss.NewResharing(ctx, params, oldECDSAPub, nil, oldsids, newsids, w.Threshold)
		if err != nil {
			return fmt.Errorf("failed to start dkls23 reshare for new party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rp *dklstss.ResharingParty) {
			defer wg.Done()
			select {
			case key := <-rp.Done:
				p.dklsData = key
			case err := <-rp.Err:
				log.Printf("dkls23 reshare new-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(p, rp)
	}

	// OLD-side parties (with oldKey). Skip RemoteKey shares — those run
	// on the wdrone side via the spotPeer transport.
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			continue
		}
		params := tss.NewParameters(curve, combinedCtx, oldidmap[n], len(combinedSorted), w.Threshold)
		params.SetBroker(hub.local[oldidmap[n].Id])
		dklsKey, err := p.decryptDkls(kd, keyResharePurpose)
		if err != nil {
			return fmt.Errorf("ReshareDkls: failed to decrypt old share %s: %w", kd.Id, err)
		}
		rp, err := dklstss.NewResharing(ctx, params, oldECDSAPub, dklsKey, oldsids, newsids, w.Threshold)
		if err != nil {
			return fmt.Errorf("failed to start dkls23 reshare for old party %d: %w", n, err)
		}
		wg.Add(1)
		go func(rp *dklstss.ResharingParty) {
			defer wg.Done()
			select {
			case <-rp.Done:
				// OLD-only: discard the nil-sentinel result.
			case err := <-rp.Err:
				log.Printf("dkls23 reshare old-committee err: %s", err)
				reshareErrOnce.Do(func() { reshareErr = err })
			case <-ctx.Done():
				reshareErrOnce.Do(func() { reshareErr = ctx.Err() })
			}
		}(rp)
	}

	wg.Wait()

	if reshareErr != nil {
		return reshareErr
	}
	for _, p := range newWKeys {
		if p.dklsData == nil {
			return errors.New("dkls23 reshare failed: missing new committee key data")
		}
	}

	w.Keys = newWKeys
	for i, kInfo := range newKeys {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			return err
		}
	}
	dklsReshareFinalScope.report(1)
	return nil
}

// startReshareRemotes opens spotPeer connections for every RemoteKey
// share in oldKeys. Identical to the inline block in ReshareEdDSA but
// factored out so the modern protocol entry points don't have to clone
// it. Returns the started peers in case the caller needs them later
// (they're already registered with the hub).
func (w *Wallet) startReshareRemotes(ctx context.Context, hub *tssHub, oldKeys []*wltsign.KeyDescription, oldidmap map[int]*tss.PartyID, oldsids, newsids tss.SortedPartyIDs, oldPartyCount, newPartyCount int, protocol string) ([]*spotPeer, error) {
	var remotes []*spotPeer
	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p == nil {
			return nil, fmt.Errorf("could not find key id=%s", kd.Id)
		}
		if p.Type != "RemoteKey" {
			continue
		}
		info := &walletSignReshareInit{
			OldPeers:      oldsids,
			NewPeers:      newsids,
			Name:          oldidmap[n],
			OldPartycount: oldPartyCount,
			NewPartycount: newPartyCount,
			OldThreshold:  w.Threshold,
			NewThreshold:  w.Threshold,
			Curve:         w.Curve,
			Protocol:      protocol,
		}
		spot, err := envSpot(ctx)
		if err != nil {
			return nil, err
		}
		if err := waitOnlineSpot(spot); err != nil {
			return nil, err
		}
		log.Printf("initializing %s remote peer %s with info=%+v", protocol, p.Id.String(), info)
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
			return nil, fmt.Errorf("failed to start remote peer %s: %w", rp.partyId.Id, err)
		}
	}
	return remotes, nil
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
	if err := spot.WaitOnline(ctx); err != nil {
		return err
	}
	// spot.WaitOnline returns at onlineCnt > 0 — i.e. after exactly
	// ONE relay finishes its handshake. spotlib typically dials
	// multiple relays in parallel (we observe 2 hosts:
	// epvjsdy.g-dns.net + ekmcdli.g-dns.net) and the second takes
	// ~1-2 s longer than the first to authenticate. Firing a peer
	// init query in that gap means our spot client routes via a
	// single relay; if the target wdrone is preferentially reached
	// via the relay we don't have up yet, the query can stall or
	// take the long way around.
	//
	// Wait for the connection mesh to settle: poll ConnectionCount
	// until connCnt stops growing for `stableFor` AND onlineCnt has
	// caught up to connCnt. Cap at `maxWait` so a single permanently
	// unreachable relay doesn't block forever — best-effort fallback
	// is to proceed with whatever's online.
	return waitSpotMeshStable(spot, 8*time.Second, 1*time.Second)
}

// waitSpotMeshStable polls the spot client's connection counts until
// no new connections arrive for `stableFor`, or `maxWait` elapses.
// Returns nil even on timeout as long as at least one relay is online —
// the caller can proceed with degraded routing rather than failing the
// whole reshare on a partial mesh.
func waitSpotMeshStable(spot *spotlib.Client, maxWait, stableFor time.Duration) error {
	deadline := time.Now().Add(maxWait)
	var lastConn uint32
	stableSince := time.Time{}
	for {
		connCnt, onlineCnt := spot.ConnectionCount()
		if connCnt != lastConn {
			lastConn = connCnt
			stableSince = time.Now()
		}
		if connCnt > 0 && connCnt == onlineCnt && !stableSince.IsZero() && time.Since(stableSince) >= stableFor {
			log.Printf("spot mesh stable: conn=%d online=%d", connCnt, onlineCnt)
			return nil
		}
		if time.Now().After(deadline) {
			log.Printf("spot mesh wait timed out: conn=%d online=%d (proceeding)", connCnt, onlineCnt)
			if onlineCnt == 0 {
				return fmt.Errorf("spot mesh did not come online within %s", maxWait)
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
