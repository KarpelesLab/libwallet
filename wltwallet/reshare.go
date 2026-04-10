package wltwallet

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/tss-lib/v2/ecdsa/keygen"
	"github.com/KarpelesLab/tss-lib/v2/ecdsa/resharing"
	eddsakeygen "github.com/KarpelesLab/tss-lib/v2/eddsa/keygen"
	eddsaresharing "github.com/KarpelesLab/tss-lib/v2/eddsa/resharing"
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
	m := make(map[string]tssPartyUpdateOnly)
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

	// new keys
	newWKeys := make([]*WalletKey, nk)

	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating key %d/%d", i, nk)
		apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": i + 1})

		k, err := w.createWalletKey(ctx, kInfo.Type)
		if err != nil {
			return err
		}
		sdata := keygen.NewLocalPartySaveData(len(newWKeys))
		sdata.LocalPreParams = *k.pre
		k.sdata = &sdata
		newWKeys[i] = k
	}

	// perform final operation (actual key generation)
	apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": nk + 1})

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

	outCh := make(chan tss.Message, len(newWKeys)+len(oldKeys))
	defer close(outCh)
	var wg sync.WaitGroup
	wg.Add(len(newWKeys))

	for n, p := range newWKeys {
		endCh := make(chan *keygen.LocalPartySaveData)
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, newidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		party := resharing.NewLocalParty(params, *p.sdata, outCh, endCh)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			p.sdata = <-endCh
		}(p)
	}

	wg.Add(len(oldKeys))

	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			wg.Done() // this one is remote, do not wait for it
			// perform remote initialization and connect outCh to receive remote messages
			// info is used to construct tss.NewReSharingParameters on the remote side
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
			var spot *spotlib.Client
			if env := wltintf.GetEnv(ctx); env != nil {
				spot = env.Spot()
			}
			if spot == nil {
				var err error
				// establish new spot connection (this will only happen in test mode, typically)
				spot, err = spotlib.New()
				if err != nil {
					return err
				}
			}
			if err := waitOnlineSpot(spot); err != nil {
				return err
			}
			log.Printf("initializing remote peer %s with info=%+v", p.Id.String(), info)
			log.Printf("remote sid = %s", kd.Key)
			m[p.Id.String()] = &spotParty{info: info, spot: spot, sid: kd.Key, parties: m}
			// setup is done, skip the normal decrypt
			continue
		}
		endCh := make(chan *keygen.LocalPartySaveData)
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, oldidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		sdata, err := p.decrypt(kd, keyResharePurpose)
		if err != nil {
			return err
		}
		party := resharing.NewLocalParty(params, *sdata, outCh, endCh)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			p.sdata = <-endCh
		}(p)
	}

	errCh := make(chan error, 2)
	var wgStart sync.WaitGroup
	wgStart.Add(len(m))

	// start all
	for _, p := range m {
		go func(party tssPartyUpdateOnly) {
			defer wgStart.Done()

			err := party.Start()
			if err != nil {
				log.Printf("failed to start tss party: %s", err)
				select {
				case errCh <- err:
				default:
				}
			}
		}(p)
	}

	wgStart.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}

	// only route messages after everyone has started
	go tssRouter(ctx, m, outCh)

	// wait for all save data to fill
	wg.Wait()

	w.Keys = newWKeys

	// params shouldn't have changed
	//pk := w.Keys[0].sdata.ECDSAPub.ToSecp256k1PubKey()
	//w.Pubkey = base64.RawURLEncoding.EncodeToString(pk.SerializeCompressed())

	// encrypt new keys

	for i, kInfo := range newKeys {
		err := w.Keys[i].encrypt(kInfo)
		if err != nil {
			return err
		}
	}

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

	// prepare old ids
	var oldids tss.UnSortedPartyIDs
	m := make(map[string]tssPartyUpdateOnly)
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

	// new keys
	newWKeys := make([]*WalletKey, nk)

	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating eddsa reshare key %d/%d", i, nk)
		apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": i + 1})

		k, err := w.createWalletKey(ctx, kInfo.Type)
		if err != nil {
			return err
		}
		eddata := eddsakeygen.NewLocalPartySaveData(len(newWKeys))
		k.eddata = &eddata
		newWKeys[i] = k
	}

	// perform final operation (actual key resharing)
	apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": nk + 1})

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

	outCh := make(chan tss.Message, len(newWKeys)+len(oldKeys))
	defer close(outCh)
	var wg sync.WaitGroup
	wg.Add(len(newWKeys))

	for n, p := range newWKeys {
		endCh := make(chan *eddsakeygen.LocalPartySaveData)
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, newidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		party := eddsaresharing.NewLocalParty(params, *p.eddata, outCh, endCh)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			p.eddata = <-endCh
		}(p)
	}

	wg.Add(len(oldKeys))

	for n, kd := range oldKeys {
		p := w.getKey(kd.Id)
		if p.Type == "RemoteKey" {
			wg.Done()
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
			var spot *spotlib.Client
			if env := wltintf.GetEnv(ctx); env != nil {
				spot = env.Spot()
			}
			if spot == nil {
				var err error
				spot, err = spotlib.New()
				if err != nil {
					return err
				}
			}
			if err := waitOnlineSpot(spot); err != nil {
				return err
			}
			log.Printf("initializing eddsa remote peer %s with info=%+v", p.Id.String(), info)
			m[p.Id.String()] = &spotParty{info: info, spot: spot, sid: kd.Key, parties: m}
			continue
		}
		endCh := make(chan *eddsakeygen.LocalPartySaveData)
		params := tss.NewReSharingParameters(curve, oldtssctx, newtssctx, oldidmap[n], len(oldKeys), w.Threshold, len(newKeys), w.Threshold)
		eddata, err := p.decryptEdDSA(kd, keyResharePurpose)
		if err != nil {
			return err
		}
		party := eddsaresharing.NewLocalParty(params, *eddata, outCh, endCh)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			p.eddata = <-endCh
		}(p)
	}

	errCh := make(chan error, 2)
	var wgStart sync.WaitGroup
	wgStart.Add(len(m))

	// start all
	for _, p := range m {
		go func(party tssPartyUpdateOnly) {
			defer wgStart.Done()

			err := party.Start()
			if err != nil {
				log.Printf("failed to start eddsa reshare party: %s", err)
				select {
				case errCh <- err:
				default:
				}
			}
		}(p)
	}

	wgStart.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}

	// only route messages after everyone has started
	go tssRouter(ctx, m, outCh)

	// wait for all save data to fill
	wg.Wait()

	w.Keys = newWKeys

	// encrypt new keys
	for i, kInfo := range newKeys {
		err := w.Keys[i].encrypt(kInfo)
		if err != nil {
			return err
		}
	}

	return nil
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
