// Wallet:promote — convert a 1-of-1 imported wallet (RawKey /
// Mnemonic) into a normal N-of-M TSS wallet via tss-lib's resharing
// protocol. Promotion preserves the wallet's master pubkey and
// chaincode (the address doesn't change), only the storage of the
// signing key changes from "single share, full privkey" to
// "M shares with T-threshold reconstruction".
//
// Scope:
//   - secp256k1 only in this commit; ed25519 (frost) follow-up.
//   - No optional DerivationPath: we always promote at the wallet's
//     existing master, so the post-promote address is identical.
//     Promoting a mnemonic at a sub-path is a v2 feature.

package wltwallet

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	tsscrypto "github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// apiWalletPromote implements Wallet:promote.
//
//	Old        []*wltsign.KeyDescription  // length 1: how to decrypt the imported share
//	New        []*wltsign.KeyDescription  // length ≥ Threshold+1
//	Threshold  int                        // new committee threshold (1 ≤ T < len(New))
func apiWalletPromote(ctx *apirouter.Context, in struct {
	Old       []*wltsign.KeyDescription
	New       []*wltsign.KeyDescription
	Threshold int
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	w := apirouter.GetObject[Wallet](ctx, "Wallet")
	if w == nil {
		return nil, errors.New("Wallet required")
	}
	if err := w.Promote(ctx, in.Old, in.New, in.Threshold); err != nil {
		return nil, err
	}
	if err := w.save(e); err != nil {
		return nil, err
	}
	return w, nil
}

// Promote converts an imported 1-of-1 wallet (Schema "raw" or
// "mnemonic") into a DKLs23 N-of-T TSS wallet. The master pubkey and
// chaincode are preserved; only the storage of the signing key
// changes. After successful promote, the original imported WalletKey
// row is deleted and wallet.Protocol becomes "dkls23".
func (w *Wallet) Promote(ctx context.Context, oldKeys, newKeys []*wltsign.KeyDescription, newThreshold int) error {
	if w.Curve != "secp256k1" {
		return fmt.Errorf("Promote currently supports secp256k1 wallets only (got %q); ed25519 promote follow-up pending", w.Curve)
	}
	if len(w.Keys) != 1 {
		return fmt.Errorf("Promote requires a 1-of-1 imported wallet (got %d keys)", len(w.Keys))
	}
	imported := w.Keys[0]
	if imported.Schema != "raw" && imported.Schema != "mnemonic" {
		return fmt.Errorf("Promote requires an imported wallet (Schema=\"raw\" or \"mnemonic\"; got %q)", imported.Schema)
	}
	if len(oldKeys) != 1 {
		return fmt.Errorf("Promote: Old must contain exactly 1 KeyDescription (the import's encryption descriptor), got %d", len(oldKeys))
	}
	if len(newKeys) < 2 {
		return fmt.Errorf("Promote: New must contain at least 2 KeyDescriptions, got %d", len(newKeys))
	}
	if newThreshold < 1 || newThreshold >= len(newKeys) {
		return fmt.Errorf("Promote: Threshold must be between 1 and len(New)-1=%d, got %d", len(newKeys)-1, newThreshold)
	}

	// 1) Recover the master privkey from the imported share.
	masterPriv, err := importedMasterPrivkey(imported, oldKeys[0])
	if err != nil {
		return fmt.Errorf("decrypt imported share: %w", err)
	}
	defer zero(masterPriv)

	// 2) Allocate new committee WalletKey rows. DKLs23 doesn't need
	//    Paillier preparams; use thin rows rather than going through
	//    createWalletKey (which still runs Paillier for secp256k1).
	nk := len(newKeys)
	newWKeys := make([]*WalletKey, nk)
	root := newProgressScope(ctx)
	root.report(0)
	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
		default:
			return fmt.Errorf("unsupported key type %s for new key #%d", kInfo.Type, i+1)
		}
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: w.Id,
			Type:   kInfo.Type,
			Gen:    w.Gen + 1,
		}
		root.sub(i, nk+1).report(1)
	}
	finalScope := root.sub(nk, nk+1)
	finalScope.report(0)

	// 3) Run the modern import + reshare. The dkls23 path delivers fresh
	//    dklsData on every new WalletKey; the public key is preserved by
	//    construction (dklstss.NewResharing's oldECDSAPub binding).
	if err := promoteToDkls23(ctx, masterPriv, imported, newWKeys, newThreshold); err != nil {
		return err
	}

	// 4) Encrypt + persist. wallet.Pubkey / Chaincode stay (they were
	//    already correct on the imported wallet); we only advance the
	//    protocol marker so the sign / reshare dispatchers route the
	//    new shares through the dkls23 paths.
	w.Protocol = ProtocolDKLS
	for i, kInfo := range newKeys {
		if err := newWKeys[i].encrypt(kInfo); err != nil {
			return fmt.Errorf("encrypt new committee key %d: %w", i, err)
		}
	}

	// 5) Delete the imported WalletKey row before swapping in the new
	//    committee. The new rows are saved by the caller's w.save().
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("Promote: cannot delete imported share without env")
	}
	if _, err := psql.ForceDelete[WalletKey](e, map[string]any{"Id": imported.Id}); err != nil {
		return fmt.Errorf("delete imported WalletKey: %w", err)
	}

	w.Keys = newWKeys
	w.Threshold = newThreshold
	w.Modified = time.Now()
	finalScope.report(1)
	return nil
}

// promoteToDkls23 wraps the (masterPriv, importerPartyID) input as a
// 1-of-1 dklstss.Key via dklstss.ImportKey and reshares to the new
// committee defined by newWKeys. The importer party plays the sole OLD
// role; newWKeys play NEW. After return, every newWKeys[i].dklsData
// holds the new committee's share and shares the original pubkey.
//
// All parties run in-process. A real "wdrone holds an old share"
// reshare uses Wallet.Reshare (modern); promote is always purely
// local because the imported privkey lives only on this machine.
func promoteToDkls23(ctx context.Context, masterPriv []byte, imported *WalletKey, newWKeys []*WalletKey, newThreshold int) error {
	importerKey := new(big.Int).SetBytes(imported.Id.UUID[:])
	importerParty := tss.NewPartyID(imported.Id.String(), imported.Id.String(), importerKey)

	priv := secp256k1.PrivKeyFromBytes(masterPriv).ToECDSA()
	// dklstss.ImportKey accepts *ecdsa.PrivateKey but checks the curve
	// via tss.SameCurve(priv.Curve, tss.S256()). secp256k1.ToECDSA
	// returns a key whose Curve is the decred secp256k1 elliptic.Curve;
	// substitute the tss S256 curve so SameCurve succeeds.
	priv.Curve = tss.S256().(elliptic.Curve)
	oldKey, err := dklstss.ImportKey(priv, importerParty)
	if err != nil {
		return fmt.Errorf("dklstss.ImportKey: %w", err)
	}
	oldECDSAPub := oldKey.ECDSAPub

	oldSubset := tss.SortedPartyIDs{importerParty}

	var newIds tss.UnSortedPartyIDs
	newIdMap := make(map[int]*tss.PartyID)
	for n, p := range newWKeys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		newIds = append(newIds, id)
		newIdMap[n] = id
	}
	newSubset := tss.SortPartyIDs(newIds)

	// dklstss uses a single combined peer context for params (oldSubset
	// + newSubset). The patched dklstss/v2.2.8 indexes finalize arrays
	// by position-within-newSubset, so the interleave order of the
	// combined sort no longer matters for correctness.
	combined := make(tss.UnSortedPartyIDs, 0, 1+len(newWKeys))
	combined = append(combined, importerParty)
	combined = append(combined, []*tss.PartyID(newSubset)...)
	combinedSorted := tss.SortPartyIDs(combined)
	combinedCtx := tss.NewPeerContext(combinedSorted)

	hub := newTssHub()
	hub.addLocal(importerParty)
	for _, id := range newSubset {
		hub.addLocal(id)
	}

	curve := tss.S256()
	var wg sync.WaitGroup
	var reshareErr error
	var once sync.Once

	for n, p := range newWKeys {
		params := tss.NewParameters(curve, combinedCtx, newIdMap[n], len(combinedSorted), newThreshold)
		params.SetBroker(hub.local[newIdMap[n].Id])
		rp, err := dklstss.NewResharing(ctx, params, oldECDSAPub, nil, oldSubset, newSubset, newThreshold)
		if err != nil {
			return fmt.Errorf("start dkls23 promote new party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rp *dklstss.ResharingParty) {
			defer wg.Done()
			select {
			case key := <-rp.Done:
				p.dklsData = key
			case err := <-rp.Err:
				log.Printf("Promote: dkls23 new-committee err: %s", err)
				once.Do(func() { reshareErr = err })
			case <-ctx.Done():
				once.Do(func() { reshareErr = ctx.Err() })
			}
		}(p, rp)
	}

	{
		params := tss.NewParameters(curve, combinedCtx, importerParty, len(combinedSorted), newThreshold)
		params.SetBroker(hub.local[importerParty.Id])
		rp, err := dklstss.NewResharing(ctx, params, oldECDSAPub, oldKey, oldSubset, newSubset, newThreshold)
		if err != nil {
			return fmt.Errorf("start dkls23 promote old party: %w", err)
		}
		wg.Add(1)
		go func(rp *dklstss.ResharingParty) {
			defer wg.Done()
			select {
			case <-rp.Done:
				// importer signals nil after round 1; discard.
			case err := <-rp.Err:
				log.Printf("Promote: dkls23 old-committee err: %s", err)
				once.Do(func() { reshareErr = err })
			case <-ctx.Done():
				once.Do(func() { reshareErr = ctx.Err() })
			}
		}(rp)
	}

	wg.Wait()
	if reshareErr != nil {
		return reshareErr
	}
	for i, p := range newWKeys {
		if p.dklsData == nil {
			return fmt.Errorf("Promote: dkls23 new committee key %d missing share data", i)
		}
	}

	// Sanity: pubkey is preserved by NewResharing (it's the C-1 binding
	// check on the inside), but we double-check against the new shares
	// to catch a hypothetical regression before it lands in a stored
	// row. Cheap.
	for i, p := range newWKeys {
		if p.dklsData.ECDSAPub == nil || !p.dklsData.ECDSAPub.Equals(oldECDSAPub) {
			return fmt.Errorf("Promote: dkls23 new committee key %d has mismatched pubkey", i)
		}
	}
	return nil
}

// importedMasterPrivkey decrypts an imported WalletKey and returns
// the master 32-byte private key. For raw imports this is just the
// stored privkey; for mnemonic imports it's the BIP32 / SLIP-0010
// master derived from the BIP39 seed.
func importedMasterPrivkey(wk *WalletKey, kd *wltsign.KeyDescription) ([]byte, error) {
	switch wk.Schema {
	case "raw":
		share, err := wk.decryptRaw(kd)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(share.Privkey))
		copy(out, share.Privkey)
		return out, nil
	case "mnemonic":
		share, err := wk.decryptMnemonic(kd)
		if err != nil {
			return nil, err
		}
		seed, err := mnemonicToSeed(share)
		if err != nil {
			return nil, err
		}
		defer zero(seed)
		master, _, err := masterFromSeed(seed, share.Curve)
		if err != nil {
			return nil, err
		}
		return master, nil
	default:
		return nil, fmt.Errorf("importedMasterPrivkey: unexpected schema %q", wk.Schema)
	}
}

// indexOfWKey is a tiny helper kept for the reshare hub-registration
// callers that still inline pointer-identity lookups.
func indexOfWKey(arr []*WalletKey, target *WalletKey) int {
	for i, p := range arr {
		if p == target {
			return i
		}
	}
	return -1
}

// _ pulls tsscrypto into the package's import graph for the duration
// of the dkls23 migration; future ed25519 promote (frost via
// frosttss.ImportKey) will use it again to build the importer point
// from a scalar.
var _ = tsscrypto.NewECPoint
