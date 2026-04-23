// Wallet:promote — convert a 1-of-1 imported wallet (RawKey /
// Mnemonic) into a normal N-of-M TSS wallet via tss-lib's resharing
// protocol. Promotion preserves the wallet's master pubkey and
// chaincode (the address doesn't change), only the storage of the
// signing key changes from "single share, full privkey" to
// "M shares with T-threshold reconstruction".
//
// Scope:
//   - secp256k1 only in this commit; ed25519 (eddsatss) follow-up.
//   - No optional DerivationPath: we always promote at the wallet's
//     existing master, so the post-promote address is identical.
//     Promoting a mnemonic at a sub-path is a v2 feature.

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
	"github.com/KarpelesLab/secp256k1"
	tsscrypto "github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
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
// "mnemonic") into a normal N-of-T TSS wallet. The master pubkey
// and chaincode are preserved; only the storage of the signing key
// changes. After successful promote, the original imported
// WalletKey row is deleted.
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

	// 2) Synthesize a 1-of-1 ecdsatss.Key with Xi = masterPriv. Use a
	//    deterministic ShareID = the imported WalletKey's UUID-derived
	//    big.Int, matching the old-committee party ID we'll register
	//    with tss.
	oldPartyKey := new(big.Int).SetBytes(imported.Id.UUID[:])
	oldParty := tss.NewPartyID(imported.Id.String(), imported.Id.String(), oldPartyKey)
	oldSynth, err := synthesizeOneOfOneECDSAKey(masterPriv, oldPartyKey)
	if err != nil {
		return fmt.Errorf("synthesize 1-of-1 share: %w", err)
	}

	// 3) Allocate the new committee's WalletKey rows (with Paillier
	//    pre-params, since they're the new TSS parties).
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
		k, err := w.createWalletKey(ctx, kInfo.Type, root.sub(i, nk+1))
		if err != nil {
			return fmt.Errorf("create new committee key %d: %w", i, err)
		}
		newWKeys[i] = k
	}
	finalScope := root.sub(nk, nk+1)
	finalScope.report(0)

	// 4) Build TSS contexts: old committee = [oldParty], new committee
	//    = newWKeys' party IDs.
	oldSorted := tss.SortPartyIDs(tss.UnSortedPartyIDs{oldParty})
	oldTssCtx := tss.NewPeerContext(oldSorted)

	var newIds tss.UnSortedPartyIDs
	newIdMap := make(map[int]*tss.PartyID)
	for n, p := range newWKeys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		newIds = append(newIds, id)
		newIdMap[n] = id
	}
	newSorted := tss.SortPartyIDs(newIds)
	newTssCtx := tss.NewPeerContext(newSorted)

	curve, ok := tss.GetCurveByName(tss.CurveName(w.Curve))
	if !ok {
		return fmt.Errorf("unknown curve %s", w.Curve)
	}

	// 5) Run resharing. All parties are local to this process — the
	//    imported wallet has no remote peers, and the new committee
	//    is being created here. RemoteKey targets in the new committee
	//    upload their share blobs after success (handled in the
	//    encrypt() loop at the end via the RemoteKey case).
	hub := newTssHub()
	hub.addLocal(oldParty)
	for _, p := range newWKeys {
		hub.addLocal(newIdMap[indexOfWKey(newWKeys, p)])
	}

	var wg sync.WaitGroup
	var reshareErr error
	var once sync.Once

	// New committee
	for n, p := range newWKeys {
		params := tss.NewReSharingParameters(
			curve, oldTssCtx, newTssCtx, newIdMap[n],
			1, 0, // old: 1 party, threshold 0
			nk, newThreshold, // new: nk parties, requested threshold
		)
		params.SetBroker(hub.local[newIdMap[n].Id])
		rs, err := ecdsatss.NewResharing(ctx, params, nil, *p.pre)
		if err != nil {
			return fmt.Errorf("start new-committee resharing for party %d: %w", n, err)
		}
		wg.Add(1)
		go func(p *WalletKey, rs *ecdsatss.Resharing) {
			defer wg.Done()
			select {
			case k := <-rs.Done:
				p.sdata = k
			case err := <-rs.Err:
				log.Printf("Promote: new-committee err: %s", err)
				once.Do(func() { reshareErr = err })
			case <-ctx.Done():
				once.Do(func() { reshareErr = ctx.Err() })
			}
		}(p, rs)
	}

	// Old committee (the synthesized 1-of-1)
	{
		params := tss.NewReSharingParameters(
			curve, oldTssCtx, newTssCtx, oldParty,
			1, 0, // old
			nk, newThreshold, // new
		)
		params.SetBroker(hub.local[oldParty.Id])
		rs, err := ecdsatss.NewResharing(ctx, params, oldSynth)
		if err != nil {
			return fmt.Errorf("start old-committee resharing: %w", err)
		}
		wg.Add(1)
		go func(rs *ecdsatss.Resharing) {
			defer wg.Done()
			select {
			case <-rs.Done:
				// old committee result has Xi zeroed by the protocol; discard.
			case err := <-rs.Err:
				log.Printf("Promote: old-committee err: %s", err)
				once.Do(func() { reshareErr = err })
			case <-ctx.Done():
				once.Do(func() { reshareErr = ctx.Err() })
			}
		}(rs)
	}

	wg.Wait()
	if reshareErr != nil {
		return reshareErr
	}
	for i, p := range newWKeys {
		if p.sdata == nil {
			return fmt.Errorf("Promote: new committee key %d missing share data", i)
		}
	}

	// 6) Encrypt and persist the new committee. Threshold and
	//    generation are updated atomically with the keys.
	for i, kInfo := range newKeys {
		if err := newWKeys[i].encrypt(kInfo); err != nil {
			return fmt.Errorf("encrypt new committee key %d: %w", i, err)
		}
	}

	// 7) Delete the old imported WalletKey row. The new committee's
	//    rows are saved by w.save() which the caller invokes; but the
	//    imported row needs explicit removal because it's not in
	//    w.Keys after we swap.
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

// synthesizeOneOfOneECDSAKey constructs a tss-lib ecdsatss.Key with
// Xi = the imported master privkey. This is the input to
// `NewResharing` on the old committee side of the promotion.
//
// Per the package layout in `tss-lib/v2/ecdsatss/key.go`:
//   - Xi              = master privkey as big.Int
//   - ShareID         = the synthesized party's tss.PartyID.Key
//   - Ks              = [ShareID]                    (single-party keygen index)
//   - BigXj           = [ECDSAPub]                   (per-party public commitment)
//   - ECDSAPub        = Xi*G                         (the master pubkey)
//   - LocalPreParams  = unset; only the new committee runs the
//                       Paillier-protected new-share rounds, the old
//                       committee just decrypts/sends shares for
//                       resharing-out
//   - NTildej/H1j/H2j/PaillierPKs = nil; same reason as PreParams
func synthesizeOneOfOneECDSAKey(privkey []byte, partyKey *big.Int) (*ecdsatss.Key, error) {
	priv := secp256k1.PrivKeyFromBytes(privkey)
	pub := priv.PubKey()
	ecdsaPub, err := tsscrypto.NewECPoint(secp256k1.S256(), pub.X(), pub.Y())
	if err != nil {
		return nil, fmt.Errorf("compute ECDSAPub point: %w", err)
	}
	k := ecdsatss.NewKey(1)
	k.Xi = new(big.Int).SetBytes(privkey)
	k.ShareID = partyKey
	k.Ks = []*big.Int{partyKey}
	k.BigXj = []*tsscrypto.ECPoint{ecdsaPub}
	k.ECDSAPub = ecdsaPub
	return k, nil
}

// indexOfWKey is a tiny helper for the hub registration loop above —
// the inner closure needs the party index and we already have the
// pointer-to-WalletKey, so look up by identity.
func indexOfWKey(arr []*WalletKey, target *WalletKey) int {
	for i, p := range arr {
		if p == target {
			return i
		}
	}
	return -1
}

// _ keeps the xuid import alive for parity with the rest of the
// package; future Promote variants (e.g., per-account derivation)
// will use it to generate fresh wallet IDs.
var _ = xuid.New
