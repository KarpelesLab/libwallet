// Wallet:promoteMnemonic — migrates a mnemonic-backed wallet into
// N fresh MPC wallets, one per chain the caller selected from the
// Wallet:probeActivity output. The source mnemonic wallet is NOT
// modified; the caller deletes it separately when they've confirmed
// each MPC wallet is usable.
//
// Each migrated chain gets its own MPC wallet because TSS shards a
// single private key — you can't cover multiple chains under one
// TSS wallet when each chain uses a different derivation path, as
// BIP44 requires. One mnemonic → N TSS wallets.

package wltwallet

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/KarpelesLab/xuid"
	"github.com/tyler-smith/go-bip39"
)

// ChainMigration describes one entry in the multi-chain promote
// request — which BIP32 path on the source mnemonic wallet to
// migrate. Typically populated from a Wallet:probeActivity row the
// user ticked.
type ChainMigration struct {
	Network        string `json:"network"`        // display label (e.g. "ethereum", "bitcoin"); copied through to the result
	DerivationPath string `json:"derivationPath"` // BIP32 path at which to derive the privkey; empty = Sollet Solana convention
	Name           string `json:"name,omitempty"` // optional name for the newly-created wallet
}

// apiWalletPromoteMnemonic implements Wallet/{id}:promoteMnemonic.
//
//	Old       []*wltsign.KeyDescription  // length 1: decrypts the source mnemonic
//	Chains    []ChainMigration           // 1+ chains to migrate; each creates a new MPC wallet
//	New       []*wltsign.KeyDescription  // the TSS committee for EACH new wallet (shared config)
//	Threshold int                        // TSS threshold for the new committee
func apiWalletPromoteMnemonic(ctx *apirouter.Context, in struct {
	Old       []*wltsign.KeyDescription
	Chains    []ChainMigration
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

	result, err := w.PromoteMnemonic(ctx, in.Old, in.Chains, in.New, in.Threshold)
	if err != nil {
		return nil, err
	}
	// Persist the newly-created wallets. (Each created Wallet carries
	// its own Keys slice already encrypted by PromoteMnemonic.)
	for _, nw := range result {
		if err := nw.save(e); err != nil {
			return nil, fmt.Errorf("save migrated wallet %s (%s): %w", nw.Name, nw.Id, err)
		}
	}
	return result, nil
}

// PromoteMnemonic walks the Chains list and, for each entry, creates
// a fresh MPC wallet whose master privkey is the mnemonic-derived
// privkey at ChainMigration.DerivationPath. Returns the list of
// newly-created wallets (NOT persisted — caller owns save()).
//
// The source mnemonic wallet (the receiver) is NOT modified. The
// caller is expected to delete it once they've validated each
// migrated wallet is operational.
//
// secp256k1 only. Ed25519 mnemonic migration ships in a follow-up.
func (w *Wallet) PromoteMnemonic(ctx context.Context, oldKeys []*wltsign.KeyDescription, chains []ChainMigration, newKeys []*wltsign.KeyDescription, newThreshold int) ([]*Wallet, error) {
	if len(w.Keys) != 1 || w.Keys[0].Schema != "mnemonic" {
		return nil, errors.New("PromoteMnemonic requires a mnemonic-backed source wallet")
	}
	if w.Curve != "secp256k1" {
		return nil, fmt.Errorf("PromoteMnemonic currently supports secp256k1 source wallets only (got %q)", w.Curve)
	}
	if len(oldKeys) != 1 {
		return nil, fmt.Errorf("PromoteMnemonic: Old must contain exactly 1 KeyDescription (got %d)", len(oldKeys))
	}
	if len(chains) == 0 {
		return nil, errors.New("PromoteMnemonic: at least one ChainMigration required")
	}
	if len(newKeys) < 2 {
		return nil, fmt.Errorf("PromoteMnemonic: New must contain at least 2 KeyDescriptions (got %d)", len(newKeys))
	}
	if newThreshold < 1 || newThreshold >= len(newKeys) {
		return nil, fmt.Errorf("PromoteMnemonic: Threshold must be 1 ≤ T < len(New)=%d (got %d)", len(newKeys), newThreshold)
	}

	// Decrypt the mnemonic once; reconstruct the seed for per-chain derivation.
	share, err := w.Keys[0].decryptMnemonic(oldKeys[0])
	if err != nil {
		return nil, fmt.Errorf("decrypt mnemonic: %w", err)
	}
	mnemonicStr, err := reconstructMnemonic(share)
	if err != nil {
		return nil, err
	}
	seed := bip39.NewSeed(mnemonicStr, share.Passphrase)
	defer zero(seed)

	results := make([]*Wallet, 0, len(chains))
	for i, c := range chains {
		log.Printf("PromoteMnemonic: chain %d/%d %s at %q", i+1, len(chains), c.Network, c.DerivationPath)
		nw, err := w.migrateOneChain(ctx, seed, c, newKeys, newThreshold)
		if err != nil {
			return nil, fmt.Errorf("migrate chain %d (%s at %q): %w", i, c.Network, c.DerivationPath, err)
		}
		results = append(results, nw)
	}
	return results, nil
}

// migrateOneChain creates a single new MPC wallet for one chain
// entry: derives the privkey + chaincode at the BIP32 path, runs
// TSS resharing with the derived privkey as Xi, and returns the new
// Wallet with its committee Keys populated and encrypted.
func (w *Wallet) migrateOneChain(ctx context.Context, seed []byte, c ChainMigration, newKeys []*wltsign.KeyDescription, newThreshold int) (*Wallet, error) {
	// 1) Derive privkey + chaincode at the target path via full BIP32
	//    (hardened steps supported — that's the whole point of the
	//    migration flow).
	xk, err := ecckd.FromBitcoinSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("bip32 master: %w", err)
	}
	if steps, err := parseBip32Path(c.DerivationPath); err != nil {
		return nil, err
	} else if len(steps) > 0 {
		xk, err = xk.Derive(steps)
		if err != nil {
			return nil, fmt.Errorf("bip32 derive %q: %w", c.DerivationPath, err)
		}
	}
	if !xk.IsPrivate() || len(xk.KeyData) != 32 {
		return nil, fmt.Errorf("bip32 derive %q produced non-private key data", c.DerivationPath)
	}
	derivedPriv := make([]byte, 32)
	copy(derivedPriv, xk.KeyData)
	defer zero(derivedPriv)
	derivedCC := make([]byte, len(xk.ChainCode))
	copy(derivedCC, xk.ChainCode)

	pub := secp256k1.PrivKeyFromBytes(derivedPriv).PubKey()

	// 2) Shell out the new Wallet + thin WalletKey rows. dkls23 doesn't
	//    need Paillier preparams; the shares are materialised by the
	//    reshare below. Threshold is scratch until reshare completes.
	name := c.Name
	if strings.TrimSpace(name) == "" {
		name = w.Name + " / " + c.Network
	}
	now := time.Now()
	nw := &Wallet{
		Id:        xuid.New("wlet"),
		Name:      name,
		Curve:     "secp256k1",
		Protocol:  ProtocolDKLS,
		Threshold: 0,
		Pubkey:    base64.RawURLEncoding.EncodeToString(pub.SerializeCompressed()),
		Chaincode: base64.RawURLEncoding.EncodeToString(derivedCC),
		Created:   now,
		Modified:  now,
	}

	nk := len(newKeys)
	newWKeys := make([]*WalletKey, nk)
	root := newProgressScope(ctx)
	root.report(0)
	for i, kInfo := range newKeys {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
		default:
			return nil, fmt.Errorf("unsupported key type %s for new key #%d", kInfo.Type, i+1)
		}
		newWKeys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: nw.Id,
			Type:   kInfo.Type,
			Gen:    1,
		}
		root.sub(i, nk+1).report(1)
	}
	finalScope := root.sub(nk, nk+1)
	finalScope.report(0)

	// 3) Stand up an importer WalletKey for promoteToDkls23 so the
	//    helper can build a deterministic importer PartyID. The row is
	//    in-memory only — it never reaches the database.
	importerShell := &WalletKey{Id: xuid.New("wkey")}
	if err := promoteToDkls23(ctx, derivedPriv, importerShell, newWKeys, newThreshold); err != nil {
		return nil, err
	}

	// 4) Encrypt + attach the committee, finalize the wallet's threshold.
	for i, kInfo := range newKeys {
		if err := newWKeys[i].encrypt(kInfo); err != nil {
			return nil, fmt.Errorf("encrypt new committee key %d: %w", i, err)
		}
	}
	nw.Keys = newWKeys
	nw.Threshold = newThreshold
	finalScope.report(1)
	return nw, nil
}
