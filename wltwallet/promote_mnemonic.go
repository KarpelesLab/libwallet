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
	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/KarpelesLab/xuid"
	"github.com/tyler-smith/go-bip39"
)

// ChainMigration describes one entry in the multi-chain promote
// request — which BIP32 path on the source mnemonic wallet to
// migrate. Typically populated from a Wallet:probeActivity row the
// user ticked.
type ChainMigration struct {
	Network        string `json:"network"`        // display label (e.g. "ethereum", "bitcoin", "solana"); copied through to the result
	DerivationPath string `json:"derivationPath"` // BIP32 (secp256k1) or SLIP-0010 (ed25519) path; empty = Sollet Solana convention for ed25519, master for secp256k1
	Name           string `json:"name,omitempty"` // optional name for the newly-created wallet
	// Curve selects the chain's signing curve. Empty defaults to
	// "secp256k1" for backwards-compat with callers from before the
	// ed25519 migration path existed. Set to "ed25519" to materialise
	// a FROST(Ed25519) wallet — Solana, Sui, etc. Each chain in the
	// list can pick independently, so a single mnemonic can fan out
	// to a Bitcoin/Ethereum wallet AND a Solana wallet in one call.
	Curve string `json:"curve,omitempty"`
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
// The source wallet's Curve is irrelevant — the same BIP39 PBKDF2
// seed feeds both BIP32 (secp256k1) and SLIP-0010 (ed25519)
// derivation, so one mnemonic can migrate to chains on either curve
// independently. Each ChainMigration picks via its Curve field.
//
// ──────────────────────────────────────────────────────────────────
//
// # New committee shape (newKeys + newThreshold)
//
// The promoted wallets are real TSS wallets (FROST for ed25519,
// DKLs23 for secp256k1) and therefore need a real MPC committee. The
// canonical shape is the same three keys the standard wallet-create
// flow uses:
//
//	newKeys = [
//	    {Type: "StoreKey", Key: <fresh device-pubkey>},   // device-local
//	    {Type: "RemoteKey", Key: <wdrone session id>},     // server-side via 2FA
//	    {Type: "Password",  Key: <user password>},         // user-memorised
//	]
//	newThreshold = 1                                       // any 2 of 3 can sign
//
// newThreshold is the protocol threshold T: signing requires exactly
// T+1 parties. So newThreshold=1 over three keys is a 2-of-3 scheme —
// any two of the three keys can sign, and no single key alone can.
// A 2-of-3 committee gives the user three independent recovery paths
// (lose the device → re-sign with password + remote 2FA; forget the
// password → re-sign with device + remote 2FA; lose 2FA access →
// re-sign with device + password). Fewer than three keys is allowed
// but degrades recovery: a 2-of-2 [StoreKey + Password] has no
// redundancy — losing either key bricks the wallet.
//
// Validation:
//   - len(newKeys) >= 2. Required by the underlying TSS protocol —
//     a single-party "threshold" scheme isn't a meaningful sharing.
//     Callers passing exactly 1 KeyDescription are almost always
//     misusing the API; finish the standard onboarding flow (with
//     SMS/email 2FA to mint the RemoteKey) and reuse those keys here.
//   - 1 <= newThreshold < len(newKeys). The strict upper bound
//     ensures at least one party can be lost without bricking the
//     wallet.
func (w *Wallet) PromoteMnemonic(ctx context.Context, oldKeys []*wltsign.KeyDescription, chains []ChainMigration, newKeys []*wltsign.KeyDescription, newThreshold int) ([]*Wallet, error) {
	if len(w.Keys) != 1 || w.Keys[0].Schema != "mnemonic" {
		return nil, errors.New("PromoteMnemonic requires a mnemonic-backed source wallet")
	}
	if len(oldKeys) != 1 {
		return nil, fmt.Errorf("PromoteMnemonic: Old must contain exactly 1 KeyDescription (got %d)", len(oldKeys))
	}
	if len(chains) == 0 {
		return nil, errors.New("PromoteMnemonic: at least one ChainMigration required")
	}
	if len(newKeys) < 2 {
		return nil, fmt.Errorf("PromoteMnemonic: New must contain at least 2 KeyDescriptions (got %d) — canonical shape is [StoreKey, RemoteKey, Password] with threshold 1; see PromoteMnemonic godoc for the full layout", len(newKeys))
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
	curve := c.Curve
	if curve == "" {
		curve = "secp256k1"
	}
	switch curve {
	case "secp256k1", "ed25519":
	default:
		return nil, fmt.Errorf("migrateOneChain: unsupported curve %q for chain %q", curve, c.Network)
	}

	// 1) Derive the privkey + chaincode at the target path. derivePrivkeyFromSeed
	//    handles both BIP32 (secp256k1) and SLIP-0010 (ed25519 hardened-only).
	//    The chaincode lives on the parent for secp256k1; for ed25519 we
	//    compute it via the same SLIP-0010 master walk so HD child
	//    derivation off the resulting wallet stays consistent.
	derivedPriv, err := derivePrivkeyFromSeed(seed, curve, c.DerivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive %s privkey at %q: %w", curve, c.DerivationPath, err)
	}
	defer zero(derivedPriv)

	// Chaincode: for secp256k1, BIP32 returns it alongside the privkey
	// at the derivation step. For ed25519 we use the SLIP-0010 master
	// chaincode (Solana wallets typically don't rely on the chaincode
	// for further non-hardened derivation, but persisting it keeps the
	// wallet's HD metadata complete).
	var derivedCC []byte
	switch curve {
	case "secp256k1":
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
		derivedCC = make([]byte, len(xk.ChainCode))
		copy(derivedCC, xk.ChainCode)
	case "ed25519":
		_, cc, err := masterFromSeed(seed, "ed25519")
		if err != nil {
			return nil, fmt.Errorf("slip-0010 master: %w", err)
		}
		derivedCC = cc
	}

	pubBytes, err := derivePub(curve, derivedPriv)
	if err != nil {
		return nil, fmt.Errorf("derive pub: %w", err)
	}

	// 2) Shell out the new Wallet + thin WalletKey rows. Modern
	//    protocols don't need Paillier preparams; the shares are
	//    materialised by the reshare below. Threshold is scratch
	//    until reshare completes.
	name := c.Name
	if strings.TrimSpace(name) == "" {
		name = w.Name + " / " + c.Network
	}
	now := time.Now()
	protocol := ProtocolDKLS
	if curve == "ed25519" {
		protocol = ProtocolFROST
	}
	nw := &Wallet{
		Id:        xuid.New("wlt"),
		Name:      name,
		Curve:     curve,
		Protocol:  protocol,
		Threshold: 0,
		Pubkey:    base64.RawURLEncoding.EncodeToString(pubBytes),
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

	// 3) Stand up an importer WalletKey for the curve-appropriate
	//    promote helper. The shell row is in-memory only — never
	//    reaches the database.
	importerShell := &WalletKey{Id: xuid.New("wkey")}
	switch curve {
	case "secp256k1":
		if err := promoteToDkls23(ctx, derivedPriv, importerShell, newWKeys, newThreshold); err != nil {
			return nil, err
		}
	case "ed25519":
		if err := promoteToFrost(ctx, derivedPriv, importerShell, newWKeys, newThreshold); err != nil {
			return nil, err
		}
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
