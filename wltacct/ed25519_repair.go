package wltacct

import (
	"context"
	"log"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wltwallet"
)

// EnsureEd25519PubkeyOnAccount runs the Ed25519 pubkey self-heal
// (see wltwallet.EnsureEd25519Pubkey) and also synchronously updates
// the account record when the parent wallet was repaired — so that
// callers which read back a.Address on the returned object, AND any
// later FindAccount/AccountById lookup, both see the corrected value.
//
// The wltwallet-level helper only saves the Wallet row and emits
// wallet:pubkey_repaired; that event handler eventually rewrites
// linked Account rows, but asynchronously. This helper closes the
// window by persisting the account synchronously before returning,
// which matters for pre-built tx flows (dApp signs, Account:
// signAndSendTransaction) where the NEXT call needs to see the
// repaired Address.
//
// Returns true when a repair happened, false when nothing needed
// fixing. A non-nil error means the self-heal could not run (most
// often: the provided Keys did not decrypt) — callers can treat it
// as a soft failure and attempt signing anyway.
func EnsureEd25519PubkeyOnAccount(ctx context.Context, a *Account, keys []*wltsign.KeyDescription) (bool, error) {
	if a == nil {
		log.Printf("ed25519-repair: skip — account is nil")
		return false, nil
	}
	// a.Curve is only populated if the account was loaded via
	// AccountById (which runs check()). The address-lookup path
	// in FindAccount bypasses check(), so a.Curve may be empty
	// here even for a proper Ed25519 account. Fall back to the
	// wallet's curve in that case.
	if a.Wallet == nil {
		log.Printf("ed25519-repair: skip — account %s has no wallet (view-only?)", a.Id)
		return false, nil
	}
	e := wltintf.GetEnv(ctx)
	if e == nil {
		log.Printf("ed25519-repair: skip — GetEnv(ctx) returned nil (account %s)", a.Id)
		return false, nil
	}
	w, err := wltwallet.WalletById(e, a.Wallet)
	if err != nil {
		log.Printf("ed25519-repair: skip — WalletById(%s) failed: %s", a.Wallet, err)
		return false, err
	}
	if a.Curve == "" {
		a.Curve = w.Curve
	}
	if a.Curve != "ed25519" {
		log.Printf("ed25519-repair: skip — account %s curve is %q, wallet curve is %q", a.Id, a.Curve, w.Curve)
		return false, nil
	}
	if len(keys) == 0 {
		log.Printf("ed25519-repair: skip — account %s has no keys provided for decrypt", a.Id)
		return false, nil
	}
	want, err := wltwallet.EnsureEd25519Pubkey(e, w, keys)
	if err != nil {
		log.Printf("ed25519-repair: skip — EnsureEd25519Pubkey on wallet %s failed: %s (key[0].Id=%s)", w.Id, err, keys[0].Id)
		return false, err
	}
	if want == "" {
		log.Printf("ed25519-repair: skip — EnsureEd25519Pubkey returned empty want (wallet %s)", w.Id)
		return false, nil
	}
	// Diagnostic: always log the comparison so testers can tell
	// whether the wallet+account were ALREADY on the correct
	// encoding (so this repair wasn't the fix they needed).
	log.Printf("ed25519-repair: account %s wallet %s: want=%q acct.Pubkey=%q wallet.Pubkey=%q acct.Address=%q",
		a.Id, w.Id, want, a.Pubkey, w.Pubkey, a.Address)
	if want == a.Pubkey {
		return false, nil
	}
	oldPubkey := a.Pubkey
	oldAddress := a.Address
	a.Pubkey = want
	if net, nerr := wltnet.CurrentNetwork(e); nerr == nil {
		_ = a.UpdateAddressForNetwork(net)
	}
	// Persist synchronously. The async wallet:pubkey_repaired
	// handler does the same for every linked account, but a
	// concurrent Account:signAndSendTransaction or Web3 callback
	// may arrive before it runs — save now so the next FindAccount
	// sees the corrected row.
	if serr := a.save(e); serr != nil {
		log.Printf("ed25519-repair: account %s pubkey repaired in-memory but save failed: %s", a.Id, serr)
		return true, serr
	}
	log.Printf("ed25519-repair: account %s (wallet %s) pubkey/address repaired: pubkey %q → %q, address %q → %q",
		a.Id, a.Wallet, oldPubkey, a.Pubkey, oldAddress, a.Address)
	return true, nil
}

