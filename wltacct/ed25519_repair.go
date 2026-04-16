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
	if a == nil || a.Curve != "ed25519" || a.Wallet == nil {
		return false, nil
	}
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return false, nil
	}
	w, err := wltwallet.WalletById(e, a.Wallet)
	if err != nil {
		return false, err
	}
	want, err := wltwallet.EnsureEd25519Pubkey(e, w, keys)
	if err != nil {
		return false, err
	}
	if want == "" || want == a.Pubkey {
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
	// High-visibility log: when a tester reports that Solana sends
	// still fail, grep for this line to confirm the self-heal fired.
	log.Printf("ed25519-repair: account %s (wallet %s) pubkey/address repaired: pubkey %q → %q, address %q → %q",
		a.Id, a.Wallet, oldPubkey, a.Pubkey, oldAddress, a.Address)
	return true, nil
}

