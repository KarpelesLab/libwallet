package wltacct

import (
	"log"
	"time"

	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// handleWalletPubkeyRepair updates cached Account.Pubkey for every
// account linked to a wallet whose Ed25519 pubkey was re-serialized
// from the old (buggy X-coord) encoding to the standard compressed-Y
// form. Without this, the account's displayed Solana address would
// stay stale even after the wallet self-healed.
func handleWalletPubkeyRepair(e wltintf.Env, ch <-chan *emitter.Event) {
	for ev := range ch {
		payload, err := emitter.Arg[map[string]string](ev, 0)
		if err != nil {
			log.Printf("wallet:pubkey_repaired: bad payload: %s", err)
			continue
		}
		walletId, newPubkey := payload["wallet"], payload["pubkey"]
		if walletId == "" || newPubkey == "" {
			continue
		}
		accts, err := psql.Fetch[Account](e, map[string]any{"Wallet": walletId})
		if err != nil {
			log.Printf("wallet:pubkey_repaired: fetch accounts: %s", err)
			continue
		}
		for _, acct := range accts {
			if acct.Pubkey == newPubkey {
				continue
			}
			acct.Pubkey = newPubkey
			// Re-derive Address for whatever the current network is.
			acct.save(e)
			// Deferred Address refresh: the next check() call
			// (triggered by the account being loaded) picks up
			// the new Pubkey.
		}
	}
}

func handleWalletRestore(e wltintf.Env, ch <-chan *emitter.Event) {
	for ev := range ch {
		// create an account for this new wallet
		wallet, err := emitter.Arg[*wltwallet.Wallet](ev, 0)
		if err != nil {
			log.Printf("failed to fetch wallet in wallet:restored: %s", err)
			continue
		}
		newAcct := &Account{
			Id:        xuid.New("acct"),
			Name:      "Restored Account",
			Chaincode: wallet.Chaincode,
			Wallet:    wallet.Id,
			Type:      "ethereum",
			Created:   time.Now(),
		}
		err = newAcct.init(wallet)
		if err != nil {
			log.Printf("failed to init account: %s", err)
			continue
		}

		err = newAcct.save(e)
		if err != nil {
			log.Printf("failed to save account: %s", err)
		}

	}
}

func handleWalletDelete(e wltintf.Env, ch <-chan *emitter.Event) {
	for ev := range ch {
		// delete each account
		accts, err := psql.Fetch[Account](e, map[string]any{"Wallet": ev.Args[0]})
		if err != nil {
			log.Printf("failed to fetch accounts for wallet delete: %s", err)
			continue
		}

		for _, acct := range accts {
			err := acct.accountDelete(e)
			if err != nil {
				log.Printf("failed to cascade delete account: %s", err)
			}
		}
	}
}
