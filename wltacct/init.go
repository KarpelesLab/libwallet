package wltacct

import "github.com/KarpelesLab/libwallet/wltintf"

func InitEnv(e wltintf.Env) {
	// psql auto-creates tables, no migration needed.
	//
	// Subscribe to wallet-level events the account layer must react to:
	go handleWalletDelete(e, e.Emitter().On("wallet:delete"))
	go handleWalletRestore(e, e.Emitter().On("wallet:restored"))
	go handleWalletPubkeyRepair(e, e.Emitter().On("wallet:pubkey_repaired"))
}
