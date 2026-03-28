package wltwallet

import "github.com/KarpelesLab/libwallet/wltintf"

func InitEnv(e wltintf.Env) {
	e.AutoMigrate(&Wallet{})
	e.AutoMigrate(&WalletKey{})
}
