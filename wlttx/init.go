package wlttx

import "github.com/KarpelesLab/libwallet/wltintf"

func InitEnv(e wltintf.Env) {
	e.AutoMigrate(&Transaction{})
}
