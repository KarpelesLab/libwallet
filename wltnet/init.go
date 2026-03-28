package wltnet

import "github.com/KarpelesLab/libwallet/wltintf"

func InitEnv(e wltintf.Env) {
	e.AutoMigrate(&Network{})
	MakeDefaultNetworks(e)
}
