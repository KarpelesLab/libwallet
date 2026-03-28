package wltnet

import "github.com/KarpelesLab/libwallet/wltintf"

func InitEnv(e wltintf.Env) {
	// psql auto-creates tables, no migration needed
	MakeDefaultNetworks(e)
}
