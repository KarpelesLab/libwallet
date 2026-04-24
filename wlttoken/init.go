package wlttoken

import (
	"github.com/KarpelesLab/libwallet/wltintf"

	// Blank import so the subpackage's init() runs and registers
	// the Token:listCurated endpoint. The subpackage is isolated
	// from this one (different package clause, separate go:embed
	// area) to keep user-token code and the curated registry
	// from entangling — pulling it in here is the cheapest
	// wiring that doesn't require touching wltbase/env.go.
	_ "github.com/KarpelesLab/libwallet/wlttoken/curated"
)

func InitEnv(e wltintf.Env) {
	// psql auto-creates tables, no migration needed
}
