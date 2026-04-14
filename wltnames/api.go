package wltnames

import (
	"errors"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("Names:resolve", apiNamesResolve)
}

// Resolution is the result of a name resolution lookup.
type Resolution struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Network string `json:"network"` // "ethereum" or "solana"
}

// apiNamesResolve implements `POST Names:resolve`.
//
// Auto-detects ENS (.eth) vs SNS (.sol) by suffix.
func apiNamesResolve(ctx *apirouter.Context, in struct {
	Name string `json:"Name"`
}) (*Resolution, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if name == "" {
		return nil, errors.New("Name is required")
	}

	switch {
	case strings.HasSuffix(name, ".eth"):
		addr, err := ResolveENS(e, name)
		if err != nil {
			return nil, err
		}
		return &Resolution{Name: name, Address: addr, Network: "ethereum"}, nil
	case strings.HasSuffix(name, ".sol"):
		addr, err := ResolveSNS(e, name)
		if err != nil {
			return nil, err
		}
		return &Resolution{Name: name, Address: addr, Network: "solana"}, nil
	default:
		return nil, errors.New("unsupported name suffix (only .eth and .sol are supported)")
	}
}
