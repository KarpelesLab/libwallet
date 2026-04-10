package wltwallet

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
)

func init() {
	pobj.RegisterStatic("TSS:genParams", tssGenParams)
}

func tssGenParams(ctx context.Context) (any, error) {
	preParams, err := (&ecdsatss.LocalPreGenerator{Context: ctx}).Generate()
	if err != nil {
		return nil, err
	}
	res, err := json.Marshal(preParams)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.EncodeToString(res), nil
}
