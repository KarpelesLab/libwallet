package wltwallet

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func init() {
	pobj.RegisterStatic("RemoteKey:new", remotekeyNew)
	pobj.RegisterStatic("RemoteKey:reshare", remotekeyReshare)
	pobj.RegisterStatic("RemoteKey:validate", remotekeyValidate)
}

// walletSignReshareInit is the first packet sent when doing a reshare negociation
//
// Remote will use: params := tss.NewReSharingParameters(tss.EC(), oldctx, newctx, p.Name, p.OldPartycount, p.OldThreshold, p.NewPartycount, p.NewThreshold)
type walletSignReshareInit struct {
	OldPeers      tss.SortedPartyIDs `json:"old_peers"`
	NewPeers      tss.SortedPartyIDs `json:"new_peers"`
	Name          *tss.PartyID       `json:"name"`
	OldPartycount int                `json:"old_partycount"`
	NewPartycount int                `json:"new_partycount"`
	OldThreshold  int                `json:"old_threshold"`
	NewThreshold  int                `json:"new_threshold"`
	Curve         string             `json:"curve"` // "secp256k1" or "ed25519"
}

type remoteKeyNewResult struct {
	Session string `json:"session"`
	Format  string `json:"format"` // all-digits
	Length  int    `json:"length"` // 6
}

func remoteNew(ctx context.Context, number string) (*remoteKeyNewResult, error) {
	var res *remoteKeyNewResult
	return res, rest.Apply(ctx, "Crypto/WalletSign:new", "POST", rest.Param{"number": number}, &res)
}

// remotekeyNew starts a 2FA session for a phone number or email address.
// The `number` param accepts either format — the Crypto/WalletSign backend
// routes SMS vs email based on whether the value contains an "@".
func remotekeyNew(ctx context.Context, in struct {
	Number string `json:"number"` // phone (international format) or email address
	Email  string `json:"email"`  // alias for Number when using email
}) (any, error) {
	target := in.Number
	if target == "" {
		target = in.Email
	}
	if target == "" {
		return nil, errors.New("number or email is required")
	}
	res, err := rest.Do(ctx, "Crypto/WalletSign:new", "POST", rest.Param{"number": target})
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

func remoteSign(ctx context.Context, key string, hash []byte, il []byte, curve string) (*remoteKeyNewResult, error) {
	var res *remoteKeyNewResult
	return res, rest.Apply(ctx, "Crypto/WalletSign:sign", "POST", rest.Param{"key": key, "hash": hex.EncodeToString(hash), "il": hex.EncodeToString(il), "curve": curve}, &res)
}

func remoteReshare(ctx context.Context, key string, curve string) (*remoteKeyNewResult, error) {
	var res *remoteKeyNewResult
	return res, rest.Apply(ctx, "Crypto/WalletSign:reshare", "POST", rest.Param{"key": key, "threshold": 1, "count": 3, "curve": curve}, &res)
}

func remotekeyReshare(ctx context.Context, in struct {
	Key   string `json:"key"`
	Curve string `json:"curve"`
}) (any, error) {
	res, err := rest.Do(ctx, "Crypto/WalletSign:reshare", "POST", rest.Param{"key": in.Key, "threshold": 1, "count": 3, "curve": in.Curve})
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

type remoteKeyVerifyResult struct {
	RemoteKey string
}

func remoteVerify(ctx context.Context, session, code string) (*remoteKeyVerifyResult, error) {
	var res *remoteKeyVerifyResult
	return res, rest.Apply(ctx, "Crypto/WalletSign:verify", "POST", rest.Param{"session": session, "code": code}, &res)
}

// Will return a map[string]any{"RemoteKey": "key"}
func remotekeyValidate(ctx context.Context, in struct {
	Session string `json:"session"`
	Code    string `json:"code"`
}) (any, error) {
	res, err := rest.Do(ctx, "Crypto/WalletSign:verify", "POST", rest.Param{"session": in.Session, "code": in.Code})
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}
