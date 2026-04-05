package wltwallet

import (
	"context"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/xuid"
)

// NewWalletForTesting creates a properly initialized wallet with three Plain keys.
// Curve can be "secp256k1" (default if empty) or "ed25519".
// This should ONLY be used in tests.
func NewWalletForTesting(name string, curve string) (*Wallet, error) {
	keyDesc := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	wallet := &Wallet{
		Id:        xuid.New("wlt"),
		Name:      name,
		Threshold: 1,
		Created:   time.Now(),
		Modified:  time.Now(),
	}

	var err error
	if curve == "ed25519" {
		err = wallet.initializeEdDSAWallet(context.Background(), keyDesc)
	} else {
		err = wallet.initializeWallet(context.Background(), keyDesc)
	}
	if err != nil {
		return nil, err
	}

	return wallet, nil
}
