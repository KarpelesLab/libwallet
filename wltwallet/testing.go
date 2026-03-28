package wltwallet

import (
	"context"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/xuid"
)

// NewWalletForTesting creates a properly initialized wallet with three Plain keys
// This should ONLY be used in tests
func NewWalletForTesting(name string) (*Wallet, error) {
	// Create key descriptions
	keyDesc := []*wltsign.KeyDescription{
		{Type: "Plain"},
		{Type: "Plain"},
		{Type: "Plain"},
	}

	// Create basic wallet structure
	wallet := &Wallet{
		Id:        xuid.New("wlt"),
		Name:      name,
		Threshold: 1,
		Created:   time.Now(),
		Modified:  time.Now(),
	}

	// Initialize the wallet with proper key generation
	// This will create the WalletKey objects and set up the wallet properly
	err := wallet.initializeWallet(context.Background(), keyDesc)
	if err != nil {
		return nil, err
	}

	return wallet, nil
}
