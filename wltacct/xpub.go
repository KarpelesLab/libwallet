package wltacct

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/secp256k1/ecckd"
)

// Xpub returns a BIP-32 serialized extended public key (xpub) for this account.
//
// The returned string (base58) can be used with modchain's xpub-aware endpoints
// (modchain_assets, modchain_lookupTxoBIP32, modchain_maketx) to perform
// gap-limit scans and UTXO operations without client-side indexing.
//
// Note: because TSS holds only public key material, the returned xpub is built
// from Account.Pubkey + Account.Chaincode. All child derivations are
// non-hardened. Addresses produced from this xpub are NOT directly importable
// into seed-based wallets (they'd use different derivation paths), but they
// are consistent within libwallet.
func (a *Account) Xpub() (string, error) {
	if a.Pubkey == "" {
		return "", errors.New("account has no pubkey")
	}
	if a.Chaincode == "" {
		return "", errors.New("account has no chaincode")
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(a.Pubkey)
	if err != nil {
		return "", fmt.Errorf("decode pubkey: %w", err)
	}
	ccBytes, err := base64.RawURLEncoding.DecodeString(a.Chaincode)
	if err != nil {
		return "", fmt.Errorf("decode chaincode: %w", err)
	}

	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("parse pubkey: %w", err)
	}

	// ecckd.FromPublicKey expects a *ecdsa.PublicKey
	ecPub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pub.X(),
		Y:     pub.Y(),
	}

	ext, err := ecckd.FromPublicKey(ecPub, ccBytes)
	if err != nil {
		return "", fmt.Errorf("build extended key: %w", err)
	}
	return ext.String(), nil
}
