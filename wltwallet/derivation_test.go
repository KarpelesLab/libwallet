package wltwallet

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/base58"
	"github.com/tyler-smith/go-bip39"
)

// Mirror of the locked-in vectors but exercised through the
// production helpers (derivePrivkeyFromSeed / derivePubkeyForPath)
// rather than ecckd.FromBitcoinSeed directly. Ensures the string-
// path parser + the dispatch in derivePrivkeyFromSeed keep matching
// the user-supplied test vectors.

func TestDerivePrivkeyFromSeed_AllVectors(t *testing.T) {
	secpSeed := bip39.NewSeed(secpMnemonic, "")
	solSeed := bip39.NewSeed(solMnemonic, "")

	cases := []struct {
		name        string
		seed        []byte
		curve       string
		path        string
		wantPubkey  string // hex, 33-byte compressed for secp; 32-byte raw for ed25519
		wantAddress string
		addressFn   func([]byte) string
	}{
		{
			name:        "BTC P2PKH via path",
			seed:        secpSeed,
			curve:       "secp256k1",
			path:        "m/44'/0'/0'/0/0",
			wantPubkey:  "03983ff9d365e50c933bdf18d8f157105779bc047395f9635b39bfd543ad58d7ff",
			wantAddress: "1PFNjDKjBMA25oLqfY8Y4EmRR51T4b5NCM",
			addressFn:   btcP2PKH,
		},
		{
			name:        "EVM via path",
			seed:        secpSeed,
			curve:       "secp256k1",
			path:        "m/44'/60'/0'/0/0",
			wantPubkey:  "03b5894b03ca3c7850e8269a34019ec9870b0a030836e5f2d65203b2299c3dec20",
			wantAddress: "0x2f0765840477A3c7F76EEc53663006bA7c974d31",
			addressFn:   evmAddressLower,
		},
		{
			name:        "BTC native segwit via path",
			seed:        secpSeed,
			curve:       "secp256k1",
			path:        "m/84'/0'/0'/0/0",
			wantPubkey:  "03bd60d87d8363526cb5486539373b53706a2a3bb650c7ce11faaa8d1ac4f1d102",
			wantAddress: "bc1qrsje8aswzyhyg94us33mlcrsfds4vd5f7th9eh",
			addressFn:   btcBech32,
		},
		{
			name:        "Solana seed[:32] via empty path",
			seed:        solSeed,
			curve:       "ed25519",
			path:        "", // empty = Sollet/Backpack no-derivation mode
			wantAddress: "FeAf77cBkToyr9b59TfnC3rZES6UddQdctfXQvwQJNuR",
			addressFn:   ed25519SeedToSolanaAddress,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv, err := derivePrivkeyFromSeed(c.seed, c.curve, c.path)
			if err != nil {
				t.Fatalf("derivePrivkeyFromSeed: %v", err)
			}

			if c.curve == "secp256k1" && c.wantPubkey != "" {
				pub, err := derivePub("secp256k1", priv)
				if err != nil {
					t.Fatalf("derivePub: %v", err)
				}
				gotPub := hex.EncodeToString(pub)
				if gotPub != c.wantPubkey {
					t.Fatalf("pubkey mismatch:\n  got=%s\n want=%s", gotPub, c.wantPubkey)
				}
				got := c.addressFn(pub)
				if !stringEqualIgnoreCase(got, c.wantAddress) {
					t.Fatalf("address mismatch:\n  got=%s\n want=%s", got, c.wantAddress)
				}
			}
			if c.curve == "ed25519" {
				got := c.addressFn(priv)
				if got != c.wantAddress {
					t.Fatalf("Solana address mismatch:\n  got=%s\n want=%s", got, c.wantAddress)
				}
			}
		})
	}
}

// ed25519SeedToSolanaAddress expands a 32-byte ed25519 seed into the
// public key and encodes it as a Solana base58 address.
func ed25519SeedToSolanaAddress(seed []byte) string {
	full := ed25519.NewKeyFromSeed(seed)
	pub := full[32:]
	return base58.Bitcoin.Encode(pub)
}
