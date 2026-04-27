package wltacct

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/KarpelesLab/secp256k1"
)

// TestAddressFormats_ByChain locks in the per-chain catalog: every
// supported chain returns at least one format, the default matches
// what bitcoinAddress() emits (so frontends that switch from
// Account.Address to Account:addressFormats see the same first
// entry), and addresses carry the chain's expected prefix.
func TestAddressFormats_ByChain(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %s", err)
	}
	pub := priv.PubKey()

	// Build an Account whose DerivePublic("m/0/0") returns this
	// pubkey verbatim. We do that by setting Pubkey + Chaincode +
	// IL such that the derivation re-derives this exact key. The
	// shortest path is to pre-compute pub at m/0/0 of an arbitrary
	// chaincode — but simpler: use a chaincode of zeroes and check
	// that DerivePublic doesn't fail. The point is the test
	// validates the catalog logic, not key derivation; we replace
	// DerivePublic via a small wrapper-style assertion below.
	a := &Account{
		Pubkey:    base64.RawURLEncoding.EncodeToString(pub.SerializeCompressed()),
		Chaincode: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Curve:     "secp256k1",
		Path:      "m/44/60/0/0",
	}

	cases := []struct {
		chainId      string
		wantKinds    []string // in order
		wantPrefixes []string // address prefix to assert (case-sensitive)
	}{
		{
			chainId:      "bitcoin",
			wantKinds:    []string{"p2wpkh", "p2sh:p2wpkh", "p2pkh"},
			wantPrefixes: []string{"bc1", "3", "1"},
		},
		{
			chainId:      "litecoin",
			wantKinds:    []string{"p2wpkh", "p2sh:p2wpkh", "p2pkh"},
			wantPrefixes: []string{"ltc1", "M", "L"},
		},
		{
			chainId:      "monacoin",
			wantKinds:    []string{"p2wpkh", "p2pkh"},
			wantPrefixes: []string{"mona1", "M"},
		},
		{
			chainId:      "bitcoin-cash",
			wantKinds:    []string{"p2pkh"},
			wantPrefixes: []string{"bitcoincash:"},
		},
		{
			chainId:      "dogecoin",
			wantKinds:    []string{"p2pkh"},
			wantPrefixes: []string{"D"},
		},
	}

	for _, c := range cases {
		t.Run(c.chainId, func(t *testing.T) {
			formats, err := a.AddressFormats(c.chainId)
			if err != nil {
				t.Fatalf("AddressFormats(%q): %s", c.chainId, err)
			}
			if len(formats) != len(c.wantKinds) {
				t.Fatalf("got %d formats, want %d (formats=%+v)", len(formats), len(c.wantKinds), formats)
			}
			for i, f := range formats {
				if f.Kind != c.wantKinds[i] {
					t.Errorf("[%d] kind = %q, want %q", i, f.Kind, c.wantKinds[i])
				}
				if !strings.HasPrefix(f.Address, c.wantPrefixes[i]) {
					t.Errorf("[%d] address %q does not start with %q", i, f.Address, c.wantPrefixes[i])
				}
				if f.Path != "m/0/0" {
					t.Errorf("[%d] path = %q, want m/0/0", i, f.Path)
				}
				if (i == 0) != f.Default {
					t.Errorf("[%d] Default = %v, want %v (only first entry is default)", i, f.Default, i == 0)
				}
			}
			// Sanity: the default-flagged entry's address must
			// exactly match bitcoinAddress(chainId, 0, false) so
			// Account.Address and the default of AddressFormats
			// don't drift.
			defaultAddr, err := a.bitcoinAddress(c.chainId, 0, false)
			if err != nil {
				t.Fatalf("bitcoinAddress(%q): %s", c.chainId, err)
			}
			if formats[0].Address != defaultAddr {
				t.Errorf("default mismatch: AddressFormats[0]=%q, bitcoinAddress=%q",
					formats[0].Address, defaultAddr)
			}
		})
	}
}

func TestAddressFormats_UnknownChain(t *testing.T) {
	a := &Account{
		Curve: "secp256k1",
	}
	if _, err := a.AddressFormats("solana"); err == nil {
		t.Errorf("expected error for non-bitcoin-family chain, got nil")
	}
	if _, err := a.AddressFormats("evm"); err == nil {
		t.Errorf("expected error for non-bitcoin-family chain, got nil")
	}
}
