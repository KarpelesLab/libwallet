package wltacct

import (
	"fmt"
	"strconv"

	"github.com/KarpelesLab/outscript"
)

// bitcoinAddress derives a Bitcoin-family address at the given HD index under
// either the receive chain (change=false, m/0/i) or change chain (change=true, m/1/i).
// chainId selects the network-specific script format (bech32 / base58).
func (a *Account) bitcoinAddress(chainId string, index int, change bool) (string, error) {
	chain := 0
	if change {
		chain = 1
	}
	path := "m/" + strconv.Itoa(chain) + "/" + strconv.Itoa(index)

	pub, err := a.DerivePublic(path)
	if err != nil {
		return "", fmt.Errorf("derive %s: %w", path, err)
	}
	s := outscript.New(pub)

	switch chainId {
	case "bitcoin":
		out, err := s.Out("p2wpkh")
		if err != nil {
			return "", err
		}
		return out.Address("bitcoin")
	case "litecoin":
		out, err := s.Out("p2wpkh")
		if err != nil {
			return "", err
		}
		return out.Address("litecoin")
	case "monacoin":
		out, err := s.Out("p2wpkh")
		if err != nil {
			return "", err
		}
		return out.Address("monacoin")
	case "bitcoin-cash":
		out, err := s.Out("p2pkh")
		if err != nil {
			return "", err
		}
		return out.Address("bitcoincash")
	case "dogecoin":
		out, err := s.Out("p2pkh")
		if err != nil {
			return "", err
		}
		return out.Address("dogecoin")
	default:
		return "", fmt.Errorf("unsupported bitcoin-family chainId: %s", chainId)
	}
}

// ReceiveAddress returns the receive-chain address at the given HD index
// (path m/0/{index}). For Bitcoin-family accounts only.
func (a *Account) ReceiveAddress(chainId string, index int) (string, error) {
	return a.bitcoinAddress(chainId, index, false)
}

// ChangeAddress returns the change-chain address at the given HD index
// (path m/1/{index}). For Bitcoin-family accounts only.
func (a *Account) ChangeAddress(chainId string, index int) (string, error) {
	return a.bitcoinAddress(chainId, index, true)
}

// AddressFormat is one user-facing rendering of an account's receive
// address on a Bitcoin-family chain. Frontend uses this to offer the
// user a "show my <kind>" picker (Native SegWit / Legacy / etc.) and
// to render incoming-funds reminders that cover every shape a
// counterparty might have used.
type AddressFormat struct {
	// Kind is the outscript script type ("p2wpkh" / "p2pkh" /
	// "p2sh:p2wpkh"). Stable identifier for programmatic use.
	Kind string `json:"kind"`
	// Name is the human-facing label ("Native SegWit", "Legacy").
	Name string `json:"name"`
	// Address is the formatted address string for this chain + kind.
	Address string `json:"address"`
	// Path is the HD derivation suffix the address was generated at,
	// relative to the account root (e.g. "m/0/0" — receive chain,
	// index 0).
	Path string `json:"path"`
	// Default is true for the format Account.Address currently
	// uses on this chain (i.e. the one bitcoinAddress() picks).
	Default bool `json:"default,omitempty"`
}

// bitcoinFormatCatalog lists the address shapes we know how to render
// per chain. Order = display preference (modern first); the first
// entry is what bitcoinAddress() picks for Account.Address. Add an
// entry here when a new script type becomes mainstream on a chain
// (e.g. when bitcoin-cash standardizes a SegWit form).
var bitcoinFormatCatalog = map[string][]struct {
	kind string
	name string
}{
	"bitcoin": {
		{"p2wpkh", "Native SegWit"},
		{"p2sh:p2wpkh", "SegWit (legacy-compatible)"},
		{"p2pkh", "Legacy"},
	},
	"litecoin": {
		{"p2wpkh", "Native SegWit"},
		{"p2sh:p2wpkh", "SegWit (legacy-compatible)"},
		{"p2pkh", "Legacy"},
	},
	"monacoin": {
		{"p2wpkh", "Native SegWit"},
		{"p2pkh", "Legacy"},
	},
	"bitcoin-cash": {
		{"p2pkh", "CashAddr"},
	},
	"dogecoin": {
		{"p2pkh", "Standard"},
	},
}

// outscriptAddressTag maps our hyphenated chainId convention to the
// upstream outscript tag, which differs only for bitcoin-cash
// ("bitcoincash" with no hyphen).
func outscriptAddressTag(chainId string) string {
	if chainId == "bitcoin-cash" {
		return "bitcoincash"
	}
	return chainId
}

// AddressFormats returns every receive-address format available for
// this account on chainId, ordered by display preference (modern
// first). Use it to populate a "show address as Native SegWit / Legacy
// / ..." picker. All entries derive from m/0/0 (the same receive
// address that drives Account.Address); call ReceiveAddress for
// other indices in a chosen format.
//
// Errors when chainId is not a Bitcoin-family chain.
func (a *Account) AddressFormats(chainId string) ([]*AddressFormat, error) {
	catalog, ok := bitcoinFormatCatalog[chainId]
	if !ok {
		return nil, fmt.Errorf("unsupported bitcoin-family chainId: %s", chainId)
	}
	pub, err := a.DerivePublic("m/0/0")
	if err != nil {
		return nil, fmt.Errorf("derive m/0/0: %w", err)
	}
	s := outscript.New(pub)
	tag := outscriptAddressTag(chainId)

	out := make([]*AddressFormat, 0, len(catalog))
	for i, f := range catalog {
		scr, err := s.Out(f.kind)
		if err != nil {
			// Script type not available for this pubkey — skip
			// rather than fail the whole list (lets the catalog
			// add new kinds without breaking older builds).
			continue
		}
		addr, err := scr.Address(tag)
		if err != nil {
			continue
		}
		out = append(out, &AddressFormat{
			Kind:    f.kind,
			Name:    f.name,
			Address: addr,
			Path:    "m/0/0",
			Default: i == 0,
		})
	}
	return out, nil
}
