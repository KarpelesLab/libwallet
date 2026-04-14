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
