// Package wltnames provides on-chain name resolution (ENS and SNS).
package wltnames

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"golang.org/x/crypto/sha3"
)

// ensRegistryAddress is the canonical ENS Registry on Ethereum mainnet.
const ensRegistryAddress = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

// selectorResolver is keccak256("resolver(bytes32)")[:4].
const selectorResolver = "0178b8bf"

// selectorAddr is keccak256("addr(bytes32)")[:4].
const selectorAddr = "3b3b57de"

// ResolveENS resolves an ENS name (e.g. "vitalik.eth") to an Ethereum address.
// Returns a 0x-prefixed checksum-less lowercase address.
func ResolveENS(e wltintf.Env, name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "", errors.New("empty name")
	}

	// Find the Ethereum mainnet network
	netID := wltnet.NetworkIdForTypeAndChainId("evm", "1")
	net, err := wltnet.NetworkById(e, netID)
	if err != nil {
		return "", fmt.Errorf("ENS requires Ethereum mainnet network: %w", err)
	}

	node := namehash(name)
	nodeHex := hex.EncodeToString(node)

	// 1. Query registry.resolver(node) → resolver address
	resolverAddr, err := ethCallAddress(net, ensRegistryAddress, "0x"+selectorResolver+nodeHex)
	if err != nil {
		return "", fmt.Errorf("ENS resolver lookup: %w", err)
	}
	if isZeroAddress(resolverAddr) {
		return "", fmt.Errorf("ENS name %q has no resolver", name)
	}

	// 2. Query resolver.addr(node) → address
	target, err := ethCallAddress(net, resolverAddr, "0x"+selectorAddr+nodeHex)
	if err != nil {
		return "", fmt.Errorf("ENS addr lookup: %w", err)
	}
	if isZeroAddress(target) {
		return "", fmt.Errorf("ENS name %q resolves to zero address", name)
	}
	return target, nil
}

// namehash computes the ENS namehash of a domain (EIP-137).
func namehash(name string) []byte {
	node := make([]byte, 32) // start with 32 zero bytes
	if name == "" {
		return node
	}
	labels := strings.Split(name, ".")
	// Process labels right-to-left
	for i := len(labels) - 1; i >= 0; i-- {
		labelHash := keccak256([]byte(labels[i]))
		node = keccak256(append(node, labelHash...))
	}
	return node
}

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// ethCallAddress performs an eth_call and decodes the result as a 20-byte address.
// The selector+args should be 0x-prefixed hex.
func ethCallAddress(net *wltnet.Network, contract, data string) (string, error) {
	param := map[string]string{
		"to":   contract,
		"data": data,
	}
	hexResult, err := ethrpc.ReadString(net.DoRPC("eth_call", param, "latest"))
	if err != nil {
		return "", err
	}
	hexResult = strings.TrimPrefix(hexResult, "0x")
	if len(hexResult) < 64 {
		return "", fmt.Errorf("eth_call short result: %d bytes", len(hexResult)/2)
	}
	// Address is the last 40 hex chars (20 bytes) of a 32-byte word
	return "0x" + hexResult[24:64], nil
}

func isZeroAddress(addr string) bool {
	hex := strings.TrimPrefix(strings.ToLower(addr), "0x")
	for _, c := range hex {
		if c != '0' {
			return false
		}
	}
	return true
}
