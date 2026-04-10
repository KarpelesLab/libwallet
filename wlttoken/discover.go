package wlttoken

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
)

// ERC-20 function selectors
const (
	selectorName        = "0x06fdde03" // name()
	selectorSymbol      = "0x95d89b41" // symbol()
	selectorDecimals    = "0x313ce567" // decimals()
	selectorTotalSupply = "0x18160ddd" // totalSupply()
)

// discoverResult is the response from Token:discoverToken
type discoverResult struct {
	Name        string `json:"name"`
	Symbol      string `json:"symbol"`
	Decimals    int    `json:"decimals"`
	TotalSupply string `json:"total_supply,omitempty"`
	Address     string `json:"address"`
	Type        string `json:"type"`
}

func init() {
	pobj.RegisterStatic("Token:discoverToken", apiDiscoverToken)
}

func apiDiscoverToken(ctx *apirouter.Context, in struct {
	Network string
	Address string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, fmt.Errorf("failed to get env")
	}

	netId, err := xuid.Parse(in.Network)
	if err != nil {
		return nil, fmt.Errorf("invalid network ID: %w", err)
	}

	net, err := wltnet.NetworkById(e, netId)
	if err != nil {
		return nil, fmt.Errorf("network not found: %w", err)
	}

	switch net.Type {
	case "evm":
		return discoverERC20(net, in.Address)
	case "solana":
		return discoverSPLToken(net, in.Address)
	default:
		return nil, fmt.Errorf("token discovery is not supported on %s networks", net.Type)
	}
}

func discoverERC20(net *wltnet.Network, address string) (*discoverResult, error) {
	result := &discoverResult{
		Address: address,
		Type:    "erc20",
	}

	// Query name()
	name, err := doEthCallString(net, address, selectorName)
	if err == nil {
		result.Name = name
	}

	// Query symbol()
	symbol, err := doEthCallString(net, address, selectorSymbol)
	if err == nil {
		result.Symbol = symbol
	}

	// Query decimals()
	decimals, err := doEthCallUint256(net, address, selectorDecimals)
	if err == nil {
		result.Decimals = int(decimals.Int64())
	}

	// Query totalSupply()
	totalSupply, err := doEthCallUint256(net, address, selectorTotalSupply)
	if err == nil {
		result.TotalSupply = totalSupply.String()
	}

	if result.Name == "" && result.Symbol == "" {
		return nil, fmt.Errorf("address %s does not appear to be an ERC-20 token contract", address)
	}

	return result, nil
}

func discoverSPLToken(net *wltnet.Network, address string) (*discoverResult, error) {
	// Query Solana token metadata via getAccountInfo
	raw, err := net.DoRPC("getAccountInfo", address, map[string]any{"encoding": "jsonParsed"})
	if err != nil {
		return nil, fmt.Errorf("failed to query Solana account: %w", err)
	}

	var resp struct {
		Value *struct {
			Data struct {
				Parsed struct {
					Info struct {
						Decimals      int    `json:"decimals"`
						Supply        string `json:"supply"`
						MintAuthority string `json:"mintAuthority"`
					} `json:"info"`
					Type string `json:"type"` // "mint"
				} `json:"parsed"`
				Program string `json:"program"` // "spl-token"
			} `json:"data"`
		} `json:"value"`
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse Solana account info: %w", err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("Solana account %s not found", address)
	}

	if resp.Value.Data.Parsed.Type != "mint" {
		return nil, fmt.Errorf("address %s is not a token mint (type: %s)", address, resp.Value.Data.Parsed.Type)
	}

	tokenType := "spl-token"
	if resp.Value.Data.Program == "spl-token-2022" {
		tokenType = "spl-token-2022"
	}

	return &discoverResult{
		Address:     address,
		Type:        tokenType,
		Decimals:    resp.Value.Data.Parsed.Info.Decimals,
		TotalSupply: resp.Value.Data.Parsed.Info.Supply,
	}, nil
}

// doEthCallString performs an eth_call and decodes an ABI-encoded string result
func doEthCallString(net *wltnet.Network, contractAddress, selector string) (string, error) {
	param := map[string]string{
		"to":   contractAddress,
		"data": selector,
	}

	hexResult, err := ethrpc.ReadString(net.DoRPC("eth_call", param, "latest"))
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(hexResult, "0x") {
		hexResult = hexResult[2:]
	}

	if len(hexResult) == 0 {
		return "", fmt.Errorf("empty response")
	}

	raw, err := hex.DecodeString(hexResult)
	if err != nil {
		return "", err
	}

	// Try ABI-encoded string (offset + length + data)
	if len(raw) >= 64 {
		offset := new(big.Int).SetBytes(raw[:32])
		if offset.Int64() == 32 && len(raw) >= 64 {
			length := new(big.Int).SetBytes(raw[32:64])
			end := 64 + int(length.Int64())
			if end <= len(raw) {
				s := string(raw[64:end])
				return strings.TrimSpace(s), nil
			}
		}
	}

	// Fallback: treat as raw bytes, strip nulls
	re := regexp.MustCompile(`[[:cntrl:]]+`)
	return strings.TrimSpace(re.ReplaceAllString(string(raw), "")), nil
}

// doEthCallUint256 performs an eth_call and decodes a uint256 result
func doEthCallUint256(net *wltnet.Network, contractAddress, selector string) (*big.Int, error) {
	param := map[string]string{
		"to":   contractAddress,
		"data": selector,
	}

	hexResult, err := ethrpc.ReadString(net.DoRPC("eth_call", param, "latest"))
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(hexResult, "0x") {
		hexResult = hexResult[2:]
	}

	raw, err := hex.DecodeString(hexResult)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(raw), nil
}
