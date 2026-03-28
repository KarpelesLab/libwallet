package wltnet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/ethrpc"
)

const (
	tokenURISelector    = "c87b56dd" // ERC-721 Metadata
	uriSelector         = "0e89341c" // ERC-1155 Metadata
	contractURISelector = "e8a3d485" // OpenSea Collection Metadata
)

// List of public IPFS gateways (fallbacks)
var ipfsGateways = []string{
	"https://ipfs.io/ipfs/",
	"https://cloudflare-ipfs.com/ipfs/",
	"https://infura-ipfs.io/ipfs/",
}

type NftFetchInfo struct {
	ContractAddress string
	Tokens          []string
}

func doHTTPCall(e wltintf.Env, uri string) ([]byte, error) {
	fmt.Println("Will try uri:", uri)
	buf, err := e.CacheGet(context.Background(), uri, 30*time.Second, 24*time.Hour)
	if err != nil {
		fmt.Println("CacheGet Error:", err)
		return nil, err
	}
	return buf, nil
}

func doIPFSCall(e wltintf.Env, uri string) ([]byte, error) {
	cid := strings.TrimPrefix(uri, "ipfs://")
	newUrl := ipfsGateways[0] + cid // Use the first IPFS gateway
	buf, err := doHTTPCall(e, newUrl)
	if err == nil && buf != nil {
		return buf, nil
	}

	newUrl = ipfsGateways[1] + cid // Use the second IPFS gateway
	buf, err = doHTTPCall(e, newUrl)
	if err == nil && buf != nil {
		return buf, nil
	}

	newUrl = ipfsGateways[2] + cid // Use the third IPFS gateway
	buf, err = doHTTPCall(e, newUrl)
	if err == nil && buf != nil {
		return buf, nil
	}
	fmt.Println("IPFS Calls didnt provide any data", err)
	return nil, err
}

func (n *Network) NftMetadata(e wltintf.Env, contractAddress string, tokenId string) (*wltnft.Nft, error) {
	bytes, err := detectMetadataFunction(n, contractAddress, tokenId)
	if err != nil {
		fmt.Println("detectMetadataFunction Error:", err)
		return nil, err
	}
	uri, err := wltutil.DecodeEVMEthCallString(bytes)
	if err != nil {
		fmt.Println("DecodeEVMEthCallString Error:", err)
		return nil, err
	}
	var buf []byte
	if strings.HasPrefix(uri, "ipfs://") {
		buf, err = doIPFSCall(e, uri)
	} else {
		buf, err = doHTTPCall(e, uri)
	}
	if err != nil {
		return nil, err
	}

	var nft *wltnft.Nft

	err = json.Unmarshal(buf, &nft)
	if err != nil {
		return nil, err
	}

	nft.ContractAddress = contractAddress
	nft.Network = n.Id
	nft.TokenId = tokenId

	return nft, nil
}

func getContractName(n *Network, contractAddress string) (string, error) {
	param := map[string]string{
		"to":   contractAddress,
		"data": "0x06fdde03",
	}

	hexName, err := ethrpc.ReadString(n.DoRPC("eth_call", param, "latest"))
	if err != nil {
		fmt.Printf("error RPC %v", err)
		return "", err
	}

	fmt.Printf("hexName:%v\n", hexName)

	if strings.HasPrefix(hexName, "0x") {
		hexName = hexName[2:]
	}

	// Decode hex string to readable text
	bytes, err := hex.DecodeString(hexName)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}

	trimmed := strings.Trim(string(bytes), "\x00")

	// Also remove any non-printable control characters (extra padding)
	re := regexp.MustCompile(`[[:cntrl:]]+`)
	name := re.ReplaceAllString(trimmed, "")

	return strings.TrimSpace(name), nil
}

func (n *Network) NftList(e wltintf.Env, acct AddressProvider) (*[]wltnft.Nft, error) {
	switch n.Type {
	case "bitcoin":
		return nil, fmt.Errorf("unsupported type %s", n.Type)
	case "solana":
		return n.solanaNftList(e, acct)
	case "evm":
		// get all assets
		raw, err := n.DoRPC("modchain_assets", acct.GetAddress())
		if err != nil {
			fmt.Printf("error RPC %v", err)
			return nil, err
		}
		var mapData map[string]any
		err = json.Unmarshal(raw, &mapData)
		if err != nil {
			fmt.Printf("error Unmarshal %v \n", err)
			return nil, err
		}
		if mapData["assets"] == nil {
			return &[]wltnft.Nft{}, nil
		}

		assets := mapData["assets"].([]any)
		if len(assets) == 0 {
			return &[]wltnft.Nft{}, nil
		}

		var nftInfos []NftFetchInfo
		for _, a := range assets {
			asset := a.(map[string]any)
			if asset["asset"].(string) != "nft" {
				continue
			}
			i := slices.IndexFunc(nftInfos, func(info NftFetchInfo) bool {
				return info.ContractAddress == asset["address"].(string)
			})
			if i == -1 {
				nftInfos = append(nftInfos, NftFetchInfo{
					ContractAddress: asset["address"].(string),
					Tokens:          []string{asset["token"].(string)},
				})
				continue
			}
			info := nftInfos[i]
			info.Tokens = append(info.Tokens, asset["token"].(string))
			nftInfos[i] = info
		}

		var nfts []wltnft.Nft
		for _, info := range nftInfos {
			if len(info.Tokens) == 0 {
				continue
			}

			contractName, err := getContractName(n, info.ContractAddress)
			if err != nil {
				return nil, err
			}

			for _, token := range info.Tokens {
				nft, err := n.NftMetadata(e, info.ContractAddress, token)
				if err != nil {
					continue
				}
				nft.ContractName = contractName
				nfts = append(nfts, *nft)
			}
		}

		return &nfts, nil
	default:
		return nil, fmt.Errorf("unsupported type %s", n.Type)
	}
}

// generateCallData prepares the encoded function call for eth_call
func generateCallData(selector, tokenIdStr string) (string, error) {
	// Convert token Id string to big.Int
	tokenId := new(big.Int)
	_, success := tokenId.SetString(tokenIdStr, 10)
	if !success {
		return "", fmt.Errorf("invalid token Id")
	}

	// Convert token Id to a 32-byte (64-character) padded hex string
	tokenIdHex := fmt.Sprintf("%064x", tokenId)

	// Concatenate function selector and encoded token Id
	data := selector + tokenIdHex
	return "0x" + data, nil
}

// decodeRawMessageToString extracts a readable string from json.RawMessage
func decodeRawMessageToString(raw json.RawMessage) ([]byte, error) {
	// Unmarshal raw JSON into a string
	var hexEncodedURI string
	err := json.Unmarshal(raw, &hexEncodedURI)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Ensure it starts with "0x" before decoding
	if strings.HasPrefix(hexEncodedURI, "0x") {
		hexEncodedURI = hexEncodedURI[2:]
	}

	// Decode hex string to readable text
	bytes, err := hex.DecodeString(hexEncodedURI)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return bytes, nil
}

// detectMetadataFunction tries different eth_call methods and returns the metadata URI
func detectMetadataFunction(n *Network, contractAddress, tokenId string) ([]byte, error) {
	param := map[string]string{
		"to": contractAddress,
	}

	// Try `tokenURI(tokenId)` for ERC-721
	data, _ := generateCallData(tokenURISelector, tokenId)
	param["data"] = data
	result, err := n.DoRPC("eth_call", param, "latest")
	if err == nil && len(result) > 0 {
		decodedURI, err := decodeRawMessageToString(result)
		if err == nil && decodedURI != nil {
			return decodedURI, nil
		}
	}

	// Try `uri(tokenId)` for ERC-1155
	data, _ = generateCallData(uriSelector, tokenId)
	param["data"] = data
	result, err = n.DoRPC("eth_call", param, "latest")
	if err == nil && len(result) > 0 {
		decodedURI, err := decodeRawMessageToString(result)
		if err == nil && decodedURI != nil {
			return decodedURI, nil
		}
	}

	// Try `contractURI()` for collection metadata
	param["data"] = "0x" + contractURISelector // No tokenId needed
	result, err = n.DoRPC("eth_call", param, "latest")
	if err == nil && len(result) > 0 {
		decodedURI, err := decodeRawMessageToString(result)
		if err == nil && decodedURI != nil {
			return decodedURI, nil
		}
	}

	// No valid metadata function found
	return nil, fmt.Errorf("no valid metadata function found")
}
