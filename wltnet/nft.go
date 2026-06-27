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

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnft"
	"github.com/KarpelesLab/libwallet/wltutil"
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
	// Gate the (contract-controlled) URL before handing it to the
	// fetcher: restrict the scheme to http/https and reject hosts that
	// resolve to internal addresses so contract metadata can't drive an
	// SSRF. The redirect-hop / body-size limiting for the actual
	// transfer is enforced by the hardened wltbase.CacheGet fetcher.
	if err := validateMetadataURL(uri); err != nil {
		return nil, err
	}
	return e.CacheGet(context.Background(), uri, 30*time.Second, 24*time.Hour)
}

func doIPFSCall(e wltintf.Env, uri string) ([]byte, error) {
	cid := strings.TrimPrefix(uri, "ipfs://")
	// The CID comes from contract-controlled metadata and is composed
	// onto a gateway base URL by raw concatenation. Validate its charset
	// so a value like "..%2f", "x?@evil" or "x#@evil" can't reshape the
	// request (path traversal, query/fragment/authority injection).
	if !validIPFSCID(cid) {
		return nil, fmt.Errorf("invalid IPFS CID %q", cid)
	}

	var err error
	for _, gw := range ipfsGateways {
		var buf []byte
		buf, err = doHTTPCall(e, gw+cid)
		if err == nil && buf != nil {
			return buf, nil
		}
	}
	return nil, err
}

func (n *Network) NftMetadata(e wltintf.Env, contractAddress string, tokenId string) (*wltnft.Nft, error) {
	bytes, err := detectMetadataFunction(n, contractAddress, tokenId)
	if err != nil {
		return nil, err
	}
	uri, err := wltutil.DecodeEVMEthCallString(bytes)
	if err != nil {
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

		assets, ok := mapData["assets"].([]any)
		if !ok || len(assets) == 0 {
			return &[]wltnft.Nft{}, nil
		}

		var nftInfos []NftFetchInfo
		for _, a := range assets {
			asset, ok := a.(map[string]any)
			if !ok {
				continue
			}
			assetType, _ := asset["asset"].(string)
			if assetType != "nft" {
				continue
			}
			address, _ := asset["address"].(string)
			token, _ := asset["token"].(string)
			if address == "" || token == "" {
				continue
			}
			i := slices.IndexFunc(nftInfos, func(info NftFetchInfo) bool {
				return info.ContractAddress == address
			})
			if i == -1 {
				nftInfos = append(nftInfos, NftFetchInfo{
					ContractAddress: address,
					Tokens:          []string{token},
				})
				continue
			}
			info := nftInfos[i]
			info.Tokens = append(info.Tokens, token)
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
