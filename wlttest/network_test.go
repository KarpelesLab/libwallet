package wlttest

import (
	"fmt"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

func getNetwork() *wltnet.Network {
	return &wltnet.Network{
		Id:               nil,
		Type:             "evm",
		ChainId:          "1",
		Name:             "Ethereum Mainnet",
		RPC:              "",
		CurrencySymbol:   "ETH",
		CurrencyDecimals: 0,
		BlockExplorer:    "",
		TestNet:          false,
		Priority:         0,
		Created:          time.Now(),
		Updated:          time.Now(),
	}
}

type MockAddressProvider struct {
	MockAddress string
}

func (m *MockAddressProvider) GetAddress() string {
	return m.MockAddress
}

func TestNftMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping NFT metadata test in short mode (requires live Ethereum RPC)")
	}

	dir := t.TempDir()
	v, err := wltbase.InitEnv(dir)
	if err != nil {
		t.Fatal(err)
	}

	env, ok := v.(wltintf.Env)
	if !ok {
		fmt.Println("Failed to cast to wltintf.Env")
		return
	}

	network := getNetwork()

	// this address uses HTTP token URI
	_, err = network.NftMetadata(env, "0x3E34ff1790BF0a13EfD7d77e75870Cb525687338", "1")
	if err != nil {
		t.Fatalf("Error getting NFT list from 1 : %v", err)
	}

	// this address uses IPFS token URI
	_, err = network.NftMetadata(env, "0xBd3531dA5CF5857e7CfAA92426877b022e612cf8", "1")
	if err != nil {
		t.Fatalf("Error getting NFT list from 2 : %v", err)
	}
}
