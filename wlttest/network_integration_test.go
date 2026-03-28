package wlttest

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// TestNetworkLifecycle tests the network functionality using temporary environment
func TestNetworkLifecycle(t *testing.T) {
	// Initialize temporary environment
	tempEnv, err := wltbase.InitTempEnv()
	if err != nil {
		t.Fatalf("Failed to initialize temporary environment: %v", err)
	}
	defer wltbase.CleanupTempEnv(tempEnv)

	env, ok := tempEnv.(wltintf.Env)
	if !ok {
		t.Fatalf("Temporary environment is not a valid wltintf.Env")
	}

	// Step 1: Create test networks
	networks := []*wltnet.Network{
		{
			Type:             "evm",
			ChainId:          "1",
			Name:             "Ethereum Mainnet",
			CurrencySymbol:   "ETH",
			CurrencyDecimals: 18,
			RPC:              "https://ethereum.publicnode.com",
			BlockExplorer:    "https://etherscan.io",
			TestNet:          false,
			Priority:         100,
		},
		{
			Type:             "evm",
			ChainId:          "11155111",
			Name:             "Ethereum Sepolia Testnet",
			CurrencySymbol:   "SEP",
			CurrencyDecimals: 18,
			RPC:              "https://ethereum-sepolia.publicnode.com",
			BlockExplorer:    "https://sepolia.etherscan.io",
			TestNet:          true,
			Priority:         50,
		},
		{
			Type:             "bitcoin",
			ChainId:          "bitcoin",
			Name:             "Bitcoin",
			CurrencySymbol:   "BTC",
			CurrencyDecimals: 8,
			BlockExplorer:    "https://blockstream.info",
			TestNet:          false,
			Priority:         90,
		},
	}

	// Step 2: Check current networks to avoid duplicate constraints
	// We set IDs for our networks
	for i, network := range networks {
		// Assign an ID
		network.Id = wltnet.NetworkIdForTypeAndChainId(network.Type, network.ChainId)

		// First check if it exists
		existing := new(wltnet.Network)
		err = env.FirstWhere(&existing, map[string]any{"Type": network.Type, "ChainId": network.ChainId})
		if err == nil {
			// Network already exists, skip
			networks[i] = existing
			continue
		}

		// Save the network
		err = network.Save(env)
		if err != nil {
			t.Fatalf("Failed to save network %s: %v", network.Name, err)
		}
	}

	// Step 3: Get all networks
	var allNetworks []*wltnet.Network
	err = env.ListHelper(nil, &allNetworks, "Priority DESC")
	if err != nil {
		t.Fatalf("Failed to get networks: %v", err)
	}

	// Step 4: Get networks by type
	var evmNetworks []*wltnet.Network
	err = env.Find(&evmNetworks, map[string]any{"Type": "evm"})
	if err != nil {
		t.Fatalf("Failed to get EVM networks: %v", err)
	}

	// Don't check exact count as there may be default networks

	var bitcoinNetworks []*wltnet.Network
	err = env.Find(&bitcoinNetworks, map[string]any{"Type": "bitcoin"})
	if err != nil {
		t.Fatalf("Failed to get Bitcoin networks: %v", err)
	}

	// Don't check exact count as there may be default networks

	// Step 5: Test network by ID
	var eth *wltnet.Network
	err = env.FirstWhere(&eth, map[string]any{"Type": "evm", "ChainId": "1"})
	if err != nil {
		t.Fatalf("Failed to get Ethereum network: %v", err)
	}

	if eth.Name != "Ethereum Mainnet" {
		t.Errorf("Expected network name 'Ethereum Mainnet', got '%s'", eth.Name)
	}

	// Step 6: Set current network to Ethereum Mainnet
	err = eth.SetCurrent(env)
	if err != nil {
		t.Fatalf("Failed to set current network: %v", err)
	}

	// Step 7: Get current network
	currentNetwork, err := wltnet.CurrentNetwork(env)
	if err != nil {
		t.Fatalf("Failed to get current network: %v", err)
	}

	if currentNetwork.ChainId != "1" || currentNetwork.Type != "evm" {
		t.Errorf("Expected current network to be Ethereum Mainnet (evm, 1), got (%s, %s)",
			currentNetwork.Type, currentNetwork.ChainId)
	}

	// Step 8: Update a network
	eth.RPC = "https://mainnet.infura.io/v3/your-api-key"
	err = eth.Save(env)
	if err != nil {
		t.Fatalf("Failed to update network: %v", err)
	}

	// Verify the update
	var updatedEth *wltnet.Network
	err = env.FirstWhere(&updatedEth, map[string]any{"Type": "evm", "ChainId": "1"})
	if err != nil {
		t.Fatalf("Failed to get updated Ethereum network: %v", err)
	}

	if updatedEth.RPC != eth.RPC {
		t.Errorf("Expected updated RPC URL '%s', got '%s'", eth.RPC, updatedEth.RPC)
	}

	// Step 9: Test switching networks
	var sepolia *wltnet.Network
	err = env.FirstWhere(&sepolia, map[string]any{"Type": "evm", "ChainId": "11155111"})
	if err != nil {
		t.Fatalf("Failed to get Sepolia network: %v", err)
	}

	err = sepolia.SetCurrent(env)
	if err != nil {
		t.Fatalf("Failed to set Sepolia as current network: %v", err)
	}

	currentNetwork, err = wltnet.CurrentNetwork(env)
	if err != nil {
		t.Fatalf("Failed to get current network after switch: %v", err)
	}

	if currentNetwork.ChainId != "11155111" || currentNetwork.Type != "evm" {
		t.Errorf("Expected current network to be Sepolia (evm, 11155111), got (%s, %s)",
			currentNetwork.Type, currentNetwork.ChainId)
	}
}
