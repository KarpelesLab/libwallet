package wltnet

import (
	"testing"
)

func TestNetworkIdForTypeAndChainId(t *testing.T) {
	id1 := NetworkIdForTypeAndChainId("evm", "1")
	id2 := NetworkIdForTypeAndChainId("evm", "1")
	if id1.String() != id2.String() {
		t.Error("same inputs should produce same id")
	}

	id3 := NetworkIdForTypeAndChainId("evm", "137")
	if id1.String() == id3.String() {
		t.Error("different chain ids should produce different ids")
	}

	id4 := NetworkIdForTypeAndChainId("bitcoin", "1")
	if id1.String() == id4.String() {
		t.Error("different types should produce different ids")
	}

	if id1.Prefix != "net" {
		t.Errorf("expected prefix 'net', got %q", id1.Prefix)
	}
}

func TestNetworkString(t *testing.T) {
	n := &Network{Type: "evm", ChainId: "1"}
	if s := n.String(); s != "evm.1" {
		t.Errorf("expected evm.1, got %s", s)
	}

	n2 := &Network{Type: "bitcoin", ChainId: "bitcoin"}
	if s := n2.String(); s != "bitcoin.bitcoin" {
		t.Errorf("expected bitcoin.bitcoin, got %s", s)
	}
}

func TestNetworkNativeSymbol(t *testing.T) {
	tests := []struct {
		typ     string
		chainId string
		symbol  string
		wantErr bool
	}{
		{"bitcoin", "bitcoin", "BTC", false},
		{"bitcoin", "bitcoin-cash", "BCH", false},
		{"bitcoin", "litecoin", "LTC", false},
		{"bitcoin", "dogecoin", "DOGE", false},
		{"bitcoin", "unknown", "", true},
		{"solana", "mainnet", "SOL", false},
		{"evm", "1", "ETH", false},
		{"unknown", "", "", true},
	}
	for _, tt := range tests {
		n := &Network{Type: tt.typ, ChainId: tt.chainId}
		sym, err := n.NativeSymbol()
		if tt.wantErr {
			if err == nil {
				t.Errorf("NativeSymbol(%s/%s) expected error", tt.typ, tt.chainId)
			}
			continue
		}
		if err != nil {
			t.Errorf("NativeSymbol(%s/%s) error: %v", tt.typ, tt.chainId, err)
			continue
		}
		if sym != tt.symbol {
			t.Errorf("NativeSymbol(%s/%s) = %q, want %q", tt.typ, tt.chainId, sym, tt.symbol)
		}
	}
}

func TestNetworkTransactionUrl(t *testing.T) {
	// Solana with custom explorer
	n := &Network{Type: "solana", BlockExplorer: "https://solscan.io"}
	url := n.TransactionUrl("abc123")
	if url != "https://solscan.io/tx/abc123" {
		t.Errorf("expected https://solscan.io/tx/abc123, got %s", url)
	}

	// Solana with auto explorer
	n2 := &Network{Type: "solana", BlockExplorer: "auto"}
	url2 := n2.TransactionUrl("abc123")
	if url2 != "https://explorer.solana.com/tx/abc123" {
		t.Errorf("expected default solana explorer URL, got %s", url2)
	}

	// Solana with empty explorer
	n3 := &Network{Type: "solana", BlockExplorer: ""}
	url3 := n3.TransactionUrl("abc123")
	if url3 != "https://explorer.solana.com/tx/abc123" {
		t.Errorf("expected default solana explorer URL, got %s", url3)
	}

	// EVM with custom explorer
	n4 := &Network{Type: "evm", ChainId: "1", BlockExplorer: "https://etherscan.io"}
	url4 := n4.TransactionUrl("0xdead")
	if url4 != "https://etherscan.io/tx/0xdead" {
		t.Errorf("expected https://etherscan.io/tx/0xdead, got %s", url4)
	}

	// EVM with auto explorer (uses chain info)
	n5 := &Network{Type: "evm", ChainId: "1", BlockExplorer: "auto"}
	url5 := n5.TransactionUrl("0xdead")
	if url5 == "" {
		t.Error("expected non-empty URL for ethereum mainnet")
	}
}

func TestAddEthereumChainParameterValidate(t *testing.T) {
	// Valid
	p := &AddEthereumChainParameter{
		ChainId:   "0x1",
		ChainName: "Ethereum",
		NativeCurrency: NativeCurrencyObject{
			Symbol:   "ETH",
			Decimals: 18,
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Missing 0x prefix
	p2 := &AddEthereumChainParameter{ChainId: "1", ChainName: "Ethereum", NativeCurrency: NativeCurrencyObject{Symbol: "ETH"}}
	if err := p2.Validate(); err == nil {
		t.Error("expected error for missing 0x prefix")
	}

	// Padded hex
	p3 := &AddEthereumChainParameter{ChainId: "0x01", ChainName: "Ethereum", NativeCurrency: NativeCurrencyObject{Symbol: "ETH"}}
	if err := p3.Validate(); err == nil {
		t.Error("expected error for padded hex")
	}

	// Short chain name
	p4 := &AddEthereumChainParameter{ChainId: "0x1", ChainName: "AB", NativeCurrency: NativeCurrencyObject{Symbol: "ETH"}}
	if err := p4.Validate(); err == nil {
		t.Error("expected error for short chain name")
	}

	// Symbol too short
	p5 := &AddEthereumChainParameter{ChainId: "0x1", ChainName: "Ethereum", NativeCurrency: NativeCurrencyObject{Symbol: "E"}}
	if err := p5.Validate(); err == nil {
		t.Error("expected error for short symbol")
	}

	// Symbol too long
	p6 := &AddEthereumChainParameter{ChainId: "0x1", ChainName: "Ethereum", NativeCurrency: NativeCurrencyObject{Symbol: "TOOLONG"}}
	if err := p6.Validate(); err == nil {
		t.Error("expected error for long symbol")
	}
}

func TestAddEthereumChainParameterAsNetwork(t *testing.T) {
	p := &AddEthereumChainParameter{
		ChainId:           "0x89",
		ChainName:         "Polygon",
		NativeCurrency:    NativeCurrencyObject{Symbol: "POL", Decimals: 18},
		RPCUrls:           []string{"https://polygon-rpc.com"},
		BlockExplorerUrls: []string{"https://polygonscan.com"},
	}
	n := p.AsNetwork()
	if n.Type != "evm" {
		t.Errorf("expected type evm, got %s", n.Type)
	}
	if n.ChainId != "137" {
		t.Errorf("expected chainId 137, got %s", n.ChainId)
	}
	if n.Name != "Polygon" {
		t.Errorf("expected name Polygon, got %s", n.Name)
	}
	if n.RPC != "https://polygon-rpc.com" {
		t.Errorf("expected RPC https://polygon-rpc.com, got %s", n.RPC)
	}
	if n.BlockExplorer != "https://polygonscan.com" {
		t.Errorf("expected explorer https://polygonscan.com, got %s", n.BlockExplorer)
	}

	// Without RPC URLs
	p2 := &AddEthereumChainParameter{
		ChainId:        "0x1",
		ChainName:      "Ethereum",
		NativeCurrency: NativeCurrencyObject{Symbol: "ETH", Decimals: 18},
	}
	n2 := p2.AsNetwork()
	if n2.RPC != "auto" {
		t.Errorf("expected RPC auto, got %s", n2.RPC)
	}
}

func TestNetworkCheckBitcoin(t *testing.T) {
	tests := []struct {
		chainId string
		name    string
		symbol  string
	}{
		{"bitcoin", "Bitcoin", "BTC"},
		{"bitcoin-cash", "Bitcoin Cash", "BCH"},
		{"litecoin", "Litecoin", "LTC"},
		{"dogecoin", "Dogecoin", "DOGE"},
		{"monacoin", "Monacoin", "MONA"},
		{"namecoin", "Namecoin", "NMC"},
		{"electraproto", "Electra Protocol", "XEP"},
	}
	for _, tt := range tests {
		n := &Network{Type: "bitcoin", ChainId: tt.chainId}
		err := n.check()
		if err != nil {
			t.Errorf("check() for bitcoin/%s: %v", tt.chainId, err)
			continue
		}
		if n.Name != tt.name {
			t.Errorf("bitcoin/%s name = %q, want %q", tt.chainId, n.Name, tt.name)
		}
		if n.CurrencySymbol != tt.symbol {
			t.Errorf("bitcoin/%s symbol = %q, want %q", tt.chainId, n.CurrencySymbol, tt.symbol)
		}
	}

	// Invalid bitcoin chain
	n := &Network{Type: "bitcoin", ChainId: "invalid"}
	if err := n.check(); err == nil {
		t.Error("expected error for invalid bitcoin chain")
	}
}

func TestNetworkCheckSolana(t *testing.T) {
	n := &Network{Type: "solana", ChainId: "mainnet"}
	err := n.check()
	if err != nil {
		t.Fatalf("check() error: %v", err)
	}
	if n.Name != "Solana" {
		t.Errorf("expected name Solana, got %s", n.Name)
	}
	if n.CurrencySymbol != "SOL" {
		t.Errorf("expected symbol SOL, got %s", n.CurrencySymbol)
	}
	if n.CurrencyDecimals != 9 {
		t.Errorf("expected decimals 9, got %d", n.CurrencyDecimals)
	}
	if n.RPC != "auto" {
		t.Errorf("expected RPC auto, got %s", n.RPC)
	}

	// Devnet
	n2 := &Network{Type: "solana", ChainId: "devnet"}
	err = n2.check()
	if err != nil {
		t.Fatalf("check() error: %v", err)
	}
	if n2.Name != "Solana Devnet" {
		t.Errorf("expected name Solana Devnet, got %s", n2.Name)
	}
	if !n2.TestNet {
		t.Error("expected devnet to be TestNet")
	}

	// Invalid solana chain
	n3 := &Network{Type: "solana", ChainId: "invalid"}
	if err := n3.check(); err == nil {
		t.Error("expected error for invalid solana chain")
	}
}

func TestNetworkCheckInvalidType(t *testing.T) {
	n := &Network{Type: "invalid", ChainId: "1"}
	if err := n.check(); err == nil {
		t.Error("expected error for invalid network type")
	}
}

func TestNetworkCheckPrefilledValues(t *testing.T) {
	// Bitcoin with pre-filled values should keep them
	n := &Network{
		Type:           "bitcoin",
		ChainId:        "bitcoin",
		Name:           "My Bitcoin",
		CurrencySymbol: "MYBTC",
	}
	err := n.check()
	if err != nil {
		t.Fatalf("check() error: %v", err)
	}
	if n.Name != "My Bitcoin" {
		t.Errorf("expected pre-filled name, got %s", n.Name)
	}
	if n.CurrencySymbol != "MYBTC" {
		t.Errorf("expected pre-filled symbol, got %s", n.CurrencySymbol)
	}
}

func TestNetworkGetChainInfo(t *testing.T) {
	// EVM chain
	n := &Network{Type: "evm", ChainId: "1"}
	info, err := n.GetChainInfo()
	if err != nil {
		t.Fatalf("GetChainInfo error: %v", err)
	}
	if info.Name == "" {
		t.Error("expected non-empty chain name")
	}

	// Non-EVM
	n2 := &Network{Type: "bitcoin", ChainId: "bitcoin"}
	_, err = n2.GetChainInfo()
	if err == nil {
		t.Error("expected error for non-EVM chain")
	}

	// Invalid chain id
	n3 := &Network{Type: "evm", ChainId: "notanumber"}
	_, err = n3.GetChainInfo()
	if err == nil {
		t.Error("expected error for invalid chain id")
	}
}

func TestNetworkCache(t *testing.T) {
	id := NetworkIdForTypeAndChainId("evm", "999")

	// Should be nil initially
	n := networkFromCache(id)
	if n != nil {
		t.Error("expected nil from empty cache")
	}

	// Add to cache
	net := &Network{Id: id, Type: "evm", ChainId: "999", Name: "Test"}
	net.addToCache()

	// Should find it now
	n = networkFromCache(id)
	if n == nil {
		t.Fatal("expected non-nil from cache")
	}
	if n.Name != "Test" {
		t.Errorf("expected name Test, got %s", n.Name)
	}
}

func TestNetworkMarshalJSON(t *testing.T) {
	// Bitcoin network (non-EVM path)
	n := &Network{
		Id:             NetworkIdForTypeAndChainId("bitcoin", "bitcoin"),
		Type:           "bitcoin",
		ChainId:        "bitcoin",
		Name:           "Bitcoin",
		CurrencySymbol: "BTC",
	}
	data, err := n.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	// EVM network (with EVM_Info)
	n2 := &Network{
		Id:             NetworkIdForTypeAndChainId("evm", "1"),
		Type:           "evm",
		ChainId:        "1",
		Name:           "Ethereum",
		CurrencySymbol: "ETH",
	}
	data2, err := n2.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if len(data2) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestNetworkSave(t *testing.T) {
	// We can't actually save without an env, but we can test the ID computation path
	// by checking that AsNetwork sets it
	p := &AddEthereumChainParameter{
		ChainId:        "0x1",
		ChainName:      "Ethereum",
		NativeCurrency: NativeCurrencyObject{Symbol: "ETH", Decimals: 18},
	}
	net := p.AsNetwork()
	if net.Id == nil {
		t.Error("expected non-nil Id")
	}
	if net.Id.Prefix != "net" {
		t.Errorf("expected prefix net, got %s", net.Id.Prefix)
	}
}
