package wltswap

// Offline tests for the OKX adapter — no `Crypto/Okx:*` round trip.
// The Quote() / Execute() paths go through rest.Apply which is not
// reachable without a live klb backend, so the tests here exercise
// the parsing + math helpers in isolation. Adding HTTP-level tests
// requires wiring an httptest-backed rest stub; defer until the
// klb-side surface stabilises.

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/KarpelesLab/libwallet/wltnet"
)

func TestOkxChainIndexFor(t *testing.T) {
	cases := []struct {
		net     *wltnet.Network
		want    string
		wantErr bool
	}{
		{&wltnet.Network{Type: "solana", ChainId: "mainnet"}, "501", false},
		{&wltnet.Network{Type: "solana", ChainId: "mainnet-beta"}, "501", false},
		{&wltnet.Network{Type: "solana", ChainId: ""}, "501", false},
		{&wltnet.Network{Type: "solana", ChainId: "devnet"}, "103", false},
		{&wltnet.Network{Type: "solana", ChainId: "testnet"}, "", true},
		{&wltnet.Network{Type: "evm", ChainId: "1"}, "1", false},
		{&wltnet.Network{Type: "evm", ChainId: "8453"}, "8453", false},
		{&wltnet.Network{Type: "evm", ChainId: ""}, "", true},
		{&wltnet.Network{Type: "bitcoin", ChainId: "main"}, "", true},
	}
	for _, c := range cases {
		got, err := okxChainIndexFor(c.net)
		if c.wantErr {
			if err == nil {
				t.Errorf("okxChainIndexFor(%+v) err=nil, want error", c.net)
			}
			continue
		}
		if err != nil {
			t.Errorf("okxChainIndexFor(%+v) err=%v", c.net, err)
			continue
		}
		if got != c.want {
			t.Errorf("okxChainIndexFor(%+v) = %q, want %q", c.net, got, c.want)
		}
	}
}

func TestOkxTokenAddrFor(t *testing.T) {
	sol := &wltnet.Network{Type: "solana", ChainId: "mainnet"}
	eth := &wltnet.Network{Type: "evm", ChainId: "1"}
	cases := []struct {
		net  *wltnet.Network
		in   string
		want string
	}{
		{sol, "", okxSolanaNativeSentinel},
		{sol, "NATIVE", okxSolanaNativeSentinel},
		{sol, "solana.mainnet.NATIVE", okxSolanaNativeSentinel},
		{sol, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		{sol, "solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		{eth, "", okxEVMNativeSentinel},
		{eth, "NATIVE", okxEVMNativeSentinel},
		{eth, "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48", "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48"},
		{eth, "evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48", "0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48"},
	}
	for _, c := range cases {
		got := okxTokenAddrFor(c.net, c.in)
		if got != c.want {
			t.Errorf("okxTokenAddrFor(%s, %q) = %q, want %q", c.net.Type, c.in, got, c.want)
		}
	}
}

// V6 /swap takes the slippage in percent units, not the V5 fraction.
// 50bps → "0.5" (was "0.005" under V5).
func TestOkxSlippagePercent(t *testing.T) {
	cases := map[uint16]string{
		0:    "0.5", // bps==0 → DefaultSlippageBps (50) → "0.5"
		50:   "0.5",
		100:  "1",
		500:  "5",
		1000: "10",
	}
	for in, want := range cases {
		got := okxSlippagePercent(in)
		if got != want {
			t.Errorf("okxSlippagePercent(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestOkxIsNativeEVMInput(t *testing.T) {
	cases := map[string]bool{
		"":                   true,
		"NATIVE":             true,
		"native":             true,
		okxEVMNativeSentinel: true,
		"evm.1.NATIVE":       true,
		"0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48": false,
		"evm.1.0xA0b86991":                           false,
	}
	for in, want := range cases {
		got := okxIsNativeEVMInput(in)
		if got != want {
			t.Errorf("okxIsNativeEVMInput(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOkxNativeDecimals(t *testing.T) {
	if got := okxNativeDecimals(&wltnet.Network{Type: "solana"}); got != 9 {
		t.Errorf("solana decimals = %d, want 9", got)
	}
	if got := okxNativeDecimals(&wltnet.Network{Type: "evm", CurrencyDecimals: 6}); got != 6 {
		t.Errorf("evm CurrencyDecimals=6 → %d, want 6", got)
	}
}

// TestOkxQuoteEntryDecode validates that a recorded V6
// Crypto/Okx:quote inner entry decodes into the wire struct with
// every field the adapter consumes. V6 uses `chainIndex`,
// `priceImpactPercent`, and a flat per-hop `dexRouterList`.
func TestOkxQuoteEntryDecode(t *testing.T) {
	raw := []byte(`{
		"chainIndex":"501",
		"swapMode":"exactIn",
		"contextSlot":25158299,
		"router":"So111…--EPjFW…",
		"fromTokenAmount":"10000000",
		"toTokenAmount":"1995000",
		"tradeFee":"0",
		"estimateGasFee":"5000",
		"priceImpactPercent":"0.012",
		"fromToken":{"tokenContractAddress":"So11111111111111111111111111111111111111112","tokenSymbol":"SOL","decimal":"9","tokenUnitPrice":"100"},
		"toToken":{"tokenContractAddress":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","tokenSymbol":"USDC","decimal":"6","tokenUnitPrice":"1"},
		"dexRouterList":[
			{"dexProtocol":{"dexName":"Raydium","percent":"100"},"fromToken":{"tokenSymbol":"SOL"},"toToken":{"tokenSymbol":"USDT"},"fromTokenIndex":"0","toTokenIndex":"1"},
			{"dexProtocol":{"dexName":"Orca","percent":"100"},"fromToken":{"tokenSymbol":"USDT"},"toToken":{"tokenSymbol":"USDC"},"fromTokenIndex":"1","toTokenIndex":"2"}
		],
		"platformFee":{"side":"from","percent":"0.5","amount":"50000","tokenAddress":"So11111111111111111111111111111111111111112","referrer":"PLATFORM_REF"}
	}`)

	var e okxQuoteEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.ChainIndex != "501" {
		t.Errorf("ChainIndex = %q", e.ChainIndex)
	}
	if e.FromTokenAmount != "10000000" {
		t.Errorf("FromTokenAmount = %q", e.FromTokenAmount)
	}
	if e.ToTokenAmount != "1995000" {
		t.Errorf("ToTokenAmount = %q", e.ToTokenAmount)
	}
	if e.PriceImpactPercent != "0.012" {
		t.Errorf("PriceImpactPercent = %q", e.PriceImpactPercent)
	}
	if e.FromToken.TokenSymbol != "SOL" {
		t.Errorf("FromToken.TokenSymbol = %q", e.FromToken.TokenSymbol)
	}
	if e.ToToken.TokenSymbol != "USDC" {
		t.Errorf("ToToken.TokenSymbol = %q", e.ToToken.TokenSymbol)
	}
	if len(e.DexRouterList) != 2 {
		t.Fatalf("DexRouterList len = %d, want 2: %+v", len(e.DexRouterList), e.DexRouterList)
	}
	if e.DexRouterList[0].DexProtocol.DexName != "Raydium" {
		t.Errorf("DexRouterList[0].DexProtocol.DexName = %q", e.DexRouterList[0].DexProtocol.DexName)
	}
	if e.PlatformFee == nil || e.PlatformFee.Side != "from" {
		t.Fatalf("PlatformFee missing or wrong side: %+v", e.PlatformFee)
	}

	// Route flattening: two hops, one per dexRouterList entry. Per-hop
	// symbols come from the entry's own tokens; share is the entry's
	// dexProtocol.percent expressed as a fraction.
	route := okxBuildRoute(e.DexRouterList, "SOL", "USDC")
	if len(route) != 2 {
		t.Fatalf("route len = %d, want 2", len(route))
	}
	if route[0].Venue != "Raydium" || route[0].Share < 0.99 || route[0].Share > 1.01 {
		t.Errorf("route[0] = %+v, want Raydium 1.0", route[0])
	}
	if route[0].InSymbol != "SOL" || route[0].OutSymbol != "USDT" {
		t.Errorf("route[0] symbols = %s→%s, want SOL→USDT", route[0].InSymbol, route[0].OutSymbol)
	}
	if route[1].Venue != "Orca" || route[1].InSymbol != "USDT" || route[1].OutSymbol != "USDC" {
		t.Errorf("route[1] = %+v, want Orca USDT→USDC", route[1])
	}
}

// TestOkxApplyPlatformFee covers the server-side platformFee echo
// landing on Quote.FeeBps + Quote.ReferralFee for the UI's
// "Platform fee" row.
func TestOkxApplyPlatformFee(t *testing.T) {
	req := &QuoteRequest{
		TokenIn:  TokenRef{Address: "NATIVE", Symbol: "SOL", Decimals: 9},
		TokenOut: TokenRef{Address: "EPjFW", Symbol: "USDC", Decimals: 6},
	}
	q := &Quote{}
	okxApplyPlatformFee(q, &okxPlatformFee{
		Side:    "from",
		Percent: "0.5",
		Amount:  "50000",
	}, req)
	if q.FeeBps != 50 {
		t.Errorf("FeeBps = %d, want 50 (0.5%% → 50bps)", q.FeeBps)
	}
	if q.ReferralFee == nil || q.ReferralFee.Value().Cmp(big.NewInt(50000)) != 0 {
		t.Errorf("ReferralFee value = %+v, want 50000", q.ReferralFee)
	}
	if q.ReferralFee.Exp() != 9 {
		t.Errorf("ReferralFee exp = %d, want 9 (side=from → TokenIn decimals)", q.ReferralFee.Exp())
	}

	// side="to" → take TokenOut decimals (USDC, 6).
	q = &Quote{}
	okxApplyPlatformFee(q, &okxPlatformFee{
		Side:    "to",
		Percent: "0.5",
		Amount:  "1000",
	}, req)
	if q.ReferralFee == nil || q.ReferralFee.Exp() != 6 {
		t.Errorf("side=to ReferralFee exp = %d, want 6", q.ReferralFee.Exp())
	}

	// nil fee → no-op (no platform referrer configured for this chain).
	q = &Quote{}
	okxApplyPlatformFee(q, nil, req)
	if q.FeeBps != 0 || q.ReferralFee != nil {
		t.Errorf("nil fee should be a no-op, got FeeBps=%d ReferralFee=%+v", q.FeeBps, q.ReferralFee)
	}
}

// TestOkxSwapEntryDecode covers the V6 /swap response shape — the
// `routerResult` echo + `tx` block (with `slippagePercent` and
// `maxSpendAmount` additions) + top-level `platformFee` echo.
func TestOkxSwapEntryDecode(t *testing.T) {
	raw := []byte(`{
		"routerResult":{"chainIndex":"1","fromTokenAmount":"1000000","toTokenAmount":"2500000","priceImpactPercent":"0.04"},
		"tx":{
			"from":"0x1111111111111111111111111111111111111111",
			"to":"0x2222222222222222222222222222222222222222",
			"value":"0",
			"data":"0xabcd",
			"gas":"250000",
			"gasPrice":"30000000000",
			"maxPriorityFeePerGas":"1500000000",
			"maxSpendAmount":"",
			"minReceiveAmount":"2475000",
			"slippagePercent":"1",
			"signatureData":["sig1","sig2"]
		},
		"platformFee":{"side":"from","percent":"0.5","amount":"5000","tokenAddress":"0xUSDC","referrer":"PLATFORM_REF"}
	}`)
	var e okxSwapEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.RouterResult.ChainIndex != "1" {
		t.Errorf("RouterResult.ChainIndex = %q", e.RouterResult.ChainIndex)
	}
	if e.Tx.To != "0x2222222222222222222222222222222222222222" {
		t.Errorf("Tx.To = %q", e.Tx.To)
	}
	if e.Tx.MinReceiveAmount != "2475000" {
		t.Errorf("Tx.MinReceiveAmount = %q", e.Tx.MinReceiveAmount)
	}
	if e.Tx.SlippagePercent != "1" {
		t.Errorf("Tx.SlippagePercent = %q", e.Tx.SlippagePercent)
	}
	if len(e.Tx.SignatureData) != 2 {
		t.Errorf("Tx.SignatureData len = %d, want 2", len(e.Tx.SignatureData))
	}
	if e.PlatformFee == nil || e.PlatformFee.Referrer != "PLATFORM_REF" {
		t.Errorf("PlatformFee = %+v", e.PlatformFee)
	}
}

// TestOkxApproveEntryDecode covers the /approveTransaction response
// the EVM allowance flow reads to build the approval calldata.
func TestOkxApproveEntryDecode(t *testing.T) {
	raw := []byte(`[{"data":"0x095ea7b3","dexContractAddress":"0xRouter","gasLimit":"60000","gasPrice":"30000000000"}]`)
	var arr []okxApproveEntry
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("len = %d, want 1", len(arr))
	}
	e := arr[0]
	if e.Data != "0x095ea7b3" {
		t.Errorf("Data = %q", e.Data)
	}
	if e.DexContractAddress != "0xRouter" {
		t.Errorf("DexContractAddress = %q", e.DexContractAddress)
	}
}

// TestOkxSupportedChainDecode covers the V6 /supportedChains entry
// shape that drives the EVM approve-spender cache.
func TestOkxSupportedChainDecode(t *testing.T) {
	raw := []byte(`[{"chainIndex":"1","chainName":"Ethereum","dexTokenApproveAddress":"0xRouter"}]`)
	var arr []okxSupportedChain
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(arr) != 1 {
		t.Fatalf("len = %d, want 1", len(arr))
	}
	if arr[0].ChainIndex != "1" {
		t.Errorf("ChainIndex = %q", arr[0].ChainIndex)
	}
	if arr[0].DexTokenApproveAddress != "0xRouter" {
		t.Errorf("DexTokenApproveAddress = %q", arr[0].DexTokenApproveAddress)
	}
}

func TestOkxProviderRegistration(t *testing.T) {
	// init.go registers both providers at package load. Guards
	// against a future edit dropping a RegisterProvider without
	// noticing — Swap:availability would silently return Available=false.
	if _, ok := providers["okx_solana"]; !ok {
		t.Error("okx_solana provider not registered")
	}
	if _, ok := providers["okx_evm"]; !ok {
		t.Error("okx_evm provider not registered")
	}
	// The package must keep "OKX" as the human label.
	if got := providerDisplayLabel("okx_solana"); got != "OKX" {
		t.Errorf("providerDisplayLabel(okx_solana) = %q, want OKX", got)
	}
	if got := providerDisplayLabel("okx_evm"); got != "OKX" {
		t.Errorf("providerDisplayLabel(okx_evm) = %q, want OKX", got)
	}
}

// TestComputeAvailability_Okx exercises the OKX branch of the
// availability check: registered + chain in allowlist → available,
// chain outside the allowlist → unsupported_chain, even on a network
// type OKX otherwise covers.
func TestComputeAvailability_Okx(t *testing.T) {
	reg := map[string]Provider{
		"okx_solana": &okxSolanaProvider{},
		"okx_evm":    &okxEVMProvider{},
	}

	res := computeAvailability("solana", "mainnet", reg, "")
	if !res.Available || len(res.Providers) != 1 || res.Providers[0] != "okx_solana" {
		t.Errorf("solana mainnet: %+v", res)
	}

	res = computeAvailability("solana", "devnet", reg, "")
	if res.Available || res.Reason != "unsupported_chain" {
		t.Errorf("solana devnet expected unsupported, got %+v", res)
	}

	res = computeAvailability("evm", "1", reg, "")
	if !res.Available || len(res.Providers) != 1 || res.Providers[0] != "okx_evm" {
		t.Errorf("ethereum mainnet: %+v", res)
	}

	res = computeAvailability("evm", "999999", reg, "")
	if res.Available {
		t.Errorf("unknown chainid expected unavailable, got %+v", res)
	}

	res = computeAvailability("bitcoin", "dogecoin", reg, "")
	if res.Available || res.Reason != "unsupported_chain" {
		t.Errorf("bitcoin expected unsupported, got %+v", res)
	}
}
