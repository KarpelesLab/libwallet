package wlttest

// Integration tests for the ERC-20 leg of Asset:list: registered EVM tokens
// are enumerated from the Token registry and their balances read via
// eth_call balanceOf. Feature reimplemented natively from Jeremy's `erc20`
// branch (bb114f1..a420635), which predates the wlttoken package.
//
// The balance leg talks to a live public Polygon RPC and skips on network
// failure rather than failing the build.

import (
	"context"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttoken"
	"github.com/KarpelesLab/libwallet/wlttx"
)

const (
	polygonUSDC = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359" // native USDC on Polygon
	// Any stable, well-known address works — balanceOf must round-trip,
	// the value itself doesn't matter. Polygon PoS bridge (ERC20 predicate).
	polygonKnownHolder = "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf"
)

func TestERC20TokensByNetworkAndBalanceOf(t *testing.T) {
	tempEnv, err := wltbase.InitTempEnv()
	if err != nil {
		t.Fatalf("InitTempEnv: %v", err)
	}
	defer wltbase.CleanupTempEnv(tempEnv)
	env, ok := tempEnv.(wltintf.Env)
	if !ok {
		t.Fatalf("env is not wltintf.Env")
	}
	if err := wltnet.MakeDefaultNetworks(env); err != nil {
		t.Fatalf("MakeDefaultNetworks: %v", err)
	}

	polygon, err := wltnet.NetworkById(env, wltnet.NetworkIdForTypeAndChainId("evm", "137"))
	if err != nil {
		t.Fatalf("polygon network not in defaults: %v", err)
	}

	// Registry leg: register USDC, enumerate it back.
	if _, err := wlttoken.EnsureToken(env, polygon.Id, polygonUSDC, "USDC", "USD Coin", 6, ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	tokens, err := wlttoken.TokensByNetwork(env, polygon.Id)
	if err != nil {
		t.Fatalf("TokensByNetwork: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 registered token, got %d", len(tokens))
	}
	tok := tokens[0]
	if tok.GetType() != "erc20" {
		t.Fatalf("expected default type erc20, got %q", tok.GetType())
	}
	if tok.GetDecimals() != 6 || tok.GetSymbol() != "USDC" {
		t.Fatalf("token metadata mismatch: decimals=%d symbol=%q", tok.GetDecimals(), tok.GetSymbol())
	}
	// Enumeration must be scoped to the network.
	eth, err := wltnet.NetworkById(env, wltnet.NetworkIdForTypeAndChainId("evm", "1"))
	if err == nil {
		other, err := wlttoken.TokensByNetwork(env, eth.Id)
		if err != nil {
			t.Fatalf("TokensByNetwork(eth): %v", err)
		}
		if len(other) != 0 {
			t.Fatalf("token leaked across networks: %d rows on eth", len(other))
		}
	}

	// Balance leg (live RPC): balanceOf must round-trip through eth_call.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bal, err := wlttx.EVMERC20BalanceOf(ctx, polygon, tok.GetAddress(), polygonKnownHolder)
	if err != nil {
		t.Skipf("live Polygon RPC unavailable: %v", err)
	}
	if bal == nil || bal.Sign() < 0 {
		t.Fatalf("invalid balance: %v", bal)
	}
	t.Logf("live balanceOf OK: %s USDC base units", bal)
}
