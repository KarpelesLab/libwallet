package wlttest

// LookupTokenByMint integration tests — used by the Solana asset-list
// enrichment path in wltbase/asset.go.

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttoken"
)

func TestLookupTokenByMint(t *testing.T) {
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
	solana, err := wltnet.NetworkById(env, wltnet.NetworkIdForTypeAndChainId("solana", "mainnet"))
	if err != nil {
		t.Fatalf("look up solana network: %v", err)
	}

	const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

	// Not-yet-inserted lookup returns (nil, nil) — distinguishes from
	// a real error so callers can branch on "not found" cheaply.
	got, err := wlttoken.LookupTokenByMint(env, solana.Id, usdcMint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil before insert, got %v", got)
	}

	// Insert via EnsureToken and confirm LookupTokenByMint returns it.
	if _, err := wlttoken.EnsureToken(env, solana.Id, usdcMint, "USDC", "USD Coin", 6, ""); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	got, err = wlttoken.LookupTokenByMint(env, solana.Id, usdcMint)
	if err != nil {
		t.Fatalf("unexpected error after insert: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil after insert")
	}
	if got.GetSymbol() != "USDC" {
		t.Errorf("symbol = %q, want USDC", got.GetSymbol())
	}
	if got.GetName() != "USD Coin" {
		t.Errorf("name = %q, want USD Coin", got.GetName())
	}

	// Defensive: empty inputs return (nil, nil), not a panic.
	if got, _ := wlttoken.LookupTokenByMint(env, nil, usdcMint); got != nil {
		t.Errorf("expected nil network -> nil token, got %v", got)
	}
	if got, _ := wlttoken.LookupTokenByMint(env, solana.Id, ""); got != nil {
		t.Errorf("expected empty address -> nil token, got %v", got)
	}
}
