package wlttest

// EnsureToken integration tests — exercises the helper that wltswap calls
// after a successful swap to surface previously-unknown TokenOut entries
// in the user's token list. Runs against a real (in-memory) sqlite env so
// the table-creation + uniqueness behaviour is the same as production.

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttoken"
)

func TestEnsureToken_CreatesWhenMissingAndIsIdempotent(t *testing.T) {
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
	solana, err := wltnet.CurrentNetwork(env)
	if err != nil {
		t.Fatalf("get current network: %v", err)
	}
	if solana.Type != "solana" {
		// MakeDefaultNetworks seeds an EVM mainnet plus Solana; pick the
		// Solana entry by looking it up directly so this test doesn't
		// depend on the default-selection order.
		solana, err = wltnet.NetworkById(env, wltnet.NetworkIdForTypeAndChainId("solana", "mainnet"))
		if err != nil {
			t.Fatalf("look up solana network: %v", err)
		}
	}

	// First call creates the row.
	const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	t1, err := wlttoken.EnsureToken(env, solana.Id, usdcMint, "USDC", "USD Coin", 6, "")
	if err != nil {
		t.Fatalf("EnsureToken (first call): %v", err)
	}
	if t1.GetAddress() != usdcMint {
		t.Errorf("address = %q, want %q", t1.GetAddress(), usdcMint)
	}
	if t1.GetDecimals() != 6 {
		t.Errorf("decimals = %d, want 6", t1.GetDecimals())
	}
	if t1.GetType() != "spl-token" {
		t.Errorf("type = %q, want spl-token (validate default)", t1.GetType())
	}
	firstId := t1.Id.String()

	// Second call with same (network, address) returns the same row
	// rather than inserting a duplicate. The Symbol/Name/Decimals
	// passed on the second call are intentionally different — we want
	// to confirm EnsureToken does NOT silently update the existing
	// row when the caller supplied stale metadata.
	t2, err := wlttoken.EnsureToken(env, solana.Id, usdcMint, "ignored", "ignored", 0, "")
	if err != nil {
		t.Fatalf("EnsureToken (second call): %v", err)
	}
	if t2.Id.String() != firstId {
		t.Errorf("second call returned new id %s, expected %s", t2.Id, firstId)
	}
	if t2.GetDecimals() != 6 {
		t.Errorf("decimals leaked from second call: got %d, want 6", t2.GetDecimals())
	}
}

func TestEnsureToken_RejectsBadInput(t *testing.T) {
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

	// Nil network.
	if _, err := wlttoken.EnsureToken(env, nil, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "USDC", "", 6, ""); err == nil {
		t.Errorf("expected error for nil network, got nil")
	}

	// Empty address.
	solana, err := wltnet.NetworkById(env, wltnet.NetworkIdForTypeAndChainId("solana", "mainnet"))
	if err != nil {
		t.Fatalf("look up solana network: %v", err)
	}
	if _, err := wlttoken.EnsureToken(env, solana.Id, "", "USDC", "", 6, ""); err == nil {
		t.Errorf("expected error for empty address, got nil")
	}

	// Malformed Solana address.
	if _, err := wlttoken.EnsureToken(env, solana.Id, "not-base58!!!", "BAD", "", 6, ""); err == nil {
		t.Errorf("expected error for malformed solana address, got nil")
	}
}
