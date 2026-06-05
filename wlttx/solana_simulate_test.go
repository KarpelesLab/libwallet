package wlttx

import (
	"context"
	"testing"
)

// resolveComputeUnitLimitViaSimulation returns 0 when there's no
// reason to emit a ComputeBudget instruction at all — native SOL,
// no priority opt-in, no token. That preserves the legacy
// 3-account layout buildSOLTransferMessage produces when both CU
// values are zero, and lets Solana apply its 200k default.
func TestResolveComputeUnitLimitViaSimulation_SkipsWhenNoCBWanted(t *testing.T) {
	tx := &Transaction{}
	// nil network and a panicking buildMessage prove no RPC and no
	// build are attempted on the skip path.
	got := resolveComputeUnitLimitViaSimulation(context.Background(), nil, tx,
		func() []byte { t.Fatal("should not build when skipping"); return nil })
	if got != 0 {
		t.Errorf("got %d, want 0 when no CB is wanted", got)
	}
}

// The headroom policy adds the larger of "+1000 CUs" or "+10%" on
// top of the simulated unitsConsumed, never lowers a caller-pinned
// ceiling, and caps at Solana's 1.4M per-tx maximum. Pin the math
// across the boundary cases so a regression in either the additive
// floor or the proportional headroom fails loud.
func TestApplySolanaCUHeadroom(t *testing.T) {
	cases := []struct {
		name   string
		units  uint64
		pinned uint32
		want   uint32
	}{
		// 1000-absolute headroom dominates at small unit counts.
		{"tiny tx: additive floor wins", 200, 0, 1200},
		// 10% headroom dominates at moderate sizes.
		// 15_273 * 1.1 = 16_800.3 → 16_800. The user's real USDT
		// transfer landed here, the 0.4.53 bug was returning 1000.
		{"mid tx: 10% wins (user's exact USDT tx)", 15_273, 0, 16_800},
		// 100k * 1.1 = 110k vs 100k + 1000 = 101k → 110k wins.
		{"large tx: 10% wins", 100_000, 0, 110_000},
		// Caller-pinned cap is honoured even when sim says lower.
		{"pinned > computed: pinned wins", 5_000, 50_000, 50_000},
		// Pinned lower than computed: computed wins (we never
		// undershoot the simulator's measurement).
		{"pinned < computed: computed wins", 5_000, 1_000, 6_000},
		// Solana caps a transaction at 1.4M CUs.
		{"saturate at 1.4M cap", 2_000_000, 0, 1_400_000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applySolanaCUHeadroom(c.units, c.pinned)
			if got != c.want {
				t.Errorf("units=%d pinned=%d: got=%d want=%d", c.units, c.pinned, got, c.want)
			}
		})
	}
}
