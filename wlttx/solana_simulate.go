package wlttx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// solanaSimulationCUFloor is the CB limit we declare during the
// simulation pass. Has to be wide enough that the simulation
// actually runs the program to completion — Solana caps simulated
// CUs at the declared limit, so a too-tight value would itself
// trigger "Program failed to complete" and we'd learn nothing.
// 200,000 is what Solana defaults to when no CB limit is set, so
// every healthy SPL transfer comfortably fits.
const solanaSimulationCUFloor uint32 = 200_000

// solanaCUHeadroomMin / solanaCUHeadroomBPS define the headroom added
// to the simulated unitsConsumed. We take the larger of "+1000 CUs"
// and "+10%" so a tiny tx still gets meaningful slack while large txs
// scale proportionally.
const (
	solanaCUHeadroomMin uint64 = 1000
	solanaCUHeadroomBPS uint64 = 1000 // 10%
)

// solanaSimulationTimeout caps the extra RPC round trip. simulateTransaction
// usually returns in ~150ms; 5s is well above the worst case while keeping
// the failure path fast enough that callers don't notice.
const solanaSimulationTimeout = 5 * time.Second

// resolveComputeUnitLimitViaSimulation picks the tightest correct
// ComputeUnit limit for tx by simulating the draft message against
// the network and adding a small headroom on top of the reported
// unitsConsumed. Behaviour, in order:
//
//   - Caller pinned both a non-zero ComputeUnitLimit AND a
//     ComputeUnitPrice: pinning means they know what they're doing,
//     so we honour the value and skip the RPC. (Pinning only the
//     limit without a price is unusual — we still simulate there
//     because the goal is correctness.)
//   - No simulation needed at all (native SOL with no priority
//     opt-in and no resolved token): return 0 so buildSOLTransferMessage
//     skips the CB instructions entirely and Solana applies its
//     200k default.
//   - Otherwise: build the draft with a 200k cap so the program runs
//     to completion under simulation, then resize down to
//     unitsConsumed + headroom.
//
// On simulation failure (network burped, RPC reported an error, etc.)
// we fall back to:
//
//   - For SPL: solanaSPLDefaultCULimit (30k) — covers
//     TransferChecked + ATA CreateIdempotent + Token-2022 fee
//     instruction overhead with margin.
//   - For native: solanaDefaultCULimit (1000) — the existing
//     SOL-transfer ceiling.
//
// Best-effort: a failed simulation MUST NOT block a legitimate tx.
// The fallback ensures we still ship a usable CB limit.
func resolveComputeUnitLimitViaSimulation(
	ctx context.Context,
	n *wltnet.Network,
	tx *Transaction,
	buildMessage func() []byte,
) uint32 {
	// No CB instructions wanted at all? Skip — Solana picks 200k by
	// default, which is plenty for any transfer we build.
	if tx.ComputeUnitLimit == 0 && tx.ComputeUnitPrice == 0 && tx.resolvedToken == nil {
		return 0
	}

	pinned := tx.ComputeUnitLimit

	// Run simulation with a high cap so the run completes and reports
	// real unitsConsumed.
	saved := tx.ComputeUnitLimit
	tx.ComputeUnitLimit = solanaSimulationCUFloor
	draft := buildMessage()
	tx.ComputeUnitLimit = saved

	simCtx, cancel := context.WithTimeout(ctx, solanaSimulationTimeout)
	defer cancel()

	units, simErr := solanaSimulateUnitsConsumed(simCtx, n, draft)
	if simErr != nil || units == 0 {
		// Fall back to the conservative hardcoded default for the
		// branch we're on.
		fallback := solanaCULimitDefault(tx)
		if pinned > fallback {
			fallback = pinned
		}
		wltlog.Warnf("solana-send: simulation failed (%v), falling back to %d CUs", simErr, fallback)
		return fallback
	}

	chosenU32 := applySolanaCUHeadroom(units, pinned)
	wltlog.Debugf("solana-send: simulation set CB limit to %d CUs (units_consumed=%d pinned=%d)", chosenU32, units, pinned)
	return chosenU32
}

// applySolanaCUHeadroom adds a 10%-or-+1000 headroom on top of the
// simulated unitsConsumed and never lowers a caller-pinned ceiling.
// Capped at the Solana per-tx 1.4M CU maximum.
//
// Extracted so the headroom policy can be unit-tested without
// reaching for an RPC. Real-world unitsConsumed values from mainnet
// simulations are in the 200-25k range; the headroom keeps tx
// inclusion robust against runtime-jitter (account contention,
// CPI-depth-dependent CU charges) without paying for unused budget.
func applySolanaCUHeadroom(units uint64, pinned uint32) uint32 {
	const solanaMaxCU uint64 = 1_400_000
	// A malicious/buggy RPC could report an enormous unitsConsumed.
	// Clamp it to the per-tx CU ceiling BEFORE any arithmetic so that
	// units+solanaCUHeadroomMin and units*solanaCUHeadroomBPS can't
	// overflow uint64 (the latter wraps for units > ~1.8e16).
	if units > solanaMaxCU {
		units = solanaMaxCU
	}
	chosen := units + solanaCUHeadroomMin
	if pct := units + units*solanaCUHeadroomBPS/10_000; pct > chosen {
		chosen = pct
	}
	if chosen > solanaMaxCU {
		chosen = solanaMaxCU
	}
	chosenU32 := uint32(chosen)
	if pinned > chosenU32 {
		chosenU32 = pinned
	}
	return chosenU32
}

// solanaSimulateUnitsConsumed calls simulateTransaction with
// sigVerify=false and returns the reported unitsConsumed. The
// transaction is wrapped with a zero-byte placeholder signature so
// the RPC accepts the bytes regardless of whether we've signed yet.
//
// Reports an error when the RPC fails OR the simulator says the tx
// would revert — we don't want to size CU limits off a sim that
// failed mid-flight (the unitsConsumed in that case may be the
// failure point, not the success ceiling).
func solanaSimulateUnitsConsumed(ctx context.Context, n *wltnet.Network, message []byte) (uint64, error) {
	var fullTx []byte
	fullTx = append(fullTx, compactU16(1)...)
	fullTx = append(fullTx, bytes.Repeat([]byte{0}, 64)...)
	fullTx = append(fullTx, message...)

	b64 := base64.StdEncoding.EncodeToString(fullTx)
	raw, err := n.DoRPCCtx(ctx, "simulateTransaction", b64, map[string]any{
		"sigVerify":              false,
		"encoding":               "base64",
		"replaceRecentBlockhash": false,
		"commitment":             "processed",
	})
	if err != nil {
		return 0, fmt.Errorf("simulateTransaction RPC: %w", err)
	}
	var resp struct {
		Value struct {
			Err           json.RawMessage `json:"err"`
			UnitsConsumed uint64          `json:"unitsConsumed"`
			Logs          []string        `json:"logs"`
		} `json:"value"`
	}
	if jerr := json.Unmarshal(raw, &resp); jerr != nil {
		return 0, fmt.Errorf("parse simulateTransaction: %w", jerr)
	}
	if len(resp.Value.Err) > 0 && string(resp.Value.Err) != "null" {
		return 0, fmt.Errorf("simulation reported error %s (logs: %v)", string(resp.Value.Err), resp.Value.Logs)
	}
	return resp.Value.UnitsConsumed, nil
}
