package wlttx

// Solana priority-fee resolution.
//
// Callers can opt into a priority fee either explicitly (set
// ComputeUnitPrice directly) or by setting PriorityLevel to "low",
// "medium", or "high" and letting Validate pick a percentile of the
// recent on-chain prioritization fees. "none" disables ComputeBudget
// entirely; an empty PriorityLevel with no explicit price preserves
// the legacy 5000-lamport flat-fee behaviour.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/KarpelesLab/libwallet/wltnet"
)

// Default compute-unit limit for a basic SOL transfer. The System
// Program transfer ixn needs ~200 CU in practice; we set 1000 to
// leave headroom for ComputeBudget ixns themselves without paying
// for the 200k default Solana assigns when no limit is declared.
const solanaDefaultCULimit uint32 = 1000

// Priority percentile selection for each PriorityLevel.
var solanaPriorityPercentile = map[string]float64{
	"low":    0.25,
	"medium": 0.50,
	"high":   0.75,
}

// resolveSolanaPriority fills ComputeUnitLimit + ComputeUnitPrice on
// tx based on PriorityLevel, without overwriting values the caller
// set explicitly. Safe to call on non-priority transactions (returns
// nil without side effects).
func resolveSolanaPriority(n *wltnet.Network, tx *Transaction) error {
	switch tx.PriorityLevel {
	case "":
		// Caller didn't opt in. If they did pin a specific
		// price (via ComputeUnitPrice), make sure we have a
		// limit to pair with it.
		if tx.ComputeUnitPrice > 0 && tx.ComputeUnitLimit == 0 {
			tx.ComputeUnitLimit = solanaDefaultCULimit
		}
		return nil
	case "none":
		// Explicit opt-out — strip any leftover values.
		tx.ComputeUnitLimit = 0
		tx.ComputeUnitPrice = 0
		return nil
	case "low", "medium", "high":
		// fall through
	default:
		return fmt.Errorf("invalid PriorityLevel %q (want none|low|medium|high)", tx.PriorityLevel)
	}

	// Caller pinned a price — respect it. Just make sure we
	// have a compute limit set.
	if tx.ComputeUnitPrice > 0 {
		if tx.ComputeUnitLimit == 0 {
			tx.ComputeUnitLimit = solanaDefaultCULimit
		}
		return nil
	}

	// Query recent fees and pick a percentile.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	price, err := solanaRecentPrioritizationFee(ctx, n, solanaPriorityPercentile[tx.PriorityLevel])
	if err != nil {
		// Network hiccup — don't block the tx. Caller still
		// sees no ComputeBudget (same as legacy) and pays the
		// flat 5000 lamport fee.
		return nil
	}
	tx.ComputeUnitPrice = price
	if tx.ComputeUnitLimit == 0 {
		tx.ComputeUnitLimit = solanaDefaultCULimit
	}
	return nil
}

// solanaRecentPrioritizationFee queries getRecentPrioritizationFees
// and returns the given percentile of the non-zero fees (in
// microlamports per CU). Returns 0 when the recent window contains
// only zero fees (network not congested).
func solanaRecentPrioritizationFee(ctx context.Context, n *wltnet.Network, percentile float64) (uint64, error) {
	raw, err := n.DoRPCCtx(ctx, "getRecentPrioritizationFees", []string{})
	if err != nil {
		return 0, err
	}
	var rows []struct {
		Slot              uint64 `json:"slot"`
		PrioritizationFee uint64 `json:"prioritizationFee"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return 0, fmt.Errorf("parse getRecentPrioritizationFees: %w", err)
	}
	fees := make([]uint64, 0, len(rows))
	for _, r := range rows {
		if r.PrioritizationFee > 0 {
			fees = append(fees, r.PrioritizationFee)
		}
	}
	if len(fees) == 0 {
		return 0, nil
	}
	sort.Slice(fees, func(i, j int) bool { return fees[i] < fees[j] })
	idx := int(percentile * float64(len(fees)))
	if idx >= len(fees) {
		idx = len(fees) - 1
	}
	return fees[idx], nil
}

// solanaFeeLamports returns the total fee for tx in lamports:
// 5000 base signature fee plus ceil(cuLimit * cuPrice / 1_000_000)
// lamports of priority fee. Zero cuLimit/cuPrice collapses to 5000.
func solanaFeeLamports(tx *Transaction) uint64 {
	const baseFee uint64 = 5000
	if tx.ComputeUnitLimit == 0 || tx.ComputeUnitPrice == 0 {
		return baseFee
	}
	// priority fee = ceil(cuLimit * cuPrice / 1_000_000)
	num := uint64(tx.ComputeUnitLimit) * tx.ComputeUnitPrice
	priority := num / 1_000_000
	if num%1_000_000 != 0 {
		priority++
	}
	return baseFee + priority
}
