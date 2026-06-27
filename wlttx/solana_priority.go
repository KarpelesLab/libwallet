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
	"math/big"
	"sort"
	"time"

	"github.com/KarpelesLab/libwallet/wltnet"
)

// solanaMaxCUPrice bounds the ComputeUnitPrice (microlamports per CU)
// we will ever adopt from getRecentPrioritizationFees. A malicious or
// spiking RPC could otherwise report an arbitrarily large value which,
// paired with a CU limit up to the 1.4M per-tx ceiling, makes the
// signed priority fee approach or exceed the user's whole SOL balance
// (fee burn). The ceiling is deliberately generous: even sustained
// mainnet congestion keeps the median priority fee well under 1e6
// microlamports/CU, so 50_000_000 (50 lamports/CU) leaves several
// orders of magnitude of headroom for a legitimate "high" percentile
// while still bounding the worst case. We clamp rather than error so a
// genuinely congested network never blocks a send. A price the caller
// pins explicitly (ComputeUnitPrice) is left untouched — that's an
// informed decision, not an attacker-controlled RPC value.
const solanaMaxCUPrice uint64 = 50_000_000

// Default compute-unit limit for a basic SOL transfer. The System
// Program transfer ixn needs ~200 CU in practice; we set 1000 to
// leave headroom for ComputeBudget ixns themselves without paying
// for the 200k default Solana assigns when no limit is declared.
const solanaDefaultCULimit uint32 = 1000

// Default compute-unit limit for an SPL Token transfer. The
// `TransferChecked` ixn alone is ~300 CUs, but our SPL build
// always prepends an `AssociatedToken::CreateIdempotent` so a
// brand-new recipient gets their ATA in the same tx — that
// instruction consumes ~15,200 CUs end-to-end (allocate, init mint
// state, init owner, etc.) per mainnet simulation traces. 30,000
// gives a comfortable ~2x headroom for Token-2022 with a fee
// extension (~16-20k) without paying for the 200k Solana would
// pick by default. The 1000 default we use for native SOL is
// catastrophic here — every priority-enabled SPL transfer ran
// out of compute mid-flight on 0.4.53 with the cryptic
// "Program failed to complete" error.
const solanaSPLDefaultCULimit uint32 = 30_000

// Priority percentile selection for each PriorityLevel.
var solanaPriorityPercentile = map[string]float64{
	"low":    0.25,
	"medium": 0.50,
	"high":   0.75,
}

// solanaCULimitDefault picks the right compute-unit budget for the
// instructions the sign path will actually emit. SPL transfers
// always include an ATA CreateIdempotent prelude (~15k CUs) so the
// native 1000-CU default would run them out mid-flight — that was
// the cryptic 0.4.53 "Program failed to complete" bug.
func solanaCULimitDefault(tx *Transaction) uint32 {
	if tx != nil && tx.resolvedToken != nil {
		return solanaSPLDefaultCULimit
	}
	return solanaDefaultCULimit
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
			tx.ComputeUnitLimit = solanaCULimitDefault(tx)
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
			tx.ComputeUnitLimit = solanaCULimitDefault(tx)
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
	// Clamp the RPC-derived price to a sane ceiling so a malicious or
	// spiking node can't drive the signed priority fee toward the
	// user's whole balance.
	if price > solanaMaxCUPrice {
		price = solanaMaxCUPrice
	}
	tx.ComputeUnitPrice = price
	if tx.ComputeUnitLimit == 0 {
		tx.ComputeUnitLimit = solanaCULimitDefault(tx)
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
	// priority fee = ceil(cuLimit * cuPrice / 1_000_000), computed in
	// big.Int so a large (caller-pinned) cuLimit*cuPrice product can't
	// silently wrap a uint64 and under-report the fee to the balance
	// preflight. On overflow we saturate just below ^uint64(0), which
	// the preflight then treats as "insufficient balance" rather than
	// waving a ruinous fee through.
	num := new(big.Int).Mul(
		new(big.Int).SetUint64(uint64(tx.ComputeUnitLimit)),
		new(big.Int).SetUint64(tx.ComputeUnitPrice),
	)
	num.Add(num, big.NewInt(999_999))
	num.Quo(num, big.NewInt(1_000_000))
	maxPriority := ^uint64(0) - baseFee
	priority := maxPriority
	if num.IsUint64() {
		if u := num.Uint64(); u < maxPriority {
			priority = u
		}
	}
	return baseFee + priority
}
