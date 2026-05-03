package wlttx

// In-memory UTXO state tracker for Bitcoin-family sends — bridges the
// gap between "tx broadcast succeeded" and "modchain reindexed past
// it". Without this, every back-to-back send fails:
//
//   1. Send #1 spends UTXO A, creates change UTXO B.
//   2. modchain still shows A as unspent (its index hasn't reorged
//      past the new mempool tx) and doesn't yet know B exists.
//   3. Send #2 picks A from modchain → bitcoin node rejects with
//      "bad-txns-inputs-missingorspent" because A is in the mempool
//      as the input of send #1.
//
// After every successful broadcast we record:
//   - the inputs that just got spent (so the next selection skips
//     them even though modchain still says "unspent")
//   - the new output(s) we own (typically the change, so we can
//     spend it right away in send #2)
//
// fetchBitcoinAllUTXOs applies this tracker to the modchain-returned
// list before coin selection sees it.
//
// Lifetime / pruning: entries TTL out after utxoTrackerTTL — by which
// time modchain should have reindexed (typical mempool-to-confirm
// is well under the TTL). Pending entries also drop the moment they
// show up in upstream (modchain caught up).
//
// Process-local state. Survives signAndSend calls within one
// libwallet process; lost on restart. After a restart, modchain's
// view is the only source of truth — which is fine, by that point
// the user has waited long enough that modchain is probably current.

import (
	"sync"
	"time"
)

// utxoTrackerTTL bounds how long a recorded spend or pending output
// can sit in the tracker. 1 hour is well past the "modchain catches
// up" window for every chain we support, while still bounded so a
// long-lived process doesn't accumulate stale entries forever.
const utxoTrackerTTL = 1 * time.Hour

type utxoTracker struct {
	mu     sync.Mutex
	byXpub map[string]*trackedXpub
}

type trackedXpub struct {
	// spent maps txo refs the wallet just sent → time we recorded it.
	spent map[string]time.Time
	// pending maps txo refs of new outputs we created (typically the
	// change) → entry (full bitcoinTxo + time we recorded it).
	pending map[string]pendingTxo
}

type pendingTxo struct {
	when time.Time
	txo  bitcoinTxo
}

// utxoTrackerInstance is the process-wide instance. Singleton because
// the bitcoin send path is small enough that one global is simpler
// than threading through a context-bound tracker.
var utxoTrackerInstance = &utxoTracker{byXpub: map[string]*trackedXpub{}}

// RecordTx commits the result of a successful broadcast: spentRefs are
// the "<txid>:<vout>" entries the tx consumed; pendingTxos are the new
// outputs we own (usually just the single change output) keyed by
// their post-broadcast txo ref. Safe to call with empty slices.
func (t *utxoTracker) RecordTx(xpub string, spentRefs []string, pendingTxos []bitcoinTxo) {
	if xpub == "" || (len(spentRefs) == 0 && len(pendingTxos) == 0) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	x, ok := t.byXpub[xpub]
	if !ok {
		x = &trackedXpub{
			spent:   map[string]time.Time{},
			pending: map[string]pendingTxo{},
		}
		t.byXpub[xpub] = x
	}
	now := time.Now()
	for _, ref := range spentRefs {
		x.spent[ref] = now
	}
	for _, p := range pendingTxos {
		if p.Txo == "" {
			continue
		}
		x.pending[p.Txo] = pendingTxo{when: now, txo: p}
	}
}

// Apply walks the modchain-returned txo list and:
//
//  1. drops entries the tracker says are spent (mempool-pending sends
//     this process did before modchain caught up)
//  2. adds in pending entries (newly created outputs from those sends
//     that modchain doesn't yet know about)
//
// Also prunes TTL-expired tracker entries and clears pending entries
// that have started showing up in upstream (modchain reindexed —
// the ground truth is there now, drop our local copy).
func (t *utxoTracker) Apply(xpub string, upstream []bitcoinTxo) []bitcoinTxo {
	if xpub == "" {
		return upstream
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	x, ok := t.byXpub[xpub]
	if !ok {
		return upstream
	}

	// Prune anything past TTL — by now modchain has reindexed and
	// its view is the source of truth.
	now := time.Now()
	for ref, when := range x.spent {
		if now.Sub(when) > utxoTrackerTTL {
			delete(x.spent, ref)
		}
	}
	for ref, p := range x.pending {
		if now.Sub(p.when) > utxoTrackerTTL {
			delete(x.pending, ref)
		}
	}

	// Filter upstream. While we're walking it, note which refs are
	// already in modchain so we can drop matching pending entries
	// after the loop.
	upstreamRefs := make(map[string]bool, len(upstream))
	out := make([]bitcoinTxo, 0, len(upstream))
	for _, u := range upstream {
		upstreamRefs[u.Txo] = true
		if _, isSpent := x.spent[u.Txo]; isSpent {
			continue
		}
		out = append(out, u)
	}

	// Append still-needed pending entries; drop the ones modchain
	// has caught up on.
	for ref, p := range x.pending {
		if upstreamRefs[ref] {
			delete(x.pending, ref)
			continue
		}
		out = append(out, p.txo)
	}

	return out
}
