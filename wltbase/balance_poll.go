package wltbase

// Background polling of the current account + network balances.
//
// Every pollInterval, fetch the same assetSnapshot the `Asset` list
// endpoint returns, compare against what we broadcast last time, and
// emit a `balances_changed` event when anything differs. The host
// controls pause/resume via Lifecycle:update — the poller is paused
// while the app reports status "background" / "paused" and resumed
// on "foreground" / "resumed" (or anything else). This avoids RPC
// traffic and battery drain while the app isn't visible.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/libwallet/wltutil"
)

const (
	balancePollInterval = 60 * time.Second
	// balancePollTimeout bounds how long one poll can block on RPCs. A
	// hung upstream is abandoned and we try again on the next tick —
	// much better than piling up goroutines or wedging the whole Go
	// runtime on process exit.
	balancePollTimeout = 15 * time.Second
)

// balancePoller holds the diff state for one env.
type balancePoller struct {
	env     *env
	mu      sync.Mutex
	lastKey string            // "<acctId>/<netId>" — resets lastAmts on switch
	lastAmt map[string]string // asset key → amount string

	paused atomic.Bool
	kick   chan struct{} // nudge the loop (on resume, on network/account switch)
	stop   chan struct{}
}

func newBalancePoller(e *env) *balancePoller {
	return &balancePoller{
		env:     e,
		lastAmt: make(map[string]string),
		kick:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
}

// run is the poll loop. Starts an immediate poll, then every
// balancePollInterval or whenever kick is signalled.
func (p *balancePoller) run() {
	// Subscribe to tx-broadcast events so the poller refreshes right
	// after a send instead of waiting up to 60 s for the next tick.
	go p.listenTxBroadcasts()

	ticker := time.NewTicker(balancePollInterval)
	defer ticker.Stop()
	p.poll()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			if p.paused.Load() {
				continue
			}
			p.poll()
		case <-p.kick:
			if p.paused.Load() {
				continue
			}
			p.poll()
		}
	}
}

// listenTxBroadcasts nudges the poller every time a tx-broadcast
// event fires (see wltintf.NotifyTxBroadcast). The channel lives for
// the lifetime of the env — stop is handled by the main loop, this
// goroutine just exits when the env shuts down and the channel closes.
func (p *balancePoller) listenTxBroadcasts() {
	if p.env == nil || p.env.em == nil {
		return
	}
	ch := p.env.em.On("tx:broadcast")
	for range ch {
		p.Nudge()
	}
}

// pause stops new polls. A pending tick/kick during pause is silently
// swallowed and the next poll happens on the next tick after resume.
func (p *balancePoller) pause() { p.paused.Store(true) }

// resume re-enables polling and schedules an immediate poll so the UI
// reflects whatever happened while backgrounded.
func (p *balancePoller) resume() {
	if p.paused.CompareAndSwap(true, false) {
		// Only trigger if we were actually paused, to avoid a no-op
		// kick when resume is called twice.
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
}

// Nudge schedules an immediate poll outside the tick cadence. Called
// after operations that change balances (network switch, connected
// account change, tx broadcast).
func (p *balancePoller) Nudge() {
	if p.paused.Load() {
		return
	}
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// poll fetches the current snapshot, diffs, and broadcasts on change.
func (p *balancePoller) poll() {
	ctx, cancel := context.WithTimeout(context.Background(), balancePollTimeout)
	defer cancel()
	snap, err := currentAssets(ctx, p.env, nil, nil)
	if err != nil {
		// Typical cause: no current account / network configured yet.
		// Silently skip; the first setCurrent will Nudge us.
		return
	}

	p.mu.Lock()
	key := ""
	if snap.Account != nil && snap.Account.Id != nil {
		key += snap.Account.Id.String()
	}
	if snap.Network != nil && snap.Network.Id != nil {
		key += "/" + snap.Network.Id.String()
	}

	newAmt := make(map[string]string, len(snap.Assets))
	for _, a := range snap.Assets {
		if a == nil || a.Amount == nil {
			continue
		}
		newAmt[a.Key] = a.Amount.String()
	}

	changed := key != p.lastKey
	if !changed {
		if len(newAmt) != len(p.lastAmt) {
			changed = true
		} else {
			for k, v := range newAmt {
				if p.lastAmt[k] != v {
					changed = true
					break
				}
			}
		}
	}
	if changed {
		p.lastKey = key
		p.lastAmt = newAmt
	}
	p.mu.Unlock()

	if changed {
		wltutil.BroadcastMsg("balances_changed", map[string]any{
			"network": snap.Network,
			"account": snap.Account,
			"assets":  snap.Assets,
		})
	}
}
