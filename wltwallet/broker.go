package wltwallet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// tssHub is a per-operation router that owns local brokers (one per
// in-process TSS party) and optional remote brokers (one per party reached
// over the Spot network). It is the glue that replaces the old outCh /
// tssRouter / tssPartyUpdateOnly machinery.
type tssHub struct {
	mu     sync.Mutex
	local  map[string]*localBroker // keyed by *tss.PartyID.Id
	remote map[string]*spotPeer    // keyed by *tss.PartyID.Id
}

func newTssHub() *tssHub {
	return &tssHub{
		local:  make(map[string]*localBroker),
		remote: make(map[string]*spotPeer),
	}
}

// addLocal registers a new local broker for the given party and returns it.
// Must be called for every local party before any NewKeygen/NewSigning/
// NewResharing is invoked, so that outbound messages can find destinations.
func (h *tssHub) addLocal(id *tss.PartyID) *localBroker {
	b := &localBroker{
		hub:      h,
		self:     id,
		handlers: make(map[string]tss.MessageReceiver),
		pending:  make(map[string][]*tss.JsonMessage),
	}
	h.mu.Lock()
	h.local[id.Id] = b
	h.mu.Unlock()
	return b
}

// addRemote registers a remote (Spot-backed) party. Must be called before any
// TSS round starts, since the first round may broadcast to this peer.
func (h *tssHub) addRemote(p *spotPeer) {
	h.mu.Lock()
	h.remote[p.partyId.Id] = p
	h.mu.Unlock()
}

// dispatch routes an outbound message produced by a local party.
func (h *tssHub) dispatch(msg *tss.JsonMessage) error {
	h.mu.Lock()
	if msg.To != nil {
		if lb, ok := h.local[msg.To.Id]; ok {
			h.mu.Unlock()
			return lb.Receive(msg)
		}
		if rp, ok := h.remote[msg.To.Id]; ok {
			h.mu.Unlock()
			return rp.Send(msg)
		}
		h.mu.Unlock()
		return fmt.Errorf("tssHub: unknown target party %s", msg.To.Id)
	}
	locals := make([]*localBroker, 0, len(h.local))
	for id, lb := range h.local {
		if msg.From != nil && id == msg.From.Id {
			continue
		}
		locals = append(locals, lb)
	}
	remotes := make([]*spotPeer, 0, len(h.remote))
	for id, rp := range h.remote {
		if msg.From != nil && id == msg.From.Id {
			continue
		}
		remotes = append(remotes, rp)
	}
	h.mu.Unlock()

	var firstErr error
	for _, lb := range locals {
		if err := lb.Receive(msg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, rp := range remotes {
		if err := rp.Send(msg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// deliver accepts a message that arrived from outside the process (e.g. over
// Spot) and routes it to the appropriate local broker(s).
func (h *tssHub) deliver(msg *tss.JsonMessage) error {
	h.mu.Lock()
	if msg.To != nil {
		lb, ok := h.local[msg.To.Id]
		h.mu.Unlock()
		if !ok {
			return fmt.Errorf("tssHub: no local party %s", msg.To.Id)
		}
		return lb.Receive(msg)
	}
	locals := make([]*localBroker, 0, len(h.local))
	for id, lb := range h.local {
		if msg.From != nil && id == msg.From.Id {
			continue
		}
		locals = append(locals, lb)
	}
	h.mu.Unlock()

	var firstErr error
	for _, lb := range locals {
		if err := lb.Receive(msg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// localBroker is the tss.MessageBroker implementation for an in-process TSS
// party. It distinguishes outbound from inbound messages by checking whether
// msg.From matches the owning party's id.
type localBroker struct {
	hub      *tssHub
	self     *tss.PartyID
	mu       sync.Mutex
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
}

// Connect registers a handler for a given message type and flushes any
// messages that arrived before the handler was ready.
func (b *localBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()

	for _, m := range queued {
		if err := dest.Receive(m); err != nil {
			log.Printf("localBroker %s: queued delivery of %s failed: %s", b.self.Id, typ, err)
		}
	}
}

// Receive is called by the TSS protocol in two directions:
//   - outbound: msg.From is this broker's party -> route via hub
//   - inbound: msg.From is a different party -> dispatch to handler or queue
func (b *localBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From != nil && msg.From.Id == b.self.Id {
		return b.hub.dispatch(msg)
	}

	b.mu.Lock()
	handler, ok := b.handlers[msg.Type]
	if !ok {
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return handler.Receive(msg)
}

// spotPeer represents a TSS party that lives on the other end of a Spot
// connection. It knows how to perform the walletSignReshareInit handshake
// once, and how to forward outbound JsonMessages to that peer.
//
// selfId is the local Spot TargetId; set when the spotPeer is constructed
// so outbound sender paths converge on the canonical
// `<my_spot_id>/<sid>/<my_party_id>` form (CLAWDWALLET_STAGE1.md
// integration-phase decision). When empty (legacy reshare callers),
// Send falls back to the historical `/<sid>/<my_party_id>` leading-slash
// form for backwards compat — wdrone parses both.
type spotPeer struct {
	hub     *tssHub
	partyId *tss.PartyID
	info    *walletSignReshareInit
	spot    *spotlib.Client
	sid     string
	selfId  string

	stOnce sync.Once
	stErr  error
	peer   string
}

// Start performs the walletSignReshareInit handshake exactly once. Must be
// called synchronously before any TSS round starts.
//
// Joiner mode: when s.peer is already populated and s.info is nil, Start
// only registers the inbound message handler and skips the selectPeer +
// init query. The handshake is handled out-of-band — for ClawdWallet the
// walletsign session row is opened server-side and the joining party just
// needs to listen for TSS rounds addressed to <my-spot-id>/<sid>/...
//
// Retry policy: a wdrone peer can pass /ping in sub-second yet still
// hang on /init (loadShare slow, internal goroutine wedged). Without
// retry, a single bad pick produces a reshare failure for the user
// even when other wdrones in the fleet would have served the init
// promptly. Start makes up to maxInitAttempts (3) tries, re-running
// selectPeer with the previously-tried peers excluded so a retry
// never re-rolls into the same bad peer.
//
// Timeouts: a healthy reshare init completes in seconds end-to-end
// (TestEdDSALocalToRemoteReshare lands in ~2 s including spot
// connects). 0.4.57 over-corrected the 15-s ceiling up to 90 s based
// on wdrone's *internal* loadShare worst case (60 s for a slow
// phplatform DB read), then 0.4.60 stacked the peer-fallback retry on
// top — which made a hard failure take 3 × 90 s ≈ 4–5 minutes. 0.4.62
// reverts to a tight 15-s per-attempt budget: well above the ~1–2 s
// typical, short enough that a wedged wdrone surfaces fast. With the
// retry on top, a hard failure now exhausts in ~30–45 s instead of
// 4–5 min, and a single slow peer still gets routed around.
func (s *spotPeer) Start() error {
	s.stOnce.Do(func() {
		s.spot.SetHandler(s.sid, s.messageHandler)

		if s.peer != "" && s.info == nil {
			// joiner mode: peer was set explicitly, no handshake needed
			log.Printf("spotPeer joiner: sid=%s peer=%s party=%s ready", s.sid, s.peer, s.partyId.Id)
			return
		}

		buf, err := json.Marshal(s.info)
		if err != nil {
			s.stErr = err
			return
		}

		const maxInitAttempts = 3
		var tried []string
		var lastErr error
		for attempt := 1; attempt <= maxInitAttempts; attempt++ {
			peerCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			peer, err := selectPeer(peerCtx, s.spot, tried...)
			cancel()
			if err != nil {
				lastErr = fmt.Errorf("failed to select peer: %w", err)
				break
			}
			log.Printf("spotPeer init attempt %d/%d: selected %s (excluded %d)", attempt, maxInitAttempts, peer, len(tried))
			s.peer = peer

			t0 := time.Now()
			if _, err := s.spot.QueryTimeout(15*time.Second, peer+"/walletsign/"+s.sid+"/init", buf); err != nil {
				log.Printf("spotPeer init attempt %d/%d: peer %s failed after %s: %s", attempt, maxInitAttempts, peer, time.Since(t0), err)
				tried = append(tried, peer)
				lastErr = fmt.Errorf("failed to init remote: %w", err)
				continue
			}
			log.Printf("spotPeer init attempt %d/%d: peer %s succeeded in %s, ready for TSS rounds", attempt, maxInitAttempts, peer, time.Since(t0))
			lastErr = nil
			break
		}
		if lastErr != nil {
			if len(tried) > 0 {
				s.stErr = fmt.Errorf("%w (tried %d peer(s): %v)", lastErr, len(tried), tried)
			} else {
				s.stErr = lastErr
			}
		}
	})
	return s.stErr
}

// Send forwards an outbound JsonMessage over Spot to the remote party.
func (s *spotPeer) Send(msg *tss.JsonMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	tgt := s.peer + "/walletsign/" + s.sid
	if msg.To == nil {
		tgt += "/broadcast"
	} else {
		tgt += "/single"
	}
	var fromId string
	if msg.From != nil {
		fromId = msg.From.Id
	}
	// Canonical sender form (integration-phase decision):
	//   <my_spot_id>/<sid>/<my_party_id>
	// Fall back to the legacy leading-slash form when selfId is
	// unset — wdrone tolerates both. New ClawdWallet code always
	// populates selfId via the spotPeer constructor in join.go.
	var sender string
	if s.selfId != "" {
		sender = s.selfId + "/" + s.sid + "/" + fromId
	} else {
		sender = "/" + s.sid + "/" + fromId
	}

	return s.spot.SendToWithFrom(context.Background(), tgt, body, sender)
}

// messageHandler receives JSON-encoded JsonMessages from the remote peer and
// feeds them back into the hub for dispatch to local brokers.
func (s *spotPeer) messageHandler(msg *spotproto.Message) ([]byte, error) {
	if !msg.IsEncrypted() {
		return nil, nil
	}
	if len(msg.Body) == 0 {
		return nil, nil
	}

	jm := &tss.JsonMessage{}
	if err := json.Unmarshal(msg.Body, jm); err != nil {
		log.Printf("spotPeer: failed to parse JsonMessage: %s", err)
		return nil, nil
	}
	if jm.Type == "" {
		return nil, errors.New("spotPeer: empty message type")
	}

	// Diagnostics only: validate that Sender path carries the expected /walletsign/<sid>.
	if parts := strings.Split(msg.Sender, "/"); len(parts) < 3 || parts[1] != "walletsign" {
		log.Printf("spotPeer: unexpected sender format %q", msg.Sender)
	}

	if err := s.hub.deliver(jm); err != nil {
		log.Printf("spotPeer: hub delivery failed for %s: %s", jm.Type, err)
	}
	return nil, nil
}
