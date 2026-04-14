package wltwc

// Manager is the top-level coordinator for a libwallet WalletConnect v2
// integration. One per env.
//
// Responsibilities:
//
//   - Own the relay WebSocket connection (reconnect with backoff on drop).
//   - On startup, reload every non-disconnected session from SQL and
//     re-subscribe to its topic.
//   - Decrypt inbound messages with the stored symKey and classify them
//     as propose / propose-response / settle / request / event / delete.
//   - For propose / request, emit a host-visible event so the Dart
//     approval UI can act; for settle / event / delete, update local
//     state directly.
//   - Send encrypted responses on top of the same envelope protocol.
//
// Approval itself happens host-side — the Manager exposes `approve /
// reject / respond` methods the API layer calls on user decision. This
// avoids a two-way dep between wltwc and wltbase.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/xuid"
)

// Manager lives for the lifetime of the libwallet env.
type Manager struct {
	env wltintf.Env
	log *slog.Logger

	mu        sync.Mutex
	relay     *RelayClient
	relayCtx  context.Context
	relayStop context.CancelFunc

	// proposalsByPairing maps pairing topic -> pending proposal waiting
	// for user approval (keyed so the API can approve/reject by topic).
	proposalsByPairing map[string]*pendingProposal

	// pendingRequests tracks in-flight session_request ids so a later
	// WalletConnect:respondSession can find the right envelope target.
	pendingRequests map[int64]*pendingSessionRequest
}

type pendingProposal struct {
	PairingTopic string
	ProposalID   int64
	Proposer     map[string]any // metadata
	Proposal     map[string]any // full wc_sessionPropose payload, for building reply
	SymKey       []byte         // pairing symKey, used to reply on pairing topic
}

type pendingSessionRequest struct {
	SessionTopic string
	ID           int64
	Method       string
	ChainID      string
	Params       any
}

// NewManager returns a Manager attached to env. Call Start(relayURL, projectID)
// to actually connect.
func NewManager(env wltintf.Env) *Manager {
	return &Manager{
		env:                env,
		log:                slog.Default().With("component", "wc.manager"),
		proposalsByPairing: make(map[string]*pendingProposal),
		pendingRequests:    make(map[int64]*pendingSessionRequest),
	}
}

// Start opens a relay connection and replays subscriptions for every
// non-disconnected session.
func (m *Manager) Start(relayURL, projectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relay != nil {
		return errors.New("WalletConnect already started")
	}
	priv, _ := m.env.ConfigGet("wc.relay.edPriv")
	rc, err := NewRelayClient(relayURL, projectID, priv)
	if err != nil {
		return err
	}
	// Persist the key so restarts keep the same did:key identity.
	_ = m.env.ConfigSet("wc.relay.edPriv", []byte(rc.PrivateKey()))

	ctx, cancel := context.WithCancel(context.Background())
	m.relay = rc
	m.relayCtx = ctx
	m.relayStop = cancel

	go m.runRelay()
	go m.dispatchLoop()
	return nil
}

// Stop closes the relay connection; outstanding proposals/requests are
// dropped (the dApp will retry or time out).
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relayStop != nil {
		m.relayStop()
	}
	if m.relay != nil {
		m.relay.Close()
	}
	m.relay = nil
	m.relayStop = nil
}

func (m *Manager) runRelay() {
	// Simple exponential backoff on reconnect.
	backoff := time.Second
	for {
		select {
		case <-m.relayCtx.Done():
			return
		default:
		}

		if err := m.relay.Start(m.relayCtx); err != nil {
			m.log.Info("relay disconnected", "err", err)
		}
		select {
		case <-m.relayCtx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		// On each reconnect, re-subscribe to all stored sessions.
		if err := m.resubscribeAll(); err != nil {
			m.log.Info("resubscribe failed", "err", err)
		}
	}
}

// resubscribeAll subscribes to every non-disconnected session's topic.
// Called once on startup and on every reconnect.
func (m *Manager) resubscribeAll() error {
	sessions, err := allNonClosedSessions(m.env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	for _, s := range sessions {
		if time.Now().After(s.Expiry) && !s.Expiry.IsZero() {
			continue
		}
		if _, err := m.relay.Subscribe(ctx, s.Topic); err != nil {
			m.log.Info("resubscribe topic failed", "topic", s.Topic, "err", err)
		}
	}
	return nil
}

func (m *Manager) dispatchLoop() {
	for {
		select {
		case <-m.relayCtx.Done():
			return
		case ev, ok := <-m.relay.Events:
			if !ok {
				return
			}
			m.handleIncoming(ev)
		}
	}
}

// handleIncoming decrypts one relay message and dispatches per WC method.
func (m *Manager) handleIncoming(ev RelayEvent) {
	s, err := sessionByTopic(m.env, ev.Topic)
	if err != nil || s == nil {
		m.log.Info("inbound for unknown topic", "topic", ev.Topic)
		return
	}
	sym, err := s.symKeyBytes()
	if err != nil {
		m.log.Info("symkey decode failed", "topic", ev.Topic, "err", err)
		return
	}
	selfPriv, _ := s.selfPrivBytes()
	plain, _, err := openEnvelope(sym, selfPriv, []byte(ev.Message))
	if err != nil {
		m.log.Info("envelope open failed", "topic", ev.Topic, "err", err)
		return
	}
	var rpc struct {
		ID     int64           `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(plain, &rpc); err != nil {
		m.log.Info("rpc decode failed", "err", err, "payload", string(plain))
		return
	}

	switch {
	case rpc.Method == "wc_sessionPropose":
		m.handleSessionPropose(s, rpc.ID, rpc.Params, sym)
	case rpc.Method == "wc_sessionSettle":
		m.handleSessionSettle(s, rpc.ID, rpc.Params)
	case rpc.Method == "wc_sessionRequest":
		m.handleSessionRequest(s, rpc.ID, rpc.Params)
	case rpc.Method == "wc_sessionDelete":
		m.handleSessionDelete(s)
	case rpc.Method == "wc_sessionEvent" || rpc.Method == "wc_sessionPing":
		// ack only
		m.ack(s, rpc.ID)
	case rpc.Result != nil || rpc.Error != nil:
		// Response to something we sent. For v1 we don't correlate; log.
		m.log.Debug("rpc response", "id", rpc.ID, "result", string(rpc.Result), "err", rpc.Error)
	default:
		m.log.Info("unknown wc method", "method", rpc.Method)
	}
}

// handleSessionPropose stashes the proposal and emits a host event so the
// approval UI can show it. The actual approve/reject happens via the API.
func (m *Manager) handleSessionPropose(s *wcSession, id int64, params json.RawMessage, pairingSym []byte) {
	var proposal map[string]any
	if err := json.Unmarshal(params, &proposal); err != nil {
		m.log.Info("sessionPropose decode", "err", err)
		return
	}
	var proposer map[string]any
	if p, ok := proposal["proposer"].(map[string]any); ok {
		proposer, _ = p["metadata"].(map[string]any)
	}
	pp := &pendingProposal{
		PairingTopic: s.Topic,
		ProposalID:   id,
		Proposer:     proposer,
		Proposal:     proposal,
		SymKey:       pairingSym,
	}
	m.mu.Lock()
	m.proposalsByPairing[s.Topic] = pp
	m.mu.Unlock()

	// Update session state.
	s.State = "proposed"
	s.PeerMetadata = proposer
	_ = s.save(m.env)

	wltutil.BroadcastMsg("wc_session_propose", map[string]any{
		"pairingTopic": s.Topic,
		"proposalId":   id,
		"proposer":     proposer,
		"proposal":     proposal,
	})
}

// ApproveProposal completes a pending wc_sessionPropose: generates session
// keys, derives the session topic, sends wc_sessionSettle, and sends the
// proposeResponse on the pairing topic.
//
// `accounts` is a CAIP-10 formatted list (e.g. "eip155:1:0xabc…"). See:
// https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces
func (m *Manager) ApproveProposal(pairingTopic string, accounts []string, methods, events []string) error {
	m.mu.Lock()
	pp, ok := m.proposalsByPairing[pairingTopic]
	if !ok {
		m.mu.Unlock()
		return errors.New("no pending proposal on that pairing topic")
	}
	delete(m.proposalsByPairing, pairingTopic)
	m.mu.Unlock()

	// Extract proposer's X25519 publicKey.
	proposer, _ := pp.Proposal["proposer"].(map[string]any)
	peerPubHex, _ := proposer["publicKey"].(string)
	peerPub, err := hexOrB64Decode(peerPubHex)
	if err != nil {
		return fmt.Errorf("proposer pubKey: %w", err)
	}

	selfPriv, selfPub, err := newX25519KeyPair()
	if err != nil {
		return err
	}
	sessionSym, err := deriveSymKey(selfPriv, peerPub)
	if err != nil {
		return err
	}
	sessionTopic := topicFromDerivedKey(sessionSym)

	// Build namespaces. For v1 we accept whatever the proposal asked for
	// under required+optional and attach our account list to each of
	// them. Callers can pre-filter by passing only the subset they
	// want to approve.
	namespaces := buildNamespaces(pp.Proposal, accounts, methods, events)

	// Subscribe to the session topic first so we don't miss the peer's
	// settle-ACK.
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	if _, err := m.relay.Subscribe(ctx, sessionTopic); err != nil {
		return fmt.Errorf("subscribe session topic: %w", err)
	}

	// Persist the new session.
	newSess := &wcSession{
		Id:           xuid.New("wcs"),
		Topic:        sessionTopic,
		PairingTopic: pp.PairingTopic,
		State:        "active",
		SymKey:       b64url(sessionSym),
		SelfPriv:     b64url(selfPriv),
		SelfPub:      b64url(selfPub),
		PeerPub:      b64url(peerPub),
		PeerMetadata: pp.Proposer,
		Namespaces:   namespaces,
		Expiry:       time.Now().Add(7 * 24 * time.Hour),
	}
	if err := newSess.save(m.env); err != nil {
		return err
	}

	// Send wc_sessionSettle on the session topic.
	settlePayload := map[string]any{
		"relay":          map[string]any{"protocol": "irn"},
		"controller": map[string]any{
			"publicKey": hexLower(selfPub),
			"metadata": map[string]any{
				"name":        "libwallet",
				"description": "",
				"url":         "",
				"icons":       []string{},
			},
		},
		"namespaces":        namespaces,
		"requiredNamespaces": pp.Proposal["requiredNamespaces"],
		"optionalNamespaces": pp.Proposal["optionalNamespaces"],
		"sessionProperties":  pp.Proposal["sessionProperties"],
		"expiry":             newSess.Expiry.Unix(),
	}
	settleRPC := map[string]any{
		"id":      time.Now().UnixNano(),
		"jsonrpc": "2.0",
		"method":  "wc_sessionSettle",
		"params":  settlePayload,
	}
	if err := m.publishRPC(ctx, sessionTopic, sessionSym, settleRPC, tagSessionSettle); err != nil {
		return fmt.Errorf("publish sessionSettle: %w", err)
	}

	// Send proposeResponse on the PAIRING topic.
	responseRPC := map[string]any{
		"id":      pp.ProposalID,
		"jsonrpc": "2.0",
		"result": map[string]any{
			"relay":     map[string]any{"protocol": "irn"},
			"responderPublicKey": hexLower(selfPub),
		},
	}
	if err := m.publishRPC(ctx, pp.PairingTopic, pp.SymKey, responseRPC, tagSessionSettle); err != nil {
		return fmt.Errorf("publish proposeResponse: %w", err)
	}

	wltutil.BroadcastMsg("wc_session_active", map[string]any{
		"topic":        sessionTopic,
		"pairingTopic": pp.PairingTopic,
		"peerMetadata": pp.Proposer,
		"namespaces":   namespaces,
	})
	return nil
}

// RejectProposal declines a wc_sessionPropose with a JSON-RPC error.
func (m *Manager) RejectProposal(pairingTopic string, code int, message string) error {
	m.mu.Lock()
	pp, ok := m.proposalsByPairing[pairingTopic]
	delete(m.proposalsByPairing, pairingTopic)
	m.mu.Unlock()
	if !ok {
		return errors.New("no pending proposal on that pairing topic")
	}
	if code == 0 {
		code = 5000
	}
	if message == "" {
		message = "User rejected"
	}
	response := map[string]any{
		"id":      pp.ProposalID,
		"jsonrpc": "2.0",
		"error":   map[string]any{"code": code, "message": message},
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	return m.publishRPC(ctx, pp.PairingTopic, pp.SymKey, response, tagSessionSettle)
}

// handleSessionSettle — peer confirms the session. We ACK and update state
// (state was already "active" on our side).
func (m *Manager) handleSessionSettle(s *wcSession, id int64, _ json.RawMessage) {
	m.ack(s, id)
}

// handleSessionRequest stashes the request and emits a host event. The
// host is expected to call RespondSession(topic, id, result) or
// RespondSessionError(topic, id, code, message).
func (m *Manager) handleSessionRequest(s *wcSession, id int64, params json.RawMessage) {
	var req struct {
		Request struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		} `json:"request"`
		ChainID string `json:"chainId"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		m.log.Info("sessionRequest decode", "err", err)
		return
	}
	var pBody any
	_ = json.Unmarshal(req.Request.Params, &pBody)

	m.mu.Lock()
	m.pendingRequests[id] = &pendingSessionRequest{
		SessionTopic: s.Topic,
		ID:           id,
		Method:       req.Request.Method,
		ChainID:      req.ChainID,
		Params:       pBody,
	}
	m.mu.Unlock()

	wltutil.BroadcastMsg("wc_session_request", map[string]any{
		"topic":        s.Topic,
		"id":           id,
		"method":       req.Request.Method,
		"params":       pBody,
		"chainId":      req.ChainID,
		"peerMetadata": s.PeerMetadata,
	})
}

// RespondSession publishes a wc_sessionRequest response.
func (m *Manager) RespondSession(topic string, id int64, result any) error {
	s, err := sessionByTopic(m.env, topic)
	if err != nil || s == nil {
		return errors.New("unknown topic")
	}
	sym, err := s.symKeyBytes()
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.pendingRequests, id)
	m.mu.Unlock()
	response := map[string]any{
		"id":      id,
		"jsonrpc": "2.0",
		"result":  result,
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	return m.publishRPC(ctx, topic, sym, response, tagSessionResponse)
}

// RespondSessionError publishes a JSON-RPC error on wc_sessionRequest.
func (m *Manager) RespondSessionError(topic string, id int64, code int, message string) error {
	s, err := sessionByTopic(m.env, topic)
	if err != nil || s == nil {
		return errors.New("unknown topic")
	}
	sym, err := s.symKeyBytes()
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.pendingRequests, id)
	m.mu.Unlock()
	if code == 0 {
		code = 5000
	}
	response := map[string]any{
		"id":      id,
		"jsonrpc": "2.0",
		"error":   map[string]any{"code": code, "message": message},
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	return m.publishRPC(ctx, topic, sym, response, tagSessionResponse)
}

// EmitSessionEvent publishes wc_sessionEvent on the given session (used
// for chainChanged / accountsChanged pushes).
func (m *Manager) EmitSessionEvent(topic, name string, data any, chainID string) error {
	s, err := sessionByTopic(m.env, topic)
	if err != nil || s == nil {
		return errors.New("unknown topic")
	}
	sym, err := s.symKeyBytes()
	if err != nil {
		return err
	}
	rpc := map[string]any{
		"id":      time.Now().UnixNano(),
		"jsonrpc": "2.0",
		"method":  "wc_sessionEvent",
		"params": map[string]any{
			"event":   map[string]any{"name": name, "data": data},
			"chainId": chainID,
		},
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	return m.publishRPC(ctx, topic, sym, rpc, tagSessionEvent)
}

// handleSessionDelete marks the session disconnected.
func (m *Manager) handleSessionDelete(s *wcSession) {
	s.State = "disconnected"
	_ = s.save(m.env)
	ctx, cancel := context.WithTimeout(m.relayCtx, 5*time.Second)
	defer cancel()
	if m.relay != nil {
		_ = m.relay.Unsubscribe(ctx, s.Topic, "") // subId tracking omitted in v1
	}
	wltutil.BroadcastMsg("wc_session_disconnect", map[string]any{"topic": s.Topic})
}

// Disconnect sends wc_sessionDelete to the peer and tears down locally.
func (m *Manager) Disconnect(topic string) error {
	s, err := sessionByTopic(m.env, topic)
	if err != nil || s == nil {
		return errors.New("unknown topic")
	}
	sym, err := s.symKeyBytes()
	if err != nil {
		return err
	}
	rpc := map[string]any{
		"id":      time.Now().UnixNano(),
		"jsonrpc": "2.0",
		"method":  "wc_sessionDelete",
		"params":  map[string]any{"code": 6000, "message": "User disconnected"},
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	_ = m.publishRPC(ctx, topic, sym, rpc, tagSessionDelete)
	m.handleSessionDelete(s)
	return nil
}

// StartPairing takes a wc:… URI, creates a pairing row, subscribes, and
// waits for the inbound wc_sessionPropose (which will fire the
// wc_session_propose host event when it arrives).
func (m *Manager) StartPairing(uri string) (topic string, err error) {
	p, err := parsePairingURI(uri)
	if err != nil {
		return "", err
	}
	pair := &wcSession{
		Id:           xuid.New("wcs"),
		Topic:        p.Topic,
		PairingTopic: p.Topic,
		State:        "pairing",
		SymKey:       b64url(p.SymKey),
		Expiry:       p.Expiry,
	}
	if err := pair.save(m.env); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(m.relayCtx, 10*time.Second)
	defer cancel()
	if m.relay == nil {
		return "", errors.New("relay not started")
	}
	if _, err := m.relay.Subscribe(ctx, p.Topic); err != nil {
		return "", fmt.Errorf("subscribe pairing: %w", err)
	}
	return p.Topic, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func (m *Manager) publishRPC(ctx context.Context, topic string, sym []byte, rpc map[string]any, tag int) error {
	buf, _ := json.Marshal(rpc)
	env, err := sealType0(sym, buf)
	if err != nil {
		return err
	}
	return m.relay.Publish(ctx, topic, env, tag, irnDefaultTTL)
}

func (m *Manager) ack(s *wcSession, id int64) {
	sym, _ := s.symKeyBytes()
	rpc := map[string]any{"id": id, "jsonrpc": "2.0", "result": true}
	ctx, cancel := context.WithTimeout(m.relayCtx, 5*time.Second)
	defer cancel()
	_ = m.publishRPC(ctx, s.Topic, sym, rpc, tagSessionResponse)
}

// buildNamespaces merges the proposer's required+optional namespaces with
// the wallet's approved accounts/methods/events. v1: apply accounts to
// every namespace the proposer asked for, and echo back the requested
// method/event lists (filtered by the explicit `methods`/`events` args if
// given).
func buildNamespaces(proposal map[string]any, accounts, methods, events []string) map[string]any {
	result := make(map[string]any)
	for _, k := range []string{"requiredNamespaces", "optionalNamespaces"} {
		ns, _ := proposal[k].(map[string]any)
		for name, desc := range ns {
			if _, already := result[name]; already {
				continue
			}
			dmap, _ := desc.(map[string]any)
			reqMethods, _ := dmap["methods"].([]any)
			reqEvents, _ := dmap["events"].([]any)
			reqChains, _ := dmap["chains"].([]any)

			nsAccounts := accountsForNamespace(accounts, name, reqChains)
			result[name] = map[string]any{
				"accounts": nsAccounts,
				"methods":  mergeStringList(reqMethods, methods),
				"events":   mergeStringList(reqEvents, events),
				"chains":   reqChains,
			}
		}
	}
	return result
}

func accountsForNamespace(accounts []string, ns string, chains []any) []string {
	out := make([]string, 0, len(accounts))
	prefix := ns + ":"
	for _, a := range accounts {
		if strings.HasPrefix(a, prefix) {
			out = append(out, a)
		}
	}
	return out
}

func mergeStringList(requested []any, allowed []string) []string {
	if len(allowed) == 0 {
		// No filter — echo requested.
		out := make([]string, 0, len(requested))
		for _, v := range requested {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, v := range requested {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if _, ok := allowedSet[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

func hexOrB64Decode(s string) ([]byte, error) {
	// WC proposer publicKey is lowercase hex.
	if b, err := hexDecode(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid key encoding")
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := parseHexByte(s[i*2], s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func parseHexByte(hi, lo byte) (byte, error) {
	f := func(c byte) (byte, error) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', nil
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, nil
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, nil
		}
		return 0, errors.New("non-hex")
	}
	h, err := f(hi)
	if err != nil {
		return 0, err
	}
	l, err := f(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexLower(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0xf]
	}
	return string(out)
}
