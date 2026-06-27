package wltwc

// WalletConnect v2 relay client.
//
// The relay is a dumb JSON-RPC pub/sub server over WebSocket. Per
// `specs.walletconnect.com/2.0/specs/servers/relay`:
//
//   irn_subscribe(topic)                -> subId
//   irn_batchSubscribe([topic])         -> [subId]
//   irn_publish(topic, msg, tag, ttl)   -> bool
//   irn_unsubscribe(topic, subId)       -> bool
//   irn_subscription(id, {topic, message, ...}) <- server notification
//
// Auth is a per-connection Ed25519 JWT carried via the `auth` query-string
// parameter (did:key encoded issuer; sub is a random nonce; aud is the
// relay URL). The relay also requires a projectId query param.
//
// Lifecycle: the client is goroutine-safe; Start() dials and runs read+
// write loops, Publish/Subscribe enqueue commands, inbound irn_subscription
// events are delivered on the Events channel. If the connection drops, the
// read loop returns; the caller can restart.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/base58"
	"github.com/gorilla/websocket"
)

const (
	// irnDefaultTTL is used when the caller does not specify one (5 min).
	irnDefaultTTL = 300

	// Tags classify messages per WC spec. We use 1100 for session_propose
	// and 1101 for its response; 1108/1109 for session_request /
	// response. A zero tag tells the relay "no classification" which is
	// fine for development; production-grade usage pins specific tags.
	tagSessionPropose  = 1100
	tagSessionSettle   = 1102
	tagSessionRequest  = 1108
	tagSessionResponse = 1109
	tagSessionEvent    = 1110
	tagSessionDelete   = 1112
)

// RelayClient is a single connection to a WalletConnect relay.
type RelayClient struct {
	URL       string
	ProjectID string

	log *slog.Logger

	// Ed25519 keypair is per-install; the public half encodes the
	// connection's "iss" (did:key). Persisted across restarts so the
	// relay sees the same client identity.
	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey

	conn    *websocket.Conn
	connMu  sync.Mutex
	closed  atomic.Bool
	nextID  atomic.Int64
	pending sync.Map // int64 → chan rpcResponse
	Events  chan RelayEvent
	writeCh chan rpcRequest
}

// RelayEvent is one inbound message from the relay (an irn_subscription).
type RelayEvent struct {
	Topic   string
	Message string // base64 envelope
	Tag     int
	// PublishedAt provides server-side timestamp when present.
	PublishedAt int64
}

type rpcRequest struct {
	ID      int64           `json:"id"`
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	ID      int64           `json:"id"`
	Jsonrpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewRelayClient builds a client pinned to the given relay URL + projectId.
// The Ed25519 keypair is either loaded from edPriv (if 64 bytes) or freshly
// generated; callers should persist the private key across restarts so the
// relay sees a stable client identity.
func NewRelayClient(relayURL, projectID string, edPriv ed25519.PrivateKey) (*RelayClient, error) {
	if relayURL == "" {
		return nil, fmt.Errorf("relayURL is required")
	}
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	var pub ed25519.PublicKey
	if len(edPriv) == ed25519.PrivateKeySize {
		pub = edPriv.Public().(ed25519.PublicKey)
	} else {
		var err error
		pub, edPriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return &RelayClient{
		URL:       relayURL,
		ProjectID: projectID,
		log:       slog.Default().With("component", "wc.relay"),
		edPriv:    edPriv,
		edPub:     pub,
		Events:    make(chan RelayEvent, 16),
		writeCh:   make(chan rpcRequest, 16),
	}, nil
}

// PrivateKey returns the Ed25519 private key this client is authenticating
// with, so the caller can persist it.
func (r *RelayClient) PrivateKey() ed25519.PrivateKey { return r.edPriv }

// Start opens the WebSocket and runs read / write pumps until the context
// is cancelled or the connection closes. Blocks until Start returns.
func (r *RelayClient) Start(ctx context.Context) error {
	if r.closed.Load() {
		return fmt.Errorf("client closed")
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return fmt.Errorf("parse relay URL: %w", err)
	}
	jwt, err := r.makeAuthJWT(r.URL)
	if err != nil {
		return fmt.Errorf("build auth JWT: %w", err)
	}
	q := u.Query()
	q.Set("projectId", r.ProjectID)
	q.Set("auth", jwt)
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, u.String(), http.Header{})
	if err != nil {
		return fmt.Errorf("dial relay: %w", err)
	}
	// Bound inbound WebSocket frame size so a malicious/buggy relay can't
	// force unbounded allocation (2 MiB is well above any legitimate
	// WalletConnect envelope).
	conn.SetReadLimit(1 << 21)
	r.connMu.Lock()
	r.conn = conn
	r.connMu.Unlock()
	r.log.Info("relay connected", "url", r.URL)

	// Run read + write pumps.
	done := make(chan struct{})
	go r.readLoop(done)
	go r.writeLoop(ctx, done)

	<-done
	r.connMu.Lock()
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
	r.connMu.Unlock()
	return nil
}

// Close stops the client. Subsequent Start calls will error.
func (r *RelayClient) Close() {
	if r.closed.CompareAndSwap(false, true) {
		r.connMu.Lock()
		if r.conn != nil {
			r.conn.Close()
		}
		r.connMu.Unlock()
	}
}

// Subscribe tells the relay we want messages for topic. Returns the subId
// the relay assigned.
func (r *RelayClient) Subscribe(ctx context.Context, topic string) (string, error) {
	var res string
	params, _ := json.Marshal(map[string]any{"topic": topic})
	if err := r.call(ctx, "irn_subscribe", params, &res); err != nil {
		return "", err
	}
	return res, nil
}

// Publish sends one message to topic.
func (r *RelayClient) Publish(ctx context.Context, topic, message string, tag, ttl int) error {
	if ttl == 0 {
		ttl = irnDefaultTTL
	}
	params, _ := json.Marshal(map[string]any{
		"topic":   topic,
		"message": message,
		"ttl":     ttl,
		"tag":     tag,
		"prompt":  tag == tagSessionPropose || tag == tagSessionRequest,
	})
	return r.call(ctx, "irn_publish", params, nil)
}

// Unsubscribe removes our subscription.
func (r *RelayClient) Unsubscribe(ctx context.Context, topic, subID string) error {
	params, _ := json.Marshal(map[string]any{"topic": topic, "id": subID})
	return r.call(ctx, "irn_unsubscribe", params, nil)
}

// call sends an RPC and awaits the matching reply.
func (r *RelayClient) call(ctx context.Context, method string, params json.RawMessage, out any) error {
	id := r.nextID.Add(1)
	ch := make(chan rpcResponse, 1)
	r.pending.Store(id, ch)
	defer r.pending.Delete(id)

	req := rpcRequest{ID: id, Jsonrpc: "2.0", Method: method, Params: params}
	select {
	case r.writeCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case resp := <-ch:
		if resp.Error != nil {
			return fmt.Errorf("relay %s: %s (code=%d)", method, resp.Error.Message, resp.Error.Code)
		}
		if out != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *RelayClient) readLoop(done chan<- struct{}) {
	defer close(done)
	for {
		r.connMu.Lock()
		conn := r.conn
		r.connMu.Unlock()
		if conn == nil {
			return
		}
		_, data, err := conn.ReadMessage()
		if err != nil {
			r.log.Info("relay read error", "err", err)
			return
		}
		var peek struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(data, &peek); err != nil {
			// Do not log the raw frame at Info — it may carry sensitive
			// envelope material. Length + error is enough to diagnose.
			r.log.Info("relay decode error", "err", err, "len", len(data))
			continue
		}
		if peek.Method == "irn_subscription" {
			// Inbound event — parse and deliver.
			var p struct {
				ID   string `json:"id"`
				Data struct {
					Topic       string `json:"topic"`
					Message     string `json:"message"`
					Tag         int    `json:"tag"`
					PublishedAt int64  `json:"publishedAt"`
				} `json:"data"`
			}
			if err := json.Unmarshal(peek.Params, &p); err != nil {
				r.log.Info("relay subscription decode", "err", err)
				continue
			}
			// Ack the subscription message so the relay doesn't redeliver.
			ack := rpcResponse{ID: peek.ID, Jsonrpc: "2.0"}
			ack.Result = json.RawMessage("true")
			r.writeRaw(ack)
			select {
			case r.Events <- RelayEvent{
				Topic:       p.Data.Topic,
				Message:     p.Data.Message,
				Tag:         p.Data.Tag,
				PublishedAt: p.Data.PublishedAt,
			}:
			default:
				r.log.Warn("relay Events channel full, dropping message")
			}
			continue
		}
		// Response to a call we made.
		if peek.ID != 0 {
			if ch, ok := r.pending.Load(peek.ID); ok {
				select {
				case ch.(chan rpcResponse) <- rpcResponse{
					ID:     peek.ID,
					Result: peek.Result,
					Error:  peek.Error,
				}:
				default:
				}
			}
		}
	}
}

func (r *RelayClient) writeLoop(ctx context.Context, done chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case req := <-r.writeCh:
			r.connMu.Lock()
			conn := r.conn
			r.connMu.Unlock()
			if conn == nil {
				return
			}
			buf, _ := json.Marshal(req)
			if err := conn.WriteMessage(websocket.TextMessage, buf); err != nil {
				r.log.Info("relay write error", "err", err)
				return
			}
		}
	}
}

func (r *RelayClient) writeRaw(resp rpcResponse) {
	r.connMu.Lock()
	conn := r.conn
	r.connMu.Unlock()
	if conn == nil {
		return
	}
	resp.Jsonrpc = "2.0"
	buf, _ := json.Marshal(resp)
	_ = conn.WriteMessage(websocket.TextMessage, buf)
}

// makeAuthJWT builds the Ed25519 JWT the relay expects. Claims:
//
//	iss: did:key:z6Mk<base58(multicodec-prefixed pub)>
//	sub: random 32-byte nonce (hex)
//	aud: relay URL
//	iat/exp: 1-hour window
func (r *RelayClient) makeAuthJWT(aud string) (string, error) {
	header := map[string]any{"alg": "EdDSA", "typ": "JWT"}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{
		"iss": didKeyFromEd25519(r.edPub),
		"sub": hex.EncodeToString(nonce),
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	hBuf, _ := json.Marshal(header)
	cBuf, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hBuf) + "." +
		base64.RawURLEncoding.EncodeToString(cBuf)
	sig := ed25519.Sign(r.edPriv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// didKeyFromEd25519 encodes an Ed25519 public key as a did:key URI using
// multibase + multicodec prefix 0xed 0x01, per
// https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
func didKeyFromEd25519(pub ed25519.PublicKey) string {
	// Multicodec prefix for Ed25519: 0xed 0x01
	mc := append([]byte{0xed, 0x01}, pub...)
	return "did:key:z" + base58.Bitcoin.Encode(mc)
}
