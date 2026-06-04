package wltwallet

// Device-transfer API — Wallet:exportToDevice / Wallet:importFromDevice.
//
// Use case: the user is setting up libwallet on a new device and
// wants their existing wallet (including the device share's private
// key) copied over so they can sign immediately — no reshare round
// trip. Both devices must be online with their Spot clients
// connected; pairing happens via QR code scanned on the new device
// from the old device's screen.
//
// Wire shape (one Spot Query round trip):
//
//     new device → old/<sid>/transfer  (transferQueryBody)
//     old device → new device          (sealed transferPayload)
//
// The QR-encoded pairing code is a tibane:// URL containing the old
// device's Spot id + a 32-byte random token + the session id. The
// host treats the whole string as opaque and passes it verbatim into
// Wallet:importFromDevice on the new side.
//
// Token-derived encryption (HKDF-SHA-256 → AES-256-GCM) layered on
// top of Spot's bottle encryption guards against bottle-layer leaks;
// the token also acts as the proof of QR possession (an attacker on
// the Spot transport without the QR can't decrypt the payload).
//
// The OLD device side is event-driven: Wallet:exportToDevice returns
// the pairing code immediately and registers a Spot handler. When
// the new device's request lands, the handler emits
// `wallet:transfer:pair_received` (sid + peer spot id) so the host
// can show a confirmation prompt + biometric. Host then calls
// Wallet:exportToDevice:confirm with the device-share private keys,
// or :cancel to decline. The handler thread blocks on a channel
// until one of those arrives, then either ships the payload or
// returns errTransferDeclined.
//
// 5-minute TTL on every session — matches the ClawdWallet pairing
// flow. Sessions are in-memory only; restarting libwallet aborts
// any in-flight transfer.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/spotproto"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterStatic("Wallet:exportToDevice", apiWalletExportToDevice)
	pobj.RegisterStatic("Wallet:exportToDevice:confirm", apiWalletExportToDeviceConfirm)
	pobj.RegisterStatic("Wallet:exportToDevice:cancel", apiWalletExportToDeviceCancel)
	pobj.RegisterStatic("Wallet:importFromDevice", apiWalletImportFromDevice)
}

const (
	// transferProtocolVersion goes into the QR's `v=` parameter and
	// the wire bodies. Bump on incompatible changes; old apps will
	// surface ErrCodeBadRequest when they see an unknown version.
	transferProtocolVersion = 1
	// transferTTL bounds the session lifetime end-to-end: the time
	// between Wallet:exportToDevice returning the QR code and the
	// new device's request landing on the handler, plus the
	// confirmation wait. Matches ClawdWallet pairing.
	transferTTL = 5 * time.Minute
	// transferConfirmTimeout caps how long the handler will wait
	// for the host's confirm/cancel decision once a pair request
	// has arrived. Shorter than TTL because the user is actively
	// looking at the prompt at that point.
	transferConfirmTimeout = 90 * time.Second
	// transferQueryTimeout is the new device's per-attempt timeout
	// for the Spot Query that drives the whole flow. Slightly
	// longer than transferConfirmTimeout to give the old device's
	// handler time to respond once the host approves.
	transferQueryTimeout = 2 * time.Minute
	// transferSpotPrefix is the single Spot endpoint segment under
	// which the global transfer handler is registered. Spotlib's
	// dispatcher only matches the first path segment after the
	// recipient id, so the sid travels in the request body instead
	// of in the path.
	transferSpotPrefix = "transfer"
	// transferEventPairReceived is the event name emitted when the
	// new device's request lands on the old device's handler. Hosts
	// subscribe to it to drive the confirmation UI.
	transferEventPairReceived = "wallet:transfer:pair_received"
)

// Sentinel error codes — match the ClawdWallet-pair pattern so the
// Dart side can branch on Error() strings via a typed dispatcher.
var (
	errTransferBadRequest    = errors.New("bad_request")
	errTransferTokenInvalid  = errors.New("token_invalid")
	errTransferTokenExpired  = errors.New("token_expired")
	errTransferDeclined      = errors.New("declined")
	errTransferTimeout       = errors.New("timeout")
	errTransferURLMalformed  = errors.New("url_malformed")
	errTransferPeerUnreachable = errors.New("peer_unreachable")
	errTransferSessionNotFound = errors.New("session_not_found")
	errTransferWalletNotFound  = errors.New("wallet_not_found")
	// errTransferLocalOffline is returned by Wallet:exportToDevice
	// when the source's Spot client can't reach the broker within
	// waitOnlineSpot's 15-second window. Returning early here means
	// the host doesn't paint a QR for a session that no peer can
	// reach — without this guard, spot.TargetId() (a static, key-
	// derived id) still produces a syntactically valid QR while the
	// receiver's spot.Query hangs the full 2-minute transferQueryTimeout
	// before giving up with peer_unreachable.
	errTransferLocalOffline    = errors.New("local_offline")
)

// transferQueryBody is what the new device sends to the old device's
// Spot handler. The token here MUST match the session token; the
// handler rejects with errTransferTokenInvalid otherwise.
//
// Sid MUST be set: spotlib's dispatcher only matches the first path
// segment after the recipient id, so the handler is installed under
// the bare "transfer" prefix (no sid in the path) and demuxes
// sessions out of this field instead. A request without Sid lands
// on errTransferSessionNotFound.
type transferQueryBody struct {
	V              int    `json:"v"`
	Sid            string `json:"sid"`
	Token          string `json:"token"` // base64url, no padding
	NewSpotID      string `json:"new_spot_id"`
	NewFingerprint string `json:"new_fingerprint,omitempty"` // free-text label the host may show in the confirm prompt
}

// transferPayload is the plaintext the old device ships back to the
// new device once the user confirms. Encrypted via AES-256-GCM with
// the token-derived key; the new device decrypts and hands the
// pieces to its host: the wallet JSON gets written via the standard
// restore path, and the device shares get written to the platform
// keystore.
type transferPayload struct {
	V            int                  `json:"v"`
	Wallet       json.RawMessage      `json:"wallet"`        // Wallet:backup blob for this wallet (single entry's `data` decoded base64 → JSON)
	DeviceShares []*DeviceShareEntry  `json:"device_shares"` // one per StoreKey-typed WalletKey
}

// DeviceShareEntry pairs a WalletKey.Id with the base64url-encoded
// StoreKey private key bytes the host holds in its platform
// keystore. The export side accepts this shape on
// Wallet:exportToDevice:confirm; the import side returns the same
// shape on Wallet:importFromDevice for the host to write back.
type DeviceShareEntry struct {
	WalletKeyId string `json:"wallet_key_id"`
	PrivateKey  string `json:"private_key"` // base64url-encoded 64-byte StoreKey blob (matches StoreKey:create's "private" field)
}

// transferSession is the in-memory state for one ongoing export.
// The handler goroutine, the API calls, and the cleanup ticker
// share it via the registry below.
type transferSession struct {
	Sid       string
	Token     []byte
	WalletId  string
	CreatedAt time.Time

	// Cancel fires when TTL expires or the host calls :cancel; the
	// handler returns errTransferTimeout / errTransferDeclined.
	cancel chan struct{}
	// confirm carries the host's approval + device-share material
	// from Wallet:exportToDevice:confirm into the handler.
	confirm chan *transferConfirmData

	// done is closed after the handler has finished one way or the
	// other — used so the cleanup ticker can free the session
	// without racing the handler goroutine.
	done chan struct{}

	// Set once the pair request lands. Used to emit the event with
	// the peer's spot id and to populate the response sender.
	peerSpotID string

	mu sync.Mutex
}

type transferConfirmData struct {
	DeviceShares []*DeviceShareEntry
}

// transferRegistry holds all active sessions keyed by sid. Sessions
// are removed by the cleanup ticker after TTL or by the handler
// itself on completion. Single global is fine — libwallet
// instances are per-process and the sid namespace is per-process.
var transferRegistry = struct {
	mu       sync.Mutex
	sessions map[string]*transferSession
}{sessions: make(map[string]*transferSession)}

func transferStartCleanup() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			transferRegistry.mu.Lock()
			for sid, s := range transferRegistry.sessions {
				if now.Sub(s.CreatedAt) > transferTTL {
					select {
					case <-s.cancel:
					default:
						close(s.cancel)
					}
					delete(transferRegistry.sessions, sid)
				}
			}
			transferRegistry.mu.Unlock()
		}
	}()
}

func init() {
	transferStartCleanup()
}

// ─── pairing-code helpers ────────────────────────────────────────

// buildTransferPairingURL returns the opaque string the host writes
// into the QR. Format mirrors ClawdWallet pairing's tibane:// URL
// so the host can reuse its QR rendering and scanning code; nothing
// outside libwallet should parse it.
func buildTransferPairingURL(spotID, token, sid string) string {
	q := url.Values{}
	q.Set("spot", spotID)
	q.Set("token", token)
	q.Set("sid", sid)
	q.Set("v", fmt.Sprintf("%d", transferProtocolVersion))
	return "tibane://device-transfer?" + q.Encode()
}

// parseTransferPairingURL is the inverse — used by the new device's
// Wallet:importFromDevice handler. Any malformed input lands as
// errTransferURLMalformed so the Dart side can map all parse
// failures to one typed exception.
func parseTransferPairingURL(raw string) (spotID, token, sid string, err error) {
	if raw == "" {
		return "", "", "", errTransferURLMalformed
	}
	u, parseErr := url.Parse(raw)
	if parseErr != nil {
		return "", "", "", errTransferURLMalformed
	}
	if u.Scheme != "tibane" {
		return "", "", "", errTransferURLMalformed
	}
	target := u.Host
	if target == "" {
		target = strings.TrimPrefix(u.Path, "/")
	}
	if target != "device-transfer" {
		return "", "", "", errTransferURLMalformed
	}
	q := u.Query()
	spotID = q.Get("spot")
	token = q.Get("token")
	sid = q.Get("sid")
	if spotID == "" || token == "" || sid == "" {
		return "", "", "", errTransferURLMalformed
	}
	if v := q.Get("v"); v != "" && v != "1" {
		// Only version 1 is wire-compatible with this build.
		return "", "", "", errTransferURLMalformed
	}
	return spotID, token, sid, nil
}

// ─── Wallet:exportToDevice ────────────────────────────────────────

type exportToDeviceInput struct {
	WalletId string `json:"WalletId"`
}

type exportToDeviceResult struct {
	Sid         string    `json:"sid"`
	PairingCode string    `json:"pairingCode"` // opaque; tibane://device-transfer?...
	ExpiresAt   time.Time `json:"expiresAt"`
}

// apiWalletExportToDevice opens an export session and returns the
// opaque pairing code for the host to render as a QR. The session
// stays live until the new device connects + the host confirms, or
// until transferTTL expires. The actual device-share material is
// NOT supplied here — it arrives on the :confirm call so the host
// can run its biometric prompt + keystore read between this call
// and that one.
func apiWalletExportToDevice(ctx context.Context, in *exportToDeviceInput) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if in == nil || in.WalletId == "" {
		// WalletId can also come from the object context (Wallet/<id>:exportToDevice).
		if w := apirouter.GetObject[Wallet](ctx, "Wallet"); w != nil {
			if in == nil {
				in = &exportToDeviceInput{}
			}
			in.WalletId = w.Id.String()
		}
	}
	if in == nil || in.WalletId == "" {
		return nil, errTransferBadRequest
	}

	// Validate the wallet exists and has keys — refusing here means
	// the host doesn't paint a QR for a wallet that can't actually
	// be exported.
	wlt, err := findWalletByIDString(e, in.WalletId)
	if err != nil {
		return nil, errTransferWalletNotFound
	}
	if len(wlt.Keys) == 0 {
		return nil, errTransferBadRequest
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, fmt.Errorf("exportToDevice: spot: %w", err)
	}
	// Refuse to mint a pairing code unless our own Spot is actually
	// reachable. spot.TargetId() returns the static, key-derived id
	// even when the broker handshake hasn't completed, so without this
	// guard the source would happily paint a QR for an unroutable
	// node and the receiver would hang for the full transferQueryTimeout.
	if werr := waitOnlineSpot(spot); werr != nil {
		return nil, errTransferLocalOffline
	}

	token := make([]byte, transferTokenBytes)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("exportToDevice: rand: %w", err)
	}
	sidBytes := make([]byte, 16)
	if _, err := rand.Read(sidBytes); err != nil {
		return nil, fmt.Errorf("exportToDevice: rand sid: %w", err)
	}
	sid := base64.RawURLEncoding.EncodeToString(sidBytes)
	tokenStr := base64.RawURLEncoding.EncodeToString(token)

	s := &transferSession{
		Sid:       sid,
		Token:     token,
		WalletId:  in.WalletId,
		CreatedAt: time.Now(),
		cancel:    make(chan struct{}),
		confirm:   make(chan *transferConfirmData, 1),
		done:      make(chan struct{}),
	}

	transferRegistry.mu.Lock()
	transferRegistry.sessions[sid] = s
	transferRegistry.mu.Unlock()

	// Per-session SetHandler used to live here, keyed at
	// "transfer/<sid>". Spotlib's connect.go dispatcher only matches
	// the first path segment after the recipient ("transfer"), so the
	// lookup always missed and the receiver hung the full
	// transferQueryTimeout before giving up. The handler is now
	// installed once at InitEnv time under the bare "transfer"
	// prefix; this function only registers the session in
	// transferRegistry, and the global handler looks the session up
	// by sid from the request body.

	return &exportToDeviceResult{
		Sid:         sid,
		PairingCode: buildTransferPairingURL(spot.TargetId(), tokenStr, sid),
		ExpiresAt:   s.CreatedAt.Add(transferTTL),
	}, nil
}

// transferHandle is the single Spot handler bound to the bare
// "transfer" endpoint at InitEnv time. Demuxes incoming pair
// requests by the `sid` field of the body, claims the matching
// session out of transferRegistry, emits the pair-received event
// so the host can prompt for confirmation, then blocks on
// s.confirm / s.cancel until the host decides (or
// transferConfirmTimeout fires). On approval, builds + seals the
// payload and returns it as the Spot response. On rejection or
// timeout, returns the appropriate sentinel string as an error so
// Spot wraps it as MsgFlagError back to the requester.
//
// Why a single endpoint instead of "transfer/<sid>": spotlib's
// dispatcher (spotlib/connect.go) only matches the first path
// segment after the recipient id, so the deeper key never resolved.
// Multiple concurrent transfers all land here and are
// disambiguated by sid.
func transferHandle(e wltintf.Env, msg *spotproto.Message) ([]byte, error) {
	var req transferQueryBody
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		return nil, errTransferBadRequest
	}
	if req.V != transferProtocolVersion {
		return nil, errTransferBadRequest
	}
	if req.Sid == "" {
		return nil, errTransferSessionNotFound
	}
	got, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, errTransferBadRequest
	}

	// Claim the session out of the registry under one lock so a
	// concurrent valid request for the same sid sees session_not_found
	// instead of racing on the channels. The defer-removal pattern
	// from the per-session handler isn't available now that the
	// handler is global and permanent.
	transferRegistry.mu.Lock()
	s, ok := transferRegistry.sessions[req.Sid]
	if ok {
		delete(transferRegistry.sessions, req.Sid)
	}
	transferRegistry.mu.Unlock()
	if !ok {
		return nil, errTransferSessionNotFound
	}
	defer func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}()

	// Late arrival after TTL: refuse before validating token.
	if time.Since(s.CreatedAt) > transferTTL {
		return nil, errTransferTokenExpired
	}
	if !constantTimeTokenEqual(got, s.Token) {
		return nil, errTransferTokenInvalid
	}

	s.mu.Lock()
	s.peerSpotID = req.NewSpotID
	if s.peerSpotID == "" {
		s.peerSpotID = msg.Sender
	}
	s.mu.Unlock()

	// Notify the host so it can paint a confirmation prompt + run
	// biometric + read the device share from the platform keystore.
	//
	// MUST use apirouter.BroadcastJson, not e.Emitter().Emit — the
	// in-process emitter hub is for cross-package Go signals only
	// (wltacct subscribes to wallet:pubkey_repaired etc.); host
	// events reach the FFI bridge through the BroadcastJson →
	// MakeJsonSocketFD → `client.events` pipe wired up in
	// cshared/ffi.go. Emitting to e.Emitter() puts the event on a
	// channel nothing forwards, so the host never sees it — which
	// is why 0.4.49 receivers were getting transferConfirmTimeout
	// (90 s) instead of a host prompt + confirm.
	apirouter.BroadcastJson(context.Background(), map[string]any{
		"result": "event",
		"event":  transferEventPairReceived,
		"data": map[string]any{
			"sid":              s.Sid,
			"wallet_id":        s.WalletId,
			"peer_spot_id":     s.peerSpotID,
			"peer_fingerprint": req.NewFingerprint,
		},
	})

	// Wait for the host's decision. Bound the wait by
	// transferConfirmTimeout — the user is actively looking at the
	// prompt by now, so the long TTL is no longer the right ceiling.
	select {
	case c := <-s.confirm:
		if c == nil {
			return nil, errTransferDeclined
		}
		payload, err := buildTransferPayload(e, s.WalletId, c.DeviceShares)
		if err != nil {
			return nil, fmt.Errorf("transfer: build payload: %w", err)
		}
		sealed, err := sealTransferPayload(s.Token, s.Sid, payload)
		if err != nil {
			return nil, fmt.Errorf("transfer: seal: %w", err)
		}
		return sealed, nil
	case <-s.cancel:
		return nil, errTransferDeclined
	case <-time.After(transferConfirmTimeout):
		return nil, errTransferTimeout
	}
}

// buildTransferPayload assembles the wallet JSON + device shares
// into the plaintext sealTransferPayload encrypts. Wallet JSON
// comes from doBackup so the wire shape is identical to what
// Wallet:restore already consumes — keeps the import side from
// inventing a new wallet-shape parser.
func buildTransferPayload(e wltintf.Env, walletId string, shares []*DeviceShareEntry) ([]byte, error) {
	wlt, err := findWalletByIDString(e, walletId)
	if err != nil {
		return nil, err
	}
	dat, err := wlt.doBackup()
	if err != nil {
		return nil, err
	}
	if len(dat) == 0 {
		return nil, fmt.Errorf("transfer: wallet %s has no backup data", walletId)
	}
	walletBlob, err := base64.RawURLEncoding.DecodeString(dat[0].Data)
	if err != nil {
		return nil, fmt.Errorf("transfer: decode backup: %w", err)
	}
	payload := &transferPayload{
		V:            transferProtocolVersion,
		Wallet:       walletBlob,
		DeviceShares: shares,
	}
	return json.Marshal(payload)
}

// findWalletByIDString resolves a wallet by its xuid string form
// without forcing every caller to wire up xuid.ParsePrefix
// themselves. Returns errTransferWalletNotFound on any failure so
// callers can pass it through verbatim.
func findWalletByIDString(e wltintf.Env, id string) (*Wallet, error) {
	x, err := xuid.Parse(id)
	if err != nil {
		return nil, err
	}
	if x.Prefix != "wlt" && x.Prefix != "wlet" {
		return nil, fmt.Errorf("transfer: unexpected id prefix %q", x.Prefix)
	}
	return WalletById(e, x)
}

// ─── Wallet:exportToDevice:confirm ────────────────────────────────

type exportToDeviceConfirmInput struct {
	Sid          string              `json:"Sid"`
	DeviceShares []*DeviceShareEntry `json:"DeviceShares"`
}

// apiWalletExportToDeviceConfirm hands the device-share material
// to the export handler, which is presumably blocked on s.confirm
// waiting for it. After the handler returns its response over Spot,
// the session is cleaned up automatically by transferHandle.
//
// Authorization model: the host already ran its biometric +
// keystore read before calling this, so this endpoint just routes
// the bytes. libwallet doesn't see fingerprint / passcode; that's
// platform-level and intentionally outside our trust boundary.
func apiWalletExportToDeviceConfirm(ctx context.Context, in *exportToDeviceConfirmInput) (any, error) {
	if in == nil || in.Sid == "" {
		return nil, errTransferBadRequest
	}
	if len(in.DeviceShares) == 0 {
		return nil, errTransferBadRequest
	}
	transferRegistry.mu.Lock()
	s, ok := transferRegistry.sessions[in.Sid]
	transferRegistry.mu.Unlock()
	if !ok {
		return nil, errTransferSessionNotFound
	}
	select {
	case s.confirm <- &transferConfirmData{DeviceShares: in.DeviceShares}:
		return map[string]any{"status": "ok"}, nil
	case <-s.done:
		return nil, errTransferSessionNotFound
	default:
		// Channel is already full — confirm was called twice. Treat
		// the second as a no-op rather than blocking.
		return nil, errTransferBadRequest
	}
}

// ─── Wallet:exportToDevice:cancel ─────────────────────────────────

type exportToDeviceCancelInput struct {
	Sid string `json:"Sid"`
}

// apiWalletExportToDeviceCancel aborts an export session. Safe to
// call before or after the peer has connected — closes s.cancel,
// the handler responds with errTransferDeclined (if it was waiting
// on confirm) or just exits.
func apiWalletExportToDeviceCancel(ctx context.Context, in *exportToDeviceCancelInput) (any, error) {
	if in == nil || in.Sid == "" {
		return nil, errTransferBadRequest
	}
	transferRegistry.mu.Lock()
	s, ok := transferRegistry.sessions[in.Sid]
	transferRegistry.mu.Unlock()
	if !ok {
		return nil, errTransferSessionNotFound
	}
	select {
	case <-s.cancel:
		// Already cancelled — idempotent.
	default:
		close(s.cancel)
	}
	return map[string]any{"status": "ok"}, nil
}

// ─── Wallet:importFromDevice ──────────────────────────────────────

type importFromDeviceInput struct {
	PairingCode string `json:"PairingCode"`
}

// importFromDeviceResult is what the new device's host receives.
// The wallet JSON has already been written to the local store by
// the time this returns; the host's only remaining job is to write
// each DeviceShareEntry's PrivateKey into the platform keystore
// before the next unlock call.
type importFromDeviceResult struct {
	WalletId     string              `json:"walletId"`
	DeviceShares []*DeviceShareEntry `json:"deviceShares"`
}

// apiWalletImportFromDevice runs the new-device side end-to-end:
// parse the pairing code, send the Spot request to the old device,
// wait for the encrypted response, decrypt, persist the wallet, and
// return the device-share material for the host to write to the
// platform keystore.
//
// The whole call is one Spot Query round trip — Spot's own retry +
// timeout machinery handles transport flakes, and the
// transferQueryTimeout cap keeps a stuck old device from hanging
// the new device forever.
func apiWalletImportFromDevice(ctx context.Context, in *importFromDeviceInput) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if in == nil || in.PairingCode == "" {
		return nil, errTransferURLMalformed
	}
	spotID, tokenB64, sid, err := parseTransferPairingURL(in.PairingCode)
	if err != nil {
		return nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(tokenB64)
	if err != nil || len(token) != transferTokenBytes {
		return nil, errTransferURLMalformed
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, fmt.Errorf("importFromDevice: spot: %w", err)
	}
	if werr := waitOnlineSpot(spot); werr != nil {
		return nil, errTransferPeerUnreachable
	}

	body := &transferQueryBody{
		V:         transferProtocolVersion,
		Sid:       sid,
		Token:     tokenB64,
		NewSpotID: spot.TargetId(),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("importFromDevice: marshal: %w", err)
	}

	// Single path segment after the spot id: spotlib's dispatcher
	// only matches the first segment after the recipient, so a deeper
	// "transfer/<sid>" target never lands on the source's handler.
	// The sid travels in the body instead.
	target := spotID + "/" + transferSpotPrefix
	queryCtx, cancel := context.WithTimeout(ctx, transferQueryTimeout)
	defer cancel()
	resp, err := spot.Query(queryCtx, target, buf)
	if err != nil {
		// Spot wraps handler-side `errors.New("token_invalid")` etc.
		// into transport errors whose Error() contains the sentinel
		// string verbatim. Bubble the known codes through; everything
		// else maps to peer_unreachable so callers don't need to
		// learn Spot internals.
		if mapped := mapTransferRemoteError(err); mapped != nil {
			return nil, mapped
		}
		return nil, errTransferPeerUnreachable
	}

	plaintext, err := openTransferPayload(token, sid, resp)
	if err != nil {
		return nil, fmt.Errorf("importFromDevice: decrypt: %w", err)
	}
	var payload transferPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("importFromDevice: unmarshal: %w", err)
	}
	if payload.V != transferProtocolVersion {
		return nil, errTransferBadRequest
	}
	if len(payload.Wallet) == 0 || len(payload.DeviceShares) == 0 {
		return nil, errTransferBadRequest
	}

	// Persist the wallet through the standard restore path. Reusing
	// it ensures the import side behaves exactly like a normal
	// Wallet:restore from a backup file — including the wallet:
	// restored event the host already listens to.
	restoreFile := &backupDataEntry{
		Filename: "wallet_" + extractWalletIdFromPayload(payload.Wallet) + ".dat",
		Data:     base64.RawURLEncoding.EncodeToString(payload.Wallet),
	}
	res := &walletRestoreResponse{checked: make(map[string]bool)}
	if rerr := restoreSingleWalletFile(e, restoreFile.Filename, restoreFile.Data, &walletRestoreRequest{}, res); rerr != nil {
		return nil, fmt.Errorf("importFromDevice: restore: %w", rerr)
	}
	walletId := ""
	for id := range res.checked {
		walletId = id
		break
	}

	return &importFromDeviceResult{
		WalletId:     walletId,
		DeviceShares: payload.DeviceShares,
	}, nil
}

// mapTransferRemoteError lifts handler-side sentinel strings out of
// the Spot-transport error wrapper. The host-side sentinel set is
// closed, so a substring check is safe — false positives would
// require an unrelated error message to embed one of these strings
// verbatim.
func mapTransferRemoteError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "token_invalid"):
		return errTransferTokenInvalid
	case strings.Contains(msg, "token_expired"):
		return errTransferTokenExpired
	case strings.Contains(msg, "declined"):
		return errTransferDeclined
	case strings.Contains(msg, "timeout"):
		return errTransferTimeout
	case strings.Contains(msg, "bad_request"):
		return errTransferBadRequest
	case strings.Contains(msg, "session_not_found"):
		return errTransferSessionNotFound
	case strings.Contains(msg, "local_offline"):
		return errTransferLocalOffline
	}
	return nil
}

// extractWalletIdFromPayload pulls the base64url-encoded wallet UUID
// out of the wallet JSON so the import side can construct the
// canonical wallet_<id>.dat filename Wallet:restore expects. The
// wallet JSON's `Id` field is a serialized xuid (prefix + hyphen-
// separated chunks); xuid has its own JSON shape, so the easiest
// thing is to decode the wallet partially and pull the Id.
func extractWalletIdFromPayload(walletJSON []byte) string {
	var probe struct {
		Id string `json:"Id"`
	}
	if err := json.Unmarshal(walletJSON, &probe); err != nil {
		return ""
	}
	x, err := xuid.Parse(probe.Id)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(x.UUID[:])
}
