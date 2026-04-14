package wltwc

import (
	"encoding/base64"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// wcSession is one WalletConnect v2 pairing/session record.
//
// A single row represents the full lifecycle: while a dApp is pairing it's
// in State="pairing" and Topic is the pairing topic; once the wallet has
// settled (user approved sessionPropose), the row is updated to
// State="active" and Topic is the session topic, with the per-session
// derived SymKey persisted so encrypted traffic survives restart.
type wcSession struct {
	TableName psql.Name  `sql:"WalletConnect"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`

	// Current topic the relay subscription is bound to. Pairing topic
	// while proposing, session topic once settled. Always sha256-hex.
	Topic string `sql:",type=VARCHAR,size=255,key=UNIQUE"`

	// Original pairing topic — kept for reference (for sending the
	// sessionProposeResponse back on it) and for user diagnostics.
	PairingTopic string `sql:",type=VARCHAR,size=255"`

	// State: "pairing" (awaiting sessionPropose), "proposed" (prompt
	// shown to user, awaiting approval), "active" (session settled),
	// "disconnected".
	State string `sql:",type=VARCHAR,size=255"`

	// SymKey for envelope encryption on Topic. Base64url-encoded 32B.
	// For pairing-state rows this is the URI-provided symKey; for
	// active sessions it's HKDF(X25519(selfPriv, peerPub)).
	SymKey string `sql:",type=VARCHAR,size=512"`

	// X25519 keypair the wallet generated for this session.
	// Base64url-encoded 32B each. Priv is used only during the
	// sessionSettle derivation; once SymKey is computed it's retained
	// for auditability / debugging and could be rotated in a reshare.
	SelfPriv string `sql:",type=VARCHAR,size=512"`
	SelfPub  string `sql:",type=VARCHAR,size=512"`
	PeerPub  string `sql:",type=VARCHAR,size=512"`

	// Proposer metadata (name, description, url, icons).
	PeerMetadata map[string]any `sql:",type=JSON,format=json"`

	// Approved namespaces: {eip155: {accounts:[...], methods:[...],
	// events:[...]}, solana: {...}, ...}.
	Namespaces map[string]any `sql:",type=JSON,format=json"`

	// Expiry — WC v2 sessions default to 7 days; we persist whatever
	// the peer proposed and we agreed to.
	Expiry  time.Time `sql:",type=DATETIME"`
	Created time.Time `sql:",type=DATETIME"`
	Updated time.Time `sql:",type=DATETIME"`
}

func (s *wcSession) save(e wltintf.Env) error {
	now := time.Now()
	if s.Created.IsZero() {
		s.Created = now
	}
	s.Updated = now
	return psql.Replace(e, s)
}

// symKeyBytes decodes the persisted SymKey back to raw bytes.
func (s *wcSession) symKeyBytes() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s.SymKey)
}

// selfPrivBytes / selfPubBytes / peerPubBytes decode the persisted
// X25519 keys. An empty field yields a nil slice, not an error.
func (s *wcSession) selfPrivBytes() ([]byte, error) {
	if s.SelfPriv == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s.SelfPriv)
}

func (s *wcSession) peerPubBytes() ([]byte, error) {
	if s.PeerPub == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s.PeerPub)
}

// allActiveSessions returns every session row with State == "active".
// Used on startup to re-subscribe to the relay for each one.
func allActiveSessions(e wltintf.Env) ([]*wcSession, error) {
	rows, err := psql.Fetch[wcSession](e, map[string]any{"State": "active"})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// allNonClosedSessions returns pairing + proposed + active. Disconnected
// rows are filtered out. Caller handles expired filtering in-process.
func allNonClosedSessions(e wltintf.Env) ([]*wcSession, error) {
	var out []*wcSession
	for _, state := range []string{"pairing", "proposed", "active"} {
		rows, err := psql.Fetch[wcSession](e, map[string]any{"State": state})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// sessionByTopic finds the (one) non-disconnected session currently using
// the given topic. Returns (nil, nil) if none found.
func sessionByTopic(e wltintf.Env, topic string) (*wcSession, error) {
	s, err := psql.Get[wcSession](e, map[string]any{"Topic": topic})
	if err != nil {
		return nil, nil
	}
	return s, nil
}
