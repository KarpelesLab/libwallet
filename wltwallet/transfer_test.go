package wltwallet

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KarpelesLab/xuid"
)

// freshToken pulls 32 bytes from crypto/rand — the same source the
// production sealer uses so the test mirrors the live key strength.
func freshToken(t *testing.T) []byte {
	t.Helper()
	tok := make([]byte, transferTokenBytes)
	if _, err := rand.Read(tok); err != nil {
		t.Fatalf("rand: %s", err)
	}
	return tok
}

// TestSealOpenRoundTrip pins the basic happy path: the same
// (token, sid, plaintext) tuple round-trips byte-for-byte through
// seal → open under matching keys. Failing this means either the
// HKDF key derivation diverged across calls or the GCM auth tag is
// being computed against different additional-data on the two
// sides — both are silent corruption bugs that a higher-level
// integration test would surface as "decrypt failed" without
// pointing at the responsible layer, so it's worth pinning here.
func TestSealOpenRoundTrip(t *testing.T) {
	token := freshToken(t)
	const sid = "session-id-abcde"
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	sealed, err := sealTransferPayload(token, sid, plaintext)
	if err != nil {
		t.Fatalf("seal: %s", err)
	}
	if bytes.Equal(sealed, plaintext) {
		t.Fatal("sealed output equals plaintext — encryption did not run")
	}

	got, err := openTransferPayload(token, sid, sealed)
	if err != nil {
		t.Fatalf("open: %s", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch:\n got=%q\nwant=%q", got, plaintext)
	}
}

// TestSealOpenWrongKeyMaterialFails ensures every input that
// participates in key derivation is actually load-bearing — a
// silent passthrough on a mismatched sid or token would defeat the
// whole point of the per-session key.
func TestSealOpenWrongKeyMaterialFails(t *testing.T) {
	tokenA := freshToken(t)
	tokenB := freshToken(t)
	const sidA = "session-A"
	const sidB = "session-B"
	plaintext := []byte("super secret device share")

	sealed, err := sealTransferPayload(tokenA, sidA, plaintext)
	if err != nil {
		t.Fatalf("seal: %s", err)
	}

	t.Run("wrong token rejects", func(t *testing.T) {
		if _, err := openTransferPayload(tokenB, sidA, sealed); err == nil {
			t.Fatal("decrypt with mismatched token must fail")
		}
	})
	t.Run("wrong sid rejects", func(t *testing.T) {
		// sid is hashed into the HKDF salt AND used as AEAD
		// additional-data, so even if HKDF collapsed somehow the
		// AEAD layer would still catch the mismatch.
		if _, err := openTransferPayload(tokenA, sidB, sealed); err == nil {
			t.Fatal("decrypt with mismatched sid must fail")
		}
	})
	t.Run("flipped byte rejects", func(t *testing.T) {
		// GCM is an AEAD — single-bit flip in the ciphertext should
		// fail the auth check, not silently produce garbage.
		tamper := append([]byte{}, sealed...)
		tamper[len(tamper)-1] ^= 0x01
		if _, err := openTransferPayload(tokenA, sidA, tamper); err == nil {
			t.Fatal("decrypt of tampered ciphertext must fail")
		}
	})
}

// TestSealOpenInputValidation covers the boundary cases the open /
// seal helpers explicitly reject. Without these the caller might
// hit cryptic AES errors or nil-pointer panics; the explicit
// messages are part of the contract.
func TestSealOpenInputValidation(t *testing.T) {
	t.Run("seal rejects short token", func(t *testing.T) {
		if _, err := sealTransferPayload([]byte("too-short"), "sid", []byte("x")); err == nil {
			t.Fatal("expected error on undersized token")
		}
	})
	t.Run("seal rejects empty sid", func(t *testing.T) {
		if _, err := sealTransferPayload(freshToken(t), "", []byte("x")); err == nil {
			t.Fatal("expected error on empty sid")
		}
	})
	t.Run("open rejects too-short ciphertext", func(t *testing.T) {
		if _, err := openTransferPayload(freshToken(t), "sid", []byte{1, 2, 3}); err == nil {
			t.Fatal("expected error on undersized ciphertext")
		}
	})
}

// TestPairingURLRoundTrip pins the QR encode/decode pair. The host
// app treats this string as opaque so a small format change would
// break old QRs silently; pinning the format here forces an
// explicit decision when the wire format moves.
func TestPairingURLRoundTrip(t *testing.T) {
	const (
		spot  = "k.QXP9_7RkhIWLmB9QKPpARECGgx5gXFCXBbiVpLphYlA"
		token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		sid   = "AAAAAAAAAAAAAAAAAAAAAA"
	)
	url := buildTransferPairingURL(spot, token, sid)
	if !strings.HasPrefix(url, "tibane://device-transfer?") {
		t.Errorf("URL must start with tibane://device-transfer?; got %q", url)
	}
	if !strings.Contains(url, "v=1") {
		t.Errorf("URL must carry the protocol version (v=1); got %q", url)
	}

	gotSpot, gotToken, gotSid, err := parseTransferPairingURL(url)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if gotSpot != spot || gotToken != token || gotSid != sid {
		t.Errorf("round-trip mismatch: got (%q,%q,%q) want (%q,%q,%q)",
			gotSpot, gotToken, gotSid, spot, token, sid)
	}
}

// TestPairingURLParseRejections enumerates the malformed-input
// surface. The Dart side maps every parse failure to the same
// PairingURLMalformedException, so the test just confirms each
// shape reaches errTransferURLMalformed — false positives would
// let real garbage flow into the Spot Query stage and surface as
// a less actionable "peer_unreachable".
func TestPairingURLParseRejections(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"empty string", ""},
		{"wrong scheme", "http://device-transfer?spot=x&token=y&sid=z&v=1"},
		{"unknown path", "tibane://something-else?spot=x&token=y&sid=z&v=1"},
		{"missing spot", "tibane://device-transfer?token=y&sid=z&v=1"},
		{"missing token", "tibane://device-transfer?spot=x&sid=z&v=1"},
		{"missing sid", "tibane://device-transfer?spot=x&token=y&v=1"},
		{"future version", "tibane://device-transfer?spot=x&token=y&sid=z&v=99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := parseTransferPairingURL(tc.url); !errors.Is(err, errTransferURLMalformed) {
				t.Errorf("expected errTransferURLMalformed; got %v", err)
			}
		})
	}
}

// TestMapTransferRemoteError pins the wire-error mapping that lets
// the new device's caller branch on a typed exception without
// learning Spot internals. The old device's handler returns
// errors.New("token_invalid") and friends as plain strings;
// Spot wraps them with transport metadata; the new device unwraps
// via substring match. Test that each sentinel survives the trip.
func TestMapTransferRemoteError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"token_invalid", errors.New("handler returned: token_invalid"), errTransferTokenInvalid},
		{"token_expired", errors.New("rpc: token_expired"), errTransferTokenExpired},
		{"declined", errors.New("remote: declined by user"), errTransferDeclined},
		{"timeout", errors.New("remote: timeout"), errTransferTimeout},
		{"bad_request", errors.New("400: bad_request: missing field"), errTransferBadRequest},
		{"session_not_found", errors.New("session_not_found"), errTransferSessionNotFound},
		// Anything unrecognised falls through so the caller can map
		// it to peer_unreachable rather than picking the wrong typed
		// error.
		{"unknown error", errors.New("connection refused"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapTransferRemoteError(tc.err)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExtractWalletIdFromPayload exercises the narrow parser that
// reaches into the wallet JSON to pull the base64url-encoded UUID
// for the restore filename. The wallet shape includes many other
// fields; pinning that this helper ignores them is cheap.
func TestExtractWalletIdFromPayload(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		// Generate a real xuid so the parser exercises the actual
		// production format rather than a hand-typed string that
		// xuid.Parse won't accept.
		realId := xuid.New("wlt")
		body, _ := json.Marshal(map[string]any{
			"Id":        realId.String(),
			"Name":      "Test",
			"Curve":     "secp256k1",
			"Threshold": 1,
		})
		got := extractWalletIdFromPayload(body)
		if got == "" {
			t.Fatal("expected non-empty wallet id")
		}
		wantId := base64.RawURLEncoding.EncodeToString(realId.UUID[:])
		if got != wantId {
			t.Errorf("decoded UUID mismatch: got %q want %q", got, wantId)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		if got := extractWalletIdFromPayload([]byte("not json")); got != "" {
			t.Errorf("expected empty string on bad JSON, got %q", got)
		}
	})
	t.Run("missing Id", func(t *testing.T) {
		if got := extractWalletIdFromPayload([]byte(`{"Name":"x"}`)); got != "" {
			t.Errorf("expected empty string when Id missing, got %q", got)
		}
	})
}
