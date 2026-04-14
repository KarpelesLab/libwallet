package wltwc

// WalletConnect v2 envelope cryptography.
//
// The relay is a dumb pub/sub — all confidentiality / integrity comes from
// the envelope. Two types are in use:
//
//   Type 0 — symmetric only. The topic has a shared symKey the wallet got
//            from the pairing URI (or derived from session keypair ECDH).
//            Layout: [type:1][nonce:12][ciphertext][tag:16]
//
//   Type 1 — asymmetric, used only for the one-shot wc_sessionPropose from
//            dApp → wallet during pairing, before a session is settled.
//            Sender attaches an ephemeral X25519 public key; the receiver
//            derives the per-message symmetric key via X25519 + HKDF.
//            Layout: [type:1][senderPubKey:32][nonce:12][ciphertext][tag:16]
//
// The full envelope is then base64-encoded before being placed in the
// `message` field of the relay JSON-RPC payload.
//
// Spec reference: https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	envelopeTypeSym  = 0 // symmetric (symKey)
	envelopeTypeAsym = 1 // one-shot X25519 (sessionPropose)

	nonceSize      = chacha20poly1305.NonceSize     // 12
	tagSize        = chacha20poly1305.Overhead      // 16
	x25519KeySize  = curve25519.PointSize           // 32
	symKeySize     = chacha20poly1305.KeySize       // 32
	ed25519KeySize = ed25519.PublicKeySize          // 32
)

// sealType0 encrypts plaintext with symKey and returns a base64(url-safe)
// envelope: [0x00][nonce:12][ciphertext][tag:16].
func sealType0(symKey, plaintext []byte) (string, error) {
	if len(symKey) != symKeySize {
		return "", fmt.Errorf("symKey must be %d bytes, got %d", symKeySize, len(symKey))
	}
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := make([]byte, 1, 1+nonceSize+len(plaintext)+tagSize)
	out[0] = envelopeTypeSym
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// sealType1 encrypts plaintext addressed to peerPub using an ephemeral
// sender keypair. Returns the envelope bytes (base64) and the sender's
// public key (so the caller can pin it to the new session).
func sealType1(peerPub ed25519.PublicKey, plaintext []byte) (envelope string, senderPub, senderPriv []byte, err error) {
	if len(peerPub) != x25519KeySize {
		return "", nil, nil, fmt.Errorf("peerPub must be %d bytes, got %d", x25519KeySize, len(peerPub))
	}
	senderPriv = make([]byte, x25519KeySize)
	if _, err = io.ReadFull(rand.Reader, senderPriv); err != nil {
		return
	}
	senderPub, err = curve25519.X25519(senderPriv, curve25519.Basepoint)
	if err != nil {
		return
	}
	symKey, err := deriveSymKey(senderPriv, peerPub)
	if err != nil {
		return
	}
	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return
	}
	nonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	out := make([]byte, 1, 1+x25519KeySize+nonceSize+len(plaintext)+tagSize)
	out[0] = envelopeTypeAsym
	out = append(out, senderPub...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	envelope = base64.StdEncoding.EncodeToString(out)
	return
}

// openEnvelope decrypts a base64 envelope. For Type-0 messages, symKey is
// required and mustPriv must be nil. For Type-1 messages, mustPriv is the
// recipient's X25519 private key (typically the wallet's session proposal
// keypair). On success returns the plaintext and, for Type-1, the
// sender's public key so the caller can pin it.
func openEnvelope(symKey, mustPriv, raw []byte) (plaintext, senderPub []byte, err error) {
	buf, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("envelope base64: %w", err)
	}
	if len(buf) < 1 {
		return nil, nil, errors.New("envelope empty")
	}
	switch buf[0] {
	case envelopeTypeSym:
		if len(symKey) != symKeySize {
			return nil, nil, errors.New("type-0 envelope but no symKey available")
		}
		if len(buf) < 1+nonceSize+tagSize {
			return nil, nil, errors.New("type-0 envelope truncated")
		}
		aead, err := chacha20poly1305.New(symKey)
		if err != nil {
			return nil, nil, err
		}
		nonce := buf[1 : 1+nonceSize]
		ct := buf[1+nonceSize:]
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("type-0 decrypt: %w", err)
		}
		return pt, nil, nil
	case envelopeTypeAsym:
		if len(mustPriv) != x25519KeySize {
			return nil, nil, errors.New("type-1 envelope but no recipient private key")
		}
		if len(buf) < 1+x25519KeySize+nonceSize+tagSize {
			return nil, nil, errors.New("type-1 envelope truncated")
		}
		pub := buf[1 : 1+x25519KeySize]
		nonce := buf[1+x25519KeySize : 1+x25519KeySize+nonceSize]
		ct := buf[1+x25519KeySize+nonceSize:]
		derived, err := deriveSymKey(mustPriv, pub)
		if err != nil {
			return nil, nil, err
		}
		aead, err := chacha20poly1305.New(derived)
		if err != nil {
			return nil, nil, err
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("type-1 decrypt: %w", err)
		}
		return pt, append([]byte(nil), pub...), nil
	default:
		return nil, nil, fmt.Errorf("unknown envelope type %d", buf[0])
	}
}

// deriveSymKey runs X25519 then HKDF-SHA256 with empty salt and info,
// extracting the first 32 bytes. Matches WalletConnect v2's derivation.
func deriveSymKey(priv, peerPub []byte) ([]byte, error) {
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, err
	}
	out := make([]byte, symKeySize)
	r := hkdf.New(sha256.New, shared, nil, nil)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// newX25519KeyPair generates a fresh X25519 keypair. priv is clamped per
// RFC 7748; pub = X25519(priv, basepoint).
func newX25519KeyPair() (priv, pub []byte, err error) {
	priv = make([]byte, x25519KeySize)
	if _, err = io.ReadFull(rand.Reader, priv); err != nil {
		return
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return
}

// topicFromSymKey computes the relay topic for a pairing given the symKey.
// WC v2 defines the pairing topic as sha256(symKey) hex-encoded.
func topicFromSymKey(symKey []byte) string {
	sum := sha256.Sum256(symKey)
	return hex.EncodeToString(sum[:])
}

// topicFromDerivedKey returns the sha256-hex topic for a derived session
// key (the HKDF output of X25519(self, peer)).
func topicFromDerivedKey(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}
