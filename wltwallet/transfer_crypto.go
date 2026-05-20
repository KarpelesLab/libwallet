package wltwallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Per-session key derivation for the device-transfer flow. The
// pairing token (32 bytes, generated on the OLD device and embedded
// in the QR alongside the Spot id + sid) seeds an HKDF-SHA-256
// expansion bound to a constant info label so unrelated callers
// can't accidentally collide on the same key.
//
// Why a token-derived layer on top of Spot's bottle encryption:
// Spot already encrypts the request/response under the recipient's
// IDCard, so a passive observer on the Spot transport can't read
// the device share. The HKDF layer is defense-in-depth: even if a
// future Spot bug exposes the bottle plaintext, the payload stays
// opaque to anyone who doesn't possess the out-of-band token from
// the QR.
const (
	transferKeyBytes   = 32                          // AES-256 key length
	transferTokenBytes = 32                          // bytes of randomness in the pairing token
	transferKeyInfo    = "libwallet-device-transfer" // HKDF info — change requires protocol-version bump
)

// deriveTransferKey produces a 32-byte AES key from a pairing
// token + the session id. The sid is mixed in as the HKDF salt so
// two simultaneous transfers (same device, two sessions) can never
// produce the same key even by chance.
func deriveTransferKey(token []byte, sid string) ([]byte, error) {
	if len(token) != transferTokenBytes {
		return nil, fmt.Errorf("transfer: token must be %d bytes, got %d", transferTokenBytes, len(token))
	}
	if sid == "" {
		return nil, errors.New("transfer: sid must be non-empty for key derivation")
	}
	kdf := hkdf.New(sha256.New, token, []byte(sid), []byte(transferKeyInfo))
	out := make([]byte, transferKeyBytes)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

// sealTransferPayload encrypts plaintext under a key derived from
// (token, sid) using AES-256-GCM. The output is nonce || ciphertext;
// the GCM auth tag is appended to the ciphertext per the standard
// crypto/cipher convention. Returns an error if any input is malformed.
func sealTransferPayload(token []byte, sid string, plaintext []byte) ([]byte, error) {
	key, err := deriveTransferKey(token, sid)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Sid binds the ciphertext to this specific session — a transfer
	// payload from session A can't be replayed as a response in
	// session B even if the same token were ever reused (it isn't,
	// but the binding makes the property defensive).
	ct := gcm.Seal(nil, nonce, plaintext, []byte(sid))
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// openTransferPayload reverses sealTransferPayload. Decryption fails
// if the key derived from (token, sid) doesn't match the one used
// to seal, the nonce/tag is wrong, or the additional-data sid
// doesn't match. Returns the original plaintext or an error — never
// a partial decryption.
func openTransferPayload(token []byte, sid string, sealed []byte) ([]byte, error) {
	key, err := deriveTransferKey(token, sid)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize+gcm.Overhead() {
		return nil, errors.New("transfer: ciphertext too short")
	}
	nonce, ct := sealed[:nonceSize], sealed[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, []byte(sid))
	if err != nil {
		return nil, fmt.Errorf("transfer: decrypt: %w", err)
	}
	return pt, nil
}

// constantTimeTokenEqual is a thin wrapper around hmac.Equal used to
// compare incoming token bytes against the session's stored token.
// hmac.Equal already does the constant-time compare; named here for
// intent + so the call site reads cleanly without dragging hmac into
// the picture.
func constantTimeTokenEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
