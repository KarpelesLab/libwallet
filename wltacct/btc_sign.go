package wltacct

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/KarpelesLab/secp256k1"
)

// Bitcoin-family message signing.
//
// This file wires secp256k1 TSS output (DER on the common path) to the
// Bitcoin compact signature format with recovery byte: a single byte
// (header = v + offset) followed by 32-byte R and 32-byte S, for a total
// of 65 bytes. Bitcoin Core's `signmessage` RPC uses the same shape,
// base64-encoded. Offset is 31 for P2PKH addresses derived from a
// compressed pubkey (our case — TSS pubkeys are compressed).

// bitcoinMsgPrefix holds per-chain magic strings for the
// "<length-byte><magic-string>" prefix used in message signing.
//
// All strings are exactly `<magic>` without the length byte — we prepend
// the byte at use-time so forgetting it here doesn't cause silent
// signature-verification mismatches downstream.
var bitcoinMsgPrefix = map[string]string{
	"bitcoin":     "Bitcoin Signed Message:\n",
	"bitcoincash": "Bitcoin Signed Message:\n",
	"litecoin":    "Litecoin Signed Message:\n",
	"dogecoin":    "Dogecoin Signed Message:\n",
	"monacoin":    "Monacoin Signed Message:\n",
}

// BitcoinMessagePrefix returns the full byte prefix (length byte + magic)
// for the given Bitcoin-family chain id. `ok` is false for chains we don't
// know about — the caller should refuse to sign rather than guess.
func BitcoinMessagePrefix(chainId string) ([]byte, bool) {
	magic, ok := bitcoinMsgPrefix[chainId]
	if !ok {
		return nil, false
	}
	buf := make([]byte, 0, 1+len(magic))
	buf = append(buf, byte(len(magic)))
	buf = append(buf, magic...)
	return buf, true
}

// SignCompact produces a 65-byte compact ECDSA signature over hash using
// the account's TSS key. The recovery byte is brute-forced from the known
// pubkey (because the TSS→DER path drops the recovery ID).
//
// `headerOffset` is added to the recovery ID to form the header byte —
// use 31 for compressed-pubkey P2PKH / P2WPKH addresses, 27 for
// uncompressed. Bitcoin message signing uses 31 for modern (compressed)
// addresses.
func (a *Account) SignCompact(hash []byte, headerOffset byte, opts crypto.SignerOpts) ([]byte, error) {
	if a.Curve != "secp256k1" {
		return nil, errors.New("SignCompact requires a secp256k1 account")
	}

	derSig, err := a.Sign(rand.Reader, hash, opts)
	if err != nil {
		return nil, fmt.Errorf("tss sign: %w", err)
	}
	sig, err := secp256k1.ParseDERSignature(derSig)
	if err != nil {
		return nil, fmt.Errorf("parse tss signature: %w", err)
	}
	pub := a.PublicKey()
	if pub == nil {
		return nil, errors.New("account has no usable public key")
	}
	if !sig.BruteforceRecoveryCode(hash, pub) {
		return nil, errors.New("could not determine signature recovery code")
	}
	return sig.ExportCompact(true, headerOffset), nil
}

// SignBitcoinMessage computes the Bitcoin-family signed-message digest and
// signs it, returning the 65-byte compact signature.
//
// Digest = double-SHA256( prefix || varint(len(message)) || message )
// where prefix is the per-chain magic (via BitcoinMessagePrefix).
func (a *Account) SignBitcoinMessage(prefix, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	full := make([]byte, 0, len(prefix)+9+len(message))
	full = append(full, prefix...)
	full = appendVarInt(full, uint64(len(message)))
	full = append(full, message...)

	h1 := sha256.Sum256(full)
	h2 := sha256.Sum256(h1[:])
	return a.SignCompact(h2[:], 31, opts)
}

// appendVarInt appends a Bitcoin-style variable-length integer.
func appendVarInt(buf []byte, n uint64) []byte {
	switch {
	case n < 0xfd:
		return append(buf, byte(n))
	case n <= 0xffff:
		var b [3]byte
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return append(buf, b[:]...)
	case n <= 0xffffffff:
		var b [5]byte
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		return append(buf, b[:]...)
	default:
		var b [9]byte
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		return append(buf, b[:]...)
	}
}
