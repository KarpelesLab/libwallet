package wltswap

// Solana-side helpers shared by the Jupiter and dFlow adapters:
//
//   - wSOL mint sentinel for "NATIVE" tokens
//   - compact-u16 parsing (used to walk the Solana wire format)
//   - local signing + signature splicing for pre-built transactions
//     returned by aggregators (Jupiter Ultra / dFlow /swap)

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// WrappedSOLMint is the canonical Solana mint for "wrapped SOL",
// used by Jupiter / dFlow / Solana DEXs as the sentinel for the
// native SOL token in swap routes.
const WrappedSOLMint = "So11111111111111111111111111111111111111112"

// solanaNativeMintOrAddr maps the package's "NATIVE" sentinel to
// wSOL's mint. Any other value is returned with the chain-key
// prefix stripped if present — callers can pass either the bare
// mint ("EPjFW…") or the Asset.Key form ("solana.mainnet.EPjFW…")
// returned by `Asset:list`; both resolve to the bare form Jupiter
// / dFlow expect on the wire.
func solanaNativeMintOrAddr(addr string) string {
	addr = stripChainPrefix(addr)
	if addr == "NATIVE" || addr == "" {
		return WrappedSOLMint
	}
	return addr
}

// stripChainPrefix removes the leading "<type>.<chainId>." prefix
// from an Asset.Key-shaped address ("solana.mainnet.EPjFW…",
// "evm.1.0xA0b8…"), returning the bare mint / contract.
//
// EVM addresses (0x-hex) and Solana mints (base58) never contain a
// dot, so splitting on "." and taking the last segment is always
// safe. Bare inputs (no dot) pass through unchanged. The "NATIVE"
// sentinel pre- or post-prefix likewise round-trips.
func stripChainPrefix(addr string) string {
	if idx := strings.LastIndexByte(addr, '.'); idx >= 0 {
		return addr[idx+1:]
	}
	return addr
}

// parseFloat is a permissive strconv.ParseFloat — returns 0 on
// empty or malformed input rather than propagating the error.
// Used for the provider-reported priceImpactPct fields where we'd
// rather silently drop a parse miss than fail the whole quote.
func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

// decodeCompactU16 reads Solana's compact-u16 varint at pos and
// returns (value, bytesRead, error).
//
// Compact-u16 is a 1–3 byte little-endian varint: each byte carries
// 7 payload bits; the high bit signals "another byte follows".
// Used for numSignatures, numAccounts, numInstructions, etc.
func decodeCompactU16(b []byte, pos int) (uint16, int, error) {
	if pos >= len(b) {
		return 0, 0, fmt.Errorf("compact-u16: pos %d past end of %d-byte slice", pos, len(b))
	}
	var v uint16
	n := 0
	for shift := uint(0); shift <= 14; shift += 7 {
		if pos+n >= len(b) {
			return 0, 0, fmt.Errorf("compact-u16: truncated")
		}
		byteVal := b[pos+n]
		n++
		v |= uint16(byteVal&0x7f) << shift
		if byteVal&0x80 == 0 {
			return v, n, nil
		}
	}
	return 0, 0, fmt.Errorf("compact-u16: too many bytes")
}

// solanaSplicingSignLocal extracts the message from an aggregator-
// built Solana transaction, signs it via the user's TSS keys, and
// splices the signature into slot 0. Returns the fully-signed
// transaction ready to broadcast or post back to /execute.
//
// Layout of the input rawTx (both legacy and versioned):
//
//   [compact-u16 numSignatures] [numSignatures * 64 bytes] [message...]
//
// We never parse the message — we just locate its start offset,
// sign the bytes, and drop the signature into the first 64-byte
// slot. The adapter assumes the user is the fee payer (slot 0),
// which is always true for Jupiter Ultra / dFlow swaps.
func solanaSplicingSignLocal(ctx context.Context, acct *wltacct.Account, keys []*wltsign.KeyDescription, rawTx []byte) ([]byte, error) {
	if len(rawTx) < 1 {
		return nil, fmt.Errorf("empty transaction")
	}
	numSigs, consumed, err := decodeCompactU16(rawTx, 0)
	if err != nil {
		return nil, fmt.Errorf("parse numSignatures: %w", err)
	}
	if numSigs < 1 {
		return nil, fmt.Errorf("transaction declares 0 signers — cannot splice user signature")
	}
	sigsEnd := consumed + int(numSigs)*64
	if sigsEnd > len(rawTx) {
		return nil, fmt.Errorf("signatures truncated: declared %d, tx only %d bytes", numSigs, len(rawTx))
	}
	message := rawTx[sigsEnd:]

	signOpt := &wltsign.Opts{Context: ctx, Keys: keys}
	signStart := time.Now()
	sig, err := acct.Sign(nil, message, signOpt)
	if err != nil {
		wltlog.Errorf("swap: Solana splice-sign failed after %s: %s", time.Since(signStart).Round(time.Millisecond), err)
		return nil, fmt.Errorf("sign message: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("unexpected signature length %d", len(sig))
	}

	// Local verify so an upstream "signature verification failed"
	// rejection can be ruled out before we broadcast. Uses the
	// account address (fee-payer pubkey) we just signed under.
	pubBytes, err := base58.Bitcoin.Decode(acct.GetAddress())
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decode fee-payer pubkey: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), message, sig) {
		return nil, fmt.Errorf("signature does not verify under fee-payer pubkey — TSS key shares may be inconsistent")
	}

	// Splice: copy the signed bytes into slot 0.
	out := make([]byte, len(rawTx))
	copy(out, rawTx)
	copy(out[consumed:consumed+64], sig)
	return out, nil
}

// encodeCompactU16 is the inverse of decodeCompactU16; used by
// providers that ask us to build the transaction frame rather than
// amend an existing one. Currently unused but kept next to the
// decoder so future adapters find it immediately.
func encodeCompactU16(v uint16) []byte {
	if v <= 0x7f {
		return []byte{byte(v)}
	}
	if v <= 0x3fff {
		return []byte{byte(v&0x7f) | 0x80, byte(v >> 7)}
	}
	return []byte{byte(v&0x7f) | 0x80, byte((v>>7)&0x7f) | 0x80, byte(v >> 14)}
}
