// Sign path for imported single-share wallets (Schema = "raw" or
// "mnemonic"). These bypass the TSS protocol entirely — there's only
// one party and it holds the full private key, so the 9-round MTA
// dance would be wasted work. Output is the same DER (secp256k1) /
// raw 64-byte (ed25519) shape that ecdsatss / eddsatss produce, so
// downstream callers (Account.Sign, SignEthereumDigest, etc.) don't
// branch.

package wltwallet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

// signRaw is the imported-wallet sign entry point dispatched from
// Wallet.Sign when the wallet has a single Schema=="raw" /
// Schema=="mnemonic" share. opts must be a *wltsign.Opts.
func (w *Wallet) signRaw(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	aopt, ok := opts.(*wltsign.Opts)
	if !ok {
		return nil, errors.New("sign requires *wltsign.Opts")
	}
	if len(aopt.Keys) != 1 {
		return nil, fmt.Errorf("imported single-share wallet expects 1 KeyDescription, got %d", len(aopt.Keys))
	}
	wk := w.Keys[0]

	// Resolve the leaf private key (post-HD-derivation) for this signature.
	curve, leafPriv, err := w.deriveLeafPrivkey(wk, aopt)
	if err != nil {
		return nil, err
	}
	defer zero(leafPriv)

	switch curve {
	case "secp256k1":
		// DER output matches what ecdsatss returns. wltacct/eth_sign.go's
		// SignEthereumDigest converts DER → wire format on top of this.
		priv := secp256k1.PrivKeyFromBytes(leafPriv).ToECDSA()
		return ecdsa.SignASN1(rand.Reader, priv, digest)
	case "ed25519":
		// ed25519.NewKeyFromSeed expands a 32-byte seed into the full 64-byte
		// secret key (seed||publickey). Sign returns the 64-byte signature
		// shape eddsatss uses.
		full := ed25519.NewKeyFromSeed(leafPriv)
		defer zero(full)
		return ed25519.Sign(full, digest), nil
	default:
		return nil, fmt.Errorf("unsupported curve %q for imported wallet", curve)
	}
}

// deriveLeafPrivkey decrypts the imported share and applies any
// HD-derivation requested by the Account that initiated the sign
// (Account.Sign passes its IL on aopt.IL — for imports we instead
// re-derive directly from the master, since imports may use full
// BIP44 paths including hardened components that the standard
// "non-hardened only" Account.IL path can't represent).
//
// Returns (curve, 32-byte leaf privkey, err).
func (w *Wallet) deriveLeafPrivkey(wk *WalletKey, aopt *wltsign.Opts) (string, []byte, error) {
	switch wk.Schema {
	case "raw":
		share, err := wk.decryptRaw(aopt.Keys[0])
		if err != nil {
			return "", nil, err
		}
		// Raw imports: the privkey IS the master. If the caller
		// requested HD derivation via aopt.IL, apply the same
		// non-hardened tweak Account.DerivePublicKey already used
		// to derive the public key — IL added (mod n) to the master
		// privkey yields the leaf privkey for secp256k1.
		if share.Curve == "secp256k1" && aopt.IL != nil {
			leaf := tweakSecp256k1(share.Privkey, aopt.IL)
			return share.Curve, leaf, nil
		}
		// ed25519 has no in-protocol HD; the master privkey IS the
		// account key. (Solana wallets typically don't derive child
		// accounts at runtime — Account.init sets IL=nil for ed25519.)
		out := make([]byte, len(share.Privkey))
		copy(out, share.Privkey)
		return share.Curve, out, nil
	case "mnemonic":
		share, err := wk.decryptMnemonic(aopt.Keys[0])
		if err != nil {
			return "", nil, err
		}
		seed, err := mnemonicToSeed(share)
		if err != nil {
			return "", nil, err
		}
		defer zero(seed)
		// Master derivation: BIP32 (secp256k1) or SLIP-0010 (ed25519).
		master, chaincode, err := masterFromSeed(seed, share.Curve)
		if err != nil {
			return "", nil, err
		}
		defer zero(chaincode)
		// Apply HD derivation if requested. Same caveat as above —
		// non-hardened only via Account.IL; hardened paths happen at
		// import time (deferred to the import API).
		if share.Curve == "secp256k1" && aopt.IL != nil {
			leaf := tweakSecp256k1(master, aopt.IL)
			return share.Curve, leaf, nil
		}
		return share.Curve, master, nil
	default:
		return "", nil, fmt.Errorf("walletkey %s: unexpected schema %q", wk.Id, wk.Schema)
	}
}

// tweakSecp256k1 computes (master + IL) mod n for non-hardened BIP32
// child derivation. This mirrors what ecckd.DeriveWithIL does on the
// public side: child_pub = master_pub + IL*G, child_priv = master_priv + IL.
// Returns a fresh 32-byte slice so the caller can safely zero it.
func tweakSecp256k1(master []byte, IL *big.Int) []byte {
	n := secp256k1.S256().Params().N
	x := new(big.Int).SetBytes(master)
	x.Add(x, IL)
	x.Mod(x, n)
	out := make([]byte, 32)
	xb := x.Bytes()
	copy(out[32-len(xb):], xb)
	return out
}

// mnemonicToSeed reconstructs the BIP39 mnemonic string from the
// stored entropy + language and runs PBKDF2 to produce the 64-byte
// seed. Re-encoding entropy in the original language keeps the seed
// stable; users can still display the mnemonic in another language
// for backup purposes.
func mnemonicToSeed(share *MnemonicKeyShare) ([]byte, error) {
	prevList := bip39.GetWordList()
	if list := wordlistByName(share.Language); list != nil {
		bip39.SetWordList(list)
		defer bip39.SetWordList(prevList)
	}
	mnemonic, err := bip39.NewMnemonic(share.Entropy)
	if err != nil {
		return nil, fmt.Errorf("bip39: re-encode entropy: %w", err)
	}
	return bip39.NewSeed(mnemonic, share.Passphrase), nil
}

// wordlistByName returns the bip39 wordlist for a given language tag,
// or nil if the tag is empty / unrecognized (caller falls back to the
// library's current default — English).
func wordlistByName(lang string) []string {
	switch strings.ToLower(lang) {
	case "", "english":
		return wordlists.English
	case "japanese":
		return wordlists.Japanese
	case "korean":
		return wordlists.Korean
	case "spanish":
		return wordlists.Spanish
	case "chinese_simplified", "zh-hans":
		return wordlists.ChineseSimplified
	case "chinese_traditional", "zh-hant":
		return wordlists.ChineseTraditional
	case "french":
		return wordlists.French
	case "italian":
		return wordlists.Italian
	case "czech":
		return wordlists.Czech
	}
	return nil
}

// masterFromSeed runs the curve-appropriate master-key derivation on
// a 64-byte BIP39 seed. Returns (master_privkey, master_chaincode).
//
//   - secp256k1: BIP32   — HMAC-SHA512(key="Bitcoin seed", seed)
//   - ed25519:   SLIP-0010 — HMAC-SHA512(key="ed25519 seed", seed)
//
// SLIP-0010 only supports hardened derivation for ed25519; non-hardened
// derivation is impossible on Edwards curves without leaking the priv
// key, so for ed25519 the master IS the only account-level key the
// non-import wallet flow currently uses (Account.init sets IL=nil).
func masterFromSeed(seed []byte, curve string) ([]byte, []byte, error) {
	var hmacKey []byte
	switch curve {
	case "secp256k1":
		hmacKey = []byte("Bitcoin seed")
	case "ed25519":
		hmacKey = []byte("ed25519 seed")
	default:
		return nil, nil, fmt.Errorf("masterFromSeed: unsupported curve %q", curve)
	}
	h := hmac.New(sha512.New, hmacKey)
	h.Write(seed)
	out := h.Sum(nil)
	priv, chaincode := out[:32], out[32:]

	if curve == "secp256k1" {
		// BIP32 §3: reject masters where IL == 0 or IL >= n. Probability
		// is astronomically small but mathematically possible.
		x := new(big.Int).SetBytes(priv)
		n := secp256k1.S256().Params().N
		if x.Sign() == 0 || x.Cmp(n) >= 0 {
			return nil, nil, errors.New("bip32: invalid master key (re-derive with different mnemonic)")
		}
	}
	// ed25519 SLIP-0010: any 32 bytes are a valid clamped seed; no rejection rule.

	privCopy := make([]byte, 32)
	copy(privCopy, priv)
	chainCopy := make([]byte, 32)
	copy(chainCopy, chaincode)
	zero(out)
	return privCopy, chainCopy, nil
}

// derivePrivkeyFromSeed walks the given BIP32-style path against a
// BIP39 seed and returns the resulting 32-byte private key.
//
//   - secp256k1 with a non-empty path: full BIP32 derivation (via
//     ecckd), hardened components supported. Path uses '-suffix
//     notation, e.g. "m/44'/60'/0'/0/0".
//   - secp256k1 with empty path (or just "m"): the BIP32 master
//     privkey from the seed (HMAC-SHA512 "Bitcoin seed").
//   - ed25519 with a non-empty path: SLIP-0010 hardened-only
//     derivation, also '-suffix notation. Non-hardened components
//     are a protocol error on Edwards curves; the helper rejects.
//   - ed25519 with empty path (or "m"): the BIP39 PBKDF2 seed's
//     first 32 bytes used directly as the ed25519 seed (the Sollet /
//     Solana Mobile / Backpack convention). For Phantom-style
//     derivation pass an explicit path "m/44'/501'/0'/0'".
//
// The returned byte slice is a fresh copy that the caller should
// `zero` when done.
func derivePrivkeyFromSeed(seed []byte, curve, path string) ([]byte, error) {
	steps, err := parseBip32Path(path)
	if err != nil {
		return nil, err
	}

	switch curve {
	case "secp256k1":
		xk, err := ecckd.FromBitcoinSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("bip32: master from seed: %w", err)
		}
		if len(steps) > 0 {
			xk, err = xk.Derive(steps)
			if err != nil {
				return nil, fmt.Errorf("bip32: derive %q: %w", path, err)
			}
		}
		if !xk.IsPrivate() || len(xk.KeyData) != 32 {
			return nil, fmt.Errorf("bip32: derive %q produced non-private key data", path)
		}
		out := make([]byte, 32)
		copy(out, xk.KeyData)
		return out, nil

	case "ed25519":
		// Empty path / "m": no-derivation Sollet convention (seed[:32]).
		if len(steps) == 0 {
			if len(seed) < 32 {
				return nil, errors.New("seed too short for ed25519 no-derivation mode")
			}
			out := make([]byte, 32)
			copy(out, seed[:32])
			return out, nil
		}
		return slip10DeriveEd25519(seed, steps)

	default:
		return nil, fmt.Errorf("derivePrivkeyFromSeed: unsupported curve %q", curve)
	}
}

// parseBip32Path converts a string path like "m/44'/60'/0'/0/0" (or
// "m/44h/60h/..." — both notations are accepted) into the []uint32
// ecckd.Derive expects, with the hardened bit OR'd in where
// appropriate. Empty string and bare "m" mean "master, no child
// steps".
func parseBip32Path(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "m" || path == "M" {
		return nil, nil
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 || (parts[0] != "m" && parts[0] != "M") {
		return nil, fmt.Errorf("bip32 path %q must start with m/", path)
	}
	out := make([]uint32, 0, len(parts)-1)
	for _, p := range parts[1:] {
		if p == "" {
			return nil, fmt.Errorf("bip32 path %q has an empty component", path)
		}
		hardened := false
		last := p[len(p)-1]
		if last == '\'' || last == 'h' || last == 'H' {
			hardened = true
			p = p[:len(p)-1]
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bip32 path %q component %q: %w", path, p, err)
		}
		if n >= 0x80000000 {
			return nil, fmt.Errorf("bip32 path %q component %q: value overflows 31 bits (use ' for hardened)", path, p)
		}
		v := uint32(n)
		if hardened {
			v |= 0x80000000
		}
		out = append(out, v)
	}
	return out, nil
}

// slip10DeriveEd25519 walks the all-hardened path against a BIP39
// seed using SLIP-0010 "ed25519 seed" master + hardened child
// derivation. All components MUST be hardened; non-hardened child
// derivation on Edwards curves would leak the private key.
func slip10DeriveEd25519(seed []byte, path []uint32) ([]byte, error) {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	I := h.Sum(nil)
	priv := I[:32]
	chaincode := I[32:]
	buf := make([]byte, 1+32+4)

	for i, idx := range path {
		if idx&0x80000000 == 0 {
			return nil, fmt.Errorf("SLIP-0010 ed25519: path component %d=%d must be hardened", i, idx)
		}
		buf[0] = 0x00
		copy(buf[1:33], priv)
		buf[33] = byte(idx >> 24)
		buf[34] = byte(idx >> 16)
		buf[35] = byte(idx >> 8)
		buf[36] = byte(idx)
		hh := hmac.New(sha512.New, chaincode)
		hh.Write(buf)
		next := hh.Sum(nil)
		priv = next[:32]
		chaincode = next[32:]
	}

	out := make([]byte, 32)
	copy(out, priv)
	return out, nil
}

// derivePubkeyForPath returns the canonical public representation of
// the privkey that derivePrivkeyFromSeed would produce for the given
// seed + curve + path. Handy for the probe endpoint which needs the
// address without actually touching the signing path.
//
//   - secp256k1 → 33-byte compressed SEC1 pubkey
//   - ed25519    → 32-byte raw pubkey
func derivePubkeyForPath(seed []byte, curve, path string) ([]byte, error) {
	priv, err := derivePrivkeyFromSeed(seed, curve, path)
	if err != nil {
		return nil, err
	}
	defer zero(priv)
	return derivePub(curve, priv)
}

// zero best-effort wipes a byte slice in place so a decrypted private
// key doesn't sit in the heap longer than necessary. Not a defense
// against a determined memory inspector — Go's GC may have already
// copied the slice — but cheap insurance for short-lived sign paths.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

