// Wallet import endpoints — Wallet:importPrivateKey and
// Wallet:importMnemonic. Imported wallets are 1-of-1 (no TSS), use
// the new Schema=="raw" / Schema=="mnemonic" WalletKey content
// types, and are signable immediately. They can be promoted to a
// normal multi-share TSS wallet via Wallet:promote (see promote.go).

package wltwallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/xuid"
	"github.com/tyler-smith/go-bip39"
)

// apiImportPrivateKey implements Wallet:importPrivateKey.
//
//	PrivateKey  string  // 0x-prefixed hex / bare hex / WIF (auto-sniffed)
//	Curve       string  // "secp256k1" | "ed25519"
//	Name        string
//	Keys        []*wltsign.KeyDescription  // length 1 — encryption for the RawKey blob
func apiImportPrivateKey(ctx *apirouter.Context, in struct {
	PrivateKey string
	Curve      string
	Name       string
	Keys       []*wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if len(in.Keys) != 1 {
		return nil, fmt.Errorf("import requires exactly 1 KeyDescription (got %d)", len(in.Keys))
	}
	if in.Curve != "secp256k1" && in.Curve != "ed25519" {
		return nil, fmt.Errorf("unsupported curve %q", in.Curve)
	}

	priv, err := parseImportedPrivkey(in.PrivateKey, in.Curve)
	if err != nil {
		return nil, fmt.Errorf("PrivateKey: %w", err)
	}
	defer zero(priv)

	chaincode, err := randomChaincode()
	if err != nil {
		return nil, err
	}

	share := &RawKeyShare{
		Curve:     in.Curve,
		Privkey:   priv,
		Chaincode: chaincode,
	}
	return buildImportedWallet(e, in.Name, in.Curve, share, nil, in.Keys[0])
}

// apiImportMnemonic implements Wallet:importMnemonic.
//
//	Mnemonic    string  // 12/15/18/21/24 BIP39 words
//	Passphrase  string  // optional BIP39 passphrase ("" when absent)
//	Curve       string
//	Name        string
//	Keys        []*wltsign.KeyDescription  // length 1
func apiImportMnemonic(ctx *apirouter.Context, in struct {
	Mnemonic   string
	Passphrase string
	Curve      string
	Name       string
	Keys       []*wltsign.KeyDescription
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if len(in.Keys) != 1 {
		return nil, fmt.Errorf("import requires exactly 1 KeyDescription (got %d)", len(in.Keys))
	}
	if in.Curve != "secp256k1" && in.Curve != "ed25519" {
		return nil, fmt.Errorf("unsupported curve %q", in.Curve)
	}

	entropy, language, err := decodeMnemonic(strings.TrimSpace(in.Mnemonic))
	if err != nil {
		return nil, fmt.Errorf("Mnemonic: %w", err)
	}

	share := &MnemonicKeyShare{
		Curve:      in.Curve,
		Entropy:    entropy,
		Language:   language,
		Passphrase: in.Passphrase,
	}
	return buildImportedWallet(e, in.Name, in.Curve, nil, share, in.Keys[0])
}

// buildImportedWallet is the shared backend for the two import
// endpoints. Exactly one of (raw, mnem) must be non-nil.
func buildImportedWallet(
	e wltintf.Env,
	name, curve string,
	raw *RawKeyShare,
	mnem *MnemonicKeyShare,
	keyDesc *wltsign.KeyDescription,
) (*Wallet, error) {
	// Compute the wallet's master pubkey + chaincode. This is what the
	// Account layer reads to derive child accounts via non-hardened
	// HD; for imported wallets the master = the imported (or derived)
	// privkey because there's no TSS layer in between.
	pub, chaincode, err := masterPubFromShare(curve, raw, mnem)
	if err != nil {
		return nil, err
	}

	w := &Wallet{
		Id:        xuid.New("wlet"),
		Name:      name,
		Curve:     curve,
		Threshold: 0, // 1-of-1 marker; promoted wallets get a real threshold
		Pubkey:    base64.RawURLEncoding.EncodeToString(pub),
		Chaincode: base64.RawURLEncoding.EncodeToString(chaincode),
		Created:   time.Now(),
		Modified:  time.Now(),
	}
	wk := &WalletKey{
		Id:       xuid.New("wkey"),
		Wallet:   w.Id,
		Gen:      1,
		rawData:  raw,
		mnemonic: mnem,
	}
	if err := wk.encrypt(keyDesc); err != nil {
		return nil, fmt.Errorf("encrypt imported share: %w", err)
	}
	w.Keys = []*WalletKey{wk}
	if err := w.save(e); err != nil {
		return nil, err
	}
	return w, nil
}

// masterPubFromShare resolves the wallet-level (pubkey, chaincode)
// pair for an imported share. For raw imports the chaincode comes
// from the share itself; for mnemonic imports we derive the BIP32 /
// SLIP-0010 master and use its chaincode (so non-hardened child
// derivation works the same way it does for TSS-created wallets).
func masterPubFromShare(curve string, raw *RawKeyShare, mnem *MnemonicKeyShare) (pub, chaincode []byte, err error) {
	switch {
	case raw != nil:
		pub, err = derivePub(curve, raw.Privkey)
		if err != nil {
			return nil, nil, err
		}
		return pub, raw.Chaincode, nil
	case mnem != nil:
		seed, err := mnemonicToSeed(mnem)
		if err != nil {
			return nil, nil, err
		}
		defer zero(seed)
		master, cc, err := masterFromSeed(seed, curve)
		if err != nil {
			return nil, nil, err
		}
		defer zero(master)
		pub, err = derivePub(curve, master)
		if err != nil {
			return nil, nil, err
		}
		return pub, cc, nil
	default:
		return nil, nil, errors.New("masterPubFromShare: no share provided")
	}
}

// derivePub returns the canonical compressed public key for an
// imported privkey.
//   - secp256k1: 33-byte compressed SEC1
//   - ed25519:    32-byte raw pubkey
func derivePub(curve string, priv []byte) ([]byte, error) {
	switch curve {
	case "secp256k1":
		if len(priv) != 32 {
			return nil, fmt.Errorf("secp256k1 privkey must be 32 bytes, got %d", len(priv))
		}
		k := secp256k1.PrivKeyFromBytes(priv)
		return k.PubKey().SerializeCompressed(), nil
	case "ed25519":
		if len(priv) != 32 {
			return nil, fmt.Errorf("ed25519 seed must be 32 bytes, got %d", len(priv))
		}
		full := ed25519.NewKeyFromSeed(priv)
		defer zero(full)
		// Public key = last 32 bytes of the expanded ed25519 key.
		out := make([]byte, ed25519.PublicKeySize)
		copy(out, full[ed25519.PublicKeySize:])
		return out, nil
	default:
		return nil, fmt.Errorf("derivePub: unsupported curve %q", curve)
	}
}

// parseImportedPrivkey accepts a hex string (with or without 0x
// prefix) or a Bitcoin-family WIF string and returns the raw 32-byte
// private key. WIF currently only sniffs secp256k1; ed25519 imports
// must be hex.
func parseImportedPrivkey(input, curve string) ([]byte, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, errors.New("empty private key")
	}

	// WIF sniff: secp256k1-only. WIF strings are base58check-encoded
	// and on mainnet start with 5 (uncompressed) / K | L (compressed);
	// testnet starts with 9 / c. Anything that decodes as base58check
	// with one of the known version bytes is treated as WIF.
	if curve == "secp256k1" && looksLikeWIF(s) {
		priv, err := decodeWIF(s)
		if err == nil {
			return priv, nil
		}
		// Fall through to hex if WIF decode fails — the input might
		// just look WIF-ish but actually be hex.
	}

	// Hex (with or without 0x prefix).
	hexStr := strings.TrimPrefix(s, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("hex private key must be 64 chars, got %d", len(hexStr))
	}
	priv, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return priv, nil
}

// looksLikeWIF returns true for strings whose first character matches
// a known WIF version-byte prefix on a typical chain (Bitcoin /
// Litecoin mainnet + testnet — covers the formats users actually
// paste in). False positives are harmless because decodeWIF then
// validates the base58check checksum.
func looksLikeWIF(s string) bool {
	if len(s) < 50 || len(s) > 53 {
		return false
	}
	switch s[0] {
	case '5', 'K', 'L', '9', 'c', 'T', 'M', '6':
		return true
	}
	return false
}

// decodeWIF parses a Wallet Import Format string (BIP-178). Format:
//
//	base58check( version_byte || privkey[32] || (compressed_flag 0x01)? )
//
// Returns the raw 32-byte private key. We don't keep the version
// byte because the imported wallet's curve is provided by the
// caller; WIF mostly carries chain metadata that we don't use.
func decodeWIF(s string) ([]byte, error) {
	raw, err := base58.Bitcoin.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("decode base58: %w", err)
	}
	if len(raw) < 1+32+4 {
		return nil, errors.New("WIF payload too short")
	}
	// Verify the trailing 4-byte checksum: sha256(sha256(payload[:-4]))[:4]
	body, want := raw[:len(raw)-4], raw[len(raw)-4:]
	h1 := sha256.Sum256(body)
	h2 := sha256.Sum256(h1[:])
	if !equalBytes(h2[:4], want) {
		return nil, errors.New("WIF checksum mismatch")
	}
	// body = version_byte || privkey[32] || (0x01)?
	priv := body[1:33]
	if len(body) > 33 {
		// Compressed-pubkey marker; we ignore the flag (libwallet always
		// uses compressed pubkeys), just verify it's the canonical 0x01.
		if body[33] != 0x01 {
			return nil, fmt.Errorf("unexpected WIF trailing byte 0x%02x", body[33])
		}
	}
	out := make([]byte, 32)
	copy(out, priv)
	return out, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// decodeMnemonic detects the BIP39 wordlist language from the input
// (by checking which language's wordlist contains all the words),
// returns the entropy bytes the mnemonic encodes, plus the detected
// language tag. Returns an error if the words don't match any known
// wordlist or fail BIP39's checksum validation.
func decodeMnemonic(mnemonic string) (entropy []byte, language string, err error) {
	prevList := bip39.GetWordList()
	defer bip39.SetWordList(prevList)

	for _, lang := range []string{
		"english",
		"japanese",
		"korean",
		"spanish",
		"chinese_simplified",
		"chinese_traditional",
		"french",
		"italian",
		"czech",
	} {
		list := wordlistByName(lang)
		if list == nil {
			continue
		}
		bip39.SetWordList(list)
		ent, err := bip39.EntropyFromMnemonic(mnemonic)
		if err == nil {
			return ent, lang, nil
		}
	}
	return nil, "", errors.New("mnemonic does not match any known BIP39 wordlist (or fails checksum)")
}

// randomChaincode returns 32 bytes of cryptographic randomness used
// as the wallet's HD chaincode for non-hardened child derivation.
// The value is opaque after import; users never see it.
func randomChaincode() ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, fmt.Errorf("randomChaincode: %w", err)
	}
	return out, nil
}
