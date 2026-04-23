package wltwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
)

// Round-trip the raw signRaw + parsing helpers without touching the
// DB: build a *Wallet + *WalletKey directly from a known privkey,
// run the same Wallet.Sign path Account.Sign would, then verify the
// signature against the expected pubkey. Catches any drift in the
// "imported share → DER signature" pipeline independently of the
// (heavier) Account / Env / persistence layer.

func TestRawSign_Secp256k1(t *testing.T) {
	// Well-known privkey 0x000…001 → pubkey is the secp256k1 generator.
	priv := make([]byte, 32)
	priv[31] = 1
	pubExpected := secp256k1.PrivKeyFromBytes(priv).PubKey().SerializeCompressed()

	w, wk := makeRawWallet(t, "secp256k1", priv, "Plain")

	// Sanity-check our derivePub against the same library Account uses.
	pub, err := derivePub("secp256k1", priv)
	if err != nil {
		t.Fatalf("derivePub: %v", err)
	}
	if !bytesEq(pub, pubExpected) {
		t.Fatalf("derivePub mismatch:\n  got=%x\n want=%x", pub, pubExpected)
	}

	// Sign-then-verify round trip.
	digest := sha256d([]byte("hello libwallet import"))
	sig, err := w.Sign(nil, digest, &wltsign.Opts{
		Context: context.Background(),
		Keys:    []*wltsign.KeyDescription{{Type: "Plain"}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Parse DER → r, s and verify with stdlib ecdsa.
	pubKey, err := secp256k1.ParsePubKey(pubExpected)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey.ToECDSA(), digest, sig) {
		t.Fatalf("signature did not verify")
	}

	_ = wk
}

func TestRawSign_Ed25519(t *testing.T) {
	// Use a fixed seed so failures are reproducible; any 32 bytes work.
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

	w, _ := makeRawWallet(t, "ed25519", seed, "Plain")

	pub, err := derivePub("ed25519", seed)
	if err != nil {
		t.Fatalf("derivePub: %v", err)
	}

	msg := []byte("solana sign me")
	sig, err := w.Sign(nil, msg, &wltsign.Opts{
		Context: context.Background(),
		Keys:    []*wltsign.KeyDescription{{Type: "Plain"}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("ed25519 sig wrong length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatalf("ed25519 signature did not verify")
	}
}

func TestParseImportedPrivkey(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		curve     string
		wantHex   string // empty = expect error
	}{
		{
			name:    "0x-prefixed hex",
			input:   "0x0000000000000000000000000000000000000000000000000000000000000001",
			curve:   "secp256k1",
			wantHex: "0000000000000000000000000000000000000000000000000000000000000001",
		},
		{
			name:    "bare hex",
			input:   "0000000000000000000000000000000000000000000000000000000000000001",
			curve:   "secp256k1",
			wantHex: "0000000000000000000000000000000000000000000000000000000000000001",
		},
		{
			name:    "uppercase 0X prefix",
			input:   "0X0000000000000000000000000000000000000000000000000000000000000001",
			curve:   "secp256k1",
			wantHex: "0000000000000000000000000000000000000000000000000000000000000001",
		},
		{
			// Bitcoin testnet WIF for privkey 0xef…01 (compressed flag).
			// Generated from `bitcoin-cli -testnet dumpprivkey` shape.
			// Equivalent: priv = 32 bytes of 0x01; version = 0xef; trailing 0x01.
			name:    "WIF testnet compressed for priv=0x..01",
			input:   wifEncodeForTest(t, 0xef, repeatByte(0x01, 32), true),
			curve:   "secp256k1",
			wantHex: hex.EncodeToString(repeatByte(0x01, 32)),
		},
		{
			name:  "wrong length hex",
			input: "0xabcd",
			curve: "secp256k1",
		},
		{
			name:  "non-hex chars",
			input: "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			curve: "secp256k1",
		},
		{
			name:  "empty",
			input: "",
			curve: "secp256k1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseImportedPrivkey(c.input, c.curve)
			if c.wantHex == "" {
				if err == nil {
					t.Fatalf("expected error, got privkey %x", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hex.EncodeToString(got) != c.wantHex {
				t.Fatalf("privkey mismatch:\n  got=%x\n want=%s", got, c.wantHex)
			}
		})
	}
}

func TestDecodeMnemonic_English(t *testing.T) {
	// BIP39 §"Test vectors" English: 12 words → 16 bytes of entropy.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	wantHex := "00000000000000000000000000000000"

	entropy, lang, err := decodeMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("decodeMnemonic: %v", err)
	}
	if hex.EncodeToString(entropy) != wantHex {
		t.Fatalf("entropy mismatch:\n  got=%x\n want=%s", entropy, wantHex)
	}
	if lang != "english" {
		t.Fatalf("language: got %q, want english", lang)
	}
}

func TestRawSign_HDDerivation_Secp256k1(t *testing.T) {
	// Verify that signRaw + tweakSecp256k1 produce a signature that
	// matches the pubkey ecckd would derive for the same chaincode +
	// path. This is the key invariant for Account-derived signing on
	// imported wallets: the same IL applied to (master_priv) and
	// (master_pub) must produce a key pair.
	priv := make([]byte, 32)
	priv[31] = 7

	// Pick an IL value (would normally come from ecckd.DeriveWithIL).
	il := big.NewInt(0xC0FFEE)

	// Compute child priv = (master + IL) mod n, child pub = priv*G.
	child := tweakSecp256k1(priv, il)
	childPub := secp256k1.PrivKeyFromBytes(child).PubKey().SerializeCompressed()

	// Now run the same path through Wallet.Sign (which calls signRaw,
	// which calls tweakSecp256k1 internally for non-nil aopt.IL).
	w, _ := makeRawWallet(t, "secp256k1", priv, "Plain")
	digest := sha256d([]byte("derived-account sign"))
	sig, err := w.Sign(nil, digest, &wltsign.Opts{
		Context: context.Background(),
		Keys:    []*wltsign.KeyDescription{{Type: "Plain"}},
		IL:      il,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pubKey, err := secp256k1.ParsePubKey(childPub)
	if err != nil {
		t.Fatalf("parse child pub: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey.ToECDSA(), digest, sig) {
		t.Fatalf("derived-account signature did not verify against child pubkey")
	}
}

// ── helpers ──────────────────────────────────────────────────────

// makeRawWallet builds an in-memory *Wallet + encrypted *WalletKey
// pair without touching the database. Uses Plain encryption so no
// password / KMS round-trip is required.
func makeRawWallet(t *testing.T, curve string, priv []byte, encryptionType string) (*Wallet, *WalletKey) {
	t.Helper()
	chaincode, err := randomChaincode()
	if err != nil {
		t.Fatalf("randomChaincode: %v", err)
	}
	share := &RawKeyShare{
		Curve:     curve,
		Privkey:   append([]byte(nil), priv...),
		Chaincode: chaincode,
	}
	pub, err := derivePub(curve, priv)
	if err != nil {
		t.Fatalf("derivePub: %v", err)
	}
	w := &Wallet{
		Curve:  curve,
		Pubkey: string(pub),
	}
	wk := &WalletKey{
		Type:    encryptionType, // doubles as the field set by encrypt() below
		rawData: share,
	}
	if err := wk.encrypt(&wltsign.KeyDescription{Type: encryptionType}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	w.Keys = []*WalletKey{wk}
	return w, wk
}

func sha256d(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// wifEncodeForTest is the inverse of decodeWIF — used only in tests
// to construct expected WIF strings without depending on btcsuite.
func wifEncodeForTest(t *testing.T, version byte, priv []byte, compressed bool) string {
	t.Helper()
	body := make([]byte, 0, 1+32+1+4)
	body = append(body, version)
	body = append(body, priv...)
	if compressed {
		body = append(body, 0x01)
	}
	h1 := sha256.Sum256(body)
	h2 := sha256.Sum256(h1[:])
	body = append(body, h2[:4]...)
	// Use the same base58 library decodeWIF uses.
	return base58.Bitcoin.Encode(body)
}
