package wltwallet

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// User-provided test vectors that pin our derivation math to the same
// addresses MetaMask / Electrum / Phantom produce for the same seed
// phrase. If these ever break, restore from mnemonic will silently
// land on the wrong address and users won't see their funds.
//
// Mnemonic 1 (15 words, secp256k1 vectors):
//   "drop clever eagle primary march drink tackle bounce critic lyrics
//    toast enemy expose palm crew"
//
// Mnemonic 2 (12 words, ed25519 vector):
//   "debris spring slab end soft chest fluid option accident time enact tree"

const secpMnemonic = "drop clever eagle primary march drink tackle bounce critic lyrics toast enemy expose palm crew"
const solMnemonic = "debris spring slab end soft chest fluid option accident time enact tree"

func TestBip44Vectors_Secp256k1(t *testing.T) {
	cases := []struct {
		name        string
		path        []uint32
		wantPubkey  string // 33-byte compressed, hex
		wantAddress string // chain-specific address string
		addressFn   func([]byte) string
	}{
		{
			name:        "BTC P2PKH m/44'/0'/0'/0/0",
			path:        hardened(44, 0, 0).append(0, 0),
			wantPubkey:  "03983ff9d365e50c933bdf18d8f157105779bc047395f9635b39bfd543ad58d7ff",
			wantAddress: "1PFNjDKjBMA25oLqfY8Y4EmRR51T4b5NCM",
			addressFn:   btcP2PKH,
		},
		{
			name:        "EVM m/44'/60'/0'/0/0",
			path:        hardened(44, 60, 0).append(0, 0),
			wantPubkey:  "03b5894b03ca3c7850e8269a34019ec9870b0a030836e5f2d65203b2299c3dec20",
			wantAddress: "0x2f0765840477A3c7F76EEc53663006bA7c974d31",
			addressFn:   evmAddressLower, // we compare case-insensitive below
		},
		{
			name:        "BTC native segwit m/84'/0'/0'/0/0",
			path:        hardened(84, 0, 0).append(0, 0),
			wantPubkey:  "03bd60d87d8363526cb5486539373b53706a2a3bb650c7ce11faaa8d1ac4f1d102",
			wantAddress: "bc1qrsje8aswzyhyg94us33mlcrsfds4vd5f7th9eh",
			addressFn:   btcBech32,
		},
	}

	seed := bip39.NewSeed(secpMnemonic, "")
	master, err := ecckd.FromBitcoinSeed(seed)
	if err != nil {
		t.Fatalf("FromBitcoinSeed: %v", err)
	}
	if !master.IsPrivate() {
		t.Fatalf("master must be a private extended key")
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			derived, err := master.Derive(c.path)
			if err != nil {
				t.Fatalf("Derive(%v): %v", c.path, err)
			}
			priv := derived.KeyData // 32-byte private key
			if len(priv) != 32 {
				t.Fatalf("derived KeyData is %d bytes, want 32", len(priv))
			}
			pub := secp256k1.PrivKeyFromBytes(priv).PubKey().SerializeCompressed()
			gotPub := hex.EncodeToString(pub)
			if gotPub != c.wantPubkey {
				t.Fatalf("pubkey mismatch:\n  got=%s\n want=%s", gotPub, c.wantPubkey)
			}
			gotAddr := c.addressFn(pub)
			if !stringEqualIgnoreCase(gotAddr, c.wantAddress) {
				t.Fatalf("address mismatch:\n  got=%s\n want=%s", gotAddr, c.wantAddress)
			}
		})
	}
}

func TestBip44Vectors_Solana(t *testing.T) {
	// Solana has two widely-deployed derivation conventions for the
	// same BIP39 seed:
	//
	//   - "no derivation" / seed[:32] — used by Sollet, Solana Mobile,
	//     Backpack's default, and the vector the operator locked in
	//     here. The ed25519 32-byte seed is just the first half of
	//     the BIP39 PBKDF2 output.
	//
	//   - Phantom path m/44'/501'/0'/0' — SLIP-0010 ed25519 hardened
	//     derivation. What Phantom, Solflare, and solana-web3.js use.
	//
	// Both are "correct" depending on the wallet a user came from.
	// The runtime import flow will auto-detect by probing on-chain
	// activity for both candidates and letting the user pick when
	// neither has activity (v0.5.0 feature). This test just proves
	// the math for each lands on the expected address.
	wantAddr := "FeAf77cBkToyr9b59TfnC3rZES6UddQdctfXQvwQJNuR"

	seed := bip39.NewSeed(solMnemonic, "")

	tryPriv := func(label string, priv []byte) (matched bool) {
		if len(priv) < 32 {
			t.Logf("%-44s (priv too short, skipping)", label)
			return false
		}
		pub := ed25519.NewKeyFromSeed(priv[:32])[32:]
		got := base58.Bitcoin.Encode(pub)
		marker := ""
		if got == wantAddr {
			marker = "  ← MATCH"
			matched = true
		}
		t.Logf("%-44s → %s%s", label, got, marker)
		return matched
	}

	var matched string
	// SLIP-0010 paths.
	for _, c := range []struct {
		name string
		path []uint32
	}{
		{"phantom m/44'/501'/0'/0'", hardened(44, 501, 0, 0)},
		{"solana-cli m/44'/501'/0'/0'/0'", hardened(44, 501, 0, 0, 0)},
		{"3-comp m/44'/501'/0'", hardened(44, 501, 0)},
		{"2-comp m/44'/501'", hardened(44, 501)},
		{"single account m/501'/0'/0'/0'", hardened(501, 0, 0, 0)},
	} {
		priv := slip10DeriveEd25519ForTest(t, seed, c.path)
		if tryPriv(c.name, priv) {
			matched = c.name
		}
	}
	// No-derivation: BIP39 seed bytes used directly as ed25519 seed.
	// Sollet (legacy) used seed[:32]. Some "raw" wallets do too.
	if tryPriv("seed[:32] (no derivation)", seed[:32]) {
		matched = "seed[:32]"
	}
	if tryPriv("seed[32:64] (no derivation)", seed[32:]) {
		matched = "seed[32:64]"
	}
	// Mnemonic entropy as raw seed (some old wallets).
	entropy, err := bip39.EntropyFromMnemonic(solMnemonic)
	if err == nil && len(entropy) >= 32 {
		if tryPriv("entropy[:32]", entropy[:32]) {
			matched = "entropy[:32]"
		}
	}

	if matched == "" {
		t.Fatalf("no path produced the expected Solana address %s", wantAddr)
	}
	t.Logf("matched: %s", matched)
}

// ── Path helpers ─────────────────────────────────────────────────

type pathBuilder []uint32

// hardened returns a path prefix whose every component has the
// BIP32 hardened bit set. e.g. hardened(44, 60, 0) = m/44'/60'/0'.
func hardened(components ...uint32) pathBuilder {
	out := make(pathBuilder, len(components))
	for i, c := range components {
		out[i] = c | 0x80000000
	}
	return out
}

// append appends non-hardened components to a path.
func (p pathBuilder) append(components ...uint32) []uint32 {
	out := make([]uint32, 0, len(p)+len(components))
	out = append(out, p...)
	out = append(out, components...)
	return out
}

// ── SLIP-0010 ed25519 helpers ───────────────────────────────────

// slip10DeriveEd25519ForTest walks `path` from the BIP39 seed using
// the SLIP-0010 curve "ed25519 seed" master + all-hardened child
// derivation. Returns the 32-byte ed25519 private key (pre-expansion
// into 64-byte form).
//
// Every step MUST be hardened; SLIP-0010 ed25519 doesn't support
// non-hardened child derivation. The helper rejects non-hardened
// components to catch mistakes early.
func slip10DeriveEd25519ForTest(t *testing.T, seed []byte, path []uint32) []byte {
	t.Helper()
	// Master: HMAC-SHA512("ed25519 seed", seed) → priv || chaincode.
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	masterI := h.Sum(nil)
	priv := masterI[:32]
	chaincode := masterI[32:]

	for _, i := range path {
		if i&0x80000000 == 0 {
			t.Fatalf("SLIP-0010 ed25519 path components must all be hardened; got %#x", i)
		}
		// data = 0x00 || parent_priv || ser32(i)
		data := make([]byte, 1+32+4)
		data[0] = 0x00
		copy(data[1:33], priv)
		data[33] = byte(i >> 24)
		data[34] = byte(i >> 16)
		data[35] = byte(i >> 8)
		data[36] = byte(i)

		h := hmac.New(sha512.New, chaincode)
		h.Write(data)
		I := h.Sum(nil)
		priv = I[:32]
		chaincode = I[32:]
	}
	return priv
}

// ── Bitcoin / EVM address encoders ──────────────────────────────

// btcP2PKH returns the legacy 1... P2PKH address for a compressed
// secp256k1 pubkey on Bitcoin mainnet (version byte 0x00).
func btcP2PKH(pub []byte) string {
	h160 := hash160(pub)
	payload := make([]byte, 1+20)
	payload[0] = 0x00 // mainnet P2PKH
	copy(payload[1:], h160)
	ck := sha256d(payload)[:4]
	return base58.Bitcoin.Encode(append(payload, ck...))
}

// btcBech32 returns the native-segwit (BIP84) bc1... P2WPKH address
// for a compressed secp256k1 pubkey on Bitcoin mainnet.
func btcBech32(pub []byte) string {
	h160 := hash160(pub)
	return bech32SegwitEncode("bc", 0, h160)
}

// evmAddressLower returns the 0x-prefixed lowercase Ethereum address
// derived from a compressed secp256k1 pubkey. The keccak-checksum-
// cased variant is compared case-insensitively in the test.
func evmAddressLower(compressedPub []byte) string {
	// Expand to uncompressed xy coordinate pair.
	pub, err := secp256k1.ParsePubKey(compressedPub)
	if err != nil {
		return "<invalid pubkey>"
	}
	uncompressed := pub.SerializeUncompressed() // 65 bytes: 0x04 || X || Y
	h := keccak256(uncompressed[1:])            // drop the 0x04 tag
	return "0x" + hex.EncodeToString(h[12:])    // last 20 bytes
}

// ── Hash primitives ─────────────────────────────────────────────

func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// ── Bech32 for BIP84 ────────────────────────────────────────────

var bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32SegwitEncode emits a native SegWit v0 P2WPKH / P2WSH address
// per BIP173. hrp = human-readable prefix ("bc" for Bitcoin mainnet).
// witver = 0, witprog = HASH160 for P2WPKH (20 bytes) or SHA256 for
// P2WSH (32 bytes).
func bech32SegwitEncode(hrp string, witver byte, witprog []byte) string {
	conv := convertBits(witprog, 8, 5, true)
	data := append([]byte{witver}, conv...)
	checksum := bech32Checksum(hrp, data)
	data = append(data, checksum...)

	out := hrp + "1"
	for _, d := range data {
		out += string(bech32Charset[d])
	}
	return out
}

func convertBits(data []byte, fromBits, toBits byte, pad bool) []byte {
	var acc uint32
	var bits byte
	maxv := byte(1<<toBits) - 1
	out := make([]byte, 0, (len(data)*int(fromBits)/int(toBits))+1)
	for _, v := range data {
		acc = (acc << fromBits) | uint32(v)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&uint32(maxv)))
		}
	}
	if pad && bits > 0 {
		out = append(out, byte((acc<<(toBits-bits))&uint32(maxv)))
	}
	return out
}

func bech32Polymod(values []byte) uint32 {
	generators := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= generators[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, byte(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, byte(c)&31)
	}
	return out
}

func bech32Checksum(hrp string, data []byte) []byte {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return out
}

// ── misc ─────────────────────────────────────────────────────────

func stringEqualIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
