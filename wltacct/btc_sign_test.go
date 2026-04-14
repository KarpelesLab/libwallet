package wltacct

import (
	"crypto/sha256"
	"testing"

	"github.com/KarpelesLab/secp256k1"
)

func TestBitcoinMessagePrefix(t *testing.T) {
	cases := []struct {
		chain string
		want  string // expected full prefix bytes (length byte + magic)
	}{
		// Bitcoin / Bitcoin Cash magic is 24 bytes -> 0x18 length byte.
		{"bitcoin", "\x18Bitcoin Signed Message:\n"},
		{"bitcoincash", "\x18Bitcoin Signed Message:\n"},
		// Litecoin / Dogecoin / Monacoin magic is 25 bytes -> 0x19.
		{"monacoin", "\x19Monacoin Signed Message:\n"},
		{"litecoin", "\x19Litecoin Signed Message:\n"},
		{"dogecoin", "\x19Dogecoin Signed Message:\n"},
	}
	for _, c := range cases {
		got, ok := BitcoinMessagePrefix(c.chain)
		if !ok {
			t.Errorf("%s: expected ok=true", c.chain)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s: got %q want %q", c.chain, got, c.want)
		}
	}
	if _, ok := BitcoinMessagePrefix("ethereum"); ok {
		t.Error("ethereum should not have a bitcoin-family message prefix")
	}
	if _, ok := BitcoinMessagePrefix(""); ok {
		t.Error("empty chain id should not return a prefix")
	}
}

func TestAppendVarInt(t *testing.T) {
	cases := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{0xfc, []byte{0xfc}},
		{0xfd, []byte{0xfd, 0xfd, 0x00}},
		{0xffff, []byte{0xfd, 0xff, 0xff}},
		{0x10000, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
		{0xffffffff, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		{0x100000000, []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := appendVarInt(nil, c.n)
		if string(got) != string(c.want) {
			t.Errorf("n=%d: got %x want %x", c.n, got, c.want)
		}
	}
}

// TestBitcoinMessageSignRoundTrip generates a throwaway secp256k1 key,
// replicates the SignBitcoinMessage hashing path, signs, and verifies the
// resulting 65-byte compact signature recovers to the same pubkey. Proves
// the prefix + varint + dsha256 + recovery-byte pipeline is sound
// independently of the TSS signer (which has its own tests).
func TestBitcoinMessageSignRoundTrip(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %s", err)
	}
	pub := priv.PubKey()

	prefix, ok := BitcoinMessagePrefix("monacoin")
	if !ok {
		t.Fatal("no monacoin prefix")
	}

	message := []byte("verify libwallet mpurse signing")

	// Same path SignBitcoinMessage uses:
	full := append([]byte{}, prefix...)
	full = appendVarInt(full, uint64(len(message)))
	full = append(full, message...)
	h1 := sha256.Sum256(full)
	hash := sha256.Sum256(h1[:])

	sig := secp256k1.Sign(priv, hash[:])
	if !sig.BruteforceRecoveryCode(hash[:], pub) {
		t.Fatal("could not determine recovery code")
	}

	compact := sig.ExportCompact(true, 31)
	if len(compact) != 65 {
		t.Fatalf("expected 65-byte compact signature, got %d", len(compact))
	}

	recovered, compressed, err := secp256k1.RecoverCompact(compact, hash[:])
	if err != nil {
		t.Fatalf("recover: %s", err)
	}
	if !compressed {
		t.Error("expected compressed-key flag on recovery (header offset 31)")
	}
	if !recovered.IsEqual(pub) {
		t.Error("recovered public key does not match signing key")
	}
}
