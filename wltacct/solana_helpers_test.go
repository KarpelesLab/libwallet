package wltacct

import (
	"bytes"
	"testing"
)

// buildLegacyTx assembles a minimal Solana legacy transaction:
// compact-u16(numSigs) + numSigs*64 zero bytes + header(3) +
// compact-u16(numKeys) + numKeys*32 pubkey bytes + 32 zero bytes (blockhash)
// + compact-u16(0) instructions.
// Callers control numSigs (sigSpaceCount), the header's
// numRequiredSignatures, and the account keys.
func buildLegacyTx(sigSpaceCount int, numRequiredSigs byte, accountKeys [][32]byte) []byte {
	var buf bytes.Buffer
	// Signature count + space (we keep the legacy assumption that sigs
	// are written as a compact-u16 even when 0..127).
	buf.WriteByte(byte(sigSpaceCount))
	for i := 0; i < sigSpaceCount; i++ {
		buf.Write(make([]byte, 64))
	}
	// Header.
	buf.WriteByte(numRequiredSigs)
	buf.WriteByte(0) // numReadonlySignedAccounts
	buf.WriteByte(0) // numReadonlyUnsignedAccounts
	// Account keys.
	buf.WriteByte(byte(len(accountKeys)))
	for _, k := range accountKeys {
		buf.Write(k[:])
	}
	// Recent blockhash.
	buf.Write(make([]byte, 32))
	// 0 instructions.
	buf.WriteByte(0)
	return buf.Bytes()
}

// buildV0Tx is buildLegacyTx with a 0x80 versioned-message prefix byte.
func buildV0Tx(sigSpaceCount int, numRequiredSigs byte, accountKeys [][32]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(sigSpaceCount))
	for i := 0; i < sigSpaceCount; i++ {
		buf.Write(make([]byte, 64))
	}
	buf.WriteByte(0x80) // v0 version prefix
	buf.WriteByte(numRequiredSigs)
	buf.WriteByte(0)
	buf.WriteByte(0)
	buf.WriteByte(byte(len(accountKeys)))
	for _, k := range accountKeys {
		buf.Write(k[:])
	}
	buf.Write(make([]byte, 32))
	buf.WriteByte(0)
	// v0 also has an address-table-lookups section after the instructions,
	// but a single 0 (zero lookups) is enough for the parser, and we don't
	// touch anything past the account keys.
	buf.WriteByte(0)
	return buf.Bytes()
}

func mkKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func mkSig(b byte) []byte {
	s := make([]byte, 64)
	for i := range s {
		s[i] = b
	}
	return s
}

func TestSolanaInsertSignature_Sponsored(t *testing.T) {
	relay := mkKey(0xAA)
	owner := mkKey(0xBB)
	tx := buildLegacyTx(2, 2, [][32]byte{relay, owner})
	sig := mkSig(0x11)

	signed, err := solanaInsertSignature(tx, sig, owner[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// numSigs is at byte 0 (compact-u16=2 fits in one byte), so sigs start at offset 1.
	slot0 := signed[1 : 1+64]
	slot1 := signed[1+64 : 1+128]
	if !bytes.Equal(slot0, make([]byte, 64)) {
		t.Errorf("slot 0 (relay) was modified; expected untouched zeros")
	}
	if !bytes.Equal(slot1, sig) {
		t.Errorf("slot 1 (owner) does not contain the inserted signature")
	}
}

func TestSolanaInsertSignature_SoleSigner(t *testing.T) {
	owner := mkKey(0xCC)
	tx := buildLegacyTx(1, 1, [][32]byte{owner})
	sig := mkSig(0x22)

	signed, err := solanaInsertSignature(tx, sig, owner[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	slot0 := signed[1 : 1+64]
	if !bytes.Equal(slot0, sig) {
		t.Errorf("slot 0 does not contain the inserted signature")
	}
}

func TestSolanaInsertSignature_Versioned(t *testing.T) {
	relay := mkKey(0xAA)
	owner := mkKey(0xBB)
	tx := buildV0Tx(2, 2, [][32]byte{relay, owner})
	sig := mkSig(0x33)

	signed, err := solanaInsertSignature(tx, sig, owner[:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	slot0 := signed[1 : 1+64]
	slot1 := signed[1+64 : 1+128]
	if !bytes.Equal(slot0, make([]byte, 64)) {
		t.Errorf("slot 0 (relay) was modified")
	}
	if !bytes.Equal(slot1, sig) {
		t.Errorf("slot 1 (owner) does not contain the inserted signature in versioned tx")
	}
}

func TestSolanaInsertSignature_PubkeyNotInAccountKeys(t *testing.T) {
	relay := mkKey(0xAA)
	owner := mkKey(0xBB)
	stranger := mkKey(0xCC)
	tx := buildLegacyTx(2, 2, [][32]byte{relay, owner})

	_, err := solanaInsertSignature(tx, mkSig(0x44), stranger[:])
	if err == nil {
		t.Fatal("expected error for pubkey not in account keys, got nil")
	}
}

func TestSolanaInsertSignature_PubkeyBeyondRequiredSigners(t *testing.T) {
	signer := mkKey(0xAA)
	readonlyAccount := mkKey(0xBB) // present in keys but not a signer
	// numRequiredSignatures=1, so only slot 0 is a signer; slot 1 is data.
	tx := buildLegacyTx(1, 1, [][32]byte{signer, readonlyAccount})

	_, err := solanaInsertSignature(tx, mkSig(0x55), readonlyAccount[:])
	if err == nil {
		t.Fatal("expected error for pubkey outside required-signers prefix, got nil")
	}
}

func TestSolanaInsertSignature_BadSigLength(t *testing.T) {
	owner := mkKey(0xAA)
	tx := buildLegacyTx(1, 1, [][32]byte{owner})

	_, err := solanaInsertSignature(tx, []byte{0x01, 0x02}, owner[:])
	if err == nil {
		t.Fatal("expected error for short signature, got nil")
	}
}

func TestSolanaInsertSignature_BadPubkeyLength(t *testing.T) {
	owner := mkKey(0xAA)
	tx := buildLegacyTx(1, 1, [][32]byte{owner})

	_, err := solanaInsertSignature(tx, mkSig(0x66), []byte{0x01})
	if err == nil {
		t.Fatal("expected error for short pubkey, got nil")
	}
}
