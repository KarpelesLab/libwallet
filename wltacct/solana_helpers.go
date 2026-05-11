package wltacct

import (
	"bytes"
	"errors"
	"fmt"
)

// solanaReadCompactU16 reads a compact-u16 value from a byte slice and returns the value and bytes consumed.
func solanaReadCompactU16(data []byte) (uint16, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty data for compact-u16")
	}
	b0 := data[0]
	if b0 <= 0x7f {
		return uint16(b0), 1, nil
	}
	if len(data) < 2 {
		return 0, 0, errors.New("truncated compact-u16")
	}
	b1 := data[1]
	if b1 <= 0x7f {
		return uint16(b0&0x7f) | uint16(b1)<<7, 2, nil
	}
	if len(data) < 3 {
		return 0, 0, errors.New("truncated compact-u16")
	}
	b2 := data[2]
	return uint16(b0&0x7f) | uint16(b1&0x7f)<<7 | uint16(b2)<<14, 3, nil
}

// solanaExtractMessage extracts the message portion from a serialized Solana transaction.
// The transaction format is: compact-u16(numSignatures) + (numSignatures * 64 bytes) + message
func solanaExtractMessage(txBytes []byte) ([]byte, error) {
	numSigs, consumed, err := solanaReadCompactU16(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature count: %w", err)
	}
	sigEnd := consumed + int(numSigs)*64
	if sigEnd > len(txBytes) {
		return nil, fmt.Errorf("transaction too short: need %d bytes for signatures, have %d", sigEnd, len(txBytes))
	}
	return txBytes[sigEnd:], nil
}

// solanaFindSignerSlot returns the index in the message's account-keys array
// that matches pubkey. Errors if pubkey is not present, or is present but
// outside the required-signers prefix (i.e. not actually a signer).
//
// Handles both legacy and versioned (v0+) messages. Versioned messages start
// with a byte whose high bit is set; the low 7 bits are the version.
func solanaFindSignerSlot(msg []byte, pubkey []byte) (int, error) {
	if len(pubkey) != 32 {
		return -1, fmt.Errorf("pubkey must be 32 bytes, got %d", len(pubkey))
	}
	if len(msg) == 0 {
		return -1, errors.New("empty message")
	}

	pos := 0
	if msg[0]&0x80 != 0 {
		// Versioned message: skip the version-prefix byte.
		pos = 1
	}
	if len(msg) < pos+3 {
		return -1, errors.New("message too short for header")
	}
	numRequiredSignatures := int(msg[pos])
	pos += 3

	numAccountKeys, consumed, err := solanaReadCompactU16(msg[pos:])
	if err != nil {
		return -1, fmt.Errorf("failed to read account keys count: %w", err)
	}
	pos += consumed
	if pos+int(numAccountKeys)*32 > len(msg) {
		return -1, errors.New("message too short for account keys")
	}

	for i := 0; i < int(numAccountKeys); i++ {
		keyStart := pos + i*32
		if bytes.Equal(msg[keyStart:keyStart+32], pubkey) {
			if i >= numRequiredSignatures {
				return -1, fmt.Errorf("pubkey is at account-keys slot %d but only %d account(s) are required signers", i, numRequiredSignatures)
			}
			return i, nil
		}
	}
	return -1, errors.New("pubkey not found in transaction account keys")
}

// solanaInsertSignature writes sig into the signature slot whose corresponding
// account-keys entry matches pubkey. Returns an error if pubkey isn't a signer
// for this transaction or the transaction is malformed.
//
// The previous version wrote unconditionally into slot 0, which broke sponsored
// transactions where the relay (fee payer) holds slot 0 and the wallet owner
// is at a later slot.
func solanaInsertSignature(txBytes []byte, sig []byte, pubkey []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature must be 64 bytes, got %d", len(sig))
	}

	numSigs, consumed, err := solanaReadCompactU16(txBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature count: %w", err)
	}
	sigEnd := consumed + int(numSigs)*64
	if sigEnd > len(txBytes) {
		return nil, fmt.Errorf("transaction too short: need %d bytes for signatures, have %d", sigEnd, len(txBytes))
	}

	slot, err := solanaFindSignerSlot(txBytes[sigEnd:], pubkey)
	if err != nil {
		return nil, err
	}
	if slot >= int(numSigs) {
		return nil, fmt.Errorf("signer slot %d exceeds signature array length %d (transaction is missing space for this signer)", slot, numSigs)
	}

	result := make([]byte, len(txBytes))
	copy(result, txBytes)
	sigStart := consumed + slot*64
	copy(result[sigStart:sigStart+64], sig)
	return result, nil
}
