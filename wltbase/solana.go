package wltbase

import (
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

// solanaInsertSignature replaces the first 64-byte signature slot in a serialized Solana transaction.
func solanaInsertSignature(txBytes []byte, sig []byte) []byte {
	result := make([]byte, len(txBytes))
	copy(result, txBytes)

	_, consumed, err := solanaReadCompactU16(result)
	if err != nil || consumed+64 > len(result) {
		return result
	}
	copy(result[consumed:consumed+64], sig)
	return result
}
