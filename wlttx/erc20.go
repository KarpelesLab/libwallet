package wlttx

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// erc20TransferSelector is the keccak256("transfer(address,uint256)") first 4 bytes.
const erc20TransferSelector = "a9059cbb"

// encodeERC20Transfer builds the call data for ERC-20 transfer(address to, uint256 amount).
// Returns a 0x-prefixed hex string (4-byte selector + 32-byte padded address + 32-byte padded amount).
func encodeERC20Transfer(toAddress string, amount *big.Int) (string, error) {
	addr, ok := strings.CutPrefix(strings.ToLower(toAddress), "0x")
	if !ok {
		return "", errors.New("erc20 recipient must be a 0x-prefixed address")
	}
	if len(addr) != 40 {
		return "", fmt.Errorf("erc20 recipient address must be 20 bytes (40 hex chars), got %d", len(addr))
	}
	addrBytes, err := hex.DecodeString(addr)
	if err != nil {
		return "", fmt.Errorf("erc20 recipient address: %w", err)
	}
	if amount == nil || amount.Sign() < 0 {
		return "", errors.New("erc20 amount must be non-negative")
	}

	// Pad address to 32 bytes (left-pad with zeros)
	addrPadded := make([]byte, 32)
	copy(addrPadded[12:], addrBytes)

	// Pad amount to 32 bytes (big-endian)
	amountBytes := amount.Bytes()
	if len(amountBytes) > 32 {
		return "", errors.New("erc20 amount overflow (>256 bits)")
	}
	amountPadded := make([]byte, 32)
	copy(amountPadded[32-len(amountBytes):], amountBytes)

	data := erc20TransferSelector + hex.EncodeToString(addrPadded) + hex.EncodeToString(amountPadded)
	return "0x" + data, nil
}
