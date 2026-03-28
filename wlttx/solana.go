package wlttx

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/ModChain/base58"
)

// Solana System Program ID (all ones in base58)
var solanaSystemProgram = [32]byte{}

func init() {
	// System Program = 11111111111111111111111111111111 (all zeros)
	// Already initialized to zero
}

// compactU16 encodes a uint16 in Solana's compact-u16 format
func compactU16(v uint16) []byte {
	if v <= 0x7f {
		return []byte{byte(v)}
	}
	if v <= 0x3fff {
		return []byte{byte(v&0x7f) | 0x80, byte(v >> 7)}
	}
	return []byte{byte(v&0x7f) | 0x80, byte((v>>7)&0x7f) | 0x80, byte(v >> 14)}
}

// solanaTransferInstruction builds the data for a System Program transfer
// Instruction index 2 (Transfer) followed by lamports as u64 LE
func solanaTransferInstruction(lamports uint64) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], 2) // instruction index: Transfer
	binary.LittleEndian.PutUint64(data[4:12], lamports)
	return data
}

// buildSOLTransferMessage builds a Solana transaction message for a native SOL transfer
func buildSOLTransferMessage(from, to [32]byte, lamports uint64, recentBlockhash [32]byte) []byte {
	// Message format:
	// Header: [numRequiredSignatures, numReadonlySignedAccounts, numReadonlyUnsignedAccounts]
	// compact-u16 numAccountKeys
	// accountKeys (32 bytes each)
	// recentBlockhash (32 bytes)
	// compact-u16 numInstructions
	// instructions

	var msg []byte

	// Header
	msg = append(msg, 1) // 1 required signature (sender)
	msg = append(msg, 0) // 0 readonly signed accounts
	msg = append(msg, 1) // 1 readonly unsigned account (System Program)

	// Account keys: [from, to, SystemProgram]
	msg = append(msg, compactU16(3)...)
	msg = append(msg, from[:]...)
	msg = append(msg, to[:]...)
	msg = append(msg, solanaSystemProgram[:]...)

	// Recent blockhash
	msg = append(msg, recentBlockhash[:]...)

	// Instructions (1 instruction: System Program Transfer)
	msg = append(msg, compactU16(1)...) // 1 instruction

	// Instruction:
	msg = append(msg, 2) // programIdIndex = 2 (SystemProgram is at index 2)

	// Account indexes: [0 (from, writable+signer), 1 (to, writable)]
	msg = append(msg, compactU16(2)...) // 2 accounts
	msg = append(msg, 0)               // from
	msg = append(msg, 1)               // to

	// Instruction data
	instrData := solanaTransferInstruction(lamports)
	msg = append(msg, compactU16(uint16(len(instrData)))...)
	msg = append(msg, instrData...)

	return msg
}

// signAndSendSolana handles the full Solana transaction flow
func (tx *Transaction) signAndSendSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, keys []*wltsign.KeyDescription) error {
	// Decode sender address
	fromBytes, err := base58.Bitcoin.Decode(acct.Address)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	if len(fromBytes) != 32 {
		return fmt.Errorf("invalid sender address length: %d", len(fromBytes))
	}
	var from [32]byte
	copy(from[:], fromBytes)

	// Decode recipient address
	toBytes, err := base58.Bitcoin.Decode(tx.To)
	if err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}
	if len(toBytes) != 32 {
		return fmt.Errorf("invalid recipient address length: %d", len(toBytes))
	}
	var to [32]byte
	copy(to[:], toBytes)

	// Convert amount to lamports
	if tx.Amount == nil {
		return errors.New("amount is required")
	}
	lamports := tx.Amount.Value().Uint64()

	// Get recent blockhash
	bhResult, err := n.DoRPC("getLatestBlockhash", map[string]string{"commitment": "finalized"})
	if err != nil {
		return fmt.Errorf("failed to get latest blockhash: %w", err)
	}
	var bhParsed struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := json.Unmarshal(bhResult, &bhParsed); err != nil {
		return fmt.Errorf("failed to parse blockhash: %w", err)
	}
	bhBytes, err := base58.Bitcoin.Decode(bhParsed.Value.Blockhash)
	if err != nil {
		return fmt.Errorf("invalid blockhash: %w", err)
	}
	var recentBlockhash [32]byte
	copy(recentBlockhash[:], bhBytes)

	// Build the transaction message
	message := buildSOLTransferMessage(from, to, lamports, recentBlockhash)

	// Sign the message with EdDSA TSS
	signOpt := &wltsign.Opts{
		Context: ctx,
		Keys:    keys,
	}
	signature, err := acct.Sign(nil, message, signOpt)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Build the full transaction: compact-u16(numSignatures) + signatures + message
	var rawTx []byte
	rawTx = append(rawTx, compactU16(1)...) // 1 signature
	rawTx = append(rawTx, signature...)
	rawTx = append(rawTx, message...)

	tx.Raw = rawTx

	// Broadcast via sendTransaction
	txBase58 := base58.Bitcoin.Encode(rawTx)
	result, err := n.DoRPC("sendTransaction", txBase58, map[string]any{
		"encoding": "base58",
	})
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return fmt.Errorf("failed to parse transaction hash: %w", err)
	}

	tx.Hash = txHash
	tx.URL = n.TransactionUrl(txHash)

	return nil
}
