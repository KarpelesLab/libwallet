package wlttx

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
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
	msg = append(msg, 0)                // from
	msg = append(msg, 1)                // to

	// Instruction data
	instrData := solanaTransferInstruction(lamports)
	msg = append(msg, compactU16(uint16(len(instrData)))...)
	msg = append(msg, instrData...)

	return msg
}

// signAndSendSolana handles the full Solana transaction flow
func (tx *Transaction) signAndSendSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, keys []*wltsign.KeyDescription) error {
	// Diagnostic trace so the tester's logs confirm this path is
	// reached and show the state BEFORE the repair attempt.
	log.Printf("solana-send: entry tx.From=%q tx.To=%q acct.Id=%s acct.Pubkey=%q acct.Address=%q acct.Curve=%q keys=%d",
		tx.From, tx.To, acct.Id, acct.Pubkey, acct.Address, acct.Curve, len(keys))

	// Repair the Ed25519 pubkey if it was stored under the legacy
	// X-coord-big-endian encoding — otherwise the fee-payer pubkey
	// (acct.Address) the tx carries doesn't match the pubkey the TSS
	// signs with, and Solana rejects the tx with
	// "Transaction did not pass signature verification". Decrypts one
	// key share, no user prompt. No-op when already correct.
	_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, acct, keys)
	// Re-derive a.Address explicitly against the network we're about
	// to send on. EnsureEd25519PubkeyOnAccount uses CurrentNetwork,
	// which can lag behind the caller's tx.Network override.
	_ = acct.UpdateAddressForNetwork(n)
	log.Printf("solana-send: post-repair acct.Pubkey=%q acct.Address=%q", acct.Pubkey, acct.Address)

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
	// Local verification against the pubkey we're about to put in
	// the fee-payer slot. If this fails, Solana will fail too, and
	// we'd rather surface the exact reason now than get a generic
	// "Transaction did not pass signature verification" from the RPC.
	if !verifyEd25519Signature(from[:], message, signature) {
		log.Printf("solana-send: LOCAL verify FAILED — sig does not validate under fee-payer pubkey %x (sig=%x, msg len=%d)", from[:], signature, len(message))
		return fmt.Errorf("signature does not verify against fee-payer pubkey locally (sig len=%d, acct.Address=%s) — TSS key shares may be inconsistent with stored pubkey", len(signature), acct.Address)
	}
	log.Printf("solana-send: LOCAL verify OK (sig len=%d)", len(signature))

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
	wltintf.NotifyTxBroadcast(wltintf.GetEnv(ctx))

	return nil
}

// verifyEd25519Signature checks that sig is a valid Ed25519 signature of
// msg under pubkey. Returns false on invalid pubkey length (Ed25519 is 32
// bytes) or on any verification error. Used as a local guard before
// broadcasting so we can distinguish "pubkey/share mismatch" from
// "Solana-side rejection for other reasons".
func verifyEd25519Signature(pubkey, msg, sig []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	defer func() { _ = recover() }() // stdlib panics on malformed pubkey
	return ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig)
}
