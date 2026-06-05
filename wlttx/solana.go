package wlttx

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
)

// Solana System Program ID (all ones in base58)
var solanaSystemProgram = [32]byte{}

// ComputeBudget111111111111111111111111111111 — the on-chain program
// that reads SetComputeUnitLimit / SetComputeUnitPrice instructions.
// Populated at init from the canonical base58 form.
var solanaComputeBudgetProgram [32]byte

func init() {
	// System Program = 11111111111111111111111111111111 (all zeros)
	// Already initialized to zero

	cb, err := base58.Bitcoin.Decode("ComputeBudget111111111111111111111111111111")
	if err != nil || len(cb) != 32 {
		// Fail loud: this is a compile-time constant.
		panic(fmt.Sprintf("libwallet: invalid ComputeBudget program id: %v (len=%d)", err, len(cb)))
	}
	copy(solanaComputeBudgetProgram[:], cb)
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

// computeBudgetSetLimit encodes a SetComputeUnitLimit instruction
// body: [0x02, u32 LE].
func computeBudgetSetLimit(cu uint32) []byte {
	data := make([]byte, 5)
	data[0] = 0x02
	binary.LittleEndian.PutUint32(data[1:], cu)
	return data
}

// computeBudgetSetPrice encodes a SetComputeUnitPrice instruction
// body: [0x03, u64 LE] where the price is microlamports per CU.
func computeBudgetSetPrice(microLamportsPerCU uint64) []byte {
	data := make([]byte, 9)
	data[0] = 0x03
	binary.LittleEndian.PutUint64(data[1:], microLamportsPerCU)
	return data
}

// buildSOLTransferMessage builds a Solana transaction message for a
// native SOL transfer. When cuLimit or cuPrice is non-zero, the
// message also includes the corresponding ComputeBudget instructions
// (SetComputeUnitLimit and/or SetComputeUnitPrice), the ComputeBudget
// program is appended to the account keys, and the header readonly-
// unsigned count is bumped accordingly.
func buildSOLTransferMessage(from, to [32]byte, lamports uint64, recentBlockhash [32]byte, cuLimit uint32, cuPrice uint64) []byte {
	// Message format:
	// Header: [numRequiredSignatures, numReadonlySignedAccounts, numReadonlyUnsignedAccounts]
	// compact-u16 numAccountKeys
	// accountKeys (32 bytes each)
	// recentBlockhash (32 bytes)
	// compact-u16 numInstructions
	// instructions

	hasCB := cuLimit > 0 || cuPrice > 0

	var msg []byte

	// Header
	msg = append(msg, 1) // 1 required signature (sender)
	msg = append(msg, 0) // 0 readonly signed accounts
	if hasCB {
		msg = append(msg, 2) // SystemProgram + ComputeBudget are readonly-unsigned
	} else {
		msg = append(msg, 1) // SystemProgram only
	}

	// Account keys
	// Legacy: [from, to, SystemProgram] (indices 0,1,2)
	// With CB: [from, to, SystemProgram, ComputeBudget] (indices 0,1,2,3)
	if hasCB {
		msg = append(msg, compactU16(4)...)
	} else {
		msg = append(msg, compactU16(3)...)
	}
	msg = append(msg, from[:]...)
	msg = append(msg, to[:]...)
	msg = append(msg, solanaSystemProgram[:]...)
	if hasCB {
		msg = append(msg, solanaComputeBudgetProgram[:]...)
	}

	// Recent blockhash
	msg = append(msg, recentBlockhash[:]...)

	// Instructions. ComputeBudget instructions come first (Solana
	// requires them before any instruction that would consume CUs).
	numInstr := uint16(1)
	if cuLimit > 0 {
		numInstr++
	}
	if cuPrice > 0 {
		numInstr++
	}
	msg = append(msg, compactU16(numInstr)...)

	const (
		programIdxSystem = byte(2)
		programIdxCB     = byte(3)
	)

	if cuLimit > 0 {
		msg = append(msg, programIdxCB)        // programIdIndex = ComputeBudget
		msg = append(msg, compactU16(0)...)    // no accounts
		data := computeBudgetSetLimit(cuLimit)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}
	if cuPrice > 0 {
		msg = append(msg, programIdxCB)        // programIdIndex = ComputeBudget
		msg = append(msg, compactU16(0)...)    // no accounts
		data := computeBudgetSetPrice(cuPrice)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}

	// System Program Transfer instruction.
	msg = append(msg, programIdxSystem)
	msg = append(msg, compactU16(2)...) // 2 accounts
	msg = append(msg, 0)                // from
	msg = append(msg, 1)                // to
	instrData := solanaTransferInstruction(lamports)
	msg = append(msg, compactU16(uint16(len(instrData)))...)
	msg = append(msg, instrData...)

	return msg
}

// signAndSendSolana handles the full Solana transaction flow
func (tx *Transaction) signAndSendSolana(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, keys []*wltsign.KeyDescription) error {
	// Debug trace so the tester's logs confirm this path is reached
	// and show the state BEFORE the repair attempt.
	wltlog.Debugf("solana-send: entry tx.From=%q tx.To=%q acct.Id=%s acct.Pubkey=%q acct.Address=%q acct.Curve=%q keys=%d",
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
	wltlog.Debugf("solana-send: post-repair acct.Pubkey=%q acct.Address=%q", acct.Pubkey, acct.Address)

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

	// Build the transaction message. ComputeBudget instructions
	// are included when tx.ComputeUnitLimit or ComputeUnitPrice was
	// set (either explicitly by the caller or via PriorityLevel in
	// Validate). Zero values reproduce the legacy 3-account layout
	// so unchanged callers keep their byte-for-byte behaviour.
	//
	// SPL routing: when tx.resolvedToken is non-nil (set by Validate
	// from tx.Asset), build an SPL transfer message under the
	// resolved mint instead of a native SOL transfer. The "amount"
	// stays in tx.Amount as base units of the token (e.g. 1_315_764
	// for 1.315764 USDT @ 6 decimals); the per-asset interpretation
	// happens here, not in the caller.
	//
	// Token-1 (spl-token) → TransferChecked + the Token-1 program id.
	// Token-2022 (spl-token-2022) → TransferChecked + the Token-2022
	// program id; or TransferCheckedWithFee + a pre-computed fee
	// when the mint has the TransferFeeConfig extension active for
	// the current epoch.
	var message []byte
	var splMintB58 string
	var splFee uint64
	if tx.resolvedToken != nil {
		mintBytes, err := base58.Bitcoin.Decode(tx.resolvedToken.GetAddress())
		if err != nil || len(mintBytes) != 32 {
			return fmt.Errorf("invalid SPL mint address %q: %w (len=%d)", tx.resolvedToken.GetAddress(), err, len(mintBytes))
		}
		var mint [32]byte
		copy(mint[:], mintBytes)

		tokenProgram, err := tokenProgramForType(tx.resolvedToken.GetType())
		if err != nil {
			return err
		}

		senderATA, _, err := deriveAssociatedTokenAccount(from, mint, tokenProgram)
		if err != nil {
			return fmt.Errorf("derive sender ATA: %w", err)
		}
		recipientATA, _, err := deriveAssociatedTokenAccount(to, mint, tokenProgram)
		if err != nil {
			return fmt.Errorf("derive recipient ATA: %w", err)
		}

		amount := tx.Amount.Value().Uint64()
		decimals := uint8(tx.resolvedToken.GetDecimals())
		splMintB58 = tx.resolvedToken.GetAddress()

		// Token-2022: introspect the mint to find any active
		// TransferFee extension. The program checks the supplied
		// fee against its own computation and reverts on mismatch,
		// so the caller MUST compute the same fee for the current
		// epoch using the on-chain config.
		useFeePath := false
		if tx.resolvedToken.GetType() == "spl-token-2022" {
			mintCtx, mintCancel := context.WithTimeout(ctx, 5*time.Second)
			data, err := solanaFetchMintAccount(mintCtx, n, splMintB58)
			mintCancel()
			if err != nil {
				return fmt.Errorf("fetch token-2022 mint %s: %w", splMintB58, err)
			}
			cfg, err := parseToken2022TransferFeeConfig(data)
			if err != nil {
				return fmt.Errorf("parse token-2022 mint extensions: %w", err)
			}
			if cfg != nil {
				epochCtx, epochCancel := context.WithTimeout(ctx, 5*time.Second)
				epoch, err := solanaCurrentEpoch(epochCtx, n)
				epochCancel()
				if err != nil {
					return fmt.Errorf("fetch current epoch: %w", err)
				}
				active := cfg.epochFee(epoch)
				splFee = active.calculateFee(amount)
				if splFee > 0 || active.TransferFeeBasisPoints > 0 {
					// A zero fee with bps>0 is legal at amount=0;
					// still take the fee path so the on-chain
					// program isn't asked to interpret a plain
					// TransferChecked against a fee-extension mint.
					useFeePath = true
				}
			}
		}

		if useFeePath {
			message = buildSPLTransferWithFeeMessage(
				from, to, mint, senderATA, recipientATA,
				tokenProgram,
				amount, decimals, splFee,
				recentBlockhash,
				tx.ComputeUnitLimit, tx.ComputeUnitPrice,
			)
		} else {
			message = buildSPLTransferMessage(
				from, to, mint, senderATA, recipientATA,
				tokenProgram,
				amount, decimals,
				recentBlockhash,
				tx.ComputeUnitLimit, tx.ComputeUnitPrice,
			)
		}
		wltlog.Debugf("solana-send: SPL transfer type=%s mint=%s symbol=%s amount=%d decimals=%d fee=%d sender_ata=%s recipient_ata=%s",
			tx.resolvedToken.GetType(), splMintB58, tx.resolvedToken.GetSymbol(), amount, decimals, splFee,
			base58.Bitcoin.Encode(senderATA[:]), base58.Bitcoin.Encode(recipientATA[:]))

		// Run SPL preflight: SOL covers fee + potential ATA rent;
		// sender's SPL balance covers the transfer amount. The check
		// is best-effort — on RPC failure we let the broadcast surface
		// any real problem rather than blocking a legitimate tx.
		preCtx, preCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := preflightSolanaSplSend(preCtx, n, acct.Address, senderATA, tx, amount); err != nil {
			preCancel()
			return err
		}
		preCancel()
	} else {
		message = buildSOLTransferMessage(from, to, lamports, recentBlockhash, tx.ComputeUnitLimit, tx.ComputeUnitPrice)
	}

	// Sign the message with EdDSA TSS
	signOpt := &wltsign.Opts{
		Context: ctx,
		Keys:    keys,
	}
	signStart := time.Now()
	signature, err := acct.Sign(nil, message, signOpt)
	if err != nil {
		wltlog.Errorf("solana-send: TSS sign failed after %s: %s", time.Since(signStart).Round(time.Millisecond), err)
		return fmt.Errorf("failed to sign transaction: %w", err)
	}
	wltlog.Debugf("solana-send: TSS sign complete in %s (sig len=%d)", time.Since(signStart).Round(time.Millisecond), len(signature))

	// Local verification against the pubkey we're about to put in
	// the fee-payer slot. If this fails, Solana will fail too, and
	// we'd rather surface the exact reason now than get a generic
	// "Transaction did not pass signature verification" from the RPC.
	if !verifyEd25519Signature(from[:], message, signature) {
		wltlog.Errorf("solana-send: LOCAL verify FAILED — sig does not validate under fee-payer pubkey %x (sig=%x, msg len=%d)", from[:], signature, len(message))
		return fmt.Errorf("signature does not verify against fee-payer pubkey locally (sig len=%d, acct.Address=%s) — TSS key shares may be inconsistent with stored pubkey", len(signature), acct.Address)
	}
	wltlog.Debugf("solana-send: LOCAL verify OK")

	// Build the full transaction: compact-u16(numSignatures) + signatures + message
	var rawTx []byte
	rawTx = append(rawTx, compactU16(1)...) // 1 signature
	rawTx = append(rawTx, signature...)
	rawTx = append(rawTx, message...)

	tx.Raw = rawTx

	// Broadcast via sendTransaction
	txBase58 := base58.Bitcoin.Encode(rawTx)
	broadcastStart := time.Now()
	result, err := n.DoRPC("sendTransaction", txBase58, map[string]any{
		"encoding": "base58",
	})
	if err != nil {
		wltlog.Errorf("solana-send: broadcast failed after %s: %s", time.Since(broadcastStart).Round(time.Millisecond), err)
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return fmt.Errorf("failed to parse transaction hash: %w", err)
	}

	tx.Hash = txHash
	tx.URL = n.TransactionUrl(txHash)
	wltintf.NotifyTxBroadcast(wltintf.GetEnv(ctx))
	// State change worth emitting at info level — shows up in
	// release binaries so the support team can correlate a broadcast
	// event with on-chain data.
	if splMintB58 != "" {
		wltlog.Infof("solana-send: broadcast OK chain=%s from=%s to=%s spl_mint=%s amount=%d (base units) hash=%s (broadcast %s)",
			n.ChainId, acct.Address, tx.To, splMintB58, tx.Amount.Value().Uint64(), txHash, time.Since(broadcastStart).Round(time.Millisecond))
	} else {
		wltlog.Infof("solana-send: broadcast OK chain=%s from=%s to=%s lamports=%d hash=%s (broadcast %s)",
			n.ChainId, acct.Address, tx.To, lamports, txHash, time.Since(broadcastStart).Round(time.Millisecond))
	}

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
