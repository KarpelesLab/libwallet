package wlttx

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/base58"
)

// SPL Token Program v1 (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA).
// Holds the program id used by every USDT, USDC, etc. mint that
// predates Token-2022. Populated at init from the canonical base58
// form so a typo would fail loud at startup, not silently route
// instructions to the wrong program.
var solanaSplTokenProgram [32]byte

// Associated Token Account program
// (ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL). Owns the
// per-(owner, mint) ATA addresses and exposes the create instruction
// (idempotent variant) we attach to every SPL transfer so the
// recipient's ATA is provisioned in-tx when it doesn't exist yet.
var solanaAtaProgram [32]byte

// Rent sysvar (SysvarRent111111111111111111111111111111111). Required
// as the third account by the ATA create instruction even though the
// rent values are read from the in-memory sysvar at runtime; the
// program still expects the account in the instruction.
var solanaRentSysvar [32]byte

// "ProgramDerivedAddress" — the constant suffix mixed into the
// sha256 input when deriving a PDA. Per the Solana runtime; matches
// the bytes the on-chain ed25519_program / curve check uses.
var solanaPdaMarker = []byte("ProgramDerivedAddress")

func init() {
	for _, c := range []struct {
		dst   *[32]byte
		b58   string
		label string
	}{
		{&solanaSplTokenProgram, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SPL Token program"},
		{&solanaAtaProgram, "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Associated Token Account program"},
		{&solanaRentSysvar, "SysvarRent111111111111111111111111111111111", "Rent sysvar"},
	} {
		raw, err := base58.Bitcoin.Decode(c.b58)
		if err != nil || len(raw) != 32 {
			panic(fmt.Sprintf("libwallet: invalid %s id: %v (len=%d)", c.label, err, len(raw)))
		}
		copy(c.dst[:], raw)
	}
}

// deriveAssociatedTokenAccount returns the canonical ATA pubkey for
// (owner, mint) under the given SPL token program id (so it works
// for both Token-1 and Token-2022 with the right caller).
//
// The Solana ATA is a Program-Derived Address with seeds
//
//	[owner, token_program_id, mint]
//
// under the ATA program's id. Per the Solana runtime, PDA derivation
// counts down a single-byte bump from 255 looking for a candidate
// whose sha256 hash is NOT a valid ed25519 curve point — that
// off-curve guarantee is what makes the PDA unsignable by anyone
// without invoking the owning program, which is the security property
// the ATA depends on. A bump that fails the curve check is the
// canonical one; we return the first hit.
//
// `filippo.io/edwards25519`'s Point.SetBytes returns an error iff the
// bytes don't decompress to a valid point — exactly the "not on
// curve" oracle we need.
func deriveAssociatedTokenAccount(owner, mint, tokenProgram [32]byte) ([32]byte, byte, error) {
	for bump := byte(255); ; bump-- {
		h := sha256.New()
		h.Write(owner[:])
		h.Write(tokenProgram[:])
		h.Write(mint[:])
		h.Write([]byte{bump})
		h.Write(solanaAtaProgram[:])
		h.Write(solanaPdaMarker)
		sum := h.Sum(nil)

		var p [32]byte
		copy(p[:], sum)
		if _, err := new(edwards25519.Point).SetBytes(p[:]); err != nil {
			// Not on curve → valid PDA.
			return p, bump, nil
		}
		if bump == 0 {
			// 256 candidates all on curve; mathematically possible but
			// catastrophically unlikely for a real (owner, mint) pair.
			return [32]byte{}, 0, errors.New("deriveATA: no off-curve bump found (caller passed degenerate seeds?)")
		}
	}
}

// splTransferCheckedInstruction encodes the data field of an SPL
// Token Program TransferChecked instruction (opcode 12).
//
//	[opcode=12, amount: u64 LE, decimals: u8]
//
// TransferChecked is preferred over Transfer (opcode 3) because the
// program verifies that the supplied decimals match the mint's
// on-chain decimals — so a caller that resolved decimals from a stale
// off-chain cache fails the tx rather than silently moving the wrong
// number of base units. Also required for Token-2022 mints with the
// transfer-fee extension; using opcode 3 there strips the fee path
// and the tx reverts.
func splTransferCheckedInstruction(amount uint64, decimals uint8) []byte {
	data := make([]byte, 10)
	data[0] = 12
	binary.LittleEndian.PutUint64(data[1:9], amount)
	data[9] = decimals
	return data
}

// ataCreateIdempotentInstruction encodes the data for the Associated
// Token Account program's CreateIdempotent instruction (opcode 1).
// The plain Create (opcode 0) fails when the ATA already exists,
// which makes for a brittle wallet UX (caller has to query
// getAccountInfo first and only attach Create on miss); the
// idempotent variant short-circuits to a no-op when the account is
// already there, so we can unconditionally include it and let the
// program decide. The byte cost on-chain is one instruction either
// way; rent is only charged on actual creation.
func ataCreateIdempotentInstruction() []byte {
	return []byte{1}
}

// buildSPLTransferMessage assembles a Solana transaction message for
// an SPL Token Program transfer.
//
// Layout (legacy message v0 with optional ComputeBudget on the
// front):
//
//	1. SetComputeUnitLimit  (optional, if cuLimit > 0)
//	2. SetComputeUnitPrice  (optional, if cuPrice > 0)
//	3. ATA CreateIdempotent for (recipient owner, mint)
//	4. SPL TransferChecked  (from = sender ATA, to = recipient ATA)
//
// Account list ordering follows Solana's required convention —
// writable+signed first, then writable+unsigned, then read-only:
//
//	0: payer / sender owner pubkey                (writable + signer)
//	1: sender ATA                                  (writable)
//	2: recipient ATA                               (writable)
//	3: recipient owner pubkey                      (read-only)
//	4: mint pubkey                                 (read-only)
//	5: SPL Token program id                        (read-only program)
//	6: System program id                           (read-only program)
//	7: Associated Token Account program id         (read-only program)
//	8: ComputeBudget program id  (read-only program, only when used)
//
// `tokenProgram` controls Token-1 vs Token-2022; both share the
// instruction shapes used here (Token-2022 with the transfer-fee
// extension needs opcode 26 + extra bytes — handled by the
// Token-2022 builder, not this one).
func buildSPLTransferMessage(
	senderOwner, recipientOwner, mint, senderATA, recipientATA, tokenProgram [32]byte,
	amount uint64,
	decimals uint8,
	recentBlockhash [32]byte,
	cuLimit uint32,
	cuPrice uint64,
) []byte {
	hasCBLimit := cuLimit > 0
	hasCBPrice := cuPrice > 0
	hasCB := hasCBLimit || hasCBPrice

	var msg []byte

	// ── Header ─────────────────────────────────────────────────────
	msg = append(msg, 1) // numRequiredSignatures: sender owner
	msg = append(msg, 0) // numReadonlySignedAccounts
	// Readonly-unsigned tail: recipientOwner, mint, splTokenProgram,
	// systemProgram, ataProgram (5 entries), plus computeBudget if used.
	roUnsigned := byte(5)
	if hasCB {
		roUnsigned = 6
	}
	msg = append(msg, roUnsigned)

	// ── Account keys ───────────────────────────────────────────────
	// Sorted by signer-then-writable-then-readonly so the static
	// indices used by the instructions below stay correct.
	numKeys := uint16(8)
	if hasCB {
		numKeys = 9
	}
	msg = append(msg, compactU16(numKeys)...)
	msg = append(msg, senderOwner[:]...)    // 0
	msg = append(msg, senderATA[:]...)      // 1
	msg = append(msg, recipientATA[:]...)   // 2
	msg = append(msg, recipientOwner[:]...) // 3
	msg = append(msg, mint[:]...)           // 4
	msg = append(msg, tokenProgram[:]...)   // 5
	msg = append(msg, solanaSystemProgram[:]...) // 6
	msg = append(msg, solanaAtaProgram[:]...)    // 7
	if hasCB {
		msg = append(msg, solanaComputeBudgetProgram[:]...) // 8
	}

	// ── Recent blockhash ───────────────────────────────────────────
	msg = append(msg, recentBlockhash[:]...)

	// ── Instructions ───────────────────────────────────────────────
	numInstr := uint16(2) // ATA create + TransferChecked
	if hasCBLimit {
		numInstr++
	}
	if hasCBPrice {
		numInstr++
	}
	msg = append(msg, compactU16(numInstr)...)

	const (
		idxSenderOwner    = byte(0)
		idxSenderATA      = byte(1)
		idxRecipientATA   = byte(2)
		idxRecipientOwner = byte(3)
		idxMint           = byte(4)
		idxTokenProgram   = byte(5)
		idxSystemProgram  = byte(6)
		idxAtaProgram     = byte(7)
		idxCB             = byte(8)
	)

	if hasCBLimit {
		msg = append(msg, idxCB)
		msg = append(msg, compactU16(0)...) // no accounts
		data := computeBudgetSetLimit(cuLimit)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}
	if hasCBPrice {
		msg = append(msg, idxCB)
		msg = append(msg, compactU16(0)...) // no accounts
		data := computeBudgetSetPrice(cuPrice)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}

	// ATA CreateIdempotent
	// Accounts (per the ATA program ABI): payer (signer + writable),
	// associated_token (writable, gets created), owner (read-only),
	// mint (read-only), system_program, token_program.
	msg = append(msg, idxAtaProgram)
	msg = append(msg, compactU16(6)...)
	msg = append(msg, idxSenderOwner)    // payer
	msg = append(msg, idxRecipientATA)   // associated_token (new)
	msg = append(msg, idxRecipientOwner) // owner
	msg = append(msg, idxMint)           // mint
	msg = append(msg, idxSystemProgram)
	msg = append(msg, idxTokenProgram)
	createData := ataCreateIdempotentInstruction()
	msg = append(msg, compactU16(uint16(len(createData)))...)
	msg = append(msg, createData...)

	// SPL TransferChecked
	// Accounts: source (writable), mint (read-only), destination
	// (writable), authority (signer). For a same-owner transfer
	// senderOwner is the authority.
	msg = append(msg, idxTokenProgram)
	msg = append(msg, compactU16(4)...)
	msg = append(msg, idxSenderATA)
	msg = append(msg, idxMint)
	msg = append(msg, idxRecipientATA)
	msg = append(msg, idxSenderOwner) // authority
	tcData := splTransferCheckedInstruction(amount, decimals)
	msg = append(msg, compactU16(uint16(len(tcData)))...)
	msg = append(msg, tcData...)

	return msg
}
