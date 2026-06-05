package wlttx

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// SPL Token-2022 program id (TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb).
// Distinct from Token-1's TokenkegQfeZ… — instructions sent to the
// wrong program id are silently no-ops or revert depending on the
// instruction. The ATA derivation also keys on this id, so a Token-1
// vs Token-2022 mismatch produces a different ATA than the one the
// network expects.
var solanaToken2022Program [32]byte

func init() {
	raw, err := base58.Bitcoin.Decode("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	if err != nil || len(raw) != 32 {
		panic(fmt.Sprintf("libwallet: invalid Token-2022 program id: %v (len=%d)", err, len(raw)))
	}
	copy(solanaToken2022Program[:], raw)
}

// Layout constants for a Token-2022 Mint account with extensions.
// Token-2022 reserves bytes 82..165 as padding so a Mint and an
// Account share the offset of the AccountType discriminator byte
// (165). Extension TLV entries start at index 166.
const (
	token2022BaseMintLen      = 82
	token2022AccountTypeIndex = 165
	token2022AccountTypeMint  = 1
)

// TransferFee mirrors the on-chain TransferFee struct.
//
//	epoch: u64 LE
//	maximum_fee: u64 LE
//	transfer_fee_basis_points: u16 LE
//
// 18 bytes total, packed without alignment.
type token2022TransferFee struct {
	Epoch              uint64
	MaximumFee         uint64
	TransferFeeBasisPoints uint16
}

// TransferFeeConfig extension (type id = 1 in the Token-2022
// extension TLV space). Layout:
//
//	transfer_fee_config_authority: 32 bytes (Pubkey::default() == None)
//	withdraw_withheld_authority:   32 bytes
//	withheld_amount:               u64 LE
//	older_transfer_fee:            TransferFee (18 bytes)
//	newer_transfer_fee:            TransferFee (18 bytes)
//
// 108 bytes total.
type token2022TransferFeeConfig struct {
	OlderTransferFee token2022TransferFee
	NewerTransferFee token2022TransferFee
}

// token2022ExtensionTypeTransferFeeConfig is the TLV type id for
// the TransferFeeConfig extension.
const token2022ExtensionTypeTransferFeeConfig = uint16(1)

// parseToken2022TransferFeeConfig walks the extension TLV in a
// Token-2022 mint account's raw bytes and returns the TransferFee
// epochs if present, or (nil, nil) when the mint has no transfer-fee
// extension.
//
// Returns an error when the account data is too short to be a valid
// Token-2022 mint with extensions, or when an extension's declared
// length runs off the end of the buffer (malformed account data —
// would also fail on-chain, surface the cause loud).
func parseToken2022TransferFeeConfig(data []byte) (*token2022TransferFeeConfig, error) {
	if len(data) <= token2022AccountTypeIndex {
		// Token-1-style mint (82 bytes) or short truncated buffer —
		// either way, no extensions.
		return nil, nil
	}
	if data[token2022AccountTypeIndex] != token2022AccountTypeMint {
		return nil, fmt.Errorf("token-2022 mint: account type at offset %d is %d, expected %d (Mint)",
			token2022AccountTypeIndex, data[token2022AccountTypeIndex], token2022AccountTypeMint)
	}

	off := token2022AccountTypeIndex + 1
	for off+4 <= len(data) {
		extType := binary.LittleEndian.Uint16(data[off : off+2])
		extLen := binary.LittleEndian.Uint16(data[off+2 : off+4])
		bodyOff := off + 4
		bodyEnd := bodyOff + int(extLen)
		if bodyEnd > len(data) {
			return nil, fmt.Errorf("token-2022 mint: extension type %d length %d runs off end of data (off=%d, len=%d)",
				extType, extLen, off, len(data))
		}
		if extType == token2022ExtensionTypeTransferFeeConfig {
			body := data[bodyOff:bodyEnd]
			if len(body) < 108 {
				return nil, fmt.Errorf("token-2022 TransferFeeConfig: body length %d < 108", len(body))
			}
			// Skip 32 + 32 + 8 = 72 bytes (authorities + withheld_amount).
			// Older TransferFee at offset 72, newer at 72 + 18 = 90.
			older := token2022TransferFee{
				Epoch:                  binary.LittleEndian.Uint64(body[72:80]),
				MaximumFee:             binary.LittleEndian.Uint64(body[80:88]),
				TransferFeeBasisPoints: binary.LittleEndian.Uint16(body[88:90]),
			}
			newer := token2022TransferFee{
				Epoch:                  binary.LittleEndian.Uint64(body[90:98]),
				MaximumFee:             binary.LittleEndian.Uint64(body[98:106]),
				TransferFeeBasisPoints: binary.LittleEndian.Uint16(body[106:108]),
			}
			return &token2022TransferFeeConfig{OlderTransferFee: older, NewerTransferFee: newer}, nil
		}
		off = bodyEnd
	}
	return nil, nil
}

// epochFee selects the active TransferFee for the given current
// epoch. The newer fee activates once the network reaches its
// declared epoch; before that, the older fee applies. Mirrors the
// on-chain `get_epoch_fee` logic exactly.
func (c *token2022TransferFeeConfig) epochFee(currentEpoch uint64) token2022TransferFee {
	if currentEpoch >= c.NewerTransferFee.Epoch {
		return c.NewerTransferFee
	}
	return c.OlderTransferFee
}

// calculateFee mirrors the on-chain TransferFee::calculate_fee
// formula:
//
//	fee = ceil(amount * basis_points / 10_000)
//	fee = min(fee, maximum_fee)
//
// Round-up matches the program; rounding down would let a caller pay
// 1 base unit less than the mint expects, which the program rejects.
func (t token2022TransferFee) calculateFee(amount uint64) uint64 {
	if t.TransferFeeBasisPoints == 0 || amount == 0 {
		return 0
	}
	const basisPointsDivisor = uint64(10_000)
	// (amount * bps + 9999) / 10000 — using uint128 via two uint64s
	// is unnecessary at SPL amounts (Solana caps any single SPL
	// transfer well below 2^64), but use math/big anyway to keep
	// the implementation honest under hostile inputs.
	hi, lo := mulU64(amount, uint64(t.TransferFeeBasisPoints))
	hi, lo = addU128U64(hi, lo, basisPointsDivisor-1)
	q := divU128U64(hi, lo, basisPointsDivisor)
	if q > t.MaximumFee {
		return t.MaximumFee
	}
	return q
}

// mulU64 returns the 128-bit product of two uint64s as (hi, lo).
func mulU64(a, b uint64) (hi, lo uint64) {
	const mask = uint64(1<<32 - 1)
	a0, a1 := a&mask, a>>32
	b0, b1 := b&mask, b>>32
	w0 := a0 * b0
	t := a1*b0 + w0>>32
	w1 := t & mask
	w2 := t >> 32
	w1 += a0 * b1
	lo = a * b
	hi = a1*b1 + w2 + w1>>32
	return
}

// addU128U64 returns (hi, lo) + add as a 128-bit value.
func addU128U64(hi, lo, add uint64) (uint64, uint64) {
	nlo := lo + add
	if nlo < lo {
		hi++
	}
	return hi, nlo
}

// divU128U64 returns the lower 64 bits of (hi, lo) / div. Panics on
// div=0; callers gate on bps > 0 first. Real SPL inputs never
// overflow into bits 64+ (amount * 10000 + 9999 stays well under
// 2^80 even at max-u64 amounts, so hi is tiny), but the math/big
// fallback handles it correctly for the hostile-input case.
func divU128U64(hi, lo, div uint64) uint64 {
	if div == 0 {
		panic("divU128U64: division by zero")
	}
	if hi == 0 {
		return lo / div
	}
	// Construct hi<<64 | lo in big.Int and divide.
	x := new(big.Int).SetUint64(hi)
	x.Lsh(x, 64)
	x.Or(x, new(big.Int).SetUint64(lo))
	d := new(big.Int).SetUint64(div)
	x.Quo(x, d)
	return x.Uint64()
}

// solanaCurrentEpoch fetches the current epoch via getEpochInfo. Used
// before computing the active transfer-fee.
func solanaCurrentEpoch(ctx context.Context, n *wltnet.Network) (uint64, error) {
	raw, err := n.DoRPCCtx(ctx, "getEpochInfo")
	if err != nil {
		return 0, fmt.Errorf("getEpochInfo: %w", err)
	}
	var resp struct {
		Epoch uint64 `json:"epoch"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, fmt.Errorf("parse getEpochInfo: %w", err)
	}
	return resp.Epoch, nil
}

// solanaFetchMintAccount returns the raw account data bytes for a
// Solana account, base64-decoded. Used to inspect Token-2022 mint
// extensions; jsonParsed encoding doesn't expose extension TLV.
func solanaFetchMintAccount(ctx context.Context, n *wltnet.Network, mintB58 string) ([]byte, error) {
	raw, err := n.DoRPCCtx(ctx, "getAccountInfo", mintB58, map[string]string{"encoding": "base64"})
	if err != nil {
		return nil, fmt.Errorf("getAccountInfo: %w", err)
	}
	var resp struct {
		Value *struct {
			Data []string `json:"data"` // [base64, "base64"]
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse getAccountInfo: %w", err)
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("mint %s not found", mintB58)
	}
	if len(resp.Value.Data) < 1 {
		return nil, errors.New("getAccountInfo: missing data field")
	}
	dataB64 := resp.Value.Data[0]
	return base64.StdEncoding.DecodeString(dataB64)
}

// splTransferCheckedWithFeeInstruction encodes the data for the
// Token-2022 TransferFee extension's TransferCheckedWithFee
// sub-instruction.
//
// Layout (19 bytes):
//
//	[26]                          — Token-2022 ExtensionInstruction
//	                                discriminator for TransferFee.
//	[1]                           — TransferFeeInstruction sub-discriminator
//	                                for TransferCheckedWithFee.
//	amount: u64 LE                — pre-fee amount the sender wants to move.
//	decimals: u8                  — mint decimals (verified on-chain).
//	fee: u64 LE                   — the fee amount the sender expects to be
//	                                applied; the program rejects the tx if
//	                                this disagrees with its own computation.
//
// Sending pre-fee amount with a too-low fee field reverts; too-high
// is also rejected. The caller must compute the same fee the on-chain
// program will, using the mint's active TransferFee for the current
// epoch.
func splTransferCheckedWithFeeInstruction(amount uint64, decimals uint8, fee uint64) []byte {
	data := make([]byte, 19)
	data[0] = 26 // TransferFee extension discriminator
	data[1] = 1  // TransferCheckedWithFee sub-instruction
	binary.LittleEndian.PutUint64(data[2:10], amount)
	data[10] = decimals
	binary.LittleEndian.PutUint64(data[11:19], fee)
	return data
}

// tokenProgramForType returns the on-chain program id used by the
// given Token row's Type. The caller passes this to
// deriveAssociatedTokenAccount and buildSPLTransferMessage so the
// ATAs and the SPL TransferChecked instruction route through the
// right program.
func tokenProgramForType(tokenType string) ([32]byte, error) {
	switch tokenType {
	case "spl-token":
		return solanaSplTokenProgram, nil
	case "spl-token-2022":
		return solanaToken2022Program, nil
	default:
		return [32]byte{}, fmt.Errorf("unknown SPL token type %q", tokenType)
	}
}

// buildSPLTransferWithFeeMessage is the Token-2022-with-fee variant
// of buildSPLTransferMessage. Identical layout — same accounts in
// the same positions — but with TransferCheckedWithFee (19-byte
// payload) in place of TransferChecked (10-byte). The tokenProgram
// is Token-2022's program id; the ATAs must have been derived
// against the same id by the caller.
func buildSPLTransferWithFeeMessage(
	senderOwner, recipientOwner, mint, senderATA, recipientATA, tokenProgram [32]byte,
	amount uint64,
	decimals uint8,
	fee uint64,
	recentBlockhash [32]byte,
	cuLimit uint32,
	cuPrice uint64,
) []byte {
	hasCBLimit := cuLimit > 0
	hasCBPrice := cuPrice > 0
	hasCB := hasCBLimit || hasCBPrice

	var msg []byte

	msg = append(msg, 1) // numRequiredSignatures: sender owner
	msg = append(msg, 0) // numReadonlySignedAccounts
	roUnsigned := byte(5)
	if hasCB {
		roUnsigned = 6
	}
	msg = append(msg, roUnsigned)

	numKeys := uint16(8)
	if hasCB {
		numKeys = 9
	}
	msg = append(msg, compactU16(numKeys)...)
	msg = append(msg, senderOwner[:]...)
	msg = append(msg, senderATA[:]...)
	msg = append(msg, recipientATA[:]...)
	msg = append(msg, recipientOwner[:]...)
	msg = append(msg, mint[:]...)
	msg = append(msg, tokenProgram[:]...)
	msg = append(msg, solanaSystemProgram[:]...)
	msg = append(msg, solanaAtaProgram[:]...)
	if hasCB {
		msg = append(msg, solanaComputeBudgetProgram[:]...)
	}

	msg = append(msg, recentBlockhash[:]...)

	numInstr := uint16(2) // ATA create + TransferCheckedWithFee
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
		msg = append(msg, compactU16(0)...)
		data := computeBudgetSetLimit(cuLimit)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}
	if hasCBPrice {
		msg = append(msg, idxCB)
		msg = append(msg, compactU16(0)...)
		data := computeBudgetSetPrice(cuPrice)
		msg = append(msg, compactU16(uint16(len(data)))...)
		msg = append(msg, data...)
	}

	// ATA CreateIdempotent
	msg = append(msg, idxAtaProgram)
	msg = append(msg, compactU16(6)...)
	msg = append(msg, idxSenderOwner)
	msg = append(msg, idxRecipientATA)
	msg = append(msg, idxRecipientOwner)
	msg = append(msg, idxMint)
	msg = append(msg, idxSystemProgram)
	msg = append(msg, idxTokenProgram)
	createData := ataCreateIdempotentInstruction()
	msg = append(msg, compactU16(uint16(len(createData)))...)
	msg = append(msg, createData...)

	// SPL TransferCheckedWithFee
	msg = append(msg, idxTokenProgram)
	msg = append(msg, compactU16(4)...)
	msg = append(msg, idxSenderATA)
	msg = append(msg, idxMint)
	msg = append(msg, idxRecipientATA)
	msg = append(msg, idxSenderOwner) // authority
	tcData := splTransferCheckedWithFeeInstruction(amount, decimals, fee)
	msg = append(msg, compactU16(uint16(len(tcData)))...)
	msg = append(msg, tcData...)

	return msg
}
