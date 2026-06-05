package wlttx

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The TransferFee::calculate_fee formula on-chain rounds up:
//
//	fee = ceil(amount * basis_points / 10_000)
//	fee = min(fee, maximum_fee)
//
// If we round DOWN, the program reverts with TransferFeeMismatch
// because the program's own computation rounds up. Pin the rounding
// behaviour across vectors that exercise both "ceil triggers" and
// "max cap triggers".
func TestToken2022_TransferFee_CalculateFee(t *testing.T) {
	cases := []struct {
		name       string
		amount     uint64
		bps        uint16
		maxFee     uint64
		want       uint64
	}{
		{"zero amount", 0, 100, 1_000_000, 0},
		{"zero bps", 1_000_000, 0, 1_000_000, 0},
		{"exact divisible — 100 bps on 10000 = 100", 10_000, 100, 1_000_000, 100},
		// 12345 * 100 / 10000 = 123 with remainder 4500 → ceil = 124.
		{"round up vs round down", 12_345, 100, 1_000_000, 124},
		// 1 bps on 1 base unit: 1 * 1 / 10000 = 0 remainder 1 → 1.
		{"sub-unit rounds up to 1", 1, 1, 1_000_000, 1},
		// Max-fee cap: 1_000_000 * 5000 bps = 500_000_000 but cap 250.
		{"max fee caps", 1_000_000, 5000, 250, 250},
		// 10000 bps == 100% — the entire amount becomes the fee.
		{"100% fee bps", 12_345, 10_000, 1_000_000_000, 12_345},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := token2022TransferFee{
				Epoch:                  0,
				MaximumFee:             c.maxFee,
				TransferFeeBasisPoints: c.bps,
			}
			got := f.calculateFee(c.amount)
			if got != c.want {
				t.Errorf("amount=%d bps=%d max=%d: got=%d want=%d",
					c.amount, c.bps, c.maxFee, got, c.want)
			}
		})
	}
}

// epochFee selects newer when epoch >= newer.epoch, else older.
// The boundary is inclusive at newer.epoch; a regression to strict
// `>` would underbill fees in the activation epoch.
func TestToken2022_TransferFeeConfig_EpochSelect(t *testing.T) {
	cfg := &token2022TransferFeeConfig{
		OlderTransferFee: token2022TransferFee{Epoch: 10, MaximumFee: 100, TransferFeeBasisPoints: 50},
		NewerTransferFee: token2022TransferFee{Epoch: 20, MaximumFee: 200, TransferFeeBasisPoints: 100},
	}
	cases := []struct {
		epoch uint64
		want  uint16
	}{
		{0, 50},
		{19, 50},
		{20, 100},
		{1_000_000, 100},
	}
	for _, c := range cases {
		f := cfg.epochFee(c.epoch)
		if f.TransferFeeBasisPoints != c.want {
			t.Errorf("epoch=%d: bps=%d want=%d", c.epoch, f.TransferFeeBasisPoints, c.want)
		}
	}
}

// parseToken2022TransferFeeConfig must:
//   - return (nil, nil) when the buffer is too short to be a
//     Token-2022 mint with extensions (i.e. plain 82-byte mint).
//   - return the TransferFee values from the right offsets when
//     the extension is present.
//   - error on a malformed TLV that runs off the end of the buffer.
func TestToken2022_ParseTransferFeeConfig(t *testing.T) {
	t.Run("plain mint no extensions", func(t *testing.T) {
		// 82 bytes, well under the AccountType index (165).
		data := make([]byte, 82)
		got, err := parseToken2022TransferFeeConfig(data)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got != nil {
			t.Errorf("got non-nil config on plain mint")
		}
	})

	t.Run("wrong account type at index 165", func(t *testing.T) {
		// 166 bytes total — past the index but with the wrong byte.
		data := make([]byte, 166)
		data[token2022AccountTypeIndex] = 2 // Account, not Mint
		_, err := parseToken2022TransferFeeConfig(data)
		if err == nil {
			t.Error("expected error on wrong account type")
		}
	})

	t.Run("TransferFeeConfig at first TLV slot", func(t *testing.T) {
		// 166 base bytes + 4-byte TLV header + 108-byte body = 278.
		data := make([]byte, 166+4+108)
		data[token2022AccountTypeIndex] = token2022AccountTypeMint
		// TLV header at index 166: type=1, length=108.
		binary.LittleEndian.PutUint16(data[166:168], token2022ExtensionTypeTransferFeeConfig)
		binary.LittleEndian.PutUint16(data[168:170], 108)
		body := data[170:]
		// Skip the two authorities + withheld_amount (32+32+8 = 72 bytes).
		// Older TransferFee at body[72:90].
		binary.LittleEndian.PutUint64(body[72:80], 5)              // epoch
		binary.LittleEndian.PutUint64(body[80:88], 1_000_000)      // maximum_fee
		binary.LittleEndian.PutUint16(body[88:90], 25)             // bps
		// Newer TransferFee at body[90:108].
		binary.LittleEndian.PutUint64(body[90:98], 10)             // epoch
		binary.LittleEndian.PutUint64(body[98:106], 2_000_000)     // maximum_fee
		binary.LittleEndian.PutUint16(body[106:108], 100)          // bps

		got, err := parseToken2022TransferFeeConfig(data)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got == nil {
			t.Fatal("expected config, got nil")
		}
		if got.OlderTransferFee.Epoch != 5 || got.OlderTransferFee.MaximumFee != 1_000_000 || got.OlderTransferFee.TransferFeeBasisPoints != 25 {
			t.Errorf("older: %+v", got.OlderTransferFee)
		}
		if got.NewerTransferFee.Epoch != 10 || got.NewerTransferFee.MaximumFee != 2_000_000 || got.NewerTransferFee.TransferFeeBasisPoints != 100 {
			t.Errorf("newer: %+v", got.NewerTransferFee)
		}
	})

	t.Run("TLV runs off end", func(t *testing.T) {
		// Header claims 1000 bytes but body is missing.
		data := make([]byte, 166+4)
		data[token2022AccountTypeIndex] = token2022AccountTypeMint
		binary.LittleEndian.PutUint16(data[166:168], token2022ExtensionTypeTransferFeeConfig)
		binary.LittleEndian.PutUint16(data[168:170], 1000)
		_, err := parseToken2022TransferFeeConfig(data)
		if err == nil {
			t.Error("expected error on TLV length overflow")
		}
	})

	t.Run("unrelated extension skipped", func(t *testing.T) {
		// Add an extension with a type id != 1, then a real
		// TransferFeeConfig after it. Parser must walk past the
		// first and read the second.
		const otherTLVLen = 16
		data := make([]byte, 166+4+otherTLVLen+4+108)
		data[token2022AccountTypeIndex] = token2022AccountTypeMint
		// First TLV: type=99, length=16, body=zeros
		binary.LittleEndian.PutUint16(data[166:168], 99)
		binary.LittleEndian.PutUint16(data[168:170], otherTLVLen)
		// Second TLV: TransferFeeConfig
		off := 166 + 4 + otherTLVLen
		binary.LittleEndian.PutUint16(data[off:off+2], token2022ExtensionTypeTransferFeeConfig)
		binary.LittleEndian.PutUint16(data[off+2:off+4], 108)
		body := data[off+4:]
		binary.LittleEndian.PutUint16(body[88:90], 42) // older bps
		binary.LittleEndian.PutUint16(body[106:108], 84) // newer bps

		got, err := parseToken2022TransferFeeConfig(data)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if got == nil {
			t.Fatal("expected config, got nil")
		}
		if got.OlderTransferFee.TransferFeeBasisPoints != 42 {
			t.Errorf("older bps: got %d want 42", got.OlderTransferFee.TransferFeeBasisPoints)
		}
		if got.NewerTransferFee.TransferFeeBasisPoints != 84 {
			t.Errorf("newer bps: got %d want 84", got.NewerTransferFee.TransferFeeBasisPoints)
		}
	})
}

// splTransferCheckedWithFeeInstruction must produce the exact 19-byte
// payload: discriminator 26, sub-instruction 1, amount, decimals, fee.
// Pin the bytes — the on-chain program rejects every other shape.
func TestToken2022_TransferCheckedWithFeeInstruction(t *testing.T) {
	cases := []struct {
		amount   uint64
		decimals uint8
		fee      uint64
		want     string // hex
	}{
		// 1.315764 USDT analogue with a tiny fee of 13 base units.
		// amount = 0x1413b4 LE = b4 13 14 00 00 00 00 00
		// fee = 13 = 0x0d LE = 0d 00 00 00 00 00 00 00
		{1_315_764, 6, 13, "1a01" + "b41314000000000006" + "0d00000000000000"},
		// Zero amount + zero fee — both u64 fields filled with zeros.
		{0, 9, 0, "1a01" + "000000000000000009" + "0000000000000000"},
		// Max u64 amount + max u64 fee (hostile-input sanity).
		{0xffffffffffffffff, 0, 0xffffffffffffffff,
			"1a01" + "ffffffffffffffff00" + "ffffffffffffffff"},
	}
	for _, c := range cases {
		got := splTransferCheckedWithFeeInstruction(c.amount, c.decimals, c.fee)
		gotHex := hex.EncodeToString(got)
		if gotHex != c.want {
			t.Errorf("amount=%d dec=%d fee=%d:\n  got:  %s\n  want: %s",
				c.amount, c.decimals, c.fee, gotHex, c.want)
		}
		// Sanity: decode amount + fee back out.
		if got[0] != 26 || got[1] != 1 {
			t.Errorf("discriminators wrong: %x %x", got[0], got[1])
		}
		if amt := binary.LittleEndian.Uint64(got[2:10]); amt != c.amount {
			t.Errorf("amount roundtrip = %d, want %d", amt, c.amount)
		}
		if got[10] != c.decimals {
			t.Errorf("decimals roundtrip = %d, want %d", got[10], c.decimals)
		}
		if fee := binary.LittleEndian.Uint64(got[11:19]); fee != c.fee {
			t.Errorf("fee roundtrip = %d, want %d", fee, c.fee)
		}
	}
}

// tokenProgramForType must return the correct on-chain program id
// for each supported Token row type, and error on unsupported types.
func TestToken2022_TokenProgramForType(t *testing.T) {
	if got, err := tokenProgramForType("spl-token"); err != nil || got != solanaSplTokenProgram {
		t.Errorf("spl-token: got=%x err=%v want=%x", got, err, solanaSplTokenProgram)
	}
	if got, err := tokenProgramForType("spl-token-2022"); err != nil || got != solanaToken2022Program {
		t.Errorf("spl-token-2022: got=%x err=%v want=%x", got, err, solanaToken2022Program)
	}
	if _, err := tokenProgramForType("erc20"); err == nil {
		t.Error("erc20: expected error, got nil")
	}
}

// Token-1 and Token-2022 program ids MUST be distinct, and an ATA
// derived under one must NOT match the ATA under the other for the
// same (owner, mint). Catches a regression that would route a
// Token-2022 transfer to the Token-1 ATA — funds go to the wrong
// account on-chain.
func TestToken2022_AtaDistinctFromToken1(t *testing.T) {
	var owner, mint [32]byte
	for i := range owner {
		owner[i] = byte(0x11)
		mint[i] = byte(0x22)
	}
	ata1, _, err := deriveAssociatedTokenAccount(owner, mint, solanaSplTokenProgram)
	if err != nil {
		t.Fatalf("Token-1 ATA: %v", err)
	}
	ata2022, _, err := deriveAssociatedTokenAccount(owner, mint, solanaToken2022Program)
	if err != nil {
		t.Fatalf("Token-2022 ATA: %v", err)
	}
	if ata1 == ata2022 {
		t.Errorf("Token-1 and Token-2022 ATAs match for same (owner, mint) — program id collision")
	}
}
