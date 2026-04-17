package wlttx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSolanaFeeLamports(t *testing.T) {
	cases := []struct {
		name     string
		cuLimit  uint32
		cuPrice  uint64
		wantFee  uint64
	}{
		{"legacy (no compute budget)", 0, 0, 5000},
		{"cuLimit only — zero price → still 5000", 1000, 0, 5000},
		{"cuPrice only — zero limit → still 5000", 0, 2000, 5000},
		{
			// 1000 * 10_000 = 10_000_000 microlamports = 10 lamports priority.
			name:    "medium priority",
			cuLimit: 1000,
			cuPrice: 10_000,
			wantFee: 5010,
		},
		{
			// Non-multiple-of-1_000_000 rounds up (ceil).
			// 500 * 1001 = 500_500 → priority 1 lamport.
			name:    "tiny fractional rounds up",
			cuLimit: 500,
			cuPrice: 1001,
			wantFee: 5001,
		},
		{
			// Exact 1 lamport.
			name:    "exactly 1M",
			cuLimit: 1000,
			cuPrice: 1000,
			wantFee: 5001,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx := &Transaction{ComputeUnitLimit: c.cuLimit, ComputeUnitPrice: c.cuPrice}
			if got := solanaFeeLamports(tx); got != c.wantFee {
				t.Errorf("fee = %d, want %d", got, c.wantFee)
			}
		})
	}
}

// TestBuildSOLTransferMessage_Legacy verifies that when no
// ComputeBudget is requested the serialized message is byte-identical
// to the pre-Pass-3 layout: 3 accounts, numReadonlyUnsignedAccounts=1,
// and a single Transfer instruction at programIdIndex=2.
func TestBuildSOLTransferMessage_Legacy(t *testing.T) {
	var from, to, bh [32]byte
	from[0] = 0x11
	to[0] = 0x22
	bh[0] = 0x33

	msg := buildSOLTransferMessage(from, to, 1_000_000, bh, 0, 0)

	// Header bytes: [1, 0, 1]
	if msg[0] != 1 || msg[1] != 0 || msg[2] != 1 {
		t.Errorf("legacy header = %v, want [1 0 1]", msg[:3])
	}

	// Account key count = 3 (compact-u16 → 1 byte for small values).
	if msg[3] != 3 {
		t.Errorf("account count byte = %d, want 3", msg[3])
	}

	// Number of instructions byte = 1.
	// Layout: 3 header + 1 count + 32*3 keys + 32 bh = 3+1+96+32 = 132.
	const numInstrOffset = 3 + 1 + 32*3 + 32
	if msg[numInstrOffset] != 1 {
		t.Errorf("numInstructions byte = %d, want 1", msg[numInstrOffset])
	}

	// programIdIndex of the single instruction = 2 (SystemProgram).
	if msg[numInstrOffset+1] != 2 {
		t.Errorf("first instruction programIdIndex = %d, want 2", msg[numInstrOffset+1])
	}
}

// TestBuildSOLTransferMessage_WithCompute verifies the 4-account
// layout and that the ComputeBudget instructions are serialized
// first (required: Solana validates that ComputeBudget ixns precede
// any CU-consuming ixn).
func TestBuildSOLTransferMessage_WithCompute(t *testing.T) {
	var from, to, bh [32]byte
	from[0] = 0xaa
	to[0] = 0xbb

	msg := buildSOLTransferMessage(from, to, 5_000, bh, 200_000, 3_500)

	// Header numReadonlyUnsignedAccounts must be 2
	// (SystemProgram + ComputeBudget).
	if msg[0] != 1 || msg[1] != 0 || msg[2] != 2 {
		t.Errorf("header = %v, want [1 0 2]", msg[:3])
	}
	if msg[3] != 4 {
		t.Errorf("account count = %d, want 4", msg[3])
	}

	// The ComputeBudget program bytes should appear at account slot 3.
	cbStart := 3 + 1 + 32*3
	if !bytes.Equal(msg[cbStart:cbStart+32], solanaComputeBudgetProgram[:]) {
		t.Errorf("ComputeBudget program not at slot 3")
	}

	// Number of instructions = 3 (SetLimit + SetPrice + Transfer).
	numInstrOffset := 3 + 1 + 32*4 + 32
	if msg[numInstrOffset] != 3 {
		t.Errorf("numInstructions = %d, want 3", msg[numInstrOffset])
	}

	// First instruction should be SetComputeUnitLimit on the
	// ComputeBudget program (programIdIndex = 3, empty accounts,
	// data = [0x02, u32 LE cuLimit]).
	p := numInstrOffset + 1
	if msg[p] != 3 {
		t.Errorf("first instruction programIdIndex = %d, want 3 (ComputeBudget)", msg[p])
	}
	p++
	if msg[p] != 0 {
		t.Errorf("first instruction account count = %d, want 0", msg[p])
	}
	p++
	if msg[p] != 5 {
		t.Errorf("first instruction data length = %d, want 5", msg[p])
	}
	p++
	if msg[p] != 0x02 {
		t.Errorf("first instruction discriminator = 0x%x, want 0x02 (SetComputeUnitLimit)", msg[p])
	}
	p++
	cuLimit := binary.LittleEndian.Uint32(msg[p : p+4])
	if cuLimit != 200_000 {
		t.Errorf("SetComputeUnitLimit arg = %d, want 200000", cuLimit)
	}
	p += 4

	// Second instruction should be SetComputeUnitPrice:
	// [programIdIndex=3, account_count=0, data_len=9, 0x03, u64 LE price].
	if msg[p] != 3 {
		t.Errorf("second instruction programIdIndex = %d, want 3", msg[p])
	}
	p++
	if msg[p] != 0 {
		t.Errorf("second instruction account count = %d, want 0", msg[p])
	}
	p++
	if msg[p] != 9 {
		t.Errorf("second instruction data length = %d, want 9", msg[p])
	}
	p++
	if msg[p] != 0x03 {
		t.Errorf("second instruction discriminator = 0x%x, want 0x03 (SetComputeUnitPrice)", msg[p])
	}
	p++
	cuPrice := binary.LittleEndian.Uint64(msg[p : p+8])
	if cuPrice != 3_500 {
		t.Errorf("SetComputeUnitPrice arg = %d, want 3500", cuPrice)
	}
}

// TestResolveSolanaPriority_NoneClearsValues ensures that setting
// PriorityLevel="none" strips any previously-set compute budget
// values so the caller can't accidentally pay a priority fee they
// opted out of.
func TestResolveSolanaPriority_NoneClearsValues(t *testing.T) {
	tx := &Transaction{
		PriorityLevel:    "none",
		ComputeUnitLimit: 200_000,
		ComputeUnitPrice: 5000,
	}
	if err := resolveSolanaPriority(nil, tx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tx.ComputeUnitLimit != 0 || tx.ComputeUnitPrice != 0 {
		t.Errorf("want both zeroed, got limit=%d price=%d", tx.ComputeUnitLimit, tx.ComputeUnitPrice)
	}
}

// TestResolveSolanaPriority_InvalidLevel rejects typo'd priority levels.
func TestResolveSolanaPriority_InvalidLevel(t *testing.T) {
	tx := &Transaction{PriorityLevel: "urgent"}
	if err := resolveSolanaPriority(nil, tx); err == nil {
		t.Error("want error for invalid PriorityLevel, got nil")
	}
}

// TestResolveSolanaPriority_ExplicitPriceDefaultsLimit makes sure a
// caller who pinned only a price gets a reasonable compute-unit
// limit so their ComputeBudget instruction actually lands.
func TestResolveSolanaPriority_ExplicitPriceDefaultsLimit(t *testing.T) {
	tx := &Transaction{ComputeUnitPrice: 10_000}
	if err := resolveSolanaPriority(nil, tx); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tx.ComputeUnitLimit == 0 {
		t.Errorf("want non-zero CU limit when price is set, got 0")
	}
}
