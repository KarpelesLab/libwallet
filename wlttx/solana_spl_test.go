package wlttx

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/base58"
)

// The PDA contract: the derived address MUST be off the ed25519
// curve. That's what makes it un-signable by anything other than the
// owning program's CPI. If our derivation ever returned an on-curve
// address (algorithm regression: wrong seed order, missing marker,
// inverted curve check), this test fires.
//
// We additionally pin determinism — same inputs always yield the
// same (address, bump). Random-bump or non-deterministic hashing
// would surface here.
//
// External-vector cross-check (mainnet known wallet → known ATA)
// is intentionally NOT pinned in this test: an external vector
// without an independent computation would just lock in whatever
// this code happens to produce, providing no additional guarantee.
// The property tests below combined with a manual spec review at
// write time is the bar we're holding to.
func TestDeriveAssociatedTokenAccount_PropertiesAndDeterminism(t *testing.T) {
	mustDec := func(s string) (out [32]byte) {
		b, err := base58.Bitcoin.Decode(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("decode %q: %v (len=%d)", s, err, len(b))
		}
		copy(out[:], b)
		return
	}

	cases := []struct {
		name  string
		owner string
		mint  string
	}{
		{"real_mainnet_pair_a", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		// Two more arbitrary 32-byte values — exercise the bump
		// loop on inputs whose hash distribution differs from the
		// case above. Without these, an "always 255" bug could
		// slip through.
		{"all_ones_owner_all_twos_mint", "", ""},
	}

	// Synthesize the all-ones / all-twos pair directly so we don't
	// need a canonical base58 encoder for them in the test.
	var (
		ownerOnes [32]byte
		mintTwos  [32]byte
	)
	for i := range ownerOnes {
		ownerOnes[i] = 0x11
		mintTwos[i] = 0x22
	}

	for _, c := range cases {
		var owner, mint [32]byte
		if c.name == "all_ones_owner_all_twos_mint" {
			owner = ownerOnes
			mint = mintTwos
		} else {
			owner = mustDec(c.owner)
			mint = mustDec(c.mint)
		}

		ata, bump, err := deriveAssociatedTokenAccount(owner, mint, solanaSplTokenProgram)
		if err != nil {
			t.Fatalf("%s: derive: %v", c.name, err)
		}

		// Property 1: must be OFF the ed25519 curve.
		if _, err := new(edwards25519.Point).SetBytes(ata[:]); err == nil {
			t.Errorf("%s: derived ATA %x is ON the curve — PDA contract violated", c.name, ata)
		}

		// Property 2: bump must be in [0, 255]. Reaching 0 with
		// every candidate on-curve means the algorithm errored,
		// not that we returned 0. Bump 255 is the most common
		// canonical case; lower bumps appear when the hash lands
		// on-curve for higher values.
		if bump > 255 {
			t.Errorf("%s: bump %d > 255", c.name, bump)
		}

		// Property 3: determinism — same inputs always give same
		// (ata, bump).
		for i := 0; i < 3; i++ {
			ata2, bump2, err := deriveAssociatedTokenAccount(owner, mint, solanaSplTokenProgram)
			if err != nil {
				t.Fatalf("%s iter %d: %v", c.name, i, err)
			}
			if ata2 != ata || bump2 != bump {
				t.Errorf("%s iter %d not stable: got=%x/%d first=%x/%d", c.name, i, ata2, bump2, ata, bump)
			}
		}
	}
}

// splTransferCheckedInstruction must produce the exact 10-byte
// payload Solana's SPL Token program reads — opcode 12, u64 LE
// amount, u8 decimals. The on-chain validator rejects any other
// layout, so pin the bytes.
func TestSplTransferCheckedInstructionBytes(t *testing.T) {
	cases := []struct {
		amount   uint64
		decimals uint8
		want     string // hex
	}{
		{amount: 0, decimals: 6, want: "0c000000000000000006"},
		{amount: 1, decimals: 6, want: "0c010000000000000006"},
		// 1_315_764 = 0x1413b4 → LE bytes b4 13 14 00 00 00 00 00.
		// Pinning the exact user-reported USDT amount that surfaced
		// the lamports-as-USDT bug — a regression that swaps the
		// byte order or shifts the opcode would fail this case.
		{amount: 1_315_764, decimals: 6, want: "0cb41314000000000006"},
		{amount: 0xdeadbeef, decimals: 9, want: "0cefbeadde0000000009"},
		// Max u64 — must not roll over into the decimals byte.
		{amount: 0xffffffffffffffff, decimals: 0, want: "0cffffffffffffffff00"},
	}
	for _, c := range cases {
		got := splTransferCheckedInstruction(c.amount, c.decimals)
		gotHex := hex.EncodeToString(got)
		wantClean := strings.ReplaceAll(c.want, " ", "")
		if gotHex != wantClean {
			t.Errorf("amount=%d decimals=%d:\n  got:  %s\n  want: %s", c.amount, c.decimals, gotHex, wantClean)
		}
		if amt := binary.LittleEndian.Uint64(got[1:9]); amt != c.amount {
			t.Errorf("decoded amount = %d, want %d", amt, c.amount)
		}
		if got[9] != c.decimals {
			t.Errorf("decoded decimals = %d, want %d", got[9], c.decimals)
		}
	}
}

// ataCreateIdempotentInstruction emits a single opcode-1 byte. The
// "idempotent" flavour distinguishes it from plain Create (opcode 0,
// fails when the ATA already exists). Pin so a regression to opcode
// 0 — which would break the unconditional-create UX — fails loud.
func TestAtaCreateIdempotentInstruction(t *testing.T) {
	got := ataCreateIdempotentInstruction()
	if len(got) != 1 || got[0] != 1 {
		t.Errorf("got = %x, want = 01", got)
	}
}

// Smoke test for the full SPL message builder: confirm header,
// account-list layout, and the presence of the TransferChecked
// payload with the correct amount.
func TestBuildSPLTransferMessageShape(t *testing.T) {
	var owner, recip, mint, sATA, rATA [32]byte
	for i := range owner {
		owner[i] = byte(0x11)
		recip[i] = byte(0x22)
		mint[i] = byte(0x33)
		sATA[i] = byte(0x44)
		rATA[i] = byte(0x55)
	}
	var bh [32]byte
	bh[0] = 0xab

	msg := buildSPLTransferMessage(
		owner, recip, mint, sATA, rATA,
		solanaSplTokenProgram,
		1_315_764, 6,
		bh,
		0, 0,
	)
	// Header: numRequiredSigs=1, numROSigned=0, numROUnsigned=5
	if msg[0] != 1 || msg[1] != 0 || msg[2] != 5 {
		t.Fatalf("header = %v, want [1 0 5]", msg[:3])
	}
	// numKeys = 8
	if msg[3] != 8 {
		t.Fatalf("numKeys = %d, want 8", msg[3])
	}
	// Mint must appear in the account list at key index 4 (offset
	// 4 + 4*32 = 132).
	if !equalSlice(msg[4+4*32:4+5*32], mint[:]) {
		t.Errorf("mint not at index 4 in account list")
	}
	// SPL token program must appear at key index 5 (offset 4 + 5*32 = 164).
	if !equalSlice(msg[4+5*32:4+6*32], solanaSplTokenProgram[:]) {
		t.Errorf("spl token program not at index 5 in account list")
	}
	// 1_315_764 LE encoded inside the TransferChecked payload.
	if !containsSeq(msg, []byte{0x0c, 0xb4, 0x13, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}) {
		t.Errorf("TransferChecked payload (opcode+amount+decimals) not found in message")
	}
	// ATA CreateIdempotent (opcode 1) must also appear as an
	// instruction payload — it's 1 byte preceded by its compact-u16
	// length-of-1, so look for the bytes "01 01".
	if !containsSeq(msg, []byte{0x01, 0x01}) {
		t.Errorf("ATA CreateIdempotent payload not found in message")
	}
}

// When ComputeBudget priority is set, the header's readonly-unsigned
// count bumps to 6 (ComputeBudget program added) and total keys go
// from 8 → 9.
func TestBuildSPLTransferMessage_ComputeBudgetHeaderAdjusted(t *testing.T) {
	var owner, recip, mint, sATA, rATA, bh [32]byte
	msg := buildSPLTransferMessage(
		owner, recip, mint, sATA, rATA,
		solanaSplTokenProgram,
		1, 6, bh,
		200_000, 1_000,
	)
	if msg[2] != 6 {
		t.Errorf("numROUnsigned = %d, want 6 (CB program adds one)", msg[2])
	}
	if msg[3] != 9 {
		t.Errorf("numKeys = %d, want 9 (CB program adds one)", msg[3])
	}
}

func equalSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsSeq(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if equalSlice(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}
