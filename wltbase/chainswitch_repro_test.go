package wltbase

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/xuid"
)

// User reproduction: wallet_switchEthereumChain to Linea (0xe708)
// fails on 0.4.1 with:
//
//	chain_switch: malformed request value:
//	math/big: cannot unmarshal "1.7436763532287587e+76" into a *big.Int
//
// 1.74e+76 is what a 76-digit integer becomes after a roundtrip
// through float64 (precision loss). The only *big.Int field reachable
// from a ChainSwitchValue is wltacct.Account.IL — somewhere a value
// is losing its `,string` JSON tag and getting coerced to a JSON
// number. Reproduce by simulating the persist/load roundtrip
// req.Value undergoes when the request is stashed in psql and
// later loaded for approval.
func TestChainSwitchValue_BigIntRoundtrip(t *testing.T) {
	// Account with a 254-bit IL — the magnitude where float64
	// precision loss starts producing scientific notation.
	il, _ := new(big.Int).SetString(
		"29384563453123456789012345678901234567890123456789012345678901234567890123456",
		10,
	)
	acct := &wltacct.Account{
		Id:      xuid.New("acct"),
		Curve:   "secp256k1",
		Path:    "m/44/60/0/0",
		Address: "0xdeadbeef",
		IL:      il,
	}
	val := &ChainSwitchValue{
		RequestedFamily:   "evm",
		RequestedMethod:   "wallet_switchEthereumChain",
		TargetNetwork:     &wltnet.Network{Type: "evm", ChainId: "59144", Name: "Linea"},
		IsNewNetwork:      true,
		CandidateAccounts: []*wltacct.Account{acct},
	}

	// Step 1: marshal as a typed struct (what request.go does on save).
	typedJSON, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("marshal typed: %v", err)
	}
	t.Logf("typed JSON IL fragment: %s", extractILFragment(typedJSON))

	// Step 2: unmarshal into `any` (mimics psql loading req.Value
	// where Value's Go type is `any`).
	var loaded any
	if err := json.Unmarshal(typedJSON, &loaded); err != nil {
		t.Fatalf("unmarshal into any: %v", err)
	}

	// Walk the loaded structure and report what type IL ends up as
	// — that's the smoking gun if it's float64.
	if cs, ok := loaded.(map[string]any); ok {
		if accs, ok := cs["candidateAccounts"].([]any); ok && len(accs) > 0 {
			if a0, ok := accs[0].(map[string]any); ok {
				t.Logf("loaded IL type=%T value=%v", a0["IL"], a0["IL"])
			}
		}
	}

	// Step 3: feed the loaded `any` back through decodeChainSwitchValue
	// — the actual production failure point.
	out, err := decodeChainSwitchValue(loaded)
	if err != nil {
		t.Fatalf("decodeChainSwitchValue failed: %v", err)
	}
	if out.CandidateAccounts[0].IL.Cmp(il) != 0 {
		t.Fatalf("IL roundtrip lost precision:\n  got=%s\n want=%s",
			out.CandidateAccounts[0].IL, il)
	}
}

func extractILFragment(b []byte) string {
	s := string(b)
	i := strings.Index(s, `"IL"`)
	if i < 0 {
		return "(no IL field)"
	}
	end := i + 60
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

// Sanity check: typed-struct → typed-struct roundtrip via JSON.
// If the existing ,string tag on Account.IL worked correctly, we'd
// see IL emitted as a quoted string and the decode would round-trip
// cleanly. Documenting the fact that it does NOT — Go's encoding/
// json silently ignores ,string for any type that has a custom
// MarshalJSON, which *big.Int does.
func TestAccountILDirectRoundtrip(t *testing.T) {
	il, _ := new(big.Int).SetString(
		"29384563453123456789012345678901234567890123456789012345678901234567890123456",
		10,
	)
	in := &wltacct.Account{IL: il}
	buf, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("encoded: %s", extractILFragment(buf))

	var out wltacct.Account
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatalf("unmarshal: %v (this is the type-mismatch flavor of the bug)", err)
	}
	if out.IL == nil || out.IL.Cmp(il) != 0 {
		t.Fatalf("IL roundtrip lost value:\n  got=%v\n want=%s", out.IL, il)
	}
}
