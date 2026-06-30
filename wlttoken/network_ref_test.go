package wlttoken

import (
	"testing"

	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/xuid"
)

func TestResolveNetworkRef(t *testing.T) {
	// Canonical "<type>.<chainId>" — the form the Dart Token API / Asset.network
	// send, which used to fail as "invalid UUID length: 7" (e.g. "evm.137").
	for _, c := range []struct{ ref, typ, chain string }{
		{"evm.137", "evm", "137"},      // Polygon — the reported case
		{"evm.1", "evm", "1"},          // Ethereum
		{"solana.mainnet", "solana", "mainnet"},
	} {
		got, err := resolveNetworkRef(c.ref)
		if err != nil {
			t.Fatalf("resolveNetworkRef(%q) error: %v", c.ref, err)
		}
		want := wltnet.NetworkIdForTypeAndChainId(c.typ, c.chain)
		if got.String() != want.String() {
			t.Errorf("resolveNetworkRef(%q) = %s, want %s", c.ref, got, want)
		}
	}

	// A network xuid passes through unchanged.
	id, _ := xuid.NewRandom("net")
	got, err := resolveNetworkRef(id.String())
	if err != nil {
		t.Fatalf("resolveNetworkRef(xuid) error: %v", err)
	}
	if got.String() != id.String() {
		t.Errorf("resolveNetworkRef(%s) = %s, want passthrough", id, got)
	}

	// Empty and bare-name refs must error clearly (not "invalid UUID length").
	for _, bad := range []string{"", "polygon"} {
		if _, err := resolveNetworkRef(bad); err == nil {
			t.Errorf("resolveNetworkRef(%q) = nil error, want error", bad)
		}
	}
}
