package wltwallet

import "testing"

// resolveProtocol drives the dispatch sites in keygen / sign /
// reshare. The contract:
//
//   - Explicit Protocol always wins.
//   - Empty Protocol on a legacy row maps to the curve-appropriate
//     legacy constant (gg18 / eddsa) so existing wallets without a
//     stamped Protocol continue to route through the historical
//     ecdsatss / eddsatss paths.
//   - Unknown curve + empty Protocol returns "" (caller surfaces
//     this as an error rather than silently picking a default).
//
// Pinning these cases here means a future refactor that touches the
// Protocol field can't accidentally re-route existing wallets.
func TestResolveProtocol(t *testing.T) {
	cases := []struct {
		name     string
		curve    string
		protocol string
		want     string
	}{
		{"empty Protocol on secp256k1 → legacy gg18", "secp256k1", "", ProtocolLegacyECDSA},
		{"empty Protocol on ed25519 → legacy eddsa", "ed25519", "", ProtocolLegacyEdDSA},
		{"explicit gg18 round-trips", "secp256k1", ProtocolLegacyECDSA, ProtocolLegacyECDSA},
		{"explicit eddsa round-trips", "ed25519", ProtocolLegacyEdDSA, ProtocolLegacyEdDSA},
		{"explicit dkls23 wins over curve default", "secp256k1", ProtocolDKLS, ProtocolDKLS},
		{"explicit frost wins over curve default", "ed25519", ProtocolFROST, ProtocolFROST},
		// Defensive: unknown curve with empty Protocol — caller must
		// branch on this, not pretend it's gg18.
		{"unknown curve + empty → empty", "p256", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &Wallet{Curve: tc.curve, Protocol: tc.protocol}
			if got := w.resolveProtocol(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

	// Nil receiver is allowed (avoids defensive nil-checks at every
	// callsite); returns empty.
	var nilW *Wallet
	if got := nilW.resolveProtocol(); got != "" {
		t.Errorf("nil receiver = %q, want empty", got)
	}
}
