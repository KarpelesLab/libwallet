package wltwallet

import (
	"os"
	"testing"
)

// TestMain registers a wallet-identity record for the whole package
// test binary so any Crypto/WalletSign:* call the tests make ships
// the Sec-ClientId header the backend expects.
//
// Without this, the rest library sees no ClientID and tests run
// effectively unauthenticated — the real-infra wdrone path rejects /
// rate-limits / no-ops, which is why the backend-dependent tests
// (TestRemoteWallet, TestEdDSALocalToRemoteReshare, the reshare
// scenario suite) were silently producing the same "no payload
// available" / "context deadline exceeded" failures as a genuinely
// broken backend would. We were diagnosing infra flakes when in fact
// we were sending requests the backend wouldn't honour.
//
// The ClientID value is the production app identifier
// "com.ellipx.walletapp", same string ellipx-mobile-app ships in
// main.dart. It's not an auth secret — it's the public app id that
// every shipped binary carries — so embedding it in the test source
// is fine. The backend recognises it and pairs with the testPhone
// constant ("+14045551234" / verify code "000000") for the test
// account.
func TestMain(m *testing.M) {
	SetWalletInfo(WalletInfo{
		ClientID: "com.ellipx.walletapp",
		Name:     "libwallet-tests",
		LogLevel: "debug",
	})
	os.Exit(m.Run())
}
