package wlttest

// Cascade-delete test: removing an Account must wipe its Web3
// Connection rows in the same step. The wltacct package owns
// the cascade and does it via a stub struct mapping the
// ConnectedSite table; this test exercises the end-to-end
// behaviour against a real (in-memory) sqlite env.

import (
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltbase"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// minimal stub matching wltbase.connectedSite — the wltbase one is
// unexported, so re-declare the columns we need for the test.
type connectedSiteForTest struct {
	psql.Name `sql:"ConnectedSite"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`
	Host      string     `sql:",type=VARCHAR,size=255"`
	Account   *xuid.XUID `sql:",type=VARCHAR,size=255"`
	Created   time.Time  `sql:",type=DATETIME"`
	Updated   time.Time  `sql:",type=DATETIME"`
}

func TestAccountDelete_CascadesConnectedSites(t *testing.T) {
	tempEnv, err := wltbase.InitTempEnv()
	if err != nil {
		t.Fatalf("InitTempEnv: %v", err)
	}
	defer wltbase.CleanupTempEnv(tempEnv)
	env, ok := tempEnv.(wltintf.Env)
	if !ok {
		t.Fatalf("env is not wltintf.Env")
	}

	// Set up a wallet so CreateAccount has something to derive from.
	wallet, err := wltwallet.NewWalletForTesting("CascadeWallet", "")
	if err != nil {
		t.Fatalf("NewWalletForTesting: %v", err)
	}
	for _, k := range wallet.Keys {
		if err := psql.Replace(env, k); err != nil {
			t.Fatalf("save wallet key: %v", err)
		}
	}
	if err := psql.Replace(env, wallet); err != nil {
		t.Fatalf("save wallet: %v", err)
	}

	acct, err := wltacct.CreateAccount(env, wallet, "Cascade", "ethereum", 0)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	// Create two ConnectedSite rows referencing this account, plus
	// one referencing a different account so we can confirm the
	// cascade is scoped (not a "delete everything" bug).
	otherAcctId := xuid.Must(xuid.NewRandom("acc"))
	now := time.Now()
	rows := []*connectedSiteForTest{
		{Id: xuid.Must(xuid.NewRandom("cnx")), Host: "alice.example", Account: acct.Id, Created: now, Updated: now},
		{Id: xuid.Must(xuid.NewRandom("cnx")), Host: "bob.example", Account: acct.Id, Created: now, Updated: now},
		{Id: xuid.Must(xuid.NewRandom("cnx")), Host: "carol.example", Account: otherAcctId, Created: now, Updated: now},
	}
	for _, r := range rows {
		if err := psql.Replace(env, r); err != nil {
			t.Fatalf("save ConnectedSite %s: %v", r.Host, err)
		}
	}

	// Sanity: 3 rows present before delete.
	all, err := psql.Fetch[connectedSiteForTest](env, nil)
	if err != nil {
		t.Fatalf("pre-delete fetch: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("pre-delete: have %d rows, want 3", len(all))
	}

	// Cascade-delete the account.
	if err := acct.Delete(env); err != nil {
		t.Fatalf("Account.Delete: %v", err)
	}

	// Account itself is gone.
	if _, err := psql.Get[wltacct.Account](env, map[string]any{"Id": acct.Id.String()}); err == nil {
		t.Errorf("account row still present after Delete")
	}

	// All ConnectedSite rows for the deleted account are gone.
	owned, err := psql.Fetch[connectedSiteForTest](env, map[string]any{"Account": acct.Id})
	if err != nil {
		t.Fatalf("post-delete fetch (owned): %v", err)
	}
	if len(owned) != 0 {
		t.Errorf("expected 0 connected sites for deleted account, found %d", len(owned))
	}

	// The unrelated ConnectedSite row is untouched (cascade is scoped).
	survivors, err := psql.Fetch[connectedSiteForTest](env, map[string]any{"Account": otherAcctId})
	if err != nil {
		t.Fatalf("post-delete fetch (other): %v", err)
	}
	if len(survivors) != 1 {
		t.Errorf("unrelated ConnectedSite was lost — cascade over-deleted (have %d, want 1)", len(survivors))
	}
}
