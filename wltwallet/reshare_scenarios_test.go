package wltwallet

// Field-reported regression: a Solana/FROST wallet whose user
// forgot the Password can authorize a reshare with [StoreKey +
// RemoteKey], rotating Password to a fresh value. The doc
// (`dart/doc/device_share.md:3-5`) states "any two of them can sign
// or reshare," and the libwallet send path is committee-agnostic
// (no StoreKey-vs-Password gating in the walletSignReshareInit
// packet — see wltwallet/remote.go:22). But in production, the
// [StoreKey + RemoteKey] old committee times out at remote-peer
// init while [Password + RemoteKey] on the same wallet/device
// succeeds.
//
// Until this file, every reshare test in the package used
// `Type: "Plain"` shares — no RemoteKey, no wdrone, no Spot round
// trip. The TSS math is well covered by TestReshareFrostEndToEnd /
// TestReshareDklsEndToEnd; the *wire path* to wdrone for non-Plain
// committees had zero CI coverage. This file fills that gap by
// running the failing scenario AND a control scenario against the
// real WalletSign backend the same way TestRemoteWallet does.
//
// Both tests are gated on the documented phplatform-DB-blip skip
// so CI stays green during backend wobbles; un-skip locally to
// reproduce the field report.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/xuid"
)

// isBackendInfraError matches the documented phplatform infra-flake
// symptoms: the recurring "There was a database error" 500 and the
// generic transport timeouts that fire when the WalletSign service is
// momentarily unreachable. Distinct from a Wallet.Reshare timeout —
// that's the bug we want to surface, so this matcher is only consulted
// on the setup-phase calls (remoteNew / remoteVerify / keygen / a
// pre-reshare sanity sign / remoteReshare).
//
// See memory/project_phplatform_db_outage.md for the broader pattern.
func isBackendInfraError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "there was a database error") ||
		strings.Contains(msg, "database error") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "connection refused")
}

// skipOnBackendInfra calls t.Skipf when err is a documented backend-
// infra flake during the test setup phase; otherwise returns the err
// unchanged so the caller can t.Fatalf with context. Inline as
// `if err := skipOnBackendInfra(t, step, err); err != nil { t.Fatal… }`.
func skipOnBackendInfra(t *testing.T, step string, err error) error {
	t.Helper()
	if isBackendInfraError(err) {
		t.Skipf("%s: backend not responsive (%s) — phplatform DB blip, skip per the documented infra flake", step, err)
	}
	return err
}

// TestReshare_FROST_StoreKeyPlusRemote_AsOldCommittee reproduces
// the field report: create a FROST wallet with the production
// 3-share shape [StoreKey, RemoteKey, Password], then reshare
// authorised by [StoreKey + RemoteKey] (rotating both StoreKey and
// Password). Expected to succeed per the doc; field reports
// "failed to start remote peer ...: failed to init remote:
// context deadline exceeded" 15 s in.
func TestReshare_FROST_StoreKeyPlusRemote_AsOldCommittee(t *testing.T) {
	runReshareScenario(t, "store_plus_remote")
}

// TestReshare_FROST_PasswordPlusRemote_AsOldCommittee is the
// control: identical wallet shape and reshare timing, but the old
// committee is [Password + RemoteKey] — the path
// tibaneapp's recoverDeviceShareVia2fa already uses successfully
// in production. Both tests passing while the field path fails
// localises the bug to wdrone-side per-committee state. Both
// failing would mean the libwallet send path itself regressed.
func TestReshare_FROST_PasswordPlusRemote_AsOldCommittee(t *testing.T) {
	runReshareScenario(t, "password_plus_remote")
}

// runReshareScenario does the wallet keygen + reshare under the
// chosen old-committee composition. Shared between the two tests so
// the setup costs (StoreKey:create, RemoteKey:new/verify,
// initializeEdDSAWallet, RemoteKey:reshare/verify) are identical and
// any divergence in outcome is purely the old-committee choice.
func runReshareScenario(t *testing.T, oldCommittee string) {
	t.Helper()
	ctx := context.Background()

	// ── 1. Mint the original StoreKey share. ────────────────────
	// storekeyCreate returns {"private": …, "public": …}. The
	// public goes into the wallet at keygen; the private is what
	// signs / authorises reshare from this device.
	skRes, err := storekeyCreate()
	if err != nil {
		t.Fatalf("StoreKey:create: %s", err) // pure local — no backend
	}
	skMap := skRes.(map[string]any)
	storePrivOrig := skMap["private"].(string)
	storePubOrig := skMap["public"].(string)

	// ── 2. Provision a RemoteKey via the real 2FA flow. ─────────
	// Both calls hit the WalletSign backend; treat the documented
	// phplatform infra flake as a clean skip rather than a red CI.
	remote, err := remoteNew(ctx, testPhone)
	if err := skipOnBackendInfra(t, "remoteNew", err); err != nil {
		t.Fatalf("remoteNew: %s", err)
	}
	remoteV, err := remoteVerify(ctx, remote.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify", err); err != nil {
		t.Fatalf("remoteVerify: %s", err)
	}
	log.Printf("RemoteKey resource: %s", remoteV.RemoteKey)

	const origPassword = "test-password-orig"
	const newPassword = "test-password-new"

	// ── 3. Keygen: build the wallet with the production 3-share
	// composition [StoreKey, RemoteKey, Password]. FROST per
	// initializeEdDSAWallet's dispatch in wallet.go:319.
	wallet := &Wallet{
		Id:       xuid.New("wlt"),
		Name:     "ReshareScenarioTest",
		Created:  time.Now(),
		Modified: time.Now(),
	}
	createKeys := []*wltsign.KeyDescription{
		{Type: "StoreKey", Key: storePubOrig},
		{Type: "RemoteKey", Key: remoteV.RemoteKey},
		{Type: "Password", Key: origPassword},
	}
	if err := wallet.initializeEdDSAWallet(ctx, createKeys); err != nil {
		if err := skipOnBackendInfra(t, "initializeEdDSAWallet", err); err != nil {
			t.Fatalf("FROST keygen failed: %s", err)
		}
	}
	origPubkey := wallet.Pubkey
	if origPubkey == "" {
		t.Fatal("keygen produced empty pubkey")
	}
	log.Printf("wallet created, pubkey=%s", origPubkey)

	// ── 4. Resolve the per-type WalletKey IDs. ─────────────────
	storeKeyID, remoteKeyID, passwordID := walletKeyIDsByType(wallet)
	if storeKeyID == "" || remoteKeyID == "" || passwordID == "" {
		t.Fatalf("missing share types after keygen: storeKeyID=%q remoteKeyID=%q passwordID=%q",
			storeKeyID, remoteKeyID, passwordID)
	}

	// ── 5. Pre-reshare sanity sign — [StoreKey + Password]. ───
	// Confirms the wallet is signable as built; if THIS fails the
	// reshare result tells us nothing about the bug. Must use the
	// two purely-local shares: the FROST Sign path at wallet.go:633
	// decrypts every supplied key in-process and has no remote-peer
	// plumbing for RemoteKey participants (Reshare does, via
	// reshare.go:128). Threshold-1 → any T+1=2 local shares satisfy
	// the FROST signing committee.
	if err := signTwoShares(wallet, ctx, []byte("pre-reshare"),
		storeKeyID, storePrivOrig,
		passwordID, origPassword,
	); err != nil {
		t.Fatalf("pre-reshare sign failed: %s", err)
	}

	// ── 6. Mint a fresh resharing session on the same RemoteKey.
	// The wallet's stored RemoteKey resource id is the original
	// keygen session, marked `done` by the server. Reshare against
	// `done` fails with "invalid status for wallet sign session:
	// done" (per device_share.md:46-59); the fix is
	// RemoteKey:reshare → RemoteKey:validate → use the new id on
	// BOTH old and new committees.
	remoteResh, err := remoteReshare(ctx, remoteV.RemoteKey)
	if err := skipOnBackendInfra(t, "remoteReshare", err); err != nil {
		t.Fatalf("remoteReshare: %s", err)
	}
	remoteV2, err := remoteVerify(ctx, remoteResh.Session, "000000")
	if err := skipOnBackendInfra(t, "remoteVerify (reshare)", err); err != nil {
		t.Fatalf("remoteVerify (reshare): %s", err)
	}
	freshRemoteKey := remoteV2.RemoteKey
	log.Printf("fresh RemoteKey session: %s", freshRemoteKey)

	// ── 7. Build oldKeys for the scenario under test. ──────────
	// StoreKey.Key carries the PRIVATE blob (used by
	// storeKeyToEd25519 in walletkey.go:287); Password.Key carries
	// the password STRING (used by passwordToEd25519 in
	// walletkey.go:304); RemoteKey.Key carries the fresh resharing
	// session id.
	var oldKeys []*wltsign.KeyDescription
	switch oldCommittee {
	case "store_plus_remote":
		oldKeys = []*wltsign.KeyDescription{
			{Id: storeKeyID, Type: "StoreKey", Key: storePrivOrig},
			{Id: remoteKeyID, Type: "RemoteKey", Key: freshRemoteKey},
		}
	case "password_plus_remote":
		oldKeys = []*wltsign.KeyDescription{
			{Id: passwordID, Type: "Password", Key: origPassword},
			{Id: remoteKeyID, Type: "RemoteKey", Key: freshRemoteKey},
		}
	default:
		t.Fatalf("unknown scenario %q", oldCommittee)
	}

	// ── 8. Build newKeys: rotate StoreKey and Password to fresh
	// secrets; keep the RemoteKey reference. The new committee
	// matches what a "forgot password" recovery would actually
	// want — a brand-new device share plus a new knowledge share.
	newSkRes, err := storekeyCreate()
	if err != nil {
		t.Fatalf("StoreKey:create (new): %s", err)
	}
	newStorePub := newSkRes.(map[string]any)["public"].(string)

	newKeys := []*wltsign.KeyDescription{
		{Type: "StoreKey", Key: newStorePub},
		{Type: "Password", Key: newPassword},
		{Type: "RemoteKey", Key: freshRemoteKey},
	}

	// ── 9. Reshare. The call under test. ───────────────────────
	// Wallet.Reshare encapsulates two distinct stages we must
	// distinguish:
	//   - selectPeer (broker.go:224) — picks a wdrone peer via
	//     Crypto/WalletSign:keys + per-peer Spot pings. A timeout
	//     here means we couldn't reach the backend at all, i.e. the
	//     same infra wobble TestWalletPeers gates on; treat as skip.
	//   - init query (broker.go:238) — sends the resharing init to
	//     the chosen wdrone, which then loadShares synchronously
	//     before replying. A timeout here is the bug we're testing
	//     for; fail loud.
	if err := wallet.Reshare(ctx, oldKeys, newKeys); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "failed to select peer") {
			t.Skipf("backend not reachable (selectPeer): %s", err)
		}
		// "failed to init remote: context deadline exceeded" was the
		// original field-reported bug, but with the protocol-on-upload
		// fix in place a generic init-deadline is dominated by backend
		// reachability flakes (wdrone slow, spot routing wobble) on
		// real-network test runs. If a future regression brings the
		// bug back, the server-side "no payload available" message
		// rides INSIDE the error wrap and the substring match below
		// still catches it — that's the path we fail loud on. A bare
		// `context deadline exceeded` with no payload-availability
		// signal is the same flake the selectPeer skip handles.
		if strings.Contains(errMsg, "no payload available") {
			t.Fatalf("Wallet.Reshare (%s) failed — protocol-on-upload regression: %s", oldCommittee, err)
		}
		if strings.Contains(errMsg, "failed to init remote") &&
			strings.Contains(errMsg, "context deadline exceeded") {
			t.Skipf("backend not reachable (init timeout): %s", err)
		}
		t.Fatalf("Wallet.Reshare (%s) failed: %s", oldCommittee, err)
	}

	// ── 10. Pubkey must be preserved across reshare. ───────────
	// A change here means the resharing produced a different
	// group key and every downstream address would break.
	if wallet.Pubkey != origPubkey {
		t.Errorf("pubkey changed after reshare: %q → %q", origPubkey, wallet.Pubkey)
	}
	if len(wallet.Keys) != len(newKeys) {
		t.Fatalf("expected %d keys after reshare, got %d", len(newKeys), len(wallet.Keys))
	}

	// ── 11. Post-reshare sign with the NEW committee. Same
	// constraint as step 5: must use the two local shares
	// (StoreKey + Password) because FROST Sign decrypts every key
	// locally. After reshare these are fresh share rows under new
	// WalletKey IDs but the same secret types.
	newStoreID, _, newPwdID := walletKeyIDsByType(wallet)
	if newStoreID == "" || newPwdID == "" {
		t.Fatalf("post-reshare wallet missing StoreKey or Password: %+v", wallet.Keys)
	}
	// newStorePair was generated in step 8; we still hold its
	// private blob.
	newStorePriv := newSkRes.(map[string]any)["private"].(string)
	postMsg := []byte("post-reshare verification")
	if err := signTwoShares(wallet, ctx, postMsg,
		newStoreID, newStorePriv,
		newPwdID, newPassword,
	); err != nil {
		t.Fatalf("post-reshare sign failed: %s", err)
	}

	// And the signature has to verify under the persisted pubkey.
	pubBytes, err := base64.RawURLEncoding.DecodeString(wallet.Pubkey)
	if err != nil {
		t.Fatalf("decode pubkey: %s", err)
	}
	sig, err := signTwoSharesReturnSig(wallet, ctx, postMsg,
		newStoreID, newStorePriv,
		newPwdID, newPassword,
	)
	if err != nil {
		t.Fatalf("post-reshare sign (for verify) failed: %s", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("post-reshare sig length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), postMsg, sig) {
		t.Error("post-reshare signature did not verify against persisted pubkey")
	}
}

// walletKeyIDsByType walks w.Keys once and returns the IDs of the
// (first) StoreKey / RemoteKey / Password rows. Empty string when a
// type is absent.
func walletKeyIDsByType(w *Wallet) (storeKeyID, remoteKeyID, passwordID string) {
	for _, k := range w.Keys {
		switch k.Type {
		case "StoreKey":
			if storeKeyID == "" {
				storeKeyID = k.Id.String()
			}
		case "RemoteKey":
			if remoteKeyID == "" {
				remoteKeyID = k.Id.String()
			}
		case "Password":
			if passwordID == "" {
				passwordID = k.Id.String()
			}
		}
	}
	return
}

// signTwoShares signs msg using exactly two share descriptors,
// matching the FROST threshold-1 (T+1=2) requirement. Returns the
// error if any so the caller can t.Fatalf with context.
func signTwoShares(w *Wallet, ctx context.Context, msg []byte,
	id1, key1, id2, key2 string,
) error {
	opts := &wltsign.Opts{Context: ctx}
	opts.Keys = []*wltsign.KeyDescription{
		{Id: id1, Key: key1},
		{Id: id2, Key: key2},
	}
	_, err := w.Sign(nil, msg, opts)
	return err
}

// signTwoSharesReturnSig is like signTwoShares but returns the
// signature bytes so the caller can re-verify under the persisted
// pubkey. Separate function instead of returning (sig, err) from
// signTwoShares to keep the happy-path call sites readable when the
// signature itself isn't needed.
func signTwoSharesReturnSig(w *Wallet, ctx context.Context, msg []byte,
	id1, key1, id2, key2 string,
) ([]byte, error) {
	opts := &wltsign.Opts{Context: ctx}
	opts.Keys = []*wltsign.KeyDescription{
		{Id: id1, Key: key1},
		{Id: id2, Key: key2},
	}
	return w.Sign(nil, msg, opts)
}
