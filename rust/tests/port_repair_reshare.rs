//! Port tests for `Wallet:repairRemoteKey` + reshare robustness: the round
//! deadline bound, the tenacious RemoteKey share upload, and fast-fail on a
//! remote-reported ceremony error. Mirrors the Go wltwallet unit tests
//! (restretry_test.go `TestIsRetryableCriticalError` / `TestReshareRoundsContext`
//! and repair_remotekey_test.go's non-network assertions). The live-fleet
//! end-to-end legs stay gated behind `SPOT_LIVE` in the existing suite; nothing
//! here touches the network.

use libwallet::models::wallet::{self, remote_share_wire_tags};
use libwallet::reshare::{classify_upload_error, is_retryable_critical_error, RoundsGuard, UploadError};
use libwallet::{Env, Error, SqlValue};

// ── Tenacious critical-upload classifier (Go TestIsRetryableCriticalError) ───

#[test]
fn critical_retry_classifier() {
    // nil: not retryable.
    assert!(!is_retryable_critical_error(None));
    // Deterministic 4xx must not be retried.
    assert!(!is_retryable_critical_error(Some(&UploadError::Rest(400))));
    assert!(!is_retryable_critical_error(Some(&UploadError::Rest(404))));
    // 5xx retried, as in the plain retry path.
    assert!(is_retryable_critical_error(Some(&UploadError::Rest(500))));
    assert!(is_retryable_critical_error(Some(&UploadError::Rest(503))));
    // The critical difference vs the plain retry: transport-level failures ARE
    // retried — the request may have been delivered and abandoning it risks
    // desyncing the server-side share (field case: an http2 header timeout).
    assert!(is_retryable_critical_error(Some(&UploadError::Transport(
        "http2: timeout awaiting response headers".into()
    ))));
    assert!(is_retryable_critical_error(Some(&UploadError::Transport(
        "read tcp: connection reset by peer".into()
    ))));
    // A rest error with no HTTP response attached: transport failed, retry.
    assert!(is_retryable_critical_error(Some(&UploadError::RestNoResponse)));
}

#[test]
fn classify_recovers_http_status_from_rest_error_string() {
    // The rest layer collapses HTTP status into the error message; recover it.
    let e404 = Error::Env("rest Crypto/WalletSign:setGeneratedKey request failed: https://x: status code 404".into());
    assert_eq!(classify_upload_error(&e404), UploadError::Rest(404));
    let e503 = Error::Env("rest ... request failed: status code 503 something".into());
    assert_eq!(classify_upload_error(&e503), UploadError::Rest(503));
    // No status code present → transport failure.
    let et = Error::Env("Post \"https://…/setGeneratedKey\": http2: timeout awaiting response headers".into());
    assert!(matches!(classify_upload_error(&et), UploadError::Transport(_)));

    // Composed with the classifier: a stringified 404 fails fast; a transport
    // error is retried.
    assert!(!is_retryable_critical_error(Some(&classify_upload_error(&e404))));
    assert!(is_retryable_critical_error(Some(&classify_upload_error(&et))));
}

// ── Reshare rounds deadline + fast-fail wrapper (Go TestReshareRoundsContext) ─

#[test]
fn rounds_guard_other_errors_unchanged() {
    let g = RoundsGuard::new();
    let e = g.wrap("vss verification failed".into(), false);
    assert_eq!(e.to_string(), Error::Env("vss verification failed".into()).to_string());
    assert!(!e.to_string().contains("stopped responding"));
}

#[test]
fn rounds_guard_own_deadline_becomes_descriptive() {
    let g = RoundsGuard::new();
    let s = g.wrap("rounds deadline exceeded".into(), true).to_string();
    assert!(s.contains("stopped responding"), "got {s}");
    assert!(s.contains("committee is unchanged"), "got {s}");
}

#[test]
fn rounds_guard_caller_cancel_passes_through() {
    // Host cancelled: even a deadline hit must not be relabelled as a
    // participant failure.
    let g = RoundsGuard::new().with_caller_canceled();
    let s = g.wrap("rounds deadline exceeded".into(), true).to_string();
    assert!(!s.contains("stopped responding"), "caller cancel must pass through, got {s}");
}

#[test]
fn rounds_guard_remote_failure_surfaces_its_reason() {
    let g = RoundsGuard::new();
    // Simulate a `walletsign:error` frame arriving: the hub wires this hook.
    let fail = g.on_error_hook();
    fail("reshare eddsa: stored share belongs to party key 123 (stale share)".into());
    assert!(g.remote_failure().is_some());

    // Even with the deadline flag set, the remote reason must win — and must
    // not be mislabelled as a timeout.
    let s = g.wrap("rounds deadline exceeded".into(), true).to_string();
    assert!(s.contains("stale share"), "expected remote reason to surface, got {s}");
    assert!(s.contains("remote participant reported"), "got {s}");
    assert!(!s.contains("stopped responding"), "remote failure mislabelled as a timeout: {s}");
    assert!(s.contains("committee is unchanged"), "got {s}");
}

#[test]
fn rounds_guard_fail_hook_records_only_first_reason() {
    let g = RoundsGuard::new();
    let fail = g.on_error_hook();
    fail("first".into());
    fail("second".into());
    assert_eq!(g.remote_failure().as_deref(), Some("first"));
}

// ── Wallet:repairRemoteKey — wire tags + validation (Go apiWalletRepairRemoteKey) ─

#[test]
fn repair_wire_tags_match_schema_and_curve() {
    // The re-uploaded share must carry the same (curve, protocol) vocabulary
    // the wdrone's loadShare recognises — derived from the persisted schema.
    assert_eq!(remote_share_wire_tags("dkls23", "secp256k1").unwrap(), ("secp256k1", "dkls23"));
    assert_eq!(remote_share_wire_tags("frost", "ed25519").unwrap(), ("ed25519", "frost"));
    // Legacy GG18-family share (empty schema): the wallet curve disambiguates.
    assert_eq!(remote_share_wire_tags("", "secp256k1").unwrap(), ("secp256k1", "legacy"));
    assert_eq!(remote_share_wire_tags("", "ed25519").unwrap(), ("ed25519", "legacy"));
    // Legacy with an unsupported curve, and an unknown schema → error.
    assert!(remote_share_wire_tags("", "p256").is_err());
    assert!(remote_share_wire_tags("bls12", "ed25519").is_err());
}

fn seed_env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    env
}

fn insert_wallet(env: &Env, id: &str, curve: &str) {
    env.exec(
        r#"INSERT INTO "Wallet" ("Id","Name","Curve","Protocol","Threshold","Gen","Pubkey","Chaincode","Created","Modified") VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        vec![
            SqlValue::Text(id.into()),
            SqlValue::Text("W".into()),
            SqlValue::Text(curve.into()),
            SqlValue::Text(if curve == "ed25519" { "frost" } else { "dkls23" }.into()),
            SqlValue::Int(1),
            SqlValue::Int(0),
            SqlValue::Text("PUB".into()),
            SqlValue::Text("CC".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
            SqlValue::Text("2026-01-01T00:00:00.000000000Z".into()),
        ],
    )
    .unwrap();
}

fn insert_key(env: &Env, id: &str, wallet: &str, kind: &str, schema: &str, data: Vec<u8>) {
    env.exec(
        r#"INSERT INTO "WalletKey" ("Id","Wallet","Type","Schema","Key","Data","Gen") VALUES (?1,?2,?3,?4,?5,?6,?7)"#,
        vec![
            SqlValue::Text(id.into()),
            SqlValue::Text(wallet.into()),
            SqlValue::Text(kind.into()),
            SqlValue::Text(schema.into()),
            SqlValue::Text(String::new()),
            SqlValue::Blob(data),
            SqlValue::Int(0),
        ],
    )
    .unwrap();
}

#[test]
fn repair_requires_a_validated_session_key() {
    let env = seed_env();
    // Empty Key is rejected before any wallet lookup or network call.
    let err = wallet::repair_remote_key(&env, "wlt-x", "").unwrap_err();
    assert!(err.to_string().contains("validated RemoteKey session"), "got {err}");
}

#[test]
fn repair_errors_when_wallet_has_no_remote_key_share() {
    let env = seed_env();
    insert_wallet(&env, "wlt-1", "ed25519");
    insert_key(&env, "wkey-1", "wlt-1", "Plain", "frost", vec![1, 2, 3]);
    let err = wallet::repair_remote_key(&env, "wlt-1", "crws-a:crwsv-b").unwrap_err();
    assert!(err.to_string().contains("no RemoteKey share"), "got {err}");
}

#[test]
fn repair_errors_when_remote_share_has_no_local_blob() {
    let env = seed_env();
    insert_wallet(&env, "wlt-2", "ed25519");
    // A RemoteKey row whose Data blob is empty — the case a backup without key
    // data would produce; repair must refuse before attempting any upload.
    insert_key(&env, "wkey-2", "wlt-2", "RemoteKey", "frost", vec![]);
    let err = wallet::repair_remote_key(&env, "wlt-2", "crws-a:crwsv-b").unwrap_err();
    assert!(err.to_string().contains("no local data blob"), "got {err}");
}

#[test]
fn repair_errors_when_wallet_missing() {
    let env = seed_env();
    let err = wallet::repair_remote_key(&env, "wlt-nope", "crws-a:crwsv-b").unwrap_err();
    assert!(err.to_string().contains("Wallet required"), "got {err}");
}
