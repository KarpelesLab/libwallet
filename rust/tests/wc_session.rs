//! WalletConnect session store lifecycle: pairing -> settle (active) ->
//! disconnect, over the in-memory DB.

use libwallet::models::wc_session as wc;
use libwallet::Env;

#[test]
fn session_store_lifecycle() {
    let env = Env::init_memory().unwrap();
    wc::init(&env).unwrap();

    // A pairing row is created in "pairing" state on its pairing topic.
    let s = wc::create_pairing(&env, "pairtopic", "symb64", "privb64", "pubb64").unwrap();
    assert_eq!(s.state, "pairing");
    assert!(s.id.starts_with("wc-"));
    let got = wc::fetch_by_topic(&env, "pairtopic").unwrap().expect("row");
    assert_eq!(got.id, s.id);
    assert_eq!(got.sym_key, "symb64");
    assert_eq!(got.self_priv, "privb64");
    assert!(wc::list_by_state(&env, "active").unwrap().is_empty());

    // SelfPriv is never serialized out to the host (protected material).
    let j = serde_json::to_value(&got).unwrap();
    assert!(j.get("SelfPriv").is_none(), "self private key must not leak");

    // Settle it into an active session on the per-session topic.
    wc::settle(
        &env,
        &s.id,
        "sessiontopic",
        "sessionsym",
        "peerpub",
        r#"{"eip155":{}}"#,
        "2026-07-10T00:00:00Z",
    )
    .unwrap();
    // The old pairing topic no longer resolves; the session topic does.
    assert!(wc::fetch_by_topic(&env, "pairtopic").unwrap().is_none());
    let active = wc::fetch_by_topic(&env, "sessiontopic").unwrap().expect("active");
    assert_eq!(active.state, "active");
    assert_eq!(active.sym_key, "sessionsym");
    assert_eq!(active.peer_pub, "peerpub");
    assert_eq!(active.namespaces, r#"{"eip155":{}}"#);
    assert_eq!(wc::list_by_state(&env, "active").unwrap().len(), 1);

    // Disconnect removes it from the active set.
    wc::set_state(&env, &s.id, "disconnected").unwrap();
    assert!(wc::list_by_state(&env, "active").unwrap().is_empty());
    assert_eq!(wc::fetch_by_topic(&env, "sessiontopic").unwrap().unwrap().state, "disconnected");
}
