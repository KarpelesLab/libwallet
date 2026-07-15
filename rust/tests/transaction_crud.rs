//! Transaction delete / clear (Go `Transaction.ApiDelete` and
//! `apiClearTransaction`). Exercised at the model level, matching the style of
//! `transaction_read.rs`.

use libwallet::models::transaction as tx;
use libwallet::models::transaction::Transaction;
use libwallet::Env;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    tx::init(&env).unwrap();
    env
}

fn row(id: &str, from: &str, network: &str) -> Transaction {
    Transaction {
        id: id.into(),
        kind: "transfer".into(),
        from: from.into(),
        to: "0xdead".into(),
        network: network.into(),
        created: "2026-01-01T00:00:00.000000000Z".into(),
        ..Default::default()
    }
}

fn ids(env: &Env) -> Vec<String> {
    let mut v: Vec<String> = tx::list(env).unwrap().into_iter().map(|t| t.id).collect();
    v.sort();
    v
}

#[test]
fn delete_one_removes_only_that_row() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    tx::persist(&env, &row("tx-2", "acct-b", "net-1")).unwrap();

    tx::delete_one(&env, "tx-1").unwrap();

    assert_eq!(ids(&env), vec!["tx-2".to_string()]);
    assert!(tx::fetch(&env, "tx-1").unwrap().is_none());
    assert!(tx::fetch(&env, "tx-2").unwrap().is_some());
}

#[test]
fn delete_one_missing_is_noop() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    // Deleting an absent id succeeds and leaves the collection intact.
    tx::delete_one(&env, "tx-none").unwrap();
    assert_eq!(ids(&env), vec!["tx-1".to_string()]);
}

#[test]
fn clear_all_when_unfiltered() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    tx::persist(&env, &row("tx-2", "acct-b", "net-2")).unwrap();

    tx::clear(&env, None, None).unwrap();

    assert!(tx::list(&env).unwrap().is_empty());
}

#[test]
fn clear_filters_by_from() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    tx::persist(&env, &row("tx-2", "acct-b", "net-1")).unwrap();
    tx::persist(&env, &row("tx-3", "acct-a", "net-2")).unwrap();

    tx::clear(&env, Some("acct-a"), None).unwrap();

    // Only acct-b's row survives.
    assert_eq!(ids(&env), vec!["tx-2".to_string()]);
}

#[test]
fn clear_filters_by_network() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    tx::persist(&env, &row("tx-2", "acct-b", "net-2")).unwrap();

    tx::clear(&env, None, Some("net-1")).unwrap();

    assert_eq!(ids(&env), vec!["tx-2".to_string()]);
}

#[test]
fn clear_filters_by_from_and_network() {
    let env = env();
    tx::persist(&env, &row("tx-1", "acct-a", "net-1")).unwrap();
    tx::persist(&env, &row("tx-2", "acct-a", "net-2")).unwrap();
    tx::persist(&env, &row("tx-3", "acct-b", "net-1")).unwrap();

    // Both conditions must match: only tx-1 goes.
    tx::clear(&env, Some("acct-a"), Some("net-1")).unwrap();

    assert_eq!(ids(&env), vec!["tx-2".to_string(), "tx-3".to_string()]);
}
