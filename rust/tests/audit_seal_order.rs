//! Audit KC-07: sealing a RemoteKey share uploads it and overwrites the share
//! the backend holds. When a new committee also has a local descriptor that
//! cannot be sealed, the operation must fail on that descriptor BEFORE any
//! RemoteKey upload is attempted — whatever the order of the descriptors — so
//! the server-side share is never replaced while the local committee stays put.

use libwallet::models::{account, wallet};
use libwallet::sign::KeyDescription;
use libwallet::Env;

const PW: &str = "seal-password";

fn kd(kind: &str, key: &str) -> KeyDescription {
    KeyDescription { kind: kind.into(), key: key.into(), id: String::new() }
}

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    env
}

/// The local failure each bad descriptor produces on its own (no RemoteKey in
/// the committee), to compare against the RemoteKey-first committee.
fn local_failure(env: &Env, wallet_id: &str, unlock: &[(String, String)], bad: &KeyDescription) -> String {
    let new = vec![kd("Password", "good-password"), bad.clone(), kd("Password", "other-password")];
    wallet::promote(env, wallet_id, unlock, &new, 1).unwrap_err().to_string()
}

#[test]
fn a_bad_local_descriptor_fails_before_any_remote_upload() {
    for curve in ["secp256k1", "ed25519"] {
        let env = env();
        let w = wallet::import_private_key(&env, "k", curve, &[0x71u8; 32], &kd("Password", PW)).unwrap();
        let unlock = vec![(w.keys[0].id.clone(), PW.to_string())];

        for bad in [kd("Password", "short"), kd("StoreKey", "not-a-public-key"), kd("Bogus", "x")] {
            let want = local_failure(&env, &w.id, &unlock, &bad);
            // The RemoteKey descriptor comes FIRST. Had it been sealed in order,
            // the error would be the fleet-key fetch / upload failure (this
            // session id does not exist), not the local one.
            let new = vec![kd("RemoteKey", "crws-audit-kc07:crwsv-audit-kc07"), kd("Password", "good-password"), bad.clone()];
            let got = wallet::promote(&env, &w.id, &unlock, &new, 1).unwrap_err().to_string();
            assert_eq!(got, want, "{curve} / {}", bad.kind);
            assert!(!got.contains("RemoteKey share upload"), "{got}");

            // The wallet is untouched.
            let after = wallet::fetch(&env, &w.id).unwrap().unwrap();
            assert_eq!(after.keys, w.keys);
            assert_eq!((after.protocol.as_str(), after.threshold, after.generation), (w.protocol.as_str(), 0, w.generation));
        }
    }
}
