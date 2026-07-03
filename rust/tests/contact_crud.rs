use libwallet::Env;
use libwallet::models::contact::Contact;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    libwallet::models::contact::init(&env).unwrap();
    env
}

#[test]
fn create_fetch_list_roundtrip() {
    let env = env();
    assert!(libwallet::models::contact::list(&env).unwrap().is_empty());

    let c = Contact {
        name: "Alice".into(),
        address: "0xabc".into(),
        kind: "ethereum".into(),
        flags: vec!["evm".into()],
        memo: "friend".into(),
        ..Default_contact()
    };
    let created = libwallet::models::contact::create(&env, c).unwrap();
    assert!(created.id.starts_with("ct-"), "generated id has ct prefix: {}", created.id);
    assert!(!created.created.is_empty());

    let fetched = libwallet::models::contact::fetch(&env, &created.id).unwrap().expect("found");
    assert_eq!(fetched.name, "Alice");
    assert_eq!(fetched.kind, "ethereum");
    assert_eq!(fetched.flags, vec!["evm".to_string()]);
    assert_eq!(fetched, created);

    let all = libwallet::models::contact::list(&env).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0], created);
}

#[test]
fn unknown_id_is_none() {
    let env = env();
    assert!(libwallet::models::contact::fetch(&env, "ct-doesnotexist").unwrap().is_none());
}

#[test]
fn rejects_unknown_type() {
    let env = env();
    let c = Contact { kind: "dogecoin".into(), ..Default_contact() };
    assert!(libwallet::models::contact::create(&env, c).is_err());
}

// Small helper since Contact has no Default derive (its fields are all
// meaningful); build an empty one for tests.
#[allow(non_snake_case)]
fn Default_contact() -> Contact {
    Contact {
        id: String::new(),
        name: String::new(),
        address: String::new(),
        kind: String::new(),
        flags: Vec::new(),
        memo: String::new(),
        created: String::new(),
        updated: String::new(),
    }
}
