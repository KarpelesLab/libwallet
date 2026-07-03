use libwallet::Env;

fn env() -> Env {
    let env = Env::init_memory().unwrap();
    libwallet::models::crash::init(&env).unwrap();
    env
}

#[test]
fn log_fetch_list() {
    let env = env();
    assert!(libwallet::models::crash::list(&env).unwrap().is_empty());

    let id = libwallet::models::crash::log(&env, "signer", "PANIC: boom", "stack trace here").unwrap();
    assert_eq!(id.len(), 36, "uuid v4 string");

    let got = libwallet::models::crash::fetch(&env, &id).unwrap().expect("found");
    assert_eq!(got.where_, "signer");
    assert_eq!(got.message, "PANIC: boom");
    assert_eq!(got.stack, "stack trace here");
    assert!(!got.created.is_empty());

    assert_eq!(libwallet::models::crash::list(&env).unwrap().len(), 1);
    assert!(libwallet::models::crash::fetch(&env, "nope").unwrap().is_none());
}
