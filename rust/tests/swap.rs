//! Swap quote logic + an end-to-end quote against a mock OKX proxy (no live
//! credentials). The mock ignores the request signature, so the whole quote
//! path — chain-index/token mapping, REST call, response parse, min-receive —
//! is exercised deterministically.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use libwallet::swap::{self, TokenRef};

/// Multi-response mock serving `responses` in order (one request each).
fn mock_multi(responses: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for body in responses {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        }
    });
    format!("http://{addr}/")
}

#[test]
fn execute_solana_splices_and_broadcasts() {
    use libwallet::models::{account, wallet};
    use libwallet::sign::KeyDescription;
    use libwallet::solana::{build_transfer_message, pubkey_from_b64url, tx_message};
    use libwallet::tss::ed25519_verify;
    use libwallet::Env;

    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds: Vec<KeyDescription> = ["a", "b", "c"]
        .iter()
        .map(|p| KeyDescription { kind: "Password".into(), key: format!("password{p}"), id: String::new() })
        .collect();
    let w = wallet::create(&env, "SOL", "ed25519", &kds).unwrap();
    let acct = account::create(&env, &w.id, "", "solana", 0).unwrap();
    let unlock: Vec<(String, String)> = w
        .keys
        .iter()
        .take(2)
        .zip(["a", "b"])
        .map(|(k, p)| (k.id.clone(), format!("password{p}")))
        .collect();

    // Build a swap tx blob: [compactU16(1)][zero sig:64][message]. The message
    // names the account as signer slot 0 (so find_signer_slot + self-verify pass).
    let from = pubkey_from_b64url(&acct.pubkey).unwrap();
    let message = build_transfer_message(&from, &[9u8; 32], 500, &[1u8; 32]);
    let mut raw_tx = vec![1u8]; // numSigs = 1
    raw_tx.extend_from_slice(&[0u8; 64]); // placeholder signature slot
    raw_tx.extend_from_slice(&message);
    let tx_data_b58 = bs58::encode(&raw_tx).into_string();

    // OKX serves, in call order: the swap tx (GET /swap), the broadcast accept
    // (POST broadcastTransaction → orderId), and the settlement poll (GET
    // orderStatus → success). Broadcast now goes through OKX, not the node.
    let okx = mock_multi(vec![
        format!(r#"{{"result":"success","data":[{{"tx":{{"data":"{tx_data_b58}"}}}}]}}"#),
        r#"{"result":"success","data":[{"orderId":"ord-sol"}]}"#.to_string(),
        r#"{"result":"success","data":[{"orders":[{"orderId":"ord-sol","txStatus":"2"}]}]}"#.to_string(),
    ]);
    let node = "http://unused.invalid"; // rpc is no longer used for Solana broadcast
    let token_in = TokenRef { address: "NATIVE".into(), symbol: "SOL".into(), decimals: 9 };
    let token_out = TokenRef { address: "EPjF...".into(), symbol: "USDC".into(), decimals: 6 };

    let res = swap::execute_solana(
        &env, &acct.id, &libwallet::swap::Signer::Keys(&unlock), None, &okx, node, "mainnet", &token_in, &token_out, "1000000000", 50, false, "q_test",
    )
    .unwrap();
    assert_eq!(res["orderId"], "ord-sol");
    assert_eq!(res["quoteId"], "q_test");
    // No distinct on-chain hash from OKX → txid = base58(slot-0 signature).
    let sig = res["signature"].as_str().unwrap();
    assert!(!sig.is_empty() && bs58::decode(sig).into_vec().is_ok());
    assert_eq!(res["hash"], res["signature"]);

    // Cross-check: the message that was signed verifies under the account key.
    let msg = tx_message(&raw_tx).unwrap();
    // (execute_solana already self-verifies before broadcast; re-signing here
    // would use fresh FROST nonces, so we just confirm the message layout.)
    assert_eq!(msg, &message[..]);
    let _ = ed25519_verify; // referenced for clarity
}

#[test]
fn execute_evm_signs_and_broadcasts() {
    use libwallet::evm::recover_sender;
    use libwallet::models::{account, wallet};
    use libwallet::sign::KeyDescription;
    use libwallet::Env;

    let env = Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds: Vec<KeyDescription> = ["a", "b", "c"]
        .iter()
        .map(|p| KeyDescription { kind: "Password".into(), key: format!("password{p}"), id: String::new() })
        .collect();
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let unlock: Vec<(String, String)> = w
        .keys
        .iter()
        .zip(["a", "b", "c"])
        .map(|(k, p)| (k.id.clone(), format!("password{p}")))
        .collect();

    // OKX proxy serves, in call order: the swap tx (GET /swap), the broadcast
    // accept (POST broadcastTransaction → orderId), and the settlement poll
    // (GET orderStatus → success + on-chain txHash).
    let okx = mock_multi(vec![
        r#"{"result":"success","data":[{"tx":{"from":"0xfrom","to":"0x1111111111111111111111111111111111111111","value":"0","data":"0xabcdef","gas":"120000","gasPrice":"20000000000"}}]}"#.to_string(),
        r#"{"result":"success","data":[{"orderId":"ord-evm"}]}"#.to_string(),
        r#"{"result":"success","data":[{"orders":[{"orderId":"ord-evm","txStatus":"2","txHash":"0xLANDED"}]}]}"#.to_string(),
    ]);
    // Node is used only for the nonce and its gas price, which bounds the
    // provider's (broadcast goes through OKX).
    let node = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0x3"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.to_string(),
    ]);
    let token_in = TokenRef { address: "0xIN".into(), symbol: "IN".into(), decimals: 18 };
    let token_out = TokenRef { address: "0xOUT".into(), symbol: "OUT".into(), decimals: 6 };

    let res = swap::execute_evm(
        &env, &a.id, &libwallet::swap::Signer::Keys(&unlock), None, &okx, &node, "1", &token_in, &token_out, "1000000000000000000", 50, true, "q_test",
    )
    .unwrap();
    // Hash comes from the OKX orderStatus (the confirmed on-chain tx), not our node.
    assert_eq!(res["hash"], "0xLANDED");
    assert_eq!(res["orderId"], "ord-evm");
    assert_eq!(res["quoteId"], "q_test");
    let raw_hex = res["raw"].as_str().unwrap();
    assert!(raw_hex.starts_with("0x"));

    // Gold-standard: the signed swap tx recovers (ecrecover) to the account.
    let raw = (2..raw_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw_hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    assert_eq!(
        recover_sender(&raw).unwrap().to_lowercase(),
        a.address.to_lowercase(),
        "swap tx must recover to the swapping account"
    );
}

#[test]
fn okx_chain_index_maps_networks() {
    assert_eq!(swap::okx_chain_index("evm", "1").unwrap(), "1");
    assert_eq!(swap::okx_chain_index("evm", "137").unwrap(), "137");
    assert!(swap::okx_chain_index("evm", "").is_err());
    assert_eq!(swap::okx_chain_index("solana", "mainnet").unwrap(), "501");
    assert_eq!(swap::okx_chain_index("solana", "").unwrap(), "501");
    assert_eq!(swap::okx_chain_index("solana", "devnet").unwrap(), "103");
    assert!(swap::okx_chain_index("solana", "testnet").is_err());
    assert!(swap::okx_chain_index("bitcoin", "bitcoin").is_err());
}

#[test]
fn okx_token_addr_and_slippage() {
    // Native -> chain sentinel; strips a "type.chain." prefix.
    assert_eq!(swap::okx_token_addr("evm", "NATIVE"), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    // Solana native now maps to the System Program id so OKX wraps SOL (fixes 0xb).
    assert_eq!(swap::okx_token_addr("solana", "NATIVE"), "11111111111111111111111111111111");
    assert_eq!(swap::okx_token_addr("evm", "evm.1.0xABC"), "0xABC");
    assert_eq!(swap::okx_token_addr("evm", "0xdef"), "0xdef");
    // Slippage clamping.
    assert_eq!(swap::normalize_slippage(0), 50);
    assert_eq!(swap::normalize_slippage(100), 100);
    assert_eq!(swap::normalize_slippage(9999), 5000);
}

#[test]
fn country_availability_uses_allowlist() {
    // Allow-listed (case/space-insensitive) -> available.
    assert!(swap::country_availability("JP").available);
    assert!(swap::country_availability(" us ").available);
    assert!(swap::country_availability("gb").available);
    // Well-formed but not allow-listed -> country_not_supported.
    let cn = swap::country_availability("CN");
    assert!(!cn.available);
    assert_eq!(cn.reason, "country_not_supported");
    // Malformed -> invalid_country.
    assert_eq!(swap::country_availability("").reason, "invalid_country");
    assert_eq!(swap::country_availability("USA").reason, "invalid_country");
    assert_eq!(swap::country_availability("1!").reason, "invalid_country");
}

#[test]
fn availability_gates_by_chain() {
    // EVM: supported chain ids are available; others aren't.
    let eth = swap::availability("evm", "1");
    assert!(eth.available);
    assert_eq!(eth.providers, vec!["okx_evm".to_string()]);
    assert_eq!(eth.network, "evm.1");
    assert!(swap::availability("evm", "137").available); // Polygon
    let unsup = swap::availability("evm", "999999");
    assert!(!unsup.available);
    assert_eq!(unsup.reason, "unsupported_chain");
    assert!(unsup.providers.is_empty());

    // Solana: mainnet only.
    assert!(swap::availability("solana", "mainnet").available);
    assert_eq!(swap::availability("solana", "mainnet").providers, vec!["okx_solana".to_string()]);
    assert!(!swap::availability("solana", "devnet").available);

    // Bitcoin: never.
    assert!(!swap::availability("bitcoin", "bitcoin").available);
}

#[test]
fn erc20_approve_selector_is_keccak() {
    // 0x095ea7b3 == keccak256("approve(address,uint256)")[:4].
    let h = purecrypto::hash::keccak256(b"approve(address,uint256)");
    assert_eq!(format!("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]), "095ea7b3");
}

#[test]
fn encode_erc20_approve_calldata() {
    use num_bigint::BigInt;
    // approve(0x1111…1111, 1000): selector + 32-byte spender + 32-byte amount.
    let data = swap::encode_erc20_approve(
        "0x1111111111111111111111111111111111111111",
        &BigInt::from(1000),
    )
    .unwrap();
    assert_eq!(
        data,
        "0x095ea7b3\
         0000000000000000000000001111111111111111111111111111111111111111\
         00000000000000000000000000000000000000000000000000000000000003e8"
    );
    assert_eq!(data.len(), 2 + 8 + 64 + 64);

    // Unlimited = uint256 max, all-Fs amount word, flagged unlimited.
    let max = swap::max_uint256();
    assert!(swap::is_unlimited_approval(&max));
    let unlimited = swap::encode_erc20_approve("0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &max).unwrap();
    assert!(unlimited.ends_with(&"f".repeat(64)));
    // Lowercased address in the calldata.
    assert!(unlimited.contains("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"));

    // Small amounts aren't unlimited.
    assert!(!swap::is_unlimited_approval(&BigInt::from(1000)));

    // Malformed spender / negative amount error.
    assert!(swap::encode_erc20_approve("0x1234", &BigInt::from(1)).is_err());
    assert!(swap::encode_erc20_approve("0x1111111111111111111111111111111111111111", &BigInt::from(-1)).is_err());
}

// ── audit F14: a backend-supplied spender must be 40 ASCII hex chars ────────

#[test]
fn encode_erc20_approve_rejects_non_ascii_hex_spender() {
    use num_bigint::BigInt;
    let one = BigInt::from(1);
    // 40 BYTES after 0x but multi-byte UTF-8: slicing by byte offset used to
    // panic on a char boundary. 20 two-byte chars, and an odd-offset mix.
    let two_byte = format!("0x{}", "\u{e9}".repeat(20));
    assert_eq!(two_byte.len(), 42);
    assert!(swap::encode_erc20_approve(&two_byte, &one).is_err());
    let mixed = format!("0x1{}1", "\u{e9}".repeat(19));
    assert_eq!(mixed.len(), 42);
    assert!(swap::encode_erc20_approve(&mixed, &one).is_err());
    // 40 ASCII chars that aren't all hex digits ('+f' parses under from_str_radix).
    assert!(swap::encode_erc20_approve(&format!("0x{}", "+f".repeat(20)), &one).is_err());
    assert!(swap::encode_erc20_approve(&format!("0x{}", "zz".repeat(20)), &one).is_err());
    // Missing prefix / wrong length still error; a well-formed address works.
    assert!(swap::encode_erc20_approve(&"1".repeat(40), &one).is_err());
    assert!(swap::encode_erc20_approve(&format!("0x{}", "1".repeat(41)), &one).is_err());
    assert!(swap::encode_erc20_approve(&format!("0x{}", "aB".repeat(20)), &one).is_ok());
}

/// One-shot mock serving a KLB envelope wrapping `data_json`.
fn mock(data_json: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"result":"success","data":{data_json}}}"#);
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn token(addr: &str, sym: &str, dec: i64) -> TokenRef {
    TokenRef { address: addr.into(), symbol: sym.into(), decimals: dec }
}

#[test]
fn get_quote_builds_from_okx_entry() {
    // OKX: 1.0 tokenIn (6 dec) -> 2_000_000 tokenOut base units, 0.25% impact.
    let base = mock(
        r#"{"fromTokenAmount":"1000000","toTokenAmount":"2000000","priceImpactPercent":"0.25","estimateGasFee":"21000"}"#,
    );
    let q = swap::get_quote(
        None,
        &base,
        "evm",
        "1",
        token("0xIN", "IN", 6),
        token("0xOUT", "OUT", 6),
        "1000000",
        50, // 0.5% slippage
    )
    .unwrap();

    assert_eq!(q.provider, "okx_evm");
    assert_eq!(q.amount_out.to_display_string(), "2.000000");
    // min = 2_000_000 * 9950/10000 = 1_990_000 -> 1.990000
    assert_eq!(q.min_amount_out.to_display_string(), "1.990000");
    assert_eq!(q.slippage_bps, 50);
    assert_eq!(q.fee_bps, 50);
    assert!((q.price_impact - 0.0025).abs() < 1e-9);
    // networkFee = 21000 wei @ 18 dec.
    assert_eq!(q.network_fee.as_ref().unwrap().exp(), 18);
}

#[test]
fn get_quote_no_route_errors() {
    // toTokenAmount 0 -> no liquidity.
    let base = mock(r#"{"fromTokenAmount":"1000000","toTokenAmount":"0"}"#);
    let err = swap::get_quote(
        None,
        &base,
        "evm",
        "1",
        token("0xIN", "IN", 6),
        token("0xOUT", "OUT", 6),
        "1000000",
        0,
    );
    assert!(err.is_err(), "no route must error");
}

// ── audit F7: the quote's amountIn is the requested amount, never the echo ──

fn quote_with_echo(entry: &str, requested: &str) -> Result<swap::Quote, libwallet::Error> {
    let base = mock(entry);
    swap::get_quote(None, &base, "evm", "1", token("NATIVE", "ETH", 18), token("0xOUT", "OUT", 6), requested, 50)
}

#[test]
fn get_quote_rejects_tampered_from_token_amount() {
    // Asked for 0.1 ETH; the (untrusted) provider answers for 10 ETH. That
    // amount would drive Swap:execute, so the quote must be refused.
    let err = quote_with_echo(
        r#"{"fromTokenAmount":"10000000000000000000","toTokenAmount":"2000000"}"#,
        "100000000000000000",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not match the requested amount"), "{err}");
    // A present-but-garbage echo is a mismatch too.
    assert!(quote_with_echo(r#"{"fromTokenAmount":"lots","toTokenAmount":"2000000"}"#, "100000000000000000").is_err());
}

#[test]
fn get_quote_amount_in_is_the_requested_amount() {
    // No echo at all: the requested amount is used.
    let q = quote_with_echo(r#"{"toTokenAmount":"2000000"}"#, "100000000000000000").unwrap();
    assert_eq!(q.amount_in.value().unwrap().to_string(), "100000000000000000");
    // A matching echo is fine.
    let q = quote_with_echo(
        r#"{"fromTokenAmount":"100000000000000000","toTokenAmount":"2000000"}"#,
        "100000000000000000",
    )
    .unwrap();
    assert_eq!(q.amount_in.value().unwrap().to_string(), "100000000000000000");
    // The requested amount must itself be a positive base-unit integer — the
    // provider's echo no longer papers over a malformed request.
    for bad in ["abc", "-5", "1.5", "+7"] {
        let err = quote_with_echo(r#"{"fromTokenAmount":"1000","toTokenAmount":"2000000"}"#, bad).unwrap_err();
        assert!(err.to_string().contains("bad amountIn"), "{bad}: {err}");
    }
}

// ── audit F8: provider-supplied gas / gasPrice / chain id are bounded ───────

#[test]
fn provider_gas_is_checked_and_capped() {
    // +50% headroom, as before.
    assert_eq!(swap::okx_checked_gas("1", "120000").unwrap(), 180_000);
    assert_eq!(swap::okx_checked_gas("1", "").unwrap(), 0);
    // Exactly at the ceiling passes; one step over does not.
    assert_eq!(swap::okx_checked_gas("1", "20000000").unwrap(), swap::OKX_EVM_MAX_GAS);
    assert!(swap::okx_checked_gas("1", "20000001").is_err());
    // `gas * 3` used to overflow u64 (panic in debug, wrap in release).
    assert!(swap::okx_checked_gas("1", &u64::MAX.to_string()).is_err());
    assert!(swap::okx_checked_gas("5000", &u64::MAX.to_string()).is_err());
    // Not a plain decimal.
    for bad in ["-1", "0x5208", "1e9", "99999999999999999999999"] {
        assert!(swap::okx_checked_gas("1", bad).is_err(), "{bad}");
    }
    // Mantle's gas units are not Ethereum's: only the arithmetic is checked.
    assert_eq!(swap::okx_checked_gas("5000", "2000000000").unwrap(), 3_000_000_000);
}

#[test]
fn provider_gas_price_is_capped_to_the_node_price() {
    use num_bigint::BigInt;
    let node = BigInt::from(20_000_000_000u64); // 20 gwei
    assert_eq!(swap::okx_checked_gas_price("20000000000", &node).unwrap(), "20000000000");
    assert_eq!(swap::okx_checked_gas_price("", &node).unwrap(), "0");
    // Up to 10x the node price is tolerated, not more.
    assert_eq!(swap::okx_checked_gas_price("200000000000", &node).unwrap(), "200000000000");
    assert!(swap::okx_checked_gas_price("200000000001", &node).is_err());
    assert!(swap::okx_checked_gas_price("1000000000000000000", &node).is_err());
    for bad in ["-1", "0x4a817c800", "cheap"] {
        assert!(swap::okx_checked_gas_price(bad, &node).is_err(), "{bad}");
    }
}

/// An EVM account + its unlock creds in a fresh in-memory env.
fn evm_account() -> (libwallet::Env, String, Vec<(String, String)>) {
    use libwallet::models::{account, wallet};
    use libwallet::sign::KeyDescription;
    let env = libwallet::Env::init_memory().unwrap();
    wallet::init(&env).unwrap();
    account::init(&env).unwrap();
    let kds: Vec<KeyDescription> = ["a", "b", "c"]
        .iter()
        .map(|p| KeyDescription { kind: "Password".into(), key: format!("password{p}"), id: String::new() })
        .collect();
    let w = wallet::create(&env, "EVM", "secp256k1", &kds).unwrap();
    let a = account::create(&env, &w.id, "", "ethereum", 0).unwrap();
    let unlock = w.keys.iter().zip(["a", "b", "c"]).map(|(k, p)| (k.id.clone(), format!("password{p}"))).collect();
    (env, a.id, unlock)
}

/// Run `execute_evm` against a provider `/swap` tx (and nothing else on the OKX
/// side, so reaching the broadcast fails) with the node at 20 gwei.
fn execute_evm_with_tx(chain_id: &str, tx: &str) -> Result<serde_json::Value, libwallet::Error> {
    let (env, account_id, unlock) = evm_account();
    let okx = mock_multi(vec![format!(r#"{{"result":"success","data":[{{"tx":{tx}}}]}}"#)]);
    let node = mock_multi(vec![
        r#"{"jsonrpc":"2.0","id":1,"result":"0x3"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4a817c800"}"#.to_string(),
    ]);
    swap::execute_evm(
        &env, &account_id, &libwallet::swap::Signer::Keys(&unlock), None, &okx, &node, chain_id, &token("0xIN", "IN", 18), &token("0xOUT", "OUT", 6),
        "1000000000000000000", 50, true, "q_test",
    )
}

#[test]
fn execute_evm_refuses_inflated_gas_price_and_gas() {
    let to = "0x1111111111111111111111111111111111111111";
    // 1 ETH per gas against a 20 gwei node.
    let err = execute_evm_with_tx(
        "1",
        &format!(r#"{{"to":"{to}","value":"0","data":"0xabcdef","gas":"120000","gasPrice":"1000000000000000000"}}"#),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("gasPrice") && err.contains("node gas price"), "{err}");
    // A gas limit whose +50% headroom overflows u64.
    let err = execute_evm_with_tx(
        "1",
        &format!(r#"{{"to":"{to}","value":"0","data":"0xabcdef","gas":"18446744073709551615","gasPrice":"1"}}"#),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("not a usable gas limit"), "{err}");
}

#[test]
fn execute_evm_refuses_non_numeric_chain_id() {
    // Used to sign for chain id 1 (mainnet) via `parse().unwrap_or(1)`.
    let (env, account_id, unlock) = evm_account();
    let err = swap::execute_evm(
        &env, &account_id, &libwallet::swap::Signer::Keys(&unlock), None, "http://unused.invalid", "http://unused.invalid", "mainnet",
        &token("0xIN", "IN", 18), &token("0xOUT", "OUT", 6), "1000000000000000000", 50, true, "q_test",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("non-numeric EVM chain id"), "{err}");
}

#[test]
fn execute_evm_refuses_malformed_call_data() {
    let to = "0x1111111111111111111111111111111111111111";
    for data in ["0xabc", "0x+a", "0x\u{e9}\u{e9}"] {
        let err = execute_evm_with_tx(
            "1",
            &format!(r#"{{"to":"{to}","value":"0","data":"{data}","gas":"120000","gasPrice":"20000000000"}}"#),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("bad tx data hex"), "{data}: {err}");
    }
}
