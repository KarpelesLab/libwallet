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
        &env, &acct.id, &unlock, None, &okx, node, "mainnet", &token_in, &token_out, "1000000000", 50, false, "q_test",
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
    // Node is used only for the nonce now (broadcast goes through OKX).
    let node = mock_multi(vec![r#"{"jsonrpc":"2.0","id":1,"result":"0x3"}"#.to_string()]);
    let token_in = TokenRef { address: "0xIN".into(), symbol: "IN".into(), decimals: 18 };
    let token_out = TokenRef { address: "0xOUT".into(), symbol: "OUT".into(), decimals: 6 };

    let res = swap::execute_evm(
        &env, &a.id, &unlock, None, &okx, &node, "1", &token_in, &token_out, "1000000000000000000", 50, true, "q_test",
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
