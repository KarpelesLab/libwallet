//! Byte-for-byte compatibility with the Go `wltobj`. Expected values were
//! emitted by the real Go implementation (see the port notes); if any of these
//! drift, on-wire / on-disk compatibility with deployed data is broken.

use num_bigint::BigInt;
use libwallet::{Amount, TimeId};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Assert the amount's binary form, display string, and JSON match Go.
/// `f` (a lossy convenience float) is compared with a relative tolerance.
fn check(a: &Amount, want_hex: &str, want_str: Option<&str>, want_json: &str) {
    assert_eq!(hex(&a.to_bytes()), want_hex, "to_bytes mismatch");

    // binary round-trip
    let back = Amount::from_bytes(&a.to_bytes()).unwrap();
    assert_eq!(back.value(), a.value(), "from_bytes value round-trip");
    assert_eq!(back.exp(), a.exp(), "from_bytes exp round-trip");

    if let Some(s) = want_str {
        assert_eq!(a.to_display_string(), s, "display string mismatch");
    }

    let got: serde_json::Value = serde_json::to_value(a).unwrap();
    let want: serde_json::Value = serde_json::from_str(want_json).unwrap();
    assert_eq!(got["v"], want["v"], "json v mismatch");
    assert_eq!(got["e"], want["e"], "json e mismatch");
    let (gf, wf) = (got["f"].as_f64().unwrap(), want["f"].as_f64().unwrap());
    assert!(
        (gf - wf).abs() <= 1e-9 * wf.abs().max(1.0),
        "json f mismatch: got {gf}, want {wf}"
    );

    // JSON round-trip back to an equal Amount
    let reparsed: Amount = serde_json::from_value(got).unwrap();
    assert_eq!(&reparsed, a, "json round-trip");
}

#[test]
fn amount_go_vectors() {
    let big: BigInt = "123456789012345678901234567890".parse().unwrap();

    check(&Amount::new_raw(BigInt::from(123456), 3), "000601e240", Some("123.456"), r#"{"v":"123456","e":3,"f":123.456}"#);
    check(&Amount::new_raw(BigInt::from(-5), 2), "01040105", Some("-0.05"), r#"{"v":"-5","e":2,"f":-0.05}"#);
    check(&Amount::new(0, 0), "0000", Some("0"), r#"{"v":"0","e":0,"f":0}"#);
    check(&Amount::new_raw(big, 18), "0024018ee90ff6c373e0ee4e3f0ad2", Some("123456789012.345678901234567890"), r#"{"v":"123456789012345678901234567890","e":18,"f":123456789012.34567}"#);
}

#[test]
fn amount_from_string_vectors() {
    check(&Amount::from_string("0.001", 0).unwrap(), "000601", Some("0.001"), r#"{"v":"1","e":3,"f":0.001}"#);
    check(&Amount::from_string("1e3", 0).unwrap(), "000003e8", Some("1000"), r#"{"v":"1000","e":0,"f":1000}"#);
    check(&Amount::from_string("123", 0).unwrap(), "00007b", Some("123"), r#"{"v":"123","e":0,"f":123}"#);
    check(&Amount::from_string("1.5", 0).unwrap(), "00020f", Some("1.5"), r#"{"v":"15","e":1,"f":1.5}"#);
    check(&Amount::from_string("-0.05", 0).unwrap(), "01040105", Some("-0.05"), r#"{"v":"-5","e":2,"f":-0.05}"#);
}

#[test]
fn set_exp_rounds_half_away_from_zero() {
    let mut a = Amount::new_raw(BigInt::from(12345), 3);
    a.set_exp(1);
    check(&a, "00027b", Some("12.3"), r#"{"v":"123","e":1,"f":12.3}"#);
}

#[test]
fn max_sentinel_json_and_bytes() {
    let m = Amount::new_max(6);
    assert!(m.is_max());
    assert_eq!(hex(&m.to_bytes()), "000c");
    let got: serde_json::Value = serde_json::to_value(&m).unwrap();
    assert_eq!(got["v"], "MAX");
    assert_eq!(got["e"], 6);
    // Round-trips the sentinel through JSON.
    let back: Amount = serde_json::from_value(got).unwrap();
    assert!(back.is_max());
    assert_eq!(back.exp(), 6);
}

#[test]
fn amount_scan_accepts_string_and_number() {
    let from_str: Amount = serde_json::from_str(r#""1.5""#).unwrap();
    assert_eq!(from_str.to_display_string(), "1.5");
    let from_num: Amount = serde_json::from_str("123").unwrap();
    assert_eq!(from_num.to_display_string(), "123");
    let from_max: Amount = serde_json::from_str(r#""MAX""#).unwrap();
    assert!(from_max.is_max());
}

#[test]
fn amount_arithmetic() {
    // 1.50 + 0.25 = 1.75 (same exp path)
    let mut sum = Amount::new(0, 2);
    sum.add(&Amount::new(150, 2), &Amount::new(25, 2));
    assert_eq!(sum.to_display_string(), "1.75");

    // 2.00 - 0.5 with rescale
    let mut diff = Amount::new(0, 2);
    diff.sub(&Amount::new(200, 2), &Amount::new(5, 1));
    assert_eq!(diff.to_display_string(), "1.50");

    // cmp
    assert_eq!(Amount::new(100, 2).cmp(&Amount::new(200, 2)), std::cmp::Ordering::Less);
}

#[test]
fn amount_from_float64_vectors() {
    // NewAmountFromFloat64(f, 8): significand = round-half-away(f * 1e8), exp 8.
    assert_eq!(Amount::from_float64(1.0, 8).to_display_string(), "1.00000000");
    assert_eq!(Amount::from_float64(3200.5, 8).to_display_string(), "3200.50000000");
    assert_eq!(Amount::from_float64(0.12345678, 8).to_display_string(), "0.12345678");
    // half rounds away from zero
    assert_eq!(Amount::from_float64(0.000000005, 8).to_display_string(), "0.00000001");
    // negative
    assert_eq!(Amount::from_float64(-2.5, 8).to_display_string(), "-2.50000000");
    // exp <= 0 -> derive from f's decimals, min 5
    assert_eq!(Amount::from_float64(1.5, 0).exp(), 5);
    // large magnitude beyond i64 (market cap): 1.2e12 * 1e8 = 1.2e20
    assert_eq!(Amount::from_float64(1.2e12, 8).exp(), 8);
}

#[test]
fn timeid_go_vectors() {
    let t = TimeId { type_: String::new(), unix: 1_700_000_000, nano: 123, index: 0 };
    assert_eq!(t.to_string(), "nil:1700000000:123:0");
    assert_eq!(hex(&t.to_bytes()), "000000006553f1000000007b00000000");
    assert_eq!(serde_json::to_string(&t).unwrap(), r#""nil:1700000000:123:0""#);

    let t2 = TimeId { type_: "evt".into(), unix: 42, nano: 7, index: 3 };
    assert_eq!(t2.to_string(), "evt:42:7:3");
    assert_eq!(hex(&t2.to_bytes()), "000000000000002a0000000700000003");

    // string + binary round-trips
    assert_eq!("evt:42:7:3".parse::<TimeId>().unwrap(), t2);
    assert_eq!(TimeId::from_bytes(&t.to_bytes()).unwrap(), t); // t has empty type
}
