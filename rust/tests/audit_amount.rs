//! Amount exponent bounds (security audit F4): an exponent from untrusted
//! input is rejected instead of driving a gigantic power of ten or wrapping an
//! integer cast.

use libwallet::Amount;
use num_bigint::BigInt;

fn parse_json(s: &str) -> Result<Amount, serde_json::Error> {
    serde_json::from_str::<Amount>(s)
}

#[test]
fn scientific_exponent_is_bounded() {
    for s in [
        "1e999999999",           // would compute 10^999999999
        "1e4294967297",          // used to truncate to 10^1
        "1e-9223372036854775808", // i64::MIN: negation overflow
        "1e9223372036854775807",
        "1e256",
        "1e-256",
        "1.5e-255", // resulting exponent 256
    ] {
        assert!(Amount::from_string(s, 0).is_err(), "{s} must be rejected");
        assert!(parse_json(&format!("\"{s}\"")).is_err(), "JSON string {s} must be rejected");
    }
}

#[test]
fn ordinary_values_still_parse() {
    let a = Amount::from_string("1.5e3", 0).unwrap();
    assert_eq!(a.to_display_string(), "1500");
    assert_eq!(a.exp(), 0);

    let a = Amount::from_string("123.456", 0).unwrap();
    assert_eq!((a.value().unwrap().clone(), a.exp()), (BigInt::from(123456), 3));

    let a = Amount::from_string("1e-18", 0).unwrap();
    assert_eq!(a.exp(), 18);
    assert_eq!(a.to_display_string(), "0.000000000000000001");

    let a = Amount::from_string("1e36", 0).unwrap();
    assert_eq!(a.to_display_string(), format!("1{}", "0".repeat(36)));

    // The bound itself is accepted.
    assert_eq!(Amount::from_string("1e-255", 0).unwrap().exp(), 255);
    assert_eq!(Amount::from_string("1e255", 0).unwrap().to_display_string().len(), 256);
}

#[test]
fn json_object_exponent_is_bounded() {
    for e in ["-1", "256", "4294967297", "9223372036854775807", "-9223372036854775808", "\"-1\"", "\"1000000\""] {
        let js = format!(r#"{{"v":"1","e":{e},"f":0}}"#);
        assert!(parse_json(&js).is_err(), "{js} must be rejected");
        let js = format!(r#"{{"v":"MAX","e":{e},"f":0}}"#);
        assert!(parse_json(&js).is_err(), "{js} must be rejected");
    }
    // Existing wire values are unaffected.
    let a = parse_json(r#"{"v":"123456","e":3,"f":123.456}"#).unwrap();
    assert_eq!(a.to_display_string(), "123.456");
    let a = parse_json(r#"{"v":"1","e":36,"f":0}"#).unwrap();
    assert_eq!(a.exp(), 36);
    let a = parse_json(r#"{"v":"MAX","e":18,"f":0}"#).unwrap();
    assert!(a.is_max());
    assert_eq!(a.exp(), 18);
    assert_eq!(parse_json(r#"{"v":"7","e":255,"f":0}"#).unwrap().exp(), 255);
}

#[test]
fn bare_json_numbers() {
    assert_eq!(parse_json("1500").unwrap().to_display_string(), "1500");
    assert_eq!(parse_json("1.25").unwrap().to_display_string(), "1.25");
    assert_eq!(parse_json("1e-7").unwrap().to_display_string(), "0.0000001");
    // Clearly out of range.
    assert!(parse_json("1e300").is_err());
    assert!(parse_json("5e-324").is_err());
}

#[test]
fn binary_exponent_is_bounded() {
    // Round trip of a valid value is unchanged.
    let a = Amount::new_raw(BigInt::from(-123456), 18);
    assert_eq!(Amount::from_bytes(&a.to_bytes()).unwrap(), a);

    // [version 0][zigzag varint exp][magnitude]: exp = -1, 256, i64::MAX.
    assert!(Amount::from_bytes(&[0x00, 0x01, 0x01]).is_err());
    assert!(Amount::from_bytes(&[0x00, 0x80, 0x04, 0x01]).is_err());
    assert!(Amount::from_bytes(&[0x00, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01]).is_err());
    // exp = 255 (zigzag 510 = 0xfe 0x03) is the last accepted value.
    assert_eq!(Amount::from_bytes(&[0x00, 0xfe, 0x03, 0x01]).unwrap().exp(), 255);
}

#[test]
fn constructors_and_rescale_stay_in_range() {
    // A hostile decimals count cannot reach the 10^n / "0".repeat(n) paths.
    let mut a = Amount::new_raw(BigInt::from(1), i64::MAX);
    assert_eq!(a.exp(), 255);
    assert_eq!(a.to_display_string().len(), 2 + 255);
    assert_eq!(Amount::new(1, -5).exp(), 0);
    assert_eq!(Amount::new_max(i64::MIN).exp(), 0);

    a.set_exp(i64::MIN);
    assert_eq!(a.exp(), 0);
    a.set_exp(i64::MAX);
    assert_eq!(a.exp(), 255);

    // mul/div across the widest in-range exponents terminate and stay exact.
    let x = Amount::new_raw(BigInt::from(3), 255);
    let y = Amount::new_raw(BigInt::from(2), 255);
    let mut p = Amount::new(0, 255);
    p.mul(&x, &y);
    assert_eq!((p.exp(), p.is_zero()), (255, true)); // 6e-510 rounds to 0 at 255 digits
    let mut q = Amount::new(0, 255);
    q.div(&x, &y);
    assert_eq!(q.to_display_string(), format!("1.5{}", "0".repeat(254)));
}
