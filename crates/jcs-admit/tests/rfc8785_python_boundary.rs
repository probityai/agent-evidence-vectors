//! Raw input boundaries shared with the pinned Python byte comparator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit_with, Error, Options};
use serde_json::Value;

fn profile(name: &str) -> Options {
    match name {
        "rfc8785" => Options::rfc8785(),
        "ijson" => Options::ijson(),
        "ijson-integers" => Options::ijson().integers_only(true),
        other => panic!("unknown declared byte profile: {other}"),
    }
}

fn error_class(error: &Error) -> &'static str {
    match error {
        Error::DuplicateMember { .. } => "DuplicateMember",
        Error::StringNotScalar { .. } => "StringNotScalar",
        Error::UnsafeInteger { .. } => "UnsafeInteger",
        Error::NonIntegerNumber { .. } => "NonIntegerNumber",
        Error::NonFiniteNumber { .. } => "NonFiniteNumber",
        Error::TooDeep { .. } => "TooDeep",
        other => panic!("unexpected refusal class: {other:?}"),
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "expected complete hexadecimal bytes");
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn shared_python_boundary_controls_hold_on_the_raw_bytes() {
    let fixture: Value =
        serde_json::from_str(include_str!("../interop/rfc8785-py/controls.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11, "account for every boundary control");
    let (mut admitted, mut refused) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let raw = case["raw"].as_str().unwrap().as_bytes();
        let options = profile(case["profile"].as_str().unwrap());
        match admit_with(raw, &options) {
            Ok(actual) => {
                assert!(
                    case["rust_error"].is_null(),
                    "{name}: unexpectedly admitted"
                );
                let expected = decode_hex(case["rust_canonical_hex"].as_str().unwrap());
                assert_eq!(actual, expected, "{name}: canonical bytes differ");
                admitted += 1;
            }
            Err(error) => {
                assert_eq!(
                    error_class(&error),
                    case["rust_error"].as_str().unwrap(),
                    "{name}: refused in another class"
                );
                refused += 1;
            }
        }
    }
    assert_eq!((admitted, refused), (2, 9));
}
