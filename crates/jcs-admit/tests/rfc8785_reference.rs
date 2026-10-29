//! The RFC 8785 reference test suite, byte for byte.
//!
//! Every case in this file is a PINNED vector: the six input documents and the
//! six canonical forms are the files the RFC's own reference implementation
//! ships, copied unmodified. Provenance and licence are in
//! `tests/vectors/PROVENANCE.md`. Nothing here is invented.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

const CASES: [&str; 6] = [
    "arrays",
    "french",
    "structures",
    "unicode",
    "values",
    "weird",
];

fn read(kind: &str, name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/rfc8785")
        .join(kind)
        .join(format!("{name}.json"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn reference_suite_canonicalizes_byte_for_byte() {
    let mut failures = Vec::new();
    for name in CASES {
        let input = read("input", name);
        let expected = read("output", name);
        match jcs_admit::admit(&input) {
            Ok(got) if got == expected => {}
            Ok(got) => failures.push(format!(
                "{name}: got {:?}\n         want {:?}",
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&expected)
            )),
            Err(e) => failures.push(format!("{name}: refused: {e}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 6 reference vectors diverge:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn reference_outputs_are_their_own_canonical_form() {
    // The canonical form of a canonical document is itself. A canonicalizer that
    // is not idempotent has two answers for one document.
    for name in CASES {
        let expected = read("output", name);
        assert!(
            jcs_admit::is_canonical(&expected),
            "{name}: reference output is not canonical"
        );
        let again = jcs_admit::admit(&expected).unwrap();
        assert_eq!(
            again, expected,
            "{name}: canonicalization is not idempotent"
        );
    }
}
