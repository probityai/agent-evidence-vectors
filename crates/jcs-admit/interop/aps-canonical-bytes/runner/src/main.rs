// Copyright 2026 Probity AI. Apache-2.0 license.
// The raw input token reaches jcs-admit before a value parser can round it.

use serde::Deserialize;
use serde_json::{json, value::RawValue};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: Box<RawValue>,
    canonical_bytes_hex: String,
    canonical_sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn first_divergent_byte_offset(actual: &[u8], expected: &[u8]) -> Option<usize> {
    actual
        .iter()
        .zip(expected)
        .position(|(a, b)| a != b)
        .or_else(|| (actual.len() != expected.len()).then_some(actual.len().min(expected.len())))
}

fn run() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("expected fixture path")?;
    let raw = std::fs::read(&path)?;
    let fixture: Fixture = serde_json::from_slice(&raw)?;
    let mut cases = Vec::with_capacity(fixture.vectors.len());
    let (mut byte_matches, mut sha_matches) = (0, 0);
    for vector in fixture.vectors {
        let actual = jcs_admit::admit(vector.input.get().as_bytes())?;
        let expected = hex::decode(vector.canonical_bytes_hex)?;
        let actual_sha256 = sha256_hex(&actual);
        let byte_match = actual == expected;
        let sha256_match = actual_sha256 == vector.canonical_sha256;
        byte_matches += usize::from(byte_match);
        sha_matches += usize::from(sha256_match);
        cases.push(json!({
            "name": vector.name,
            "byte_match": byte_match,
            "sha256_match": sha256_match,
            "actual_bytes_hex": hex::encode(&actual),
            "actual_sha256": actual_sha256,
            "first_divergent_byte_offset": first_divergent_byte_offset(&actual, &expected),
        }));
    }
    let report = json!({
        "runner": "rust",
        "implementation": "jcs_admit::admit",
        "implementation_kind": "rfc8785",
        "implementation_version": "0.1.0",
        "runtime_version": env!("CROSSRUN_RUSTC_VERSION"),
        "fixture": path.display().to_string(),
        "fixture_sha256": sha256_hex(&raw),
        "summary": {"total": cases.len(), "byte_match": byte_matches, "sha256_match": sha_matches},
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}
