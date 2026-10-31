//! Verifies every DSSE envelope of the published agent audit record corpus.
//!
//! `verify_corpus <corpus dir>` reads `MANIFEST.json` from a copy of the
//! `vectors-agent-audit-record` corpus that the `agent-evidence-vectors` package
//! ships, takes the observer's Ed25519 public key from `keys.observer`, and
//! verifies each member's envelope with `dsse::verify` at threshold 1. Every
//! member is signed by that key, so every one must verify. As a control, each
//! envelope is verified again with one payload byte flipped, which must fail.
//! The run exits 1 on any disagreement and when the manifest lists no members.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dsse::{verify, Ed25519Verifier, Envelope, Verifier};
use serde_json::Value;

fn main() -> ExitCode {
    let Some(dir) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: verify_corpus <vectors-agent-audit-record dir>");
        return ExitCode::from(2);
    };
    match run(&dir) {
        Ok(count) => {
            println!("verified {count} of {count} envelopes; {count} tampered copies refused");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("verify_corpus: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(dir: &Path) -> Result<usize, String> {
    let manifest: Value = read_json(&dir.join("MANIFEST.json"))?;
    let observer = manifest
        .pointer("/keys/observer")
        .ok_or("MANIFEST.json has no keys.observer")?;
    let key_hex = observer
        .get("publicKey")
        .and_then(Value::as_str)
        .ok_or("keys.observer.publicKey is missing")?;
    let key_id = observer.get("keyid").and_then(Value::as_str).unwrap_or("");
    let key = Ed25519Verifier::from_bytes(&decode_hex(key_hex)?)
        .map_err(|e| format!("observer key: {e}"))?
        .with_key_id(key_id);
    let keys: [&dyn Verifier; 1] = [&key];

    let members = manifest
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or("MANIFEST.json has no vectors list")?;
    if members.is_empty() {
        return Err("the manifest lists no members".into());
    }
    let mut failures = Vec::new();
    for member in members {
        let file = member
            .get("file")
            .and_then(Value::as_str)
            .ok_or("a member has no file")?;
        if let Err(message) = check_member(&dir.join(file), &keys) {
            failures.push(format!("{file}: {message}"));
        }
    }
    if failures.is_empty() {
        Ok(members.len())
    } else {
        Err(format!(
            "{} of {} members disagreed:\n  {}",
            failures.len(),
            members.len(),
            failures.join("\n  ")
        ))
    }
}

fn check_member(path: &Path, keys: &[&dyn Verifier]) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let envelope = Envelope::from_json(&bytes).map_err(|e| e.to_string())?;
    verify(&envelope, keys, 1).map_err(|e| format!("did not verify: {e}"))?;

    let mut payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|e| e.to_string())?;
    let first = payload.first_mut().ok_or("empty payload")?;
    *first ^= 0x01;
    let tampered = Envelope {
        payload: STANDARD.encode(&payload),
        ..envelope
    };
    if verify(&tampered, keys, 1).is_ok() {
        return Err("a copy with one payload byte flipped still verified".into());
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex key".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("bad hex at {i}"))
        })
        .collect()
}
