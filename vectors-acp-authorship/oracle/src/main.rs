use dsse::{verify, Ed25519Verifier, Envelope};
use serde_json::Value;
use std::{env, fs, path::Path};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
const PREDICATE_TYPE: &str = "https://noru.tech/spec/ai-change-provenance/provenance/v0.1";

fn check(path: &Path) -> Result<(), String> {
    let key_hex = fs::read_to_string(format!("{ROOT}/public.key")).map_err(|e| e.to_string())?;
    let key = key_hex.trim();
    let public: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let verifier = Ed25519Verifier::from_bytes(&public).map_err(|e| e.to_string())?;
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let envelope = Envelope::from_json(&raw).map_err(|e| e.to_string())?;
    let checked = verify(&envelope, &[&verifier], 1).map_err(|e| e.to_string())?;
    if checked.payload_type != "application/vnd.in-toto+json" {
        return Err("wrong payload type".into());
    }
    let statement: Value = serde_json::from_slice(&checked.payload).map_err(|e| e.to_string())?;
    let head = fs::read_to_string(format!("{ROOT}/expected-head.txt")).map_err(|e| e.to_string())?;
    let head = head.trim();
    let bound = statement["subject"].as_array().is_some_and(|subjects| {
        subjects.iter().any(|subject| subject["digest"]["gitCommit"].as_str() == Some(head))
    });
    if statement["_type"] != "https://in-toto.io/Statement/v1"
        || statement["predicateType"] != PREDICATE_TYPE
        || statement["predicate"]["change"]["head_commit"] != head
        || !bound
    {
        return Err("statement is not bound to the pinned head and type".into());
    }
    Ok(())
}

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: acp-authorship-ingress-oracle CASE.json");
        std::process::exit(2);
    };
    match check(Path::new(&path)) {
        Ok(()) => println!("{{\"verdict\":\"verified\"}}"),
        Err(reason) => {
            println!("{{\"verdict\":\"rejected\"}}");
            eprintln!("{reason}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_authorship_bytes_survive_an_independent_verifier() {
        assert!(check(Path::new(&format!("{ROOT}/cases/valid.json"))).is_ok());
        assert!(check(Path::new(&format!("{ROOT}/cases/changed-operator.json"))).is_err());
    }
}
