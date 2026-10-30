//! Native oracle for the raw-byte npm binding's finite parity checks.

use std::io::{self, BufRead, Write};

use dsse::{Ed25519Verifier, Envelope, Verifier};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct TrustedKey {
    public_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Operation {
    Verify {
        envelope: Vec<u8>,
        trusted_keys: Vec<TrustedKey>,
        threshold: u32,
    },
    Pae {
        payload_type: String,
        payload: Vec<u8>,
    },
}

#[derive(Deserialize)]
struct Input {
    id: String,
    #[serde(flatten)]
    operation: Operation,
}

fn verify(
    raw: &[u8],
    inputs: Vec<TrustedKey>,
    threshold: u32,
) -> dsse::Result<dsse::VerifiedPayload> {
    let envelope = Envelope::from_json(raw)?;
    let mut keys = Vec::with_capacity(inputs.len());
    for input in inputs {
        let key = Ed25519Verifier::from_bytes(&input.public_key)?;
        keys.push(match input.key_id {
            Some(id) => key.with_key_id(id),
            None => key,
        });
    }
    let references: Vec<&dyn Verifier> = keys.iter().map(|key| key as &dyn Verifier).collect();
    dsse::verify(&envelope, &references, threshold as usize)
}

fn answer(input: Input) -> Result<Value, Box<dyn std::error::Error>> {
    let result = match input.operation {
        Operation::Pae {
            payload_type,
            payload,
        } => {
            json!({"id": input.id, "ok": true, "output": dsse::pae(&payload_type, &payload)})
        }
        Operation::Verify {
            envelope,
            trusted_keys,
            threshold,
        } => match verify(&envelope, trusted_keys, threshold) {
            Ok(verified) => json!({"id": input.id, "ok": true, "verified": {
                "payload_type": verified.payload_type,
                "payload": verified.payload,
                "accepted_keys": verified.accepted_keys,
            }}),
            Err(error) => {
                let mut payload = serde_json::to_value(&error)?;
                payload
                    .as_object_mut()
                    .ok_or("native Error is not an object")?
                    .insert("message".to_owned(), Value::String(error.to_string()));
                json!({"id": input.id, "ok": false, "error": payload})
            }
        },
    };
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lock().lines() {
        let input: Input = serde_json::from_str(&line?)?;
        serde_json::to_writer(&mut output, &answer(input)?)?;
        writeln!(output)?;
    }
    output.flush()?;
    Ok(())
}
