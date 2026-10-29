//! Native oracle for the npm package's raw-byte parity check.

use std::io::{self, BufRead, Write};

use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Repeat {
    byte: u8,
    len: usize,
}

#[derive(Deserialize)]
struct Input {
    id: String,
    profile: String,
    bytes: Option<Vec<u8>>,
    repeat: Option<Repeat>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lock().lines() {
        let request: Input = serde_json::from_str(&line?)?;
        let bytes = match (request.bytes, request.repeat) {
            (Some(bytes), None) => bytes,
            (None, Some(repeat)) => vec![repeat.byte; repeat.len],
            _ => return Err("one byte input or repeat descriptor is required".into()),
        };
        let result = match request.profile.as_str() {
            "admit" => jcs_admit::admit(&bytes),
            "admit_ijson" => jcs_admit::admit_ijson(&bytes),
            _ => return Err("unknown test transport profile".into()),
        };
        let response = match result {
            Ok(bytes) => json!({
                "id": request.id,
                "profile": request.profile,
                "ok": true,
                "output": bytes,
            }),
            Err(error) => {
                let mut payload = serde_json::to_value(&error)?;
                let fields = payload
                    .as_object_mut()
                    .ok_or("native Error serialization is not an object")?;
                fields.insert("message".to_owned(), Value::String(error.to_string()));
                json!({
                    "id": request.id,
                    "profile": request.profile,
                    "ok": false,
                    "error": payload,
                })
            }
        };
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
    }
    output.flush()?;
    Ok(())
}
