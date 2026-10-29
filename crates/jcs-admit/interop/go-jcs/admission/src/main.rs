//! A bounded raw-byte entry point for the Go consumer qualification.

use jcs_admit::{admit_with, Error, Options, DEFAULT_MAX_BYTES};
use serde_json::json;
use std::error::Error as StdError;
use std::io::{self, Read};

fn class(error: &Error) -> &'static str {
    match error {
        Error::DuplicateMember { .. } => "DuplicateMember",
        Error::StringNotScalar { .. } => "StringNotScalar",
        Error::UnsafeInteger { .. } => "UnsafeInteger",
        Error::NonIntegerNumber { .. } => "NonIntegerNumber",
        Error::NonFiniteNumber { .. } => "NonFiniteNumber",
        Error::TooDeep { .. } => "TooDeep",
        Error::TooLarge { .. } => "TooLarge",
        Error::Syntax { .. } => "Syntax",
        Error::TrailingContent { .. } => "TrailingContent",
        Error::Canonicalization { .. } => "Canonicalization",
        _ => "OtherAdmissionError",
    }
}

fn run() -> Result<(), Box<dyn StdError>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("expected profile, maximum depth and maximum bytes".into());
    }
    let profile = match args[0].as_str() {
        "rfc8785" => Options::rfc8785(),
        "ijson" => Options::ijson(),
        "ijson-integers" => Options::ijson().integers_only(true),
        _ => return Err("unknown admission profile".into()),
    };
    let depth: usize = args[1].parse()?;
    let size: usize = args[2].parse()?;
    if depth > jcs_admit::DEFAULT_MAX_DEPTH || size > DEFAULT_MAX_BYTES {
        return Err("qualification options may only lower the default caps".into());
    }
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take((size + 1) as u64)
        .read_to_end(&mut raw)?;
    let outcome = match admit_with(&raw, &profile.max_depth(depth).max_bytes(Some(size))) {
        Ok(canonical) => {
            json!({"status": "accepted", "canonical_hex": canonical.iter().map(|b| format!("{b:02x}")).collect::<String>()})
        }
        Err(error) => json!({"status": "refused", "error_class": class(&error)}),
    };
    println!("{outcome}");
    Ok(())
}

fn main() -> Result<(), Box<dyn StdError>> {
    run()
}
