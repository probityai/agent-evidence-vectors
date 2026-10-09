//! Admission reference for the MCP SDK comparison.
//!
//! Reads one JSON document per line on stdin and writes one line per input:
//! `<rfc8785>\t<ijson>`, where each field is `OK <base64 canonical bytes>` or
//! `ERR <error variant>`.
use std::io::{self, BufRead, Write};

use base64::Engine;

fn field(result: Result<Vec<u8>, jcs_admit::Error>) -> String {
    match result {
        Ok(bytes) => format!("OK {}", base64::engine::general_purpose::STANDARD.encode(bytes)),
        Err(err) => {
            let debug = format!("{err:?}");
            let variant = debug.split([' ', '{', '(']).next().unwrap_or("Unknown");
            format!("ERR {variant}")
        }
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let bytes = line.as_bytes();
        writeln!(
            out,
            "{}\t{}",
            field(jcs_admit::admit(bytes)),
            field(jcs_admit::admit_ijson(bytes))
        )?;
    }
    Ok(())
}
