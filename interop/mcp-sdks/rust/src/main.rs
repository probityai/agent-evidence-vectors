//! Decode and re-encode each JSON-RPC line with the codec of rmcp's async_rw
//! transport: `serde_json::from_slice::<ServerJsonRpcMessage>` and
//! `serde_json::to_writer`.
use std::io::{self, BufRead, Write};

use base64::Engine;
use rmcp::model::ServerJsonRpcMessage;

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        match serde_json::from_slice::<ServerJsonRpcMessage>(line.as_bytes()) {
            Ok(msg) => {
                let wire = serde_json::to_vec(&msg).map_err(io::Error::other)?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
                writeln!(out, "OK {b64}")?;
            }
            Err(err) => writeln!(out, "ERR {}", err.to_string().replace('\n', " "))?,
        }
    }
    Ok(())
}
