//! Verifier for the `rfc8785` target of the a2a-jcs-v01 conformance corpus.
//!
//! The corpus harness in agent-evidence-vectors runs `a2a_jcs <target> <input.json>`
//! once per vector. On success this prints `{"canonical_utf8_hex": "<hex>"}` and
//! exits 0; when `admit` refuses the input it exits 1. Any other target is a usage
//! error and exits 2, so a run against the wrong target can never read as a pass.

use std::fmt::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [target, path] = args.as_slice() else {
        eprintln!("usage: a2a_jcs rfc8785 <input.json>");
        return ExitCode::from(2);
    };
    if target != "rfc8785" {
        eprintln!("unsupported target {target:?}: only rfc8785 is implemented");
        return ExitCode::from(2);
    }
    let input = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {path}: {error}");
            return ExitCode::from(2);
        }
    };
    match jcs_admit::admit(&input) {
        Ok(canonical) => {
            let mut hex = String::with_capacity(canonical.len() * 2);
            for byte in &canonical {
                let _ = write!(hex, "{byte:02x}");
            }
            println!("{{\"canonical_utf8_hex\": \"{hex}\"}}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("refused: {error}");
            ExitCode::from(1)
        }
    }
}
