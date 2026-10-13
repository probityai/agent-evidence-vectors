//! Reads one JSON text on stdin and writes its RFC 8785 canonical bytes, as jcs-admit admits them.
use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        return ExitCode::from(2);
    }
    match jcs_admit::admit(&input) {
        Ok(bytes) => match std::io::stdout().write_all(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(2),
        },
        Err(err) => {
            eprintln!("refused: {err}");
            ExitCode::from(1)
        }
    }
}
