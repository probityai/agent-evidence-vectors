//! `aev-verdicts <corpus-dir>`: print `<id>\t<decision>\t<reason>` for every
//! manifest vector, in manifest order, derived from each record.json alone.
//!
//! Exit 0 when the run completed, 2 when the corpus is unreadable or its suite
//! is unknown.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir] = args.as_slice() else {
        eprintln!("usage: aev-verdicts <corpus-dir>");
        return ExitCode::from(2);
    };
    let lines = match aev_readers::verdict_lines(Path::new(dir)) {
        Ok(lines) => lines,
        Err(error) => {
            eprintln!("aev-verdicts: {error}");
            return ExitCode::from(2);
        }
    };
    let mut out = std::io::stdout().lock();
    for line in lines {
        if writeln!(out, "{line}").is_err() {
            return ExitCode::from(2);
        }
    }
    if out.flush().is_err() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
