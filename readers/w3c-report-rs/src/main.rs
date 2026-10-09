//! `w3c-report-rs`: a third reader for the v0.1 per-check report corpus.
//!
//! Usage:
//!   w3c-report-rs <corpus-dir>
//!       Judge every member of the corpus against its MANIFEST.json and print
//!       one line per finding, in the line format the other two readers print.
//!   w3c-report-rs --report <report.json> [--against <emitter-bytes>]...
//!       Validate one emitted report, recompute its check-set digest and leaf
//!       count, write its canonical layout and compare that byte for byte with
//!       the file itself and with every `--against` file.

mod arm;
mod corpus;
mod json;
mod lcd;
mod report;
mod shape;
mod tree;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: w3c-report-rs <corpus-dir> | w3c-report-rs --report <report.json> [--against <file>]...");
    ExitCode::from(2)
}

fn code(status: i32) -> ExitCode {
    ExitCode::from(u8::try_from(status).unwrap_or(2))
}

fn report_mode(path: &Path, against: &[PathBuf]) -> (String, i32) {
    let mut lines = Vec::new();
    let mut ok = true;
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return (format!("cannot read {}: {e}\n", path.display()), 2),
    };
    lines.push(format!("report: {}", path.display()));
    lines.push(format!(
        "bytes: {} sha256 {}",
        bytes.len(),
        tree::sha256_hex(&bytes)
    ));
    let doc = match json::read(&bytes) {
        Ok(d) => d,
        Err(json::ReadError::Syntax(m) | json::ReadError::Inadmissible(m)) => {
            return (
                format!("{}\nFAIL: not readable JSON: {m}\n", lines.join("\n")),
                1,
            )
        }
    };
    match report::judge(&doc, None) {
        report::Judgement::Shape(errs) => {
            ok = false;
            lines.push(format!("FAIL rows: not a v0.1 report: {}", errs.join("; ")));
        }
        report::Judgement::Rows(rows) if rows.is_empty() => lines.push(
            "ok   rows: no row fires (references unresolved, so rows reading moved degrade)".into(),
        ),
        report::Judgement::Rows(rows) => {
            ok = false;
            let rows: Vec<String> = rows.into_iter().collect();
            lines.push(format!("FAIL rows: rejected under [{}]", rows.join(", ")));
        }
    }
    match report::measure_set(&doc) {
        None => {
            ok = false;
            lines.push("FAIL check-set: the report carries no checks to recompute over".into());
        }
        Some(m) => {
            let count_ok = m.leaf_count_declared == Some(m.leaf_count_measured as i64);
            ok &= count_ok;
            lines.push(format!(
                "{} check-set leaf-count: declared {}, measured {}",
                if count_ok { "ok  " } else { "FAIL" },
                m.leaf_count_declared
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".into()),
                m.leaf_count_measured
            ));
            let digest_ok =
                m.sha256_recomputed.is_some() && m.sha256_recomputed == m.sha256_declared;
            ok &= digest_ok;
            lines.push(format!(
                "{} check-set sha256 ({}): declared {}, recomputed {}",
                if digest_ok { "ok  " } else { "FAIL" },
                m.shape.as_deref().unwrap_or("no shape"),
                m.sha256_declared.as_deref().unwrap_or("none"),
                m.sha256_recomputed.as_deref().unwrap_or("none")
            ));
        }
    }
    let written = json::pretty(&doc);
    let same = written.as_bytes() == bytes.as_slice();
    ok &= same;
    lines.push(format!(
        "{} canonical layout re-written by this reader: {} ({} bytes written, {} on disk)",
        if same { "ok  " } else { "FAIL" },
        if same {
            "byte-identical to the file"
        } else {
            "differs from the file"
        },
        written.len(),
        bytes.len()
    ));
    for other in against {
        match std::fs::read(other) {
            Err(e) => {
                ok = false;
                lines.push(format!(
                    "FAIL against {}: cannot read: {e}",
                    other.display()
                ));
            }
            Ok(b) => {
                let same = b == written.as_bytes();
                ok &= same;
                lines.push(format!(
                    "{} against {}: {} (sha256 {})",
                    if same { "ok  " } else { "FAIL" },
                    other.display(),
                    if same {
                        "byte-identical to this reader's re-write"
                    } else {
                        "differs from this reader's re-write"
                    },
                    tree::sha256_hex(&b)
                ));
            }
        }
    }
    lines.push(format!(
        "verdict: {}",
        if ok {
            "every check holds"
        } else {
            "at least one check does not hold"
        }
    ));
    (lines.join("\n") + "\n", i32::from(!ok))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (text, status) = match args.first().map(String::as_str) {
        Some("--report") => {
            let Some(path) = args.get(1) else {
                return usage();
            };
            let mut against = Vec::new();
            let mut rest = args[2..].iter();
            while let Some(flag) = rest.next() {
                match (flag.as_str(), rest.next()) {
                    ("--against", Some(p)) => against.push(PathBuf::from(p)),
                    _ => return usage(),
                }
            }
            report_mode(Path::new(path), &against)
        }
        Some(dir) if args.len() == 1 && !dir.starts_with('-') => corpus::run(Path::new(dir)),
        _ => return usage(),
    };
    print!("{text}");
    code(status)
}
