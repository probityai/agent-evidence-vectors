//! Every shipped file, decoded, names nothing on the refused list.
//!
//! A text search of the package reads the JSON text of a fixture file but not
//! the base64 inside it, and a signed payload is base64 by construction. So this
//! scanner walks every file under the crate root (or under `DSSE_SCAN_ROOT`, an
//! unpacked `.crate`), and decodes as it goes: every JSON string, every base64
//! run in either alphabet with or without padding, every hex run and every
//! percent-encoding, to a fixed depth. Each decoded text is split into tokens,
//! and each token is compared by SHA-256 digest.
//!
//! The refused list is held as digests and is supplied from outside the
//! repository in `DSSE_FORBIDDEN_SHA256` (comma-separated lowercase hex), so this
//! file names nothing itself. CI sets `DSSE_REQUIRE_FORBIDDEN_LIST=1`, which
//! turns a missing list into a failure rather than a silent pass. The control
//! test plants a canary built at run time through every encoding the scanner
//! claims to read, and fails if any one is missed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sha2::{Digest, Sha256};

const MAX_DEPTH: usize = 5;
const MIN_RUN: usize = 16;
const MAX_PARTS: usize = 12;

fn digest(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Scanner<'a> {
    refused: &'a BTreeSet<String>,
    hits: Vec<String>,
}

impl Scanner<'_> {
    fn scan(&mut self, data: &[u8], place: &str, depth: usize) {
        if depth > MAX_DEPTH || data.is_empty() {
            return;
        }
        self.tokens(data, place);
        if let Ok(text) = std::str::from_utf8(data) {
            self.json(text, place, depth);
            self.percent(text, place, depth);
            let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            if squeezed.len() != text.len() && is_b64_alphabet(&squeezed) {
                self.decode_b64(squeezed.as_bytes(), place, depth);
            }
        }
        for run in runs(data, |b| b.is_ascii_alphanumeric() || b"+/_-=".contains(&b)) {
            self.decode_b64(run, place, depth);
        }
        for run in runs(data, |b| b.is_ascii_hexdigit()) {
            if run.len() >= MIN_RUN && run.len() % 2 == 0 {
                let bytes: Vec<u8> = run
                    .chunks(2)
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect();
                self.scan(&bytes, &format!("{place} > hex"), depth + 1);
            }
        }
    }

    /// Lowercases ASCII, splits into runs of `[a-z0-9._-]`, and checks every
    /// contiguous span of dot, dash or underscore separated parts.
    fn tokens(&mut self, data: &[u8], place: &str) {
        let lower = data.to_ascii_lowercase();
        let tok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b);
        for run in runs(&lower, tok) {
            let parts: Vec<(usize, usize)> = spans(run);
            for i in 0..parts.len() {
                for j in i..parts.len().min(i + MAX_PARTS) {
                    let word = std::str::from_utf8(&run[parts[i].0..parts[j].1]).unwrap();
                    if self.refused.contains(&digest(word)) {
                        self.hits
                            .push(format!("{place}: a refused name, digest {}", digest(word)));
                    }
                }
            }
        }
    }

    fn json(&mut self, text: &str, place: &str, depth: usize) {
        let trimmed = text.trim_start();
        if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
            return;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            self.json_value(&value, place, depth);
        }
    }

    fn json_value(&mut self, v: &serde_json::Value, place: &str, depth: usize) {
        match v {
            serde_json::Value::String(s) => {
                self.scan(s.as_bytes(), &format!("{place} > json string"), depth + 1)
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| self.json_value(x, place, depth)),
            serde_json::Value::Object(o) => {
                for (k, x) in o {
                    self.scan(k.as_bytes(), &format!("{place} > json key"), depth + 1);
                    self.json_value(x, &format!("{place} > {k}"), depth);
                }
            }
            _ => {}
        }
    }

    fn percent(&mut self, text: &str, place: &str, depth: usize) {
        if !text.contains('%') {
            return;
        }
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(b) = u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                ) {
                    out.push(b);
                    i += 3;
                    changed = true;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        if changed {
            self.scan(&out, &format!("{place} > percent"), depth + 1);
        }
    }

    fn decode_b64(&mut self, run: &[u8], place: &str, depth: usize) {
        if run.len() < MIN_RUN {
            return;
        }
        for shift in 0..4 {
            let body = &run[shift.min(run.len())..];
            let body: Vec<u8> = body.iter().copied().filter(|b| *b != b'=').collect();
            let keep = body.len() - usize::from(body.len() % 4 == 1);
            let body = &body[..keep];
            // Padding is stripped above, so the unpadded engines read the padded
            // and unpadded forms of both alphabets.
            for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                if let Ok(bytes) = engine.decode(body) {
                    if bytes.len() >= 8 {
                        let label = format!("{place} > base64 at shift {shift}");
                        if looks_textual(&bytes) {
                            self.scan(&bytes, &label, depth + 1);
                        } else {
                            self.tokens(&bytes, &label);
                        }
                    }
                }
            }
        }
    }
}

fn is_b64_alphabet(s: &str) -> bool {
    s.len() >= MIN_RUN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/_-=".contains(&b))
}

fn looks_textual(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|b| (32..127).contains(*b) || b"\t\n\r".contains(b) || **b >= 0xc2)
        .count();
    printable * 100 >= bytes.len() * 85
}

fn runs(data: &[u8], keep: impl Fn(u8) -> bool) -> Vec<&[u8]> {
    data.split(|b| !keep(*b))
        .filter(|r| !r.is_empty())
        .collect()
}

/// The start and end of each part of a token, split on `.`, `-` and `_`.
fn spans(run: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, b) in run.iter().enumerate() {
        if b"._-".contains(b) {
            if i > start {
                out.push((start, i));
            }
            start = i + 1;
        }
    }
    if run.len() > start {
        out.push((start, run.len()));
    }
    out
}

fn refused_from_env() -> BTreeSet<String> {
    let raw = std::env::var("DSSE_FORBIDDEN_SHA256").unwrap_or_default();
    let set: BTreeSet<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    for d in &set {
        assert!(
            d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()),
            "DSSE_FORBIDDEN_SHA256 holds an entry that is not a SHA-256 hex digest"
        );
    }
    set
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.is_dir() {
                if name != "target" && name != ".git" {
                    stack.push(path);
                }
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn scan_root(root: &Path, refused: &BTreeSet<String>) -> (usize, Vec<String>) {
    let mut s = Scanner {
        refused,
        hits: Vec::new(),
    };
    let all = files(root);
    for path in &all {
        let rel = path.strip_prefix(root).unwrap().display().to_string();
        s.scan(&std::fs::read(path).unwrap(), &rel, 0);
    }
    (all.len(), s.hits)
}

#[test]
fn no_shipped_file_names_a_refused_name_even_when_decoded() {
    let refused = refused_from_env();
    if refused.is_empty() {
        assert!(
            std::env::var("DSSE_REQUIRE_FORBIDDEN_LIST").as_deref() != Ok("1"),
            "DSSE_REQUIRE_FORBIDDEN_LIST=1 but DSSE_FORBIDDEN_SHA256 is empty: the scan would pass without checking"
        );
        eprintln!("DSSE_FORBIDDEN_SHA256 is not set: the scan ran against an empty list");
    }
    let root = std::env::var_os("DSSE_SCAN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let (count, hits) = scan_root(&root, &refused);
    assert!(
        count >= 10,
        "the scan read {count} files under {}: too few to be the crate",
        root.display()
    );
    assert!(hits.is_empty(), "refused names found:\n{}", hits.join("\n"));
}

/// The canary is assembled at run time so this file does not contain it whole.
fn canary() -> String {
    ["leak", "canary", "7f3e"].join("-")
}

#[test]
fn the_scanner_finds_a_planted_name_through_every_encoding_it_claims() {
    let c = canary();
    let refused: BTreeSet<String> = [digest(&c)].into_iter().collect();
    let path = format!("src/{c}/x.rs");
    let inner = serde_json::json!({ "file": path }).to_string();
    let b64 = STANDARD.encode(&inner);
    let envelope = serde_json::json!({
        "payload": STANDARD.encode(serde_json::json!({ "x": b64 }).to_string()),
        "payloadType": "application/json",
        "signatures": [],
    })
    .to_string();
    let hex: String = inner.bytes().map(|b| format!("{b:02x}")).collect();
    let percent: String = path.bytes().map(|b| format!("%{b:02X}")).collect();
    let wrapped = STANDARD.encode(format!("{}{}", "A".repeat(80), inner));
    let wrapped: Vec<String> = wrapped
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();

    let planted: Vec<(&str, Vec<u8>)> = vec![
        ("plain", format!("see {path}").into_bytes()),
        (
            "json base64",
            serde_json::json!({ "canonical_b64": b64 })
                .to_string()
                .into_bytes(),
        ),
        ("dsse envelope, base64 twice", envelope.into_bytes()),
        (
            "url-safe unpadded",
            URL_SAFE_NO_PAD
                .encode([&[0xfb, 0xff][..], inner.as_bytes()].concat())
                .into_bytes(),
        ),
        ("hex", hex.into_bytes()),
        ("percent", percent.into_bytes()),
        (
            "json unicode escapes",
            format!("{{\"a\": \"src/\\u006c{}/x\"}}", &c[1..]).into_bytes(),
        ),
        (
            "wrapped base64",
            serde_json::json!({ "pem": wrapped.join("\n") })
                .to_string()
                .into_bytes(),
        ),
        (
            "base64 glued inside prose",
            format!("the blob is xyz{b64} and more").into_bytes(),
        ),
        ("padded base64", STANDARD.encode(&inner).into_bytes()),
        ("url-safe padded", URL_SAFE.encode(&inner).into_bytes()),
    ];
    for (label, data) in &planted {
        let mut s = Scanner {
            refused: &refused,
            hits: Vec::new(),
        };
        s.scan(data, label, 0);
        assert!(!s.hits.is_empty(), "the scanner missed the canary: {label}");
    }

    let mut clean = Scanner {
        refused: &refused,
        hits: Vec::new(),
    };
    clean.scan(
        serde_json::json!({ "payload": STANDARD.encode("{\"file\":\"src/lib.rs\"}") })
            .to_string()
            .as_bytes(),
        "clean",
        0,
    );
    assert!(clean.hits.is_empty(), "a clean blob must produce no hit");
}

#[test]
fn a_planted_canary_in_a_copied_tree_fails_the_tree_scan() {
    let c = canary();
    let refused: BTreeSet<String> = [digest(&c)].into_iter().collect();
    let dir = std::env::temp_dir().join(format!("dsse-scan-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("vectors")).unwrap();
    for i in 0..10 {
        std::fs::write(dir.join(format!("f{i}.txt")), "nothing here").unwrap();
    }
    let body = STANDARD.encode(format!("{{\"file\":\"cmd/{c}/main.go\"}}"));
    std::fs::write(
        dir.join("vectors/v.json"),
        serde_json::json!({ "fixtures": [{ "canonical_b64": body }] }).to_string(),
    )
    .unwrap();
    let (count, hits) = scan_root(&dir, &refused);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(count, 11);
    let files: BTreeSet<&str> = hits.iter().map(|h| h.split(' ').next().unwrap()).collect();
    assert_eq!(
        files.into_iter().collect::<Vec<_>>(),
        ["vectors/v.json"],
        "exactly the one planted file: {hits:?}"
    );
}
