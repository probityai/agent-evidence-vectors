//! The version floors this crate declares for its runtime dependencies.
//!
//! A floor is a cost every dependent pays: `cargo` must resolve the dependent's
//! whole graph at or above it. 0.1.0 declared `serde = "1.0.229"` although it
//! builds with far less, and a host on serde 1.0.228 had its lockfile moved to
//! 1.0.229, which also brought in syn 3 beside syn 2.
//!
//! The `floors` job in `.github/workflows/crate-jcs-admit.yml` (repository root) resolves every dependency,
//! direct and transitive, to its declared minimum and runs the whole suite at
//! the MSRV, so it proves each floor below is enough. It cannot notice a floor that was
//! raised for no reason, because a higher floor also passes. This test does:
//! it fails when a runtime floor changes. Change the table only together with
//! the `floors` job showing the old floor no longer builds, and say why in
//! `CHANGELOG.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

/// The runtime floors, and why each is the lowest that works.
const FLOORS: &[(&str, &str)] = &[
    // serde_json 1.0.87 is the lowest the delegate compiles against, and it
    // requires serde 1.0.100.
    ("serde", "1.0.100"),
    // 0.4.1: the release that makes serde_json_canonicalizer itself refuse a
    // duplicate object key (it previously returned Ok and kept the last
    // value). This crate already refuses duplicates earlier, in parse.rs,
    // before any byte reaches the delegate, so the behavior this crate admits
    // or refuses does not change; the floor still moves, because a caller
    // that reaches serde_json_canonicalizer directly now gets the same
    // refusal this crate already gave. See CHANGELOG.md 0.1.4.
    ("serde_json_canonicalizer", "0.4.1"),
];

/// Reads the `[dependencies]` requirements from the manifest, in both the form
/// written in this repository (`name = { version = "..." }` or `name = "..."`)
/// and the form `cargo package` normalizes it to (`[dependencies.name]`
/// followed by `version = "..."`), so the test also holds inside the published
/// crate.
fn runtime_requirements(manifest: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut section = String::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let name = if section == "dependencies" {
            key
        } else if let Some(dep) = section.strip_prefix("dependencies.") {
            if key != "version" {
                continue;
            }
            dep
        } else {
            continue;
        };
        let value = value.trim();
        let version_text = match value.find("version") {
            Some(at) if value.starts_with('{') => &value[at..],
            _ => value,
        };
        if let Some(req) = version_text.split('"').nth(1) {
            found.insert(name.to_owned(), req.to_owned());
        }
    }
    found
}

#[test]
fn runtime_floors_are_the_proven_minimums() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let manifest = std::fs::read_to_string(path).expect("read Cargo.toml");
    let declared = runtime_requirements(&manifest);
    let expected: BTreeMap<String, String> = FLOORS
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    assert_eq!(
        declared, expected,
        "a runtime dependency floor changed; every dependent's lockfile pays for a \
         raised floor, so change FLOORS only with the ci.yml `floors` job showing \
         the old floor fails"
    );
}

#[test]
fn both_manifest_forms_are_read() {
    let written = r#"
[dependencies]
serde = { version = "1.0.100", default-features = false, features = ["std"] }
serde_json_canonicalizer = "0.3.2"

[dev-dependencies]
serde_json = "1.0.87"
"#;
    let normalized = r#"
[dependencies.serde]
version = "1.0.100"
features = ["std"]
default-features = false

[dependencies.serde_json_canonicalizer]
version = "0.3.2"

[dev-dependencies.serde_json]
version = "1.0.87"
"#;
    let a = runtime_requirements(written);
    let b = runtime_requirements(normalized);
    assert_eq!(a, b);
    assert_eq!(a.get("serde").map(String::as_str), Some("1.0.100"));
    assert!(
        !a.contains_key("serde_json"),
        "dev-dependencies are not runtime floors"
    );
}
