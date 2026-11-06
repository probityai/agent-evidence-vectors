//! The published drift and depth families in `corpora/jcs-byte-vectors/cases.json`.
//!
//! `driftCases` hold bytes that a producer printed and presented as canonical,
//! which RFC 8785 does not print that way: `<`, `>` and `&` escaped as `<`
//! and its siblings (what Go's `encoding/json` does), non-ASCII text left as
//! `\u` escapes, and number spellings the ECMAScript algorithm never produces.
//! The gate must say these bytes are not canonical, and admitting them must
//! give the pinned canonical bytes, which come from the corpus and not from
//! this crate.
//!
//! `depthCases` nest arrays and objects 129, 256, 512 and 1024 levels, past the
//! cap of 128, and exactly 128 levels. The first group must be refused with the
//! depth error before anything recurses; the second must be admitted.
//!
//! The test reads the corpus from the repository checkout, two levels above this
//! crate. The packaged crate leaves this file out (`exclude` in Cargo.toml),
//! because a tarball has no corpus to read.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use jcs_admit::{admit, is_canonical, Error, DEFAULT_MAX_DEPTH};
use serde_json::Value;

fn corpus() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpora/jcs-byte-vectors/cases.json");
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&raw).unwrap()
}

fn members(corpus: &Value, key: &str) -> Vec<Value> {
    corpus[key].as_array().unwrap_or_else(|| panic!("no {key}")).clone()
}

fn text<'a>(member: &'a Value, key: &str) -> &'a str {
    member[key].as_str().unwrap_or_else(|| panic!("{member}: no {key}"))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_drift_case_is_refused_as_canonical_and_admits_to_the_pinned_bytes() {
    let corpus = corpus();
    let cases = members(&corpus, "driftCases");
    assert_eq!(cases.len(), 18, "the family changed size; update this count with the corpus");
    for case in &cases {
        let id = text(case, "id");
        let presented = text(case, "presented").as_bytes();
        let pinned = unhex(text(case, "canonicalHex"));
        assert_ne!(presented, pinned.as_slice(), "{id}: presented bytes are the canonical bytes");
        assert!(!is_canonical(presented), "{id}: the gate called drifted bytes canonical");
        assert_eq!(admit(presented).unwrap(), pinned, "{id}: admitted bytes differ from the pin");
        assert_eq!(admit(text(case, "input").as_bytes()).unwrap(), pinned, "{id}: input differs from the pin");
        assert!(is_canonical(&pinned), "{id}: the pinned bytes are not canonical to the gate");
    }
}

#[test]
fn the_drift_family_covers_html_escapes_and_every_named_family() {
    let corpus = corpus();
    let cases = members(&corpus, "driftCases");
    for family in ["html-escape", "non-ascii-escape", "number-format"] {
        assert!(
            cases.iter().any(|c| text(c, "family") == family),
            "no drift case in the {family} family"
        );
    }
    for needle in ["\\u003c", "\\u003e", "\\u0026"] {
        assert!(
            cases.iter().any(|c| text(c, "presented").contains(needle)),
            "no drift case presents {needle}"
        );
    }
}

#[test]
fn every_depth_case_past_the_cap_is_refused_and_the_cap_itself_is_admitted() {
    let corpus = corpus();
    let cases = members(&corpus, "depthCases");
    let (mut refused, mut admitted) = (0, 0);
    for case in &cases {
        let id = text(case, "id");
        let input = text(case, "input").as_bytes();
        let depth = case["depth"].as_u64().unwrap() as usize;
        match text(case, "expect") {
            "reject" => {
                assert!(depth > DEFAULT_MAX_DEPTH, "{id}: a reject case at or under the cap");
                assert!(
                    matches!(admit(input), Err(Error::TooDeep { limit: 128, .. })),
                    "{id}: nesting {depth} deep was not refused with the depth error"
                );
                refused += 1;
            }
            "accept" => {
                assert_eq!(depth, DEFAULT_MAX_DEPTH, "{id}: an accept case off the cap");
                assert_eq!(admit(input).unwrap(), unhex(text(case, "canonicalHex")), "{id}");
                admitted += 1;
            }
            other => panic!("{id}: unknown expectation {other}"),
        }
    }
    assert_eq!((refused, admitted), (8, 2), "the depth family changed size");
    for depth in [129, 256, 512, 1024] {
        for shape in ["array", "object"] {
            let id = format!("depth-{shape}-{depth}");
            assert!(cases.iter().any(|c| text(c, "id") == id), "{id} is missing");
        }
    }
}
