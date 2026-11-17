//! The embedded corpus holds together: every reader returns cases, the cases
//! are well formed, and the accept set tells a canonicalizer from an encoder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

fn nesting(text: &[u8]) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    for b in text {
        match b {
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

#[test]
fn canonical_cases_are_well_formed() {
    let vectors = jcsvectors::canonical().unwrap();
    assert!(!vectors.is_empty(), "no canonical vectors");
    for v in &vectors {
        let canonical = v
            .canonical
            .as_ref()
            .expect("an accept case carries its bytes");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&v.input).is_ok(),
            "{}: input is not JSON",
            v.id
        );
        assert!(
            serde_json::from_slice::<serde_json::Value>(canonical).is_ok(),
            "{}: canonical bytes are not JSON",
            v.id
        );
    }
}

#[test]
fn reject_cases_carry_no_canonical_bytes() {
    let vectors = jcsvectors::reject().unwrap();
    assert!(!vectors.is_empty(), "no reject vectors");
    for v in &vectors {
        // The empty input is itself a refusal case, so the input may be empty.
        assert!(v.canonical.is_none(), "{}/{}", v.corpus, v.id);
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn byte_cases() -> serde_json::Value {
    let raw = jcsvectors::files()
        .find(|(p, _)| *p == "jcs-byte-vectors/cases.json")
        .unwrap()
        .1;
    serde_json::from_slice(raw).unwrap()
}

/// Every refusal case of `jcs-byte-vectors` reaches `reject()` with its exact
/// input bytes. Version 0.1.0 returned none of the 23, so a canonicalizer that
/// accepted an escaped duplicate name, invalid UTF-8 or trailing content passed
/// every test the crate offered.
#[test]
fn reject_carries_every_refusal_case() {
    let reject = jcsvectors::reject().unwrap();
    let cases = byte_cases();
    let refusals = cases["refusalCases"].as_array().unwrap();
    assert!(!refusals.is_empty());
    for case in refusals {
        let id = case["id"].as_str().unwrap();
        let want = match (case["input"].as_str(), case["inputHex"].as_str()) {
            (Some(text), None) => text.as_bytes().to_vec(),
            (None, Some(h)) => hex(h),
            _ => panic!("{id}: needs exactly one of input and inputHex"),
        };
        let got = reject
            .iter()
            .find(|v| v.corpus == jcsvectors::BYTE_CORPUS && v.id == id)
            .unwrap_or_else(|| panic!("{id}: refusal case missing from reject()"));
        assert_eq!(got.input, want, "{id}: input bytes differ");
    }
}

/// The inputs a lenient canonicalizer accepted while refusing every case of
/// version 0.1.0's `reject()`: it compared member names before unescaping,
/// decoded invalid UTF-8 with replacement characters, stopped after the first
/// value and printed overflowing numbers.
#[test]
fn lenient_canonicalizer_counter_examples_are_reject_cases() {
    let ids: BTreeSet<_> = jcsvectors::reject()
        .unwrap()
        .into_iter()
        .map(|v| v.id)
        .collect();
    for id in [
        "refuse-duplicate-member-escaped-spelling",
        "refuse-unicode-invalid-utf8-byte",
        "refuse-unicode-surrogate-encoded-in-utf8",
        "refuse-trailing-second-value",
        "refuse-trailing-garbage",
        "refuse-non-finite-overflow-positive",
        "refuse-non-finite-overflow-negative",
        "refuse-non-finite-overflow-large-mantissa",
    ] {
        assert!(ids.contains(id), "{id} is not in reject()");
    }
}

/// Every top-level family of `cases.json` is one this crate reads or one it
/// names here with the reason it does not. A family added to the corpus must
/// fail this test until the crate exposes it, rather than be dropped silently.
#[test]
fn every_byte_corpus_family_is_read() {
    let read = [
        "format",
        "canonicalCases",
        "rejectCases",
        "driftCases",
        "depthCases",
        "refusalCases",
    ];
    let cases = byte_cases();
    for key in cases.as_object().unwrap().keys() {
        assert!(
            read.contains(&key.as_str()),
            "cases.json family {key} is not read by this crate"
        );
    }
}

#[test]
fn identifiers_are_unique_and_a2a_clauses_are_rfc8785() {
    let mut seen = BTreeSet::new();
    let mut all = jcsvectors::canonical().unwrap();
    all.extend(jcsvectors::reject().unwrap());
    for v in &all {
        assert!(
            seen.insert(format!("{}/{}", v.corpus, v.id)),
            "duplicate vector {}/{}",
            v.corpus,
            v.id
        );
        if v.corpus == jcsvectors::A2A_CORPUS {
            assert!(
                v.clause.starts_with("RFC8785-"),
                "{}: clause {:?}",
                v.id,
                v.clause
            );
        }
    }
}

/// serde_json is not an RFC 8785 canonicalizer. If its compact output matched
/// every accept case, the vectors could not tell a canonicalizer from an
/// encoder.
#[test]
fn vectors_discriminate() {
    let misses = jcsvectors::canonical()
        .unwrap()
        .iter()
        .filter(|v| {
            let value: serde_json::Value = serde_json::from_slice(&v.input).unwrap();
            serde_json::to_vec(&value).ok() != v.canonical
        })
        .count();
    assert!(misses > 0, "serde_json reproduced every canonical vector");
}

#[test]
fn drifts_differ_from_canonical_and_cover_three_families() {
    let drifts = jcsvectors::drifts().unwrap();
    assert!(drifts.iter().any(|d| d.source == jcsvectors::SOURCE_GO));
    let families: BTreeSet<_> = drifts.iter().map(|d| d.family.as_str()).collect();
    for family in ["html-escape", "non-ascii-escape", "number-format"] {
        assert!(
            families.contains(family),
            "no drift vector in the {family} family"
        );
    }
    for d in &drifts {
        assert_ne!(
            d.presented, d.canonical,
            "{}: the presented bytes are canonical",
            d.id
        );
    }
}

#[test]
fn depth_cases_straddle_the_cap() {
    let reject = jcsvectors::too_deep().unwrap();
    let admitted = jcsvectors::depth_admitted().unwrap();
    assert_eq!((reject.len(), admitted.len()), (8, 2));
    for v in &reject {
        assert!(nesting(&v.input) > jcsvectors::DEPTH_CAP, "{}", v.id);
    }
    for v in &admitted {
        assert_eq!(nesting(&v.input), jcsvectors::DEPTH_CAP, "{}", v.id);
        assert_eq!(Some(&v.input), v.canonical.as_ref(), "{}", v.id);
    }
}

/// Every file the corpora list is embedded, and nothing else is.
#[test]
fn embedded_files_are_exactly_the_listed_set() {
    let names: BTreeSet<_> = jcsvectors::files().map(|(p, _)| p).collect();
    assert!(names.contains("vectors-a2a-jcs-v01/MANIFEST.json"));
    assert!(names.contains("jcs-byte-vectors/cases.json"));
    let manifest: serde_json::Value = serde_json::from_slice(
        jcsvectors::files()
            .find(|(p, _)| *p == "vectors-a2a-jcs-v01/MANIFEST.json")
            .unwrap()
            .1,
    )
    .unwrap();
    let listed = manifest["vectors"].as_array().unwrap().len();
    assert_eq!(names.len(), listed + 2);
}
