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
        assert!(
            v.canonical.is_none() && !v.input.is_empty(),
            "{}/{}",
            v.corpus,
            v.id
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
