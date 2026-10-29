//! 317 adversarial documents aimed at strings, member names and members, each
//! pinned against an independent implementation.
//!
//! These are not examples. They are the cases where two conformant
//! canonicalizers most plausibly part company, enumerated rather than sampled:
//! every C0 control as an escape and again raw, DEL and the C1 range, each
//! escape whose mandated output differs from the escape that was written,
//! surrogate halves alone and mispaired and in either hex case, surrogates and
//! overlong forms and truncated sequences encoded directly in the bytes, the
//! Unicode noncharacters, member names differing only by escaping, only by
//! Unicode normalisation form, or only by hex case, the empty name, a name
//! carrying NUL, repeats at the top level and nested and inside an array
//! element, and member ordering across the boundary where UTF-16 code-unit
//! order stops agreeing with UTF-8 byte order.
//!
//! The expected column comes from the Go implementation named in
//! `tests/vectors/PROVENANCE.md`, not from this crate, so a shared mistake
//! cannot pass by agreeing with itself. A third implementation -- the RFC
//! author's own reference lineage, via `trailofbits/rfc8785.py` -- was run over
//! the same corpus at the value level and agreed byte for byte on all 178 cases
//! it can structurally express.
//!
//! Configuration: the Go rail applies the I-JSON string profile and the
//! integers-only tightening unconditionally, so the comparable configuration
//! here is `Options::ijson().integers_only(true)`. Under it, all 317 cases match
//! in accept-versus-refuse, and every accepted case matches byte for byte.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit_with, is_canonical_with, Options};

const CORPUS: &str = include_str!("vectors/attack/strings-keys-members.tsv");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex run: {s}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

struct Case {
    name: String,
    input: Vec<u8>,
    expect_accept: Option<Vec<u8>>,
}

fn corpus() -> Vec<Case> {
    let mut out = Vec::new();
    for line in CORPUS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let name = f.next().expect("name").to_owned();
        let input = unhex(f.next().expect("input"));
        let expected = f.next().expect("expected");
        let expect_accept = expected
            .strip_prefix("ACCEPT ")
            .map(|h| unhex(h.trim_end()));
        assert!(
            expect_accept.is_some() || expected.starts_with("REFUSE"),
            "{name}: unreadable expectation {expected:?}"
        );
        out.push(Case {
            name,
            input,
            expect_accept,
        });
    }
    // A corpus that quietly shrinks must fail loudly rather than pass on
    // whatever is left: a differential that ran over nothing reads exactly like
    // one that found nothing wrong.
    assert_eq!(out.len(), 317, "the pinned corpus has changed size");
    out
}

#[test]
fn every_case_matches_the_independent_implementation() {
    let opts = Options::ijson().integers_only(true);
    let mut diverged = Vec::new();
    let (mut accepted, mut refused) = (0, 0);
    for case in corpus() {
        let got = admit_with(&case.input, &opts);
        match (&case.expect_accept, &got) {
            (Some(want), Ok(have)) if want == have => {
                accepted += 1;
                // Canonical output must itself be canonical, or the bytes two
                // parties compare depend on how many times they were written.
                assert!(
                    is_canonical_with(have, &opts),
                    "{}: output is not its own canonical form",
                    case.name
                );
            }
            (Some(want), Ok(have)) => diverged.push(format!(
                "{}: want {:?}, got {:?}",
                case.name,
                String::from_utf8_lossy(want),
                String::from_utf8_lossy(have)
            )),
            (Some(want), Err(e)) => diverged.push(format!(
                "{}: want {:?}, refused with {e}",
                case.name,
                String::from_utf8_lossy(want)
            )),
            (None, Err(_)) => refused += 1,
            (None, Ok(have)) => diverged.push(format!(
                "{}: must be refused, produced {:?}",
                case.name,
                String::from_utf8_lossy(have)
            )),
        }
    }
    assert!(
        diverged.is_empty(),
        "{} of 317 cases diverge:\n  {}",
        diverged.len(),
        diverged.join("\n  ")
    );
    assert_eq!(
        (accepted, refused),
        (160, 157),
        "the accept/refuse split is itself pinned, so a change that turns a \
         refusal into an acceptance cannot pass by matching the other column"
    );
}

#[test]
fn the_corpus_covers_the_classes_it_claims_to() {
    // The completeness assertion. A corpus is only evidence of what it contains,
    // so the counts per class are pinned too: losing a class to a bad edit would
    // otherwise leave a shrunken corpus passing.
    let cases = corpus();
    let count = |prefix: &str| cases.iter().filter(|c| c.name.starts_with(prefix)).count();
    assert_eq!(
        count("A."),
        96,
        "every C0 control as an escape, value and key"
    );
    assert_eq!(count("B."), 64, "every C0 control raw, value and key");
    assert_eq!(count("C."), 6, "DEL and the C1 range");
    assert_eq!(count("D."), 19, "escapes whose mandated output differs");
    assert_eq!(count("E."), 8, "hex case and malformed hex");
    assert_eq!(count("F."), 20, "surrogate escapes, alone and mispaired");
    assert_eq!(count("G."), 20, "ill-formed sequences in the raw bytes");
    assert_eq!(count("H."), 21, "the Unicode noncharacters");
    assert_eq!(
        count("I."),
        9,
        "empty, NUL-bearing and escape-bearing names"
    );
    assert_eq!(count("J."), 17, "repeated members");
    assert_eq!(count("K."), 5, "names differing only by normalisation form");
    assert_eq!(count("L."), 11, "member ordering by UTF-16 code unit");
    assert_eq!(count("M."), 21, "structure, round-trip and miscellany");
}
