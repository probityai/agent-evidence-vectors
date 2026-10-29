//! What this crate refuses that `serde_json_canonicalizer` accepts, run against
//! the real crate rather than described.
//!
//! This file exists to stop the crate's own reason for existing from becoming a
//! claim nobody re-checks. Every row was measured on 2026-09-19 against
//! `serde_json_canonicalizer` 0.3.2 (7,852,211 total and 5,259,528 recent
//! downloads, crates.io API, same day) resolving `serde_json` 1.0.151 and
//! `ryu-js` 1.0.3. If the delegate ever starts refusing one of these, this file
//! goes red and the crate's scope has to shrink. That is the point of committing
//! it.
//!
//! # The delegate has four public entry points and no two of them agree
//!
//! `to_vec`, `to_string` and `to_writer` take anything `Serialize`. `pipe` takes
//! a `&str` and routes it through `serde_json::from_str` into a
//! `serde_json::Value`. That difference decides everything below:
//!
//! - `pipe` inherits `serde_json`'s deserializer, so it does refuse a lone
//!   surrogate escape, a raw control character and nesting -- and it also
//!   inherits `serde_json::Value`, so a repeated member has collapsed to
//!   last-wins before the canonicalizer runs.
//! - the other three have no parser and therefore no depth bound at all.
//!
//! So there is no entry point that both refuses a duplicate member and bounds
//! nesting. Not a quality gap: the architecture has no layer to put either check
//! in, which is why this crate is a layer above rather than a rival beside.
//!
//! # The one thing measured here and NOT asserted
//!
//! `to_vec` on 10,000 nested arrays aborts the process:
//! `thread 'main' has overflowed its stack / fatal runtime error: stack
//! overflow`, exit status 134, core dumped. A stack overflow is an abort and not
//! a catchable failure, so asserting it would take this test binary down with it.
//! The assertion below stops at 1,000 -- accepted, uncapped -- and the abort is
//! recorded here with its exit code instead of being turned into a test that
//! cannot exist.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, Error, Options};

/// `n` nested arrays around a `null`.
fn nest(n: usize) -> String {
    format!("{}null{}", "[".repeat(n), "]".repeat(n))
}

/// A map that emits one member name TWICE, so the delegate's own object assembly
/// is exercised rather than `serde_json::Value`'s deduplication.
struct RepeatedMember;

impl serde::Serialize for RepeatedMember {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("a", &1_u32)?;
        m.serialize_entry("a", &2_u32)?;
        m.end()
    }
}

/// THE refusal, now split in two by the delegate's own 0.4.1 fix.
///
/// `pipe` and the `Value` path still keep the LAST member, because
/// `serde_json::Map` has already collapsed the duplicate before the delegate
/// ever sees the document: there is one key left by the time its formatter
/// runs, so nothing in 0.4.1 changes this path. Feeding the delegate's
/// serializer directly, bypassing `serde_json::Value`, used to keep the FIRST
/// member, because its object was a `BTreeSet` and `BTreeSet::insert` does
/// not replace an equal element. 0.4.1 makes `end_object_value` check that
/// insert's return value and refuse instead
/// (<https://github.com/evik42/serde-json-canonicalizer> `v0.3.2...v0.4.1`,
/// `src/jcs.rs`). So the split view this test pinned -- two canonical forms,
/// a signature over either verifying -- survives for `pipe` and `Value`
/// callers and closes for a caller that drives the serializer directly. That
/// is a real narrowing of this crate's differential claim for this one
/// entry point, which is exactly what the module doc above says to expect
/// and record rather than paper over; see CHANGELOG.md 0.1.4.
#[test]
fn a_repeated_member_is_accepted_two_ways_and_now_refused_a_third_by_the_delegate_too() {
    const DOC: &str = r#"{"a":1,"a":2}"#;

    let via_pipe = serde_json_canonicalizer::pipe(DOC).expect("the delegate accepts it");
    assert_eq!(via_pipe, r#"{"a":2}"#, "pipe keeps the last member");

    let value: serde_json::Value = serde_json::from_str(DOC).expect("serde_json accepts it");
    let via_value = serde_json_canonicalizer::to_string(&value).expect("the delegate accepts it");
    assert_eq!(
        via_value, r#"{"a":2}"#,
        "the Value path keeps the last member"
    );

    let via_serializer_err = serde_json_canonicalizer::to_string(&RepeatedMember)
        .expect_err("0.4.1 refuses a duplicate key reaching its own object assembly");
    assert!(
        via_serializer_err
            .to_string()
            .contains("duplicate object key"),
        "want a duplicate-key refusal, got {via_serializer_err}"
    );

    match admit(DOC.as_bytes()) {
        Err(Error::DuplicateMember { name, offset }) => {
            assert_eq!(name, "a");
            assert_eq!(offset, 7, "the refusal names where the repeat is");
        }
        other => panic!("want a named duplicate refusal, got {other:?}"),
    }
}

/// Nesting. The delegate's bound exists on exactly one of its four entry points,
/// it is one level stricter than the normative 128, and it is untyped.
#[test]
fn nesting_is_bounded_on_one_delegate_entry_point_and_not_the_others() {
    // `pipe` refuses at 128 -- not 129 -- because the bound it inherits is
    // `serde_json`'s deserializer recursion limit, which counts differently from
    // a cap that admits exactly 128 levels.
    assert!(
        serde_json_canonicalizer::pipe(&nest(127)).is_ok(),
        "pipe admits 127"
    );
    let at_128 = serde_json_canonicalizer::pipe(&nest(128))
        .expect_err("pipe refuses 128, one level below the normative cap");
    let rendered = at_128.to_string();
    assert!(
        rendered.contains("recursion limit exceeded"),
        "the refusal comes from serde_json's deserializer, untyped: {rendered}"
    );
    // This crate admits exactly DEFAULT_MAX_DEPTH and refuses one more, so a
    // document at the normative depth is admissible here and is not there.
    assert!(
        admit(nest(128).as_bytes()).is_ok(),
        "128 is admissible here"
    );
    assert!(matches!(
        admit(nest(129).as_bytes()),
        Err(Error::TooDeep { limit: 128, .. })
    ));

    // The other three entry points have no parser and no bound. 1,000 levels is
    // the largest depth that can be asserted without risking the abort recorded
    // in this file's header.
    let mut deep = serde_json::Value::Null;
    for _ in 0..1_000 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    assert!(
        serde_json_canonicalizer::to_vec(&deep).is_ok(),
        "to_vec has no depth bound at 1,000 levels"
    );
    let opts = Options::rfc8785().max_bytes(None);
    assert!(matches!(
        jcs_admit::admit_with(nest(1_000).as_bytes(), &opts),
        Err(Error::TooDeep { .. })
    ));
}

/// An integer past 2^53 is not refused by the delegate; it is silently replaced
/// by a different integer.
///
/// This is the quietest row in the file. There is no error, the output is
/// well-formed canonical JSON, and it is canonical JSON for a number the wire
/// never carried. A verifier that canonicalizes and then hashes has hashed the
/// wrong document and has nothing to tell it so.
#[test]
fn an_unsafe_integer_is_silently_rewritten_by_the_delegate_and_refused_here() {
    for (token, rewritten_to) in [
        ("9007199254740993", "9007199254740992"),
        ("99999999999999999999", "100000000000000000000"),
    ] {
        let got = serde_json_canonicalizer::pipe(token).expect("the delegate accepts it");
        assert_eq!(
            got, rewritten_to,
            "{token} comes back as a different number"
        );
        assert_ne!(got, token);
        assert!(
            matches!(
                admit_ijson(token.as_bytes()),
                Err(Error::UnsafeInteger { .. })
            ),
            "{token}: the profile owes UnsafeInteger"
        );
        // And the other half of the row, which went unpinned until an
        // adversarial pass ran it: the RFC 8785 DEFAULT admits the token and
        // rewrites it exactly as the delegate does. The table used to read
        // `Error::UnsafeInteger` with no profile named, so a reader comparing the
        // two crates concluded `admit` refused this, and the test cited as
        // keeping the row true tested a different function than the row
        // described. Pinning both halves is what stops the claim drifting from
        // the code again.
        assert_eq!(
            admit(token.as_bytes()).expect("the default profile admits it"),
            rewritten_to.as_bytes(),
            "{token}: the default agrees with the delegate, and the table must say so"
        );
    }
    // 2^53 - 1 is exact, so it must survive both. A refusal that fired here would
    // be over-tight rather than correct.
    assert_eq!(
        serde_json_canonicalizer::pipe("9007199254740991").expect("exact"),
        "9007199254740991"
    );
    assert!(admit_ijson(b"9007199254740991").is_ok());
}

/// A fractional number and a Unicode noncharacter: accepted by the delegate,
/// refused here only under the profile that declares them out of scope.
#[test]
fn the_profile_refusals_have_no_counterpart_in_the_delegate() {
    for token in ["1.5", "-0.1"] {
        assert!(
            serde_json_canonicalizer::pipe(token).is_ok(),
            "{token}: the delegate has no integers-only profile"
        );
        let opts = Options::ijson().integers_only(true);
        assert!(matches!(
            jcs_admit::admit_with(token.as_bytes(), &opts),
            Err(Error::NonIntegerNumber { .. })
        ));
    }
    // Noncharacters are built from their code points, never typed, so this file
    // stays ASCII and cannot be corrupted by an editor normalising it.
    for cp in [0xFFFF_u32, 0xFDD0] {
        let doc = format!("{{\"k\":\"\\u{cp:04x}\"}}");
        assert!(
            serde_json_canonicalizer::pipe(&doc).is_ok(),
            "U+{cp:04X}: the delegate accepts it"
        );
        assert!(admit(doc.as_bytes()).is_ok(), "so does RFC 8785 as written");
        assert!(
            matches!(
                admit_ijson(doc.as_bytes()),
                Err(Error::StringNotScalar { .. })
            ),
            "U+{cp:04X}: RFC 7493 section 2.1 refuses it"
        );
    }
}

/// No size cap anywhere in the delegate.
#[test]
fn input_size_is_unbounded_in_the_delegate_and_capped_here() {
    // Comfortably over this crate's 20 MiB default without being slow to build.
    let big = format!("[{}0]", "0,".repeat(11_000_000));
    assert!(
        big.len() > jcs_admit::DEFAULT_MAX_BYTES,
        "the input has to exceed the cap or this test proves nothing"
    );
    assert!(
        serde_json_canonicalizer::pipe(&big).is_ok(),
        "{} bytes accepted with no cap",
        big.len()
    );
    assert!(matches!(
        admit(big.as_bytes()),
        Err(Error::TooLarge {
            limit: 20_971_520,
            ..
        })
    ));
}

/// The refusals the delegate DOES make, recorded so this crate never claims
/// them as its own.
///
/// On the `pipe` path `serde_json` catches a lone surrogate escape, a raw control
/// character and a number out of range. What it does not do is say which: all
/// three arrive as one untyped `serde_json::Error` carrying a line and a column,
/// so a verifier cannot act differently on a split-view document than on a typo.
/// That is the difference this test pins -- not whether the input is refused, but
/// whether the refusal can be branched on.
#[test]
fn the_delegate_refuses_some_of_these_and_names_none_of_them() {
    let cases: [(&str, &str); 3] = [
        (r#"{"k":"\ud800"}"#, "unexpected end of hex escape"),
        ("{\"k\":\"\u{1}\"}", "control character"),
        ("1e400", "number out of range"),
    ];
    for (doc, fragment) in cases {
        let err = serde_json_canonicalizer::pipe(doc)
            .expect_err("the delegate refuses this one, and that is worth recording");
        // One type for every fault: `serde_json::Error` has a `classify` that
        // reports Syntax or Data, never which rule.
        assert!(
            err.to_string().contains(fragment),
            "want {fragment:?}, got {err}"
        );
        // Ours arrives as a variant with a byte offset, which is what lets a
        // caller log the fault and a verifier route on it.
        let ours = admit(doc.as_bytes()).expect_err("refused here too");
        assert!(
            matches!(
                ours,
                Error::StringNotScalar { .. } | Error::NonFiniteNumber { .. }
            ),
            "want a typed refusal, got {ours:?}"
        );
    }
}

/// A fault the delegate cannot be handed at all, because its only byte-facing
/// entry point takes `&str`.
///
/// A surrogate written directly in UTF-8 (CESU-8, `ED A0 80`) and an overlong
/// NUL (`C0 80`) are not valid UTF-8, so they cannot exist inside a `&str` and
/// `pipe` has no signature that accepts them. The check does not disappear; it
/// moves onto the caller, who now has to validate wire bytes before calling a
/// canonicalizer. This crate takes `&[u8]`, which is the shape bytes arrive in.
#[test]
fn a_surrogate_in_the_bytes_cannot_reach_the_delegate_and_is_refused_here() {
    for raw in [
        &[
            b'{', b'"', b'k', b'"', b':', b'"', 0xED, 0xA0, 0x80, b'"', b'}',
        ][..],
        &[b'{', b'"', b'k', b'"', b':', b'"', 0xC0, 0x80, b'"', b'}'][..],
    ] {
        assert!(
            std::str::from_utf8(raw).is_err(),
            "the premise: these bytes are not a &str, so pipe cannot take them"
        );
        assert!(matches!(admit(raw), Err(Error::StringNotScalar { .. })));
    }
}

/// The composition, stated as a test: what the delegate gets right is this
/// crate's output too.
///
/// `333333333.33333329` is the number in the RFC 8785 reference suite's own
/// `values.json`, and it is there because it is the one a float formatter is most
/// likely to get wrong. The delegate gets it right, through `ryu_js` and
/// `serde_json`'s `float_roundtrip` feature, and so this crate does. Standing on
/// 5.26 million recent downloads of that is the argument for delegating rather
/// than carrying a third copy of ECMAScript `Number::toString`.
#[test]
fn the_reference_number_survives_the_delegation() {
    assert_eq!(
        String::from_utf8(admit(b"333333333.33333329").expect("admitted")).expect("utf-8"),
        "333333333.3333333"
    );
    assert_eq!(
        serde_json_canonicalizer::pipe("333333333.33333329").expect("accepted"),
        "333333333.3333333",
        "if the delegate ever stops agreeing, this crate's numbers moved with it"
    );
}
