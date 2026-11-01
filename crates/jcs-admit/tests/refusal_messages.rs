//! ATTACK: the attacker must not choose the size of the refusal message.
//!
//! Three variants carry a fragment of the input verbatim -- the repeated member
//! name, and the offending number token -- and both are unbounded in the input,
//! so `Display` hands a caller's logger a string whose length the attacker set.
//! One 2 MiB document with a 1 MiB member name repeated produced a refusal
//! message of 1,048,618 characters, measured. A verifier that logs why it
//! refused a document is the normal case, so the amplification is on the path
//! that matters: refuse a document, write a megabyte; do it in a loop, and the
//! log is the outage.
//!
//! The name and the token stay intact in the STRUCT, because a caller matching
//! on the variant wants the real value. It is the human-readable rendering that
//! has to be bounded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, Error};

/// The bound this file holds the implementation to.
///
/// Chosen against the longest HONEST message rather than against a round
/// number: an elided fragment plus its surrounding prose measures about 170
/// bytes, so 256 leaves room for wording and still fails a rendering that lets
/// several hundred bytes of attacker text through. The first version of this
/// file used 512, and a mutation that moved the bound to the wrong side of
/// escaping survived it by 22 bytes -- a loose assertion is a test that agrees
/// with the defect.
const CEILING: usize = 256;

#[test]
fn a_huge_member_name_does_not_become_a_huge_message() {
    let name = "k".repeat(1 << 20);
    let doc = format!("{{\"{name}\":1,\"{name}\":2}}");
    let err = admit(doc.as_bytes()).expect_err("a repeat must be refused");
    assert!(
        matches!(err, Error::DuplicateMember { .. }),
        "wrong variant: {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.len() <= CEILING,
        "the refusal message is {} bytes for a 1 MiB member name; an attacker \
         should not choose the size of a log line",
        rendered.len()
    );
    // The full name is still available programmatically: the bound is on the
    // rendering, not on the data.
    match err {
        Error::DuplicateMember { name: got, .. } => {
            assert_eq!(got.len(), 1 << 20, "the struct must keep the whole name");
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn a_huge_number_token_does_not_become_a_huge_message() {
    let token = "9".repeat(100_000);
    let doc = format!("{{\"k\":{token}}}");
    let err = admit_ijson(doc.as_bytes()).expect_err("an unsafe integer must be refused");
    let rendered = err.to_string();
    assert!(
        rendered.len() <= CEILING,
        "the refusal message is {} bytes for a 100000-digit token",
        rendered.len()
    );
}

#[test]
fn a_short_name_is_rendered_whole_and_unescaped_names_stay_escaped() {
    // The over-truncation control: an ordinary name must appear in full, and a
    // name carrying a control character must still be escaped rather than
    // injected into the log line raw.
    let err = admit(br#"{"ab":1,"ab":2}"#).expect_err("refused");
    let rendered = err.to_string();
    assert!(
        rendered.contains("\"ab\""),
        "an ordinary name must be rendered in full: {rendered}"
    );
    assert!(
        !rendered.contains("..."),
        "an ordinary name must not be truncated: {rendered}"
    );

    let with_newline = admit(br#"{"a\nb":1,"a\nb":2}"#).expect_err("refused");
    let rendered = with_newline.to_string();
    assert_eq!(
        rendered.lines().count(),
        1,
        "a member name must not be able to add a line to a log: {rendered:?}"
    );
    assert!(
        rendered.contains("\\n"),
        "the control character must be rendered escaped: {rendered:?}"
    );
}

#[test]
fn escaping_is_inside_the_bound_not_outside_it() {
    // 90 control characters: 90 bytes of member name, and six characters of
    // `\u{1}` each once `Debug` has escaped them. A bound measured on the raw
    // name passes this and still hands the logger a 540-character line, so the
    // bound has to be measured on what is actually written.
    let name = "\u{1}".repeat(90);
    let escaped: String = "\\u0001".repeat(90);
    let doc = format!("{{\"{escaped}\":1,\"{escaped}\":2}}");
    let err = admit(doc.as_bytes()).expect_err("a repeat must be refused");
    match &err {
        Error::DuplicateMember { name: got, .. } => assert_eq!(got, &name),
        other => panic!("wrong variant: {other:?}"),
    }
    let rendered = err.to_string();
    assert!(
        rendered.len() <= CEILING,
        "a 90-byte name of control characters rendered {} bytes; the bound must \
         be on the escaped form, not the raw one",
        rendered.len()
    );
}

#[test]
fn truncation_does_not_split_a_character() {
    // A multi-byte character sitting on the truncation boundary must not be cut
    // in half: a `Display` implementation that slices a `str` by byte index
    // panics there, and a panic inside an error's own rendering is worse than
    // the long message it was added to prevent.
    for pad in 0..8 {
        // The padding shifts every emoji by one byte, so whatever budget the
        // implementation chose, one of these runs puts a 4-byte character
        // across it.
        let name = format!("{}{}", "k".repeat(pad), "\u{1F600}".repeat(200));
        let doc = format!("{{\"{name}\":1,\"{name}\":2}}");
        let err = admit(doc.as_bytes()).expect_err("refused");
        let rendered = err.to_string();
        assert!(
            rendered.len() <= CEILING,
            "pad {pad}: {} bytes",
            rendered.len()
        );
    }
}
