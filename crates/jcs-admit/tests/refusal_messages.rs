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

/// A noncharacter is a Unicode scalar value. The refusal must say so, and must
/// not render the surrogate wording ("not a sequence of Unicode scalar values")
/// that the earlier message applied to every string fault in the variant.
#[test]
fn a_noncharacter_is_not_called_a_non_scalar_value() {
    // Raw U+FFFE after a two-byte prefix inside the run, and the same code point
    // written as an escape. Built from code points, never typed.
    let raw = format!("{{\"k\":\"ab{}\"}}", char::from_u32(0xFFFE).unwrap());
    let escaped = format!("{{\"k\":\"ab\\u{:04x}\"}}", 0xFFFE_u32);
    for doc in [raw, escaped] {
        let err = admit_ijson(doc.as_bytes()).expect_err("the profile refuses a noncharacter");
        let rendered = err.to_string();
        assert!(
            !rendered.contains("not a sequence of Unicode scalar values"),
            "a noncharacter is a scalar value: {rendered}"
        );
        assert!(
            rendered.contains("noncharacter") && rendered.contains("scalar value"),
            "the message must name the fault: {rendered}"
        );
        // The offset is the noncharacter's own first byte, after `{"k":"ab`,
        // not the start of the run that contains it.
        match err {
            Error::StringNotScalar { offset, .. } => assert_eq!(offset, 8, "{doc}"),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}

/// A raw control character is a scalar value too; JSON refuses it unescaped.
#[test]
fn a_raw_control_character_is_not_called_a_non_scalar_value() {
    let err = admit(b"{\"k\":\"a\x01\"}").expect_err("a raw control character is refused");
    let rendered = err.to_string();
    assert!(
        !rendered.contains("not a sequence of Unicode scalar values"),
        "{rendered}"
    );
    assert!(rendered.contains("raw control character"), "{rendered}");
}

/// The surrogate fault keeps a message that says what the bytes are.
#[test]
fn an_unpaired_surrogate_message_names_the_surrogate() {
    let err = admit(br#"{"k":"\ud800"}"#).expect_err("a lone surrogate is refused");
    assert!(
        err.to_string().contains("unpaired high surrogate escape"),
        "{err}"
    );
}

/// Ill-formed UTF-8 inside a longer run of text is reported at its own first
/// byte, as a noncharacter and an escape are, not at the start of the run. The
/// earlier offset pointed six bytes before the fault in each document here, and
/// the Go rail, which reports the bad byte, disagreed with it. Each document is
/// `{"k":"ab` followed by one ill-formed sequence: a stray continuation byte, a
/// byte that never starts UTF-8, an overlong `/`, a surrogate encoded directly
/// (CESU-8), and a three-byte sequence cut short by the closing quote.
#[test]
fn invalid_utf8_is_reported_at_its_own_first_byte() {
    let faults: [&[u8]; 5] = [
        &[0x80],
        &[0xFF],
        &[0xC0, 0xAF],
        &[0xED, 0xA0, 0x80],
        &[0xE2, 0x82],
    ];
    for fault in faults {
        let mut doc = b"{\"k\":\"ab".to_vec();
        doc.extend_from_slice(fault);
        doc.extend_from_slice(b"\"}");
        for (profile, result) in [("rfc8785", admit(&doc)), ("ijson", admit_ijson(&doc))] {
            match result {
                Err(Error::StringNotScalar { offset, reason }) => {
                    assert_eq!(reason, "invalid UTF-8", "{profile} {fault:02x?}");
                    assert_eq!(offset, 8, "{profile} {fault:02x?}");
                }
                other => panic!("{profile} {fault:02x?}: want StringNotScalar, got {other:?}"),
            }
        }
    }
}

/// Within one run of text the first fault in reading order is the one reported.
/// A noncharacter before ill-formed bytes in the same run was reported as the
/// later UTF-8 fault, because the run was checked for UTF-8 as a whole before
/// it was searched for noncharacters; across runs, and on the Go rail, the
/// first fault wins. Each document is `{"k":"ab`, U+FDD0 at byte 8 (built from
/// its code point), then one ill-formed sequence.
#[test]
fn a_noncharacter_before_ill_formed_bytes_is_the_fault_reported() {
    let nonchar = char::from_u32(0xFDD0).unwrap().to_string();
    let faults: [&[u8]; 3] = [&[0xFF], &[0x80], &[0xED, 0xA0, 0x80]];
    for fault in faults {
        let mut doc = b"{\"k\":\"ab".to_vec();
        doc.extend_from_slice(nonchar.as_bytes());
        doc.extend_from_slice(fault);
        doc.extend_from_slice(b"\"}");
        match admit_ijson(&doc) {
            Err(Error::StringNotScalar { offset, reason }) => {
                assert!(reason.contains("noncharacter"), "{fault:02x?}: {reason}");
                assert_eq!(offset, 8, "{fault:02x?}");
            }
            other => panic!("{fault:02x?}: want StringNotScalar, got {other:?}"),
        }
        // The RFC 8785 profile admits the noncharacter, so the ill-formed bytes
        // after it are the first fault there, at their own first byte.
        match admit(&doc) {
            Err(Error::StringNotScalar { offset, reason }) => {
                assert_eq!(reason, "invalid UTF-8", "{fault:02x?}");
                assert_eq!(offset, 8 + nonchar.len(), "{fault:02x?}");
            }
            other => panic!("{fault:02x?}: want StringNotScalar, got {other:?}"),
        }
    }
}
