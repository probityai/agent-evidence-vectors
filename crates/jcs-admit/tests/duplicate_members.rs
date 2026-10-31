//! PROPERTY 2: a repeated object member is REFUSED, never collapsed.
//!
//! Collapsing a repeat to last-wins is a split-view attack. Two parties read the
//! same bytes as two different documents, a signature over either reading
//! verifies, and nothing downstream can recover which reading the producer meant
//! -- the second member has already overwritten the first.
//!
//! The nested cases are copied from `aee/jcs_string_test.go`
//! (`TestJCSNestedDuplicateKey`) in the Go implementation this crate ports; see
//! `tests/vectors/PROVENANCE.md`. The escape-collision case and the
//! canonical-form case are this crate's own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, Error};

fn refused(raw: &[u8], what: &str) {
    match admit(raw) {
        Err(Error::DuplicateMember { .. }) => {}
        other => panic!(
            "{what}: want Error::DuplicateMember, got {:?}",
            other.map(|b| String::from_utf8_lossy(&b).into_owned())
        ),
    }
}

#[test]
fn a_repeat_at_the_top_level_is_refused() {
    refused(br#"{"a":1,"a":2}"#, "top-level repeat");
}

/// Copied from `TestJCSNestedDuplicateKey`: the scan must reach every depth and
/// every position, not only the outermost object.
#[test]
fn a_repeat_nested_in_an_object_is_refused() {
    refused(br#"{"outer":{"k":1,"k":2}}"#, "repeat one object down");
}

/// Copied from `TestJCSNestedDuplicateKey`.
#[test]
fn a_repeat_inside_an_array_element_is_refused() {
    refused(br#"[{"k":1,"k":2}]"#, "repeat inside an array element");
}

/// The comparison is on the DECODED name, so two spellings of one name collide.
/// A byte comparison of the raw member names would miss this and emit an object
/// with the same member twice.
#[test]
fn two_spellings_of_one_name_collide() {
    refused(
        br#"{"\u0061":1,"a":2}"#,
        "escaped and literal spelling of 'a'",
    );
    refused(
        "{\"caf\\u00e9\":1,\"café\":2}".as_bytes(),
        "escaped and literal e-acute",
    );
    refused(
        br#"{"\ud83d\ude00":1,"\uD83D\uDE00":2}"#,
        "one surrogate pair written in both hex cases",
    );
}

/// The refusal names the member, because a verifier that refuses without saying
/// what it refused sends its operator back to the bytes.
#[test]
fn the_refusal_names_the_member() {
    match admit(br#"{"z":1,"dupe":2,"dupe":3}"#) {
        Err(Error::DuplicateMember { name, .. }) => assert_eq!(name, "dupe"),
        other => panic!("want a named duplicate, got {other:?}"),
    }
}

/// The over-refusal guard. A fix that refused every object, or confused a
/// repeated name in a SIBLING object for a repeat, would turn these red.
#[test]
fn distinct_members_and_sibling_repeats_are_accepted() {
    for raw in [
        &br#"{"a":1,"b":2}"#[..],
        &br#"{"a":{"k":1},"b":{"k":2}}"#[..],
        &br#"[{"k":1},{"k":2}]"#[..],
        &br#"{"a":[{"k":1},{"k":2}]}"#[..],
        &br#"{}"#[..],
        &br#"{"":1}"#[..],
    ] {
        assert!(admit(raw).is_ok(), "{}", String::from_utf8_lossy(raw));
    }
}
