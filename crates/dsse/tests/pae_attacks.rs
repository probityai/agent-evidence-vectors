//! INVENTED CASES. Nothing here comes from a published vector file. Each case
//! is a payload type or payload constructed to break the length-prefix
//! discipline that makes PAE injective, because a length-prefix mistake is
//! where a signature over one message becomes a signature over another.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::pae;

/// A payload type whose bytes outnumber its characters. `LEN` is specified as
/// the byte length; a character count is the classic mistake, and it silently
/// produces a different pre-image, so a signature made by an implementation
/// that counts characters does not verify against one that counts bytes.
///
/// `tybé` is four characters and five bytes: `é` is U+00E9, two bytes in UTF-8.
#[test]
fn length_prefix_counts_bytes_not_characters() {
    let got = pae("tybé", b"x");
    assert_eq!(
        got,
        b"DSSEv1 5 tyb\xc3\xa9 1 x".to_vec(),
        "LEN must be the byte length, 5, not the character count, 4"
    );
}

/// The same defect with a wider character. `🔒` is one character and four bytes.
#[test]
fn length_prefix_counts_bytes_for_astral_characters() {
    let got = pae("🔒", b"");
    assert_eq!(got, b"DSSEv1 4 \xf0\x9f\x94\x92 0 ".to_vec());
    // A character count would have written 1.
    assert!(!got.starts_with(b"DSSEv1 1 "));
}

/// A payload type containing a space. The specification recommends a media type
/// or a URI but requires neither, so a space is legal and must not be treated
/// as a field separator. The length prefix is what delimits the field.
#[test]
fn payload_type_containing_a_space_is_carried_verbatim() {
    let got = pae("a b", b"c");
    assert_eq!(got, b"DSSEv1 3 a b 1 c".to_vec());
}

/// A payload type that is itself shaped like the middle of a PAE. An
/// implementation that recovered the type by splitting on spaces would read
/// `9` as a length here.
#[test]
fn payload_type_shaped_like_a_length_field() {
    let got = pae("9 not-a-length", b"body");
    assert_eq!(got, b"DSSEv1 14 9 not-a-length 4 body".to_vec());
}

/// An empty payload. The envelope schema requires `payload` to be set even when
/// empty, and PAE of an empty body ends in a trailing space that carries
/// meaning. An implementation that joined fields with a separator, or trimmed
/// its output, would drop that byte and change the pre-image.
#[test]
fn empty_payload_keeps_its_trailing_space() {
    let got = pae("t", b"");
    assert_eq!(got, b"DSSEv1 1 t 0 ".to_vec());
    assert_eq!(*got.last().unwrap(), b' ', "the trailing space is signed");
}

/// An empty payload type produces two adjacent spaces, for the same reason.
/// Whitespace-collapsing string handling loses one of them.
#[test]
fn empty_payload_type_keeps_both_spaces() {
    let got = pae("", b"x");
    assert_eq!(got, b"DSSEv1 0  1 x".to_vec());
    assert_eq!(
        &got[7..10],
        b"0  ",
        "zero length, then the empty type, then SP"
    );
}

/// Both empty at once: the degenerate case, and still unambiguous.
#[test]
fn both_members_empty() {
    assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
}

/// `LEN` is ASCII decimal with no leading zeros. A zero-padded or fixed-width
/// length is a different pre-image. Checked at each digit boundary, where a
/// padding implementation diverges.
#[test]
fn length_prefix_has_no_leading_zeros() {
    for n in [0usize, 1, 9, 10, 11, 99, 100, 101, 255, 1000] {
        let payload = vec![b'z'; n];
        let got = pae("t", &payload);
        let want = format!("DSSEv1 1 t {n} ");
        assert!(
            got.starts_with(want.as_bytes()),
            "payload of {n} bytes: expected prefix {want:?}, got {:?}",
            String::from_utf8_lossy(&got[..want.len().min(got.len())])
        );
        assert!(
            !got.starts_with(format!("DSSEv1 1 t 0{n} ").as_bytes()),
            "a zero-padded length is a different pre-image"
        );
    }
}

/// The encoding is injective across the type/body boundary. Shifting a byte
/// from the type into the body must change the pre-image, or a signature could
/// be re-read with the split moved.
#[test]
fn encoding_is_injective_across_the_type_body_boundary() {
    assert_ne!(pae("ab", b"c"), pae("a", b"bc"));
    assert_ne!(pae("a", b"b"), pae("", b"ab"));
    assert_ne!(pae("", b"ab"), pae("ab", b""));
}

/// A payload whose bytes are themselves a complete, valid PAE. An
/// implementation that searched for the `DSSEv1` marker, or re-parsed its own
/// output, could recover the inner pair and act on a type nobody signed. The
/// outer length prefix makes the inner occurrence inert.
#[test]
fn payload_that_is_itself_a_valid_pae_stays_nested() {
    let inner = pae("inner-type", b"inner-body");
    let outer = pae("outer-type", &inner);

    assert_ne!(outer, inner);
    assert!(outer.starts_with(format!("DSSEv1 10 outer-type {} ", inner.len()).as_bytes()));
    assert!(outer.ends_with(&inner), "the inner PAE is carried verbatim");
    // The marker appears twice; only the first one is structural.
    let occurrences = outer.windows(6).filter(|w| *w == b"DSSEv1").count();
    assert_eq!(occurrences, 2);
}

/// A payload that is not valid UTF-8 must be carried byte for byte. PAE is
/// defined over byte sequences; only the type is a string.
#[test]
fn payload_need_not_be_valid_utf8() {
    let payload = [0xff, 0xfe, 0x00, 0x80];
    let got = pae("t", &payload);
    assert_eq!(got, b"DSSEv1 1 t 4 \xff\xfe\x00\x80".to_vec());
    assert!(String::from_utf8(payload.to_vec()).is_err());
}

/// The payload type is case-sensitive, and a case change is a different
/// pre-image, so a verifier expecting one type cannot be satisfied by the other.
#[test]
fn payload_type_is_case_sensitive() {
    assert_ne!(pae("Application/JSON", b"x"), pae("application/json", b"x"));
}
