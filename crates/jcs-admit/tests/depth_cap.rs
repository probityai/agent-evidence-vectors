//! PROPERTY 1: nesting past the cap is REFUSED, not recursed.
//!
//! Three values for this cap exist in the wild. The rails this crate is ported
//! from chose 128; an outside Rust checker chose 256; a real consumer caps at
//! nothing at all, and its third value is a stack overflow. A stack overflow is
//! not a catchable error, and it happens before any signature is checked.
//!
//! The two bound cases are copied from `aee/jcs_dos_test.go`
//! (`TestParseDepthBound`, `TestParseByteBound`) in the Go implementation this
//! crate ports; see `tests/vectors/PROVENANCE.md`. The boundary and the Value
//! path are this crate's own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_with, Error, Options, DEFAULT_MAX_DEPTH};

fn nest(depth: usize) -> Vec<u8> {
    let mut v = vec![b'['; depth];
    v.resize(depth * 2, b']');
    v
}

/// Copied from `TestParseDepthBound`: twice the cap must be refused with the
/// depth sentinel, and the payload AT the cap must still canonicalize, so the
/// guard cannot pass by being uniformly over-tight.
#[test]
fn twice_the_cap_is_refused_and_the_cap_itself_is_not() {
    let too_deep = nest(DEFAULT_MAX_DEPTH * 2);
    assert!(
        matches!(admit(&too_deep), Err(Error::TooDeep { .. })),
        "a document nested to twice the cap must be refused with Error::TooDeep, got {:?}",
        admit(&too_deep).map(|b| b.len())
    );
    let at_bound = nest(DEFAULT_MAX_DEPTH);
    assert!(
        admit(&at_bound).is_ok(),
        "the cap itself must still canonicalize"
    );
}

/// The boundary is exactly one container wide: 128 nested containers pass, 129
/// are refused. An off-by-one here is how an empty container slips one level
/// past a bound that looks correct.
#[test]
fn the_boundary_is_exact() {
    assert!(
        admit(&nest(DEFAULT_MAX_DEPTH)).is_ok(),
        "{DEFAULT_MAX_DEPTH} must pass"
    );
    assert!(
        matches!(
            admit(&nest(DEFAULT_MAX_DEPTH + 1)),
            Err(Error::TooDeep { limit: 128, .. })
        ),
        "{} must be refused",
        DEFAULT_MAX_DEPTH + 1
    );
}

/// An EMPTY container at the innermost level is still a level. Charging the cap
/// only when a child is parsed lets `[[[...[]...]]]` reach one deeper than
/// `[[[...[0]...]]]`, and the two disagree about the same document shape.
#[test]
fn an_empty_innermost_container_is_charged() {
    let mut v = vec![b'['; DEFAULT_MAX_DEPTH];
    v.extend_from_slice(b"{}");
    v.resize(v.len() + DEFAULT_MAX_DEPTH, b']');
    assert!(
        matches!(admit(&v), Err(Error::TooDeep { .. })),
        "an empty object at level {} must be refused",
        DEFAULT_MAX_DEPTH + 1
    );
}

#[test]
fn objects_are_charged_like_arrays() {
    let mut deep = Vec::new();
    for _ in 0..DEFAULT_MAX_DEPTH + 1 {
        deep.extend_from_slice(br#"{"a":"#);
    }
    deep.extend_from_slice(b"1");
    deep.resize(deep.len() + DEFAULT_MAX_DEPTH + 1, b'}');
    assert!(matches!(admit(&deep), Err(Error::TooDeep { .. })));
}

#[test]
fn the_cap_is_configurable_in_both_directions() {
    let opts = Options::rfc8785().max_depth(4);
    assert!(admit_with(&nest(4), &opts).is_ok());
    assert!(matches!(
        admit_with(&nest(5), &opts),
        Err(Error::TooDeep { limit: 4, .. })
    ));
}

/// Copied from `TestParseByteBound`: a depth cap bounds the stack, a size cap
/// bounds the heap, and a canonicalizer needs both.
#[test]
fn oversized_input_is_refused_before_parsing() {
    let mut big = vec![b' '; jcs_admit::DEFAULT_MAX_BYTES + 1];
    big[0] = b'[';
    let last = big.len() - 1;
    big[last] = b']';
    assert!(matches!(admit(&big), Err(Error::TooLarge { .. })));
}

/// The ceiling the builder must not let a caller past. Held as a literal here
/// rather than read from the crate, so this test states the bound independently
/// of the constant that implements it.
const HARD_CEILING: usize = 512;

/// The cap may be lowered freely and raised only to a ceiling, because the
/// parser and the `Value` walk both recurse: a cap above the ceiling hands the
/// caller back the crash the cap exists to prevent. Measured on this machine
/// before the ceiling existed, `Options::rfc8785().max_depth(usize::MAX)` on
/// 19,414 nested arrays aborted the process with "fatal runtime error: stack
/// overflow" -- not an `Err`, not catchable, and reached through safe public API
/// with no `unsafe` anywhere in the crate.
#[test]
fn the_cap_cannot_be_raised_into_a_stack_overflow() {
    let opts = Options::rfc8785().max_depth(usize::MAX).max_bytes(None);
    match admit_with(&nest(HARD_CEILING + 1), &opts) {
        Err(Error::TooDeep { limit, .. }) => assert_eq!(
            limit, HARD_CEILING,
            "a raised cap must be reported at the ceiling actually enforced"
        ),
        other => panic!(
            "a cap raised past the ceiling must still refuse, got {:?}",
            other.map(|bytes| bytes.len())
        ),
    }
    assert!(
        admit_with(&nest(HARD_CEILING), &opts).is_ok(),
        "the ceiling itself must not be refused, or the guard passes by being over-tight"
    );
}

/// A raise BELOW the ceiling is honoured exactly, so the clamp is a ceiling and
/// not a silent replacement of whatever the caller asked for.
#[test]
fn a_raise_below_the_ceiling_is_honoured_exactly() {
    let opts = Options::rfc8785().max_depth(200);
    assert!(admit_with(&nest(200), &opts).is_ok());
    assert!(matches!(
        admit_with(&nest(201), &opts),
        Err(Error::TooDeep { limit: 200, .. })
    ));
}

// The delegate recurses over an admitted tree too, so the ceiling has to hold
// for the WHOLE path and not only for the parser.
//
// No separate test: `the_cap_cannot_be_raised_into_a_stack_overflow` above
// admits a document at exactly `HARD_CEILING` and that call runs the delegate's
// own recursive serializer to completion. Measured independently on
// 2026-09-19, the delegate alone accepts 1,000 nested arrays and aborts the
// process at 10,000, which is why the ceiling is this crate's to enforce rather
// than something the delegate can be relied on for.
