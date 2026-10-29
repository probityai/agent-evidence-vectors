//! The depth ceiling has to be safe on the SMALLEST stack in ordinary use, not
//! just on the one the test harness happens to give the main thread.
//!
//! `tests/depth_cap.rs` already covers what the ceiling does: it clamps, it
//! refuses past itself, and it reaches the `serde_json` path. What no other test
//! establishes is the measurement the number rests on. The cap is a stack bound,
//! so a ceiling is only correct relative to a stack size, and asserting it on
//! an 8 MiB main thread proves it for a configuration much of the world does
//! not have -- a spawned thread gets 2 MiB by default, and a pool worker can be
//! given less.
//!
//! Measured on this crate in an unoptimized build: about 1.15 KiB of stack per
//! nesting level, so a 1 MiB thread survived 896 levels and died at 1024. The
//! ceiling of 512 is chosen against that, and this file is what keeps the
//! choice honest: if it ever ABORTS rather than fails, the per-level cost has
//! grown and `MAX_SUPPORTED_DEPTH` is what must come down.
//!
//! It lives on its own because its failure mode is process death, and
//! everything sharing a test binary with it would go down too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{Error, Options, DEFAULT_MAX_DEPTH, MAX_SUPPORTED_DEPTH};

/// The smallest stack this crate claims to work in: half of what `std` gives a
/// spawned thread by default.
const SMALL_STACK: usize = 1 << 20;

fn nest(depth: usize) -> Vec<u8> {
    let mut v = vec![b'['; depth];
    v.resize(depth * 2, b']');
    v
}

fn on_a_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the worker must return a value, not die")
}

#[test]
fn a_document_nested_to_the_ceiling_is_canonicalized_on_a_small_stack() {
    let doc = nest(MAX_SUPPORTED_DEPTH);
    let opts = Options::rfc8785().max_depth(MAX_SUPPORTED_DEPTH);
    let got = on_a_small_stack(move || jcs_admit::admit_with(&doc, &opts).map(|b| b.len()));
    assert_eq!(
        got,
        Ok(MAX_SUPPORTED_DEPTH * 2),
        "the ceiling must be usable in {SMALL_STACK} bytes of stack"
    );
}

#[test]
fn an_uncapped_request_is_refused_on_a_small_stack_rather_than_aborting() {
    let doc = nest(200_000);
    let opts = Options::rfc8785().max_depth(usize::MAX).max_bytes(None);
    let got = on_a_small_stack(move || jcs_admit::admit_with(&doc, &opts));
    assert!(
        matches!(got, Err(Error::TooDeep { .. })),
        "must refuse, got {:?}",
        got.map(|b| b.len())
    );
}

// Relations between two constants belong at compile time: asserted at runtime
// they are folded by the optimizer and measure nothing, while as anonymous
// constants they fail the build.
const _: () = assert!(
    DEFAULT_MAX_DEPTH == 128,
    "the default cap is normative in an upstream specification proposal"
);
const _: () = assert!(
    DEFAULT_MAX_DEPTH < MAX_SUPPORTED_DEPTH,
    "the default must leave room to be raised"
);
