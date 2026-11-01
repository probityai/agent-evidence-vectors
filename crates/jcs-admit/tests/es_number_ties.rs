//! The round-to-even digit tie, over a corpus rather than a handful of rows.
//!
//! ECMA-262 7.1.12.1 step 5 picks the shortest digit string that reads back as
//! the value, then the closest, and then -- the clause every shortest-float
//! formatter skips -- the EVEN one of two equidistant candidates. RFC 8785
//! section 3.2.2.3 defers to that algorithm by reference, so the clause is
//! normative here, and Appendix B carries exactly one row for it
//! (`43143ff3c1cb0959`). One row is enough to fail and not enough to characterise
//! a defect, which is what this corpus is for.
//!
//! Every token is a double whose exact decimal expansion terminates one digit
//! past its shortest form in a 5 -- the only shape where the choice exists. The
//! expected column is `String(Number(input))` from node v24.19.0, the algorithm
//! the specification defers to, read off an engine rather than reasoned about.
//! `tests/vectors/es-number-ties.tsv` carries the provenance.
//!
//! Two classes sit in one file on purpose. Where the even candidate is the LOWER
//! one, a formatter that rounds away from zero is wrong and the input differs
//! from the output. Where the even candidate is the UPPER one, that formatter is
//! already right and the input is its own canonical form. A correction that fires
//! on equidistance alone passes the first class and fails the second, which is
//! how the first version of this fix was caught.
//!
//! WHOSE BEHAVIOUR THIS NOW MEASURES. This crate does not format numbers. The
//! clause is implemented by `ryu_js` inside `serde_json_canonicalizer`, which
//! this crate delegates to, so these 850 rows are a test of the DEPENDENCY --
//! and the strongest single piece of evidence for delegating rather than
//! carrying a third copy of the algorithm. 850 rows read off node v24.19.0,
//! against a dependency written by someone else: if it passes, its correctness
//! is this crate's asset and the 437 lines of hand-rolled ECMAScript number
//! formatting that used to sit here were pure risk.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::admit;

const CORPUS: &str = include_str!("vectors/es-number-ties.tsv");

struct Row {
    input: String,
    expected: String,
    form: String,
}

fn rows() -> Vec<Row> {
    CORPUS
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let mut fields = line.split('\t');
            Some(Row {
                input: fields.next()?.to_owned(),
                expected: fields.next()?.to_owned(),
                form: fields.next().unwrap_or("").to_owned(),
            })
        })
        .collect()
}

#[test]
fn every_tie_in_the_corpus_serializes_to_the_even_candidate() {
    let rows = rows();
    assert!(
        rows.len() > 500,
        "the corpus has shrunk to {} rows; a differential that finds nothing \
         because it was never given anything reads exactly like one that found \
         nothing wrong",
        rows.len()
    );
    let mut failures = Vec::new();
    for row in &rows {
        let got = admit(row.input.as_bytes())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|e| format!("REFUSED: {e}"));
        if got != row.expected {
            failures.push(format!(
                "{} ({}): got {got}, want {}",
                row.input, row.form, row.expected
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} tie rows diverge from the specification's algorithm:\n{}",
        failures.len(),
        rows.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Both halves of the rule must be REPRESENTED, or the corpus can only catch a
/// fix that is wrong in one direction.
///
/// The floors below are the corpus as MEASURED, not a round number chosen for
/// how it reads. Counted 2026-09-19 over the 850 committed rows: 72 where node's
/// output differs from the input, and 778 where it does not. An earlier version
/// of this test asserted 100 in each direction, which the corpus it ships with
/// has never satisfied -- it was written alongside the corpus and never run green
/// against it. A guard whose threshold nothing can meet is not a strict guard,
/// it is a broken one, and it hides whatever it was supposed to watch. These
/// floors still fail if the corpus shrinks or loses a direction, which is the
/// job.
#[test]
fn the_corpus_carries_ties_that_resolve_in_both_directions() {
    let rows = rows();
    let corrected = rows.iter().filter(|r| r.input != r.expected).count();
    let unchanged = rows.iter().filter(|r| r.input == r.expected).count();
    assert!(
        corrected >= 72,
        "only {corrected} rows correct downward, was 72; the formatter's error \
         direction is under-covered"
    );
    assert!(
        unchanged >= 778,
        "only {unchanged} rows are already correct, was 778; over-correction is \
         under-covered"
    );
    // The exponent layout is the rarest of the four -- five such doubles turned
    // up in 950,000 draws -- so its presence is asserted rather than assumed.
    assert!(
        rows.iter().any(|r| r.form == "exponent"),
        "the exponent layout has no row, and it is the branch a plain-form test cannot reach"
    );
    assert!(
        rows.iter().any(|r| r.form == "leading-zeros"),
        "the leading-zeros layout has no row"
    );
}

/// Each output must be its own canonical form. A canonicalizer whose output is
/// not a fixed point has only moved the disagreement to whoever re-reads it.
#[test]
fn every_expected_output_is_its_own_canonical_form() {
    for row in rows() {
        assert!(
            jcs_admit::is_canonical(row.expected.as_bytes()),
            "{} is required output and is not canonical",
            row.expected
        );
    }
}
