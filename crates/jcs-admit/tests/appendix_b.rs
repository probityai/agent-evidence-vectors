//! RFC 8785 Appendix B, the specification's own number table.
//!
//! Appendix B is the only place RFC 8785 states what an integer beyond 2^53
//! serializes as -- row `4430000000000000`, with note (2) saying the algorithm
//! "does not take [the extended precision] into consideration" -- and the only
//! place it pins the ECMAScript "Note 2" tie-break, in note (4): row
//! `43143ff3c1cb0959` "is exactly 1424953923781206.25 but will ... be truncated
//! and rounded to the closest even value."
//!
//! Two independent checks per row, so neither can pass on the other's account:
//! the double is rebuilt from the bit pattern and serialized, and the RFC's own
//! output is required to be its own canonical form.
//!
//! Source: `tests/vectors/rfc8785/appendix-b.tsv`, copied from the RFC text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

const TABLE: &str = include_str!("vectors/rfc8785/appendix-b.tsv");

struct Row {
    bits: u64,
    expected: String,
    comment: String,
}

fn rows() -> Vec<Row> {
    let rows: Vec<Row> = TABLE
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut f = l.split('\t');
            let bits = u64::from_str_radix(f.next()?, 16).ok()?;
            let expected = f.next()?.to_owned();
            let comment = f.next().unwrap_or("-").to_owned();
            if expected == "-" {
                return None; // NaN / Infinity: no JSON number denotes them.
            }
            Some(Row {
                bits,
                expected,
                comment,
            })
        })
        .collect();
    assert!(
        rows.len() >= 24,
        "Appendix B did not parse ({} rows); a differential that reads nothing \
         reports the same clean run as one that found nothing wrong",
        rows.len()
    );
    rows
}

/// A JSON number token that parses back to exactly `value`.
///
/// `{:?}` selects shortest-round-trip digits, so the token denotes the same
/// double whatever its digits are; the point here is to reach the serializer with
/// this value, not to test the token's spelling.
fn token(value: f64) -> String {
    format!("{value:?}")
}

#[test]
fn every_appendix_b_row_serializes_as_the_rfc_says_from_the_bit_pattern() {
    let mut bad = Vec::new();
    for row in rows() {
        let value = f64::from_bits(row.bits);
        let input = token(value);
        match jcs_admit::admit(input.as_bytes()) {
            Ok(got) => {
                let got = String::from_utf8(got).unwrap();
                if got != row.expected {
                    bad.push(format!(
                        "  {:016x} ({}): in {input}, want {}, got {got}",
                        row.bits, row.comment, row.expected
                    ));
                }
            }
            Err(e) => bad.push(format!(
                "  {:016x} ({}): in {input}, want {}, REFUSED {e}",
                row.bits, row.comment, row.expected
            )),
        }
    }
    assert!(
        bad.is_empty(),
        "{} Appendix B rows diverge from the specification:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn every_appendix_b_output_is_already_canonical() {
    let mut bad = Vec::new();
    for row in rows() {
        match jcs_admit::admit(row.expected.as_bytes()) {
            Ok(got) => {
                let got = String::from_utf8(got).unwrap();
                if got != row.expected {
                    bad.push(format!(
                        "  {:016x}: {} is not its own canonical form, got {got}",
                        row.bits, row.expected
                    ));
                }
            }
            Err(e) => bad.push(format!("  {:016x}: {} REFUSED {e}", row.bits, row.expected)),
        }
    }
    assert!(
        bad.is_empty(),
        "{} Appendix B outputs are not canonical:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// The ECMAScript "Note 2" tie-break, which is the case a shortest-digits float
/// formatter gets wrong on its own.
///
/// Each value below is an exact decimal midpoint between two digit strings that
/// both round-trip to it, so the shortest-round-trip rule alone does not pick
/// one. RFC 8785 section 3.2.2.3 requires the "Note 2" enhancement: the closest
/// value, and on a tie the even one.
///
/// The rows are the first cases a sweep of 89,657 doubles turned up, measured
/// against the Python rail and Go's `strconv.FormatFloat`, which agree with each
/// other and with Appendix B note (4).
#[test]
fn an_exact_midpoint_rounds_to_the_even_digit() {
    // (bit pattern, required output). Every one ends in an even last digit; the
    // shortest-digits formatter reaches for the odd neighbour.
    let cases: &[(u64, &str)] = &[
        (0x4314_3ff3_c1cb_0959, "1424953923781206.2"), // Appendix B note (4)
        (0x3e60_0000_0000_0000, "2.9802322387695312e-8"),
        (0x3ea4_0000_0000_0000, "5.960464477539062e-7"),
        (0x3eb2_0000_0000_0000, "0.0000010728836059570312"),
        (0x3ee0_8000_0000_0000, "0.000007867813110351562"),
        (0x3ef0_4000_0000_0000, "0.000015497207641601562"),
    ];
    let mut bad = Vec::new();
    for &(bits, want) in cases {
        let value = f64::from_bits(bits);
        let input = token(value);
        let got = jcs_admit::admit(input.as_bytes())
            .map(|b| String::from_utf8(b).unwrap())
            .unwrap_or_else(|e| format!("REFUSED {e}"));
        if got != want {
            bad.push(format!("  {bits:016x}: in {input}, want {want}, got {got}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} exact midpoints round to the odd digit:\n{}",
        bad.len(),
        cases.len(),
        bad.join("\n")
    );
}

/// The tie-break must not disturb a value that is not a tie.
///
/// Appendix B's five consecutive `333333333.3333...` rows differ by one unit in
/// the last place, so a rounding change that was too eager would smear them into
/// each other.
#[test]
fn consecutive_doubles_stay_distinguishable() {
    let consecutive: &[(u64, &str)] = &[
        (0x41b3_de43_5555_5553, "333333333.3333332"),
        (0x41b3_de43_5555_5554, "333333333.33333325"),
        (0x41b3_de43_5555_5555, "333333333.3333333"),
        (0x41b3_de43_5555_5556, "333333333.3333334"),
        (0x41b3_de43_5555_5557, "333333333.33333343"),
    ];
    let mut seen = std::collections::HashSet::new();
    for &(bits, want) in consecutive {
        let input = token(f64::from_bits(bits));
        let got = String::from_utf8(jcs_admit::admit(input.as_bytes()).unwrap()).unwrap();
        assert_eq!(got, want, "{bits:016x}");
        assert!(seen.insert(got.clone()), "{got} was produced twice");
        // And the output must parse back to the very same double.
        assert_eq!(got.parse::<f64>().unwrap().to_bits(), bits, "{got}");
    }
}

/// Every output the serializer produces must parse back to the double it came
/// from. A tie-break that picked a "nicer" digit string and lost the value would
/// be a worse defect than the one this file exists to catch.
#[test]
fn every_serialization_round_trips_to_its_own_double() {
    let mut checked = 0_usize;
    for exp in -320_i32..=308 {
        for mantissa in [1.0_f64, 1.25, 1.5, 2.5, 6.0221408, 7.0, 9.999] {
            let value = mantissa * 10_f64.powi(exp);
            if !value.is_finite() || value == 0.0 {
                continue;
            }
            for v in [value, -value] {
                let input = token(v);
                let got = String::from_utf8(jcs_admit::admit(input.as_bytes()).unwrap()).unwrap();
                assert_eq!(
                    got.parse::<f64>().unwrap().to_bits(),
                    v.to_bits(),
                    "{got} does not parse back to {v:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 4000, "only {checked} values checked");
}
