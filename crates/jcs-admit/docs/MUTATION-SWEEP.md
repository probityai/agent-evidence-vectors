# Mutation sweep

Every refusal this crate makes, broken on purpose, to check that the tests measure the
mechanism rather than its presence. Run 2026-09-19. The three cases where a test
passed a broken implementation are in [The three gaps](#the-three-gaps) below.

Each row carries the implementation edit, the suite it was run against, and what the crate
accepted with the refusal removed.

17 mutations, 17 caught. Three test gaps are closed in `tests/refusal_boundaries.rs`.

Reproduce it with `tools/mutation_sweep.py`, which ships in the package.

| id | kind | refusal | edit lands in | verdict | what the break produced |
|---|---|---|---|---|---|
| R1 | red | DuplicateMember | `src/parse.rs` | caught (red) | top-level repeat: want Error::DuplicateMember, got Ok("{\"a\":1}") |
| M1 | mutate | DuplicateMember | `src/parse.rs` | caught (red) | escaped and literal spelling of 'a': want Error::DuplicateMember, got Ok("{\"a\":1}") |
| R2 | red | TooDeep | `src/parse.rs` | caught (red) | 129 containers must be refused |
| M2 | mutate | TooDeep | `src/parse.rs` | caught (red) | 129 containers must be refused |
| R3 | red | StringNotScalar/surrogate | `src/parse.rs` | caught (red) | 7 of 317 cases diverge: / F.lone-high-d800: must be refused, produced "{\"k\":\"�\"}" |
| M3 | mutate | StringNotScalar/surrogate | `src/parse.rs` | caught (red) | 4 of 317 cases diverge: / F.lone-low-dc00: must be refused, produced "{\"k\":\"�\"}" |
| R4 | red | StringNotScalar/utf8 | `src/parse.rs` | caught (red) | 17 of 317 cases diverge: / G.cesu8-d800: must be refused, produced "{\"k\":\"���\"}" |
| R5 | red | StringNotScalar/noncharacter | `src/lib.rs` | caught (red) | 18 of 317 cases diverge: / F.valid-pair-max: must be refused, produced "{\"k\":\"\u{10ffff}\"}" |
| M4 | mutate | StringNotScalar/noncharacter | `src/parse.rs` | caught (red) | 8 of 317 cases diverge: / H.noncharacter-raw-FFFE: must be refused, produced "{\"k\":\"\u{fffe}\"}" |
| R6 | red | UnsafeInteger | `src/number.rs` | caught (red) | 1e99999999999999999999: want UnsafeInteger, got Err(NonFiniteNumber { token: "1e99999999999999999999" }) |
| M5 | mutate | UnsafeInteger | `src/number.rs` | caught (red) | 1e99999999999999999999: want UnsafeInteger, got Err(NonFiniteNumber { token: "1e99999999999999999999" }) |
| R7 | red | NonIntegerNumber | `src/number.rs` | caught (red) | 2 of 15 rows diverge: / 1.5: want refused=true (non-integer), got Ok([49, 46, 53]) |
| M6 | mutate | NonIntegerNumber | `src/number.rs` | SURVIVED its target suite |  |
| R8 | red | NonFiniteNumber | `src/number.rs` | caught (red) | 1e400: want NonFiniteNumber, got Err(Canonicalization { detail: "NaN and +/-Infinity are not permitted in JSON" }) |
| M7 | mutate | NonFiniteNumber | `src/number.rs` | caught (red) | -1e400: want NonFiniteNumber, got Err(Canonicalization { detail: "NaN and +/-Infinity are not permitted in JSON" }) |
| R9 | red | TooLarge | `src/lib.rs` | caught (red) | want TooLarge, got Ok(6) |
| M8 | mutate | TooLarge | `src/lib.rs` | caught (red) | an input of exactly 20971520 bytes must be admitted, or the cap is off by one in the direction that refuses good evidence |

## The three gaps

### No negative non-finite token existed anywhere

A finiteness check written `v != f64::INFINITY` passed the entire suite, because `-1e400` was
untested.

Closed by `a_non_finite_number_is_refused_at_either_sign`. It runs both signs, and it also
pins that the largest finite double is still admitted, so the guard cannot pass by refusing
everything large.

### Nothing asserted that an input of exactly `DEFAULT_MAX_BYTES` is admitted

A size check written `>=` passed the suite.

An over-tight cap on a verifier refuses documents that are perfectly good evidence, which is a
failure in the direction nobody tests for. Closed by `the_size_cap_admits_exactly_the_cap`.

### An integer test reading `exp10 >= 0` passed the whole integration suite

Reducing `is_integer` to `exp10 >= 0` makes `0.0` a non-integer, and the whole `ijson_profile`
integration suite passed with that in place.

Only a unit test on the private decomposition helper caught it, and a unit test on a private
helper does not survive that helper being replaced.

Closed by `zero_is_an_integer_in_every_notation_at_the_entry_point`, which states the rule at
the public entry point. Re-running M6 against it now fails there too.

## Two mutations in detail

R3 removes the unpaired-surrogate refusal and substitutes U+FFFD, which is what an ordinary
decoder does.

`"\ud800"` and `"\udbff"` then canonicalize to the same bytes, and so does a literal U+FFFD.
Three distinct wire documents, one canonical form, one signature that verifies for all three.

R8 removes the finiteness refusal, and the caller does not get an acceptance. It gets
`Error::Canonicalization { detail: "NaN and +/-Infinity are not permitted in JSON" }`: the
delegate's untyped message surfacing through the seam, naming no token and no offset.

That is the difference owning the refusal makes.

