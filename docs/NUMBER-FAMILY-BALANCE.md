# The number family: `1e21`, `1e-7` and integers past 2^53

A third-party canonicalization rail published the number cases that had bitten it
and stated a coverage bar with them: two implementations that agree on `1e21`,
`1e-7`, and integers past 2^53 have covered what bit that project. All three are
covered here. This file says where each one lives, because the two corpora that
carry them are not interchangeable, and why `1e-7` could only land in one of them.

## What landed, and in which corpus, because the two are not interchangeable

**`1e21` and the integers past 2^53 are covered in `vectors/`**, the Adversarial
Execution Evidence corpus, as reject vectors carrying the literal inside a
covering record payload:

| vector | literal | refused by | condition |
| --- | --- | --- | --- |
| `vd3ead02f7ed16d0a` | `1e21` | the safe-range rule, on the value | `aee-c-18` |
| `vd5e0b3f3d1fabb05` | `1E2` | RFC 8785 canonicality, on the spelling | `aee-c-17` |
| `v97c6888cf7e88f42` | `1.0e2` | RFC 8785 canonicality, on the spelling | `aee-c-17` |
| `v13ede3e42645eb1a` | `-0e0` | RFC 8785 canonicality, on the spelling | `aee-c-17` |
| `v61efcc48543d8cea` | `9007199254740993` | the safe-range rule, on the value | `aee-c-18` |

**No exponent-form literal can ever be an ACCEPT in that corpus, and this is
provable rather than incidental.** The covering-payload rule (spec:1311-1317)
requires a payload to be canonical per RFC 8785 *and* valid I-JSON with integers
within the safe range. RFC 8785 inherits ECMAScript number-to-string, which uses
exponent notation only for magnitudes at or above 1e21 or below 1e-6. Everything
at or above 1e21 exceeds the safe-integer bound and is refused on value;
everything below 1e-6 is non-integral, and this predicate's canonicalized content
carries no fractional numbers. So every value the AEE corpus admits has a
canonical spelling in plain digits, and the accept side of the notation axis does
not exist there to be written.

**It exists in `vectors-ai-agent-action/`**, where the RFC 8785 Appendix B family
(`aia-c-16`) carries the numbers in a content payload rather than in a
chain-hash-covered field, precisely so that floats are admissible. The family
holds the 24 rows of Appendix B as accepts, whose canonical renderings include
`1e+21`, `5e-324`, `1e+23` and `9.999999999999997e-7`, and beside them the `1e-7`
pair:

| vector | kind | what it carries |
| --- | --- | --- |
| `vf1492a40d7a7c2c9` | accept | the double `3e7ad7f29abcaf48` as `1e-7`, the only text RFC 8785 produces for it |
| `v031c8b3d46725200` | reject | the same double as `0.0000001`, refused as `content-digest-mismatch` |

`1e-7` is not one of Appendix B Table 1's own rows, so its accept sits beside the
table rather than inside it: the table is a fixed quotation of the RFC and does not
grow members the RFC does not have. The reject twin is the spelling a rail that
skips the 1e-6 exponent switch produces, so such a rail computes a different
request digest and accepts a member a conforming rail refuses.

The integer past 2^53 is covered in this corpus too, under `aia-c-14`:
`v679f56481420e45a` carries 2^53 + 1, and the decode-boundary member
`v1a09354386e0ed57` carries `1234567890123456789`, a literal no double can hold.

## How the `1e-7` pair landed

Both members, together with eleven other `aia-c-16` rejects that each spell a
double in a way some serializer does and RFC 8785 does not, landed in
`8f81e37` (2026-10-04). That change moved `vectors-ai-agent-action` from 41
accepts and 21 rejects to 42 and 33, and re-recorded the corpus in
`docs/SURFACE-LEAKAGE-BASELINE.json` in the same commit.

The order mattered because of `scripts/surface-leakage-gate.py`. The gate pins
each corpus's recorded nulls to the class counts they were calibrated over and
refuses when either class moves by more than `FINGERPRINT_DRIFT`, so any reject
added to this corpus needs a re-calibration in the same change. Before it, the
Appendix B family had no reject side at all: one member path and one digest
string very nearly named the label, and the `paths`, `lexicon` and `all`
surfaces each sat outside their nulls under a declaration naming that family as
the blocker. With the reject family in place all three fell inside their nulls,
the three declarations were removed, and the gate refuses any declaration that
outlives its subject. The current figures are the `vectors-ai-agent-action` entry
of the baseline file; this page does not copy them, so it cannot drift from them.

Run `aee-verify vectors-ai-agent-action/` from the repository root to judge every
member, and `python3 scripts/surface-leakage-gate.py` to re-measure the surfaces.
