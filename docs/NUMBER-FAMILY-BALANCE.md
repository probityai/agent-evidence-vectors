# The number family, its missing reject side, and what `1e-7` is waiting on

A third-party canonicalization rail published the number cases that had bitten it
and stated a coverage bar with them: two implementations that agree on `1e21`,
`1e-7`, and integers past 2^53 have covered what bit that project. Two of the
three are now covered here and the third is not. This file says exactly what the
third costs, because the reason it has not landed is a measured refusal by one of
our own gates rather than an oversight, and a reader who does not have the
arithmetic in front of them will reasonably assume the work was simply skipped.

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
(`aia-c-16`) carries 24 accept vectors whose canonical renderings include
`1e+21`, `5e-324`, `1e+23` and `9.999999999999997e-7`. That corpus carries its
numbers in a content payload rather than in a chain-hash-covered field precisely
so that floats are admissible, and its generator says so.

## What `1e-7` is waiting on, in arithmetic

`1e-7` belongs in the Appendix B family, as an accept with a reject twin. It
cannot land alone, and the obstruction is not the leakage figure people assume.

**The binding refusal is the fingerprint-drift check, not a surface
measurement.** `scripts/surface-leakage-gate.py` pins each corpus's recorded
nulls to the class counts they were calibrated over, because the class counts set
the null's level, and refuses when either class moves by more than
`FINGERPRINT_DRIFT = 0.10`:

- `docs/SURFACE-LEAKAGE-BASELINE.json` records `vectors-ai-agent-action` at
  `{"accept": 37, "reject": 16}`.
- The corpus holds `{"accept": 37, "reject": 17}` today; the decode-boundary
  vector `v1a09354386e0ed57` added the seventeenth. That is `1/16 = 6.25%`, and
  the budget is already more than half spent.
- One more reject makes it 18, which is `2/16 = 12.5%` and over the bound. The
  gate then reports the drift and **`continue`s past all six surface checks for
  that corpus**, so the leakage measurement it exists for silently stops being
  enforced until somebody re-calibrates.

So any reject added to that corpus, whether or not it is a number, requires a
`--sync` re-calibration in the same change.

**The leakage figures move the right way, which is why the re-calibration is
honest rather than a loophole.** Measured by staging the tree and running the
real gate against it:

| surface | today (37/17) | +1 reject (37/18) | +1 accept +1 reject (38/18) | recorded null |
| --- | --- | --- | --- | --- |
| `identifier` | 0.5191 | 0.5285 | 0.5175 | 0.5245 |
| `paths` | 0.7862 | 0.7537 | 0.7571 | 0.6495 |
| `lexicon` | 0.7886 | 0.7402 | 0.7405 | 0.6462 |
| `all` | 0.7785 | 0.7355 | 0.7408 | 0.6456 |

`--sync` refuses to raise a recorded figure, and every leakage-bearing surface
falls, so the re-calibration is admissible. Two things follow that are easy to
miss:

- **The pair must be matched.** A reject alone pushes `identifier` to 0.5285,
  above its null of 0.5245 with no declaration behind it, which is a second
  refusal waiting behind the first. An accept alongside it pulls `identifier`
  down to 0.5175 instead. The identifier surface is content-addressed and
  balanced only when the class ratio is.
- **One reject does not close the leak.** `paths`, `lexicon` and `all` all stay
  outside their nulls, so the three `blockedBy` declarations on that corpus
  remain required and correctly worded. The baseline's own `reason` already says
  the fix is Appendix B "rows", plural.

## The shape, written out so the next change is transcription

**The accept.** An Appendix B-style row for `1e-7`, built through
`build_appendix_b()`'s existing loop shape in `vectors-ai-agent-action/gen_vectors.py`:
the value carried in the tool call's content payload, the expectation naming
`1e-7` as the ECMAScript rendering, condition `aia-c-16`. `1e-7` is not one of
Appendix B Table 1's own rows, so it is added beside the table rather than inside
it, and its row says so: the table is a fixed quotation of the RFC and must not
grow members the RFC does not have.

**The reject twin.** The same value serialized as `0.0000001`, which is the
spelling a rail that does not implement the 1e-6 exponent switch produces. It is
the discriminating case by construction: a rail canonicalizing decimals without
that switch emits exactly these bytes and accepts a payload a conforming rail
refuses. It is also the first member `aia-c-16` has ever had on the reject side,
which is what makes the family measurable at all.

**The sequence, in order, because two of these steps are not reversible by a
later one:**

1. Add both vectors to `vectors-ai-agent-action/gen_vectors.py` and regenerate
   (`python3 vectors-ai-agent-action/gen_vectors.py`, which writes its own
   `MANIFEST.json`).
2. Add both rows to `vectors-ai-agent-action/INDEX.md` **by hand**. That index is
   not generated, unlike `vectors/reject/INDEX.md`, and the regenerability gate's
   `OWNED` tuple does not list it.
3. Run `scripts/surface-leakage-gate.py`, read the fingerprint refusal, and
   re-calibrate with `--sync`. Read the diff: `--sync` rewrites the nulls, and a
   null is a claim about what a permutation of the labels scores.
4. Re-check that the three `blockedBy` declarations are still required. If a
   surface has fallen inside its null, the declaration must be removed in the
   same change -- the gate refuses a declaration that has outlived its subject.
5. Re-run `scripts/count-gate.py`, which will name every published figure that
   moved.

**One caveat that belongs with step 3.** The gate's separability figures are not
fully deterministic: `score_fold` sums logarithms while iterating a `frozenset`,
whose order depends on `PYTHONHASHSEED`, and float addition is not associative.
Measured across twelve fixed seeds, `vectors-scitt-cose/all` spans 0.5265 to
0.5382 -- more than half the 0.02 tolerance -- while most cells are stable to
four places. CI does not pin the seed. Anyone re-calibrating should run the sync
twice and compare, and a figure that moves between runs is the estimator talking,
not the corpus.

## What is held, stated plainly

The `1e-7` accept and its `0.0000001` reject twin are **not in this corpus**, and
this branch does not add them. They belong to `vectors-ai-agent-action`, they
require re-calibrating a published anti-scoreability ratchet for that corpus, and
that re-calibration is a change a reader should be able to review on its own
rather than find inside a branch about the recompute rail and the AEE corpus's
number notation.

A note on provenance, because the identifier has been quoted: the `1e-7` vector
is sometimes referred to as `vf1492a40d7a7c2c9`. **That identifier has never
existed in this repository.** `git log -S vf1492a40d7a7c2c9 --oneline --all` and
`git grep` across all 1172 commits on all refs both return nothing, against a
control (`v1a09354386e0ed57`) that returns three files and two commits in the same
session. Vector identifiers here are digests of the bytes, so an uncommitted
working-tree vector mints no identifier at all. Treat any document citing
`vf1492a40d7a7c2c9` as citing a vector that was written and never landed.
