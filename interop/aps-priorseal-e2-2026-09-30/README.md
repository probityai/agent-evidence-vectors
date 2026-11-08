# E2 run record: APS decision evidence to PriorSeal exact-call authorization, independent implementation

Edge E2 of the boundary map in aeoess/agent-governance-vocabulary#179, lab record
Agent-Authority-Conformance/aps-conformance-suite#139. Run 2026-09-30.

## Independence

I authored none of the fixtures and none of the implementations that produced or checked them. `e2check.py`
was written from draft-pidlisnyi-aps-03 (Sections 3.1, 4.1, 5.1 to 5.6), the APS fixture README, the PriorSeal
example README and PriorSeal's `docs/architecture/aps-priorseal-claim-boundary.md`. It imports no APS or
PriorSeal code. RFC 8785 and Ed25519 come from `agent-evidence-vectors==0.15.0` (PyPI); Keccak-256 from
`pycryptodome==3.23.0`. Keys come from `pins.json`; the adjacent `keys.json` is never read for trust.

## Inputs

APS `aeoess/agent-passport-system@948f99b8` `fixtures/priorseal-decision-binding/`; PriorSeal
`imokokok/PriorSeal@d749d269` `examples/aps-priorseal-decision-binding-v1/` and the claim-boundary document.
`fetch_inputs.sh` downloads the 31 files and checks each SHA-256. Reference time 2026-09-19T10:05:00.000Z.

## Results (`RESULTS.json`, 96 rows, one per claim per input)

States are pass, fail, inconclusive, not-exercised, void; a cause is required on the last three. Each
producer's own result is quoted beside ours, never mapped onto it.

| Lab entry | Claim | within-limit | over-limit |
|---|---|---|---|
| 1 | APS evidence under pinned keys at the reference time (manifest, both receipt ids, both signatures, Section 5.3 rules, action_ref, payload_ref, decision_ref, delegation id and signature, time) | all listed claims pass | same |
| 2 | PriorSeal signatures | not-exercised, cause out_of_scope (SPEC-GAPS.md 1) | same |
| 3 | decision_ref correlation | pass | pass |
| 4 | exact call against observation, value from execution.nativeValue | pass | fail: signed 1e15, observed 6e15 |
| 5 | APS cap compliance | pass | fail: 6e15 over the 5e15 per_action cap |
| 6 | the report: SHA-256 pin, then every value recomputed | all recomputed and producer-quoted values agree | same |

All four APS cases recompute on every integrity row. `expired` fails only the reference-time check;
`deny` does not admit dispatch. No result differs from what the producers state (DISAGREEMENTS.md).

## Negatives (`NEGATIVES.json`)

For the four fault classes the thread's table marks "no pinned negative", each negative is one change to the
pinned bytes, re-pinned so it is the only defect; the twin is the unmodified input. Claims resting on bytes
whose integrity failed read void, cause integrity-failure.

| Negative | Result |
|---|---|
| signature-invalid | killed at the decision receipt signature |
| wrong-key (re-signed with an unpinned key that the adjacent keys.json offers) | killed at the same row |
| altered-authorization (transactionValue 1e15 to 6e15, hashes left as signed) | killed at intent-hash consistency |
| altered-authorization-rehashed (every carried intentHash recomputed) | survives at its target, the principal signature, which this checker does not exercise; the PriorSeal-side exact-call check reads it as a match; the cross-check against the APS requested call refuses it |
| decision-ref-unbound (the pair presented with the narrow case's APS evidence) | killed at decision_ref correlation on both payments |
| positive control (issued_at moved 1 ms, not re-signed) | caught |
| inert control (fixture re-serialized, same JSON value) | no state moved |

## Ceiling

Offline synthetic fixtures at a fixed historical time. Nothing here establishes chain execution, live APS
currency, live revocation, decision-level single use, cumulative spend or production use. The APS unit to
PriorSeal asset mapping in entry 5 is this checker's reading (SPEC-GAPS.md 3).

## Rerun

Use Python 3.13.15. From this directory:

```sh
python -m pip install --require-hashes -r requirements-ci.txt
python -m pytest -q test_reproduction.py
sh fetch_inputs.sh
python check_reproduction.py
```

The gate writes reports and variants under the repository's `.build/e2-reproduction/`,
checks all 96 rows and seven controls, and compares both reports byte for byte with
the committed expectations. It preserves the unexercised PriorSeal signatures and
the surviving rehashed negative. A malformed report, changed vocabulary, omitted
control, unsafe output path, or byte difference fails the run. Committed reports
are never regenerated in place. `--inputs` and `--output` accept separate paths;
outputs must remain outside the inputs and this suite.

the `e2_reproduction` job in `.github/workflows/ci.yml` runs the same tests, fetches and SHA-256
checks all 31 inputs, and executes the gate on relevant pushes and pull requests.
It installs version- and hash-pinned dependencies and retains the generated
reports as CI artifacts. This is a reproduction of offline fixture results.

Both outputs reproduced byte for byte from a clean directory before publication (Python 3.13.3).
