# External-verifier contract

Implement this contract to compare your AEE verifier with [vectors/MANIFEST.json](../../vectors/MANIFEST.json). Other corpora declare their own [reader routes](corpus-readers.md).

## Invocation and output

The harness invokes `<cmd> <vector-file>` twice with identical arguments: once with `AEE_SUBSTRATE_KEYS` naming a consumer key-policy file, and once with that variable unset.

| Channel or field | Contract |
| --- | --- |
| Last nonempty stdout line | One JSON object on one line. Empty, malformed or non-object output fails. |
| Exit status, no key policy | `0` means valid; nonzero means invalid. A JSON `verdict`, when supplied, must agree. |
| Exit status, pinned policy | The shipped CLI uses admission status, so JSON validity can differ. The harness permits that difference only on this pass. |
| `verdict` | Optional validity string; defaults to exit-derived validity |
| `codes` | Array of condition strings; compared as a set |
| `result` | Recomputed result string when valid |
| `tiers` | Array of evidence-tier strings |
| `primaryCode` | Optional chosen condition for indeterminate-family analysis |
| Key-policy file | `{"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}` |

The command may include flags, such as `aee-verify -validity-only --json`. Present fields are type-checked before scoring. A missing tier or result fails whenever the manifest or a behavior assertion requires it. A timeout or unavailable process does not count as an executed vector.

The shipped CLI once pretty-printed its JSON; on its first harness run it scored 0 of 186. The [external-rail gate](../../scripts/external-rail-gate.py) now runs that pairing in CI. One-line JSON is required even when other stdout lines contain diagnostics.

## Comparison rules

[packaging/run_vectors.py](../../packaging/run_vectors.py) reports two separate comparisons.

| Comparison | Requirements | Report fields |
| --- | --- | --- |
| Normative conformance | Expected validity; accepted result and declared tier columns; key-policy result invariance; invalid output has no result or tiers; corpus self-checks and indeterminate-family rules | Per-row `conformance`, `conformanceReasons`; `totals.conform` |
| Reject reason parity | At least one emitted code intersects `expected.codes`, where declared | Per-row `reasonParity`, `reasonParityFindings`; `totals.reasonParityMismatch` |
| Overall run | Both comparisons, complete verifier execution and corpus-level checks | Per-row `status`; `totals.pass`, `totals.fail`, `totals.suiteRefusals`; exit status |

A verifier can satisfy normative conformance while reporting a reason-parity mismatch. Under the current policy that mismatch still makes the row and run fail. Code order and message text do not affect the reject comparison. `primaryCode` is used only for indeterminate families.

For accepted vectors, the pinned and unpinned passes must match their declared tier columns. Validity and the recomputed result must remain unchanged when the key policy changes. Missing expected columns are failures. A manifest `expected.unmeasurableBecause` exclusion is reported through `declaredExclusion` and `totals.notExercised`; inspect those before describing a whole population as exercised.

### Additional reference emissions

`expected.alsoEmits` records extra codes emitted by the reference rail. [observed-code-closure-gate.py](../../scripts/observed-code-closure-gate.py) checks that complete reference emission set. External outputs are not compared with `alsoEmits`.

The historical measurement before `ok-055` and `bad-986` counted nineteen vectors with 24 unpinned emissions. `bad-817` declared two codes and emitted four; one undeclared emission changed when suiteRevision 28 moved its parent. Those observations motivated the reference-only closure gate.

## Verification stages

The [Go core](../../aee/) applies these stages to statement bytes.

| Stage | Checks |
| --- | --- |
| GATE 0: well-formedness | Statement type and predicate type; result vocabulary; environment members; vocabulary shape, subset and digest; corpus manifest digest and duplicate attack IDs; attack-level coverage; `actualLayer`; substrate subject and digest shape; `runEntropy`; `issuedAt` |
| GATE 1: coverage validity | RFC 6962 batch root with domain separation and no pad-last-node; duplicate and orphaned records; resolving references; canonical RFC 8785/I-JSON `+json` payloads; reserved members and derived run binding; kind-specific arming, sealed and examination constraints; row method capped by the weakest covering `aeeMethod` |
| Recompute | Carried `result` equals the result computed from carried bytes; no signature outcome or consumer policy enters it |
| GATE 2: evidence tier | `declared` for artifact basis; `attested` when all covering records verify against consumer-pinned substrate keys; otherwise `unattested` |

An invalid statement emits no result or tiers. Without pinned keys, every substrate row is `unattested`; keys are never inferred from the predicate. A record's `keyid` is a lookup hint. Signature verification affects the tier, not the recomputed result.

## Failure-code registry

[aee/codes.go](../../aee/codes.go) defines this implementation's code vocabulary. The specification defines conditions; the code spellings belong to this suite.

| Condition | Registry handling |
| --- | --- |
| Missing run-binding input | Its member code, such as `run-entropy-missing` or `subject-sha256-missing` |
| Derivable but unequal binding | `run-binding-mismatch` |
| No `observationRecords` member | `records-absent` |
| Existing records, invalid reference | `ref-out-of-range` |
| Absent, empty or non-array signatures | `record-signatures-empty`, checked before payload decoding in this rail's reading |
| Signature verification failure | Tier outcome |
| Method cap | Covering records only |
| Sealed posture | Pinned-digest and arming-claim equalities checked jointly |

Published spellings and their conditions stay stable. Codes remain available while a published suite revision names them; additions require a specification condition, matching Go/Python spelling, a vector and a suite-revision change. [code-contract-gate.py](../../scripts/code-contract-gate.py) checks the registry and vector coverage.

Only named precedence pins are contractual. Message text is not part of the contract. The signature-array-before-payload ordering is a declared rail reading, handled through indeterminate cases where the specification leaves sequencing open.

## Indeterminate families

An indeterminate member has a determined verdict and named possible readings for its condition. [vectors/indeterminate/INDEX.md](../../vectors/indeterminate/INDEX.md) records the families and deliberately excluded questions; [interpretation-decisions-open.md](../interpretation-decisions-open.md) records the arguments.

| Requirement | Check |
| --- | --- |
| Verdict | Matches the determined invalid verdict; no result or tiers |
| Closure | At least one emitted code matches a condition predicted by a declared reading |
| Coherence | One reading explains the answers across the family |
| Optional commitment | `primaryCode` names the chosen reading's condition. A code-set-only answer is reported as committing to no reading. |

New readings are added by name with an argument. A family must contain members that distinguish its readings. The consumer-policy codes `corpus-anchor-mismatch` and `substrate-anchor-mismatch` remain outside byte-pure validity and cannot be exercised by a single-statement validity vector.

## Statement-layer annotations

`statementLayer` describes an in-toto Statement parser's expected handling separately from AEE validity. The three `aee-c-109` cases omit `predicate`, set it to `null`, or set it to `{}`. An AEE verifier rejects all three with identical codes; a Statement parser accepts them under the framework's optional-predicate rule.

The [upstream Statement text](https://github.com/in-toto/attestation/blob/fd2609c16bcb0ac53443e2b4612977f997e8f9a5/spec/v1/statement.md#L62-L66) and [local statement note](../../spec/v1/statement.md) explain the boundary. [in-toto/attestation#598](https://github.com/in-toto/attestation/pull/598) fixed absent/null handling in the bindings. These annotations do not enter AEE replay scoring; [statement-layer-test.py](../../scripts/statement-layer-test.py) executes them separately.
