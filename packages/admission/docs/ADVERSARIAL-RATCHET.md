# Adversarial ratchet: the open findings

Every number below is derived by `scripts/ratchet_report.py` from a ratchet ledger and carries the digest it was derived at. None of them is typed, because this count has been quoted by hand elsewhere and has been three different numbers inside six weeks.

**62 open findings** over 39 distinct vector and mutation pairs, across 25 vectors and 8 mutation families, at corpusDigest `8b035678def9` and ledgerDigest `a56bb21f65bc`.

A finding is one vector, one mutation, and one invariant axis. A mutation that breaks the verdict and the caught label is recorded twice, once against each of those axes, because folding it into a single row hides whichever of the two broke second.

## By mutation family

| family | findings |
|---|---|
| `artifact-downgrade` | 32 |
| `coverage-suppress` | 10 |
| `issuedat-future` | 6 |
| `coverage-inflate` | 4 |
| `relabel-clean` | 4 |
| `drop-interception` | 3 |
| `vocab-narrow` | 2 |
| `refs-splice` | 1 |

## By soundness class

| class | findings |
|---|---|
| `S10` | 32 |
| `S3a` | 10 |
| `S7` | 6 |
| `S1` | 4 |
| `S3b/S4` | 4 |
| `S6` | 3 |
| `S2` | 2 |
| `U7` | 1 |

## By invariant axis

| axis | findings |
|---|---|
| `verdict` | 29 |
| `caught-label` | 21 |
| `temporal-distance` | 6 |
| `policy` | 5 |
| `tier` | 1 |

## What this does not carry

Two things are withheld. The mutator code is one: a reader can act on the fact that `artifact-downgrade` defeats a rail without being handed a generator for it. The measured transition is the other, and it ships only when whoever runs the script passes `--include-transitions`, which sets `transitionsIncluded` in the JSON beside this document. That flag reads `false` here.

Everything else is already readable elsewhere. The vector ids are published in the conformance corpus, the family names can be described from the specification text, and the classes and axes are semantics the specification itself defines.

## The findings

| vector | mutation | axis | class |
|---|---|---|---|
| `ok-001-caught-intercepted-fail` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-001-caught-intercepted-fail` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-004-degraded-out-of-scope` | `coverage-inflate` | `policy` | `S3b/S4` |
| `ok-004-degraded-out-of-scope` | `coverage-inflate` | `verdict` | `S3b/S4` |
| `ok-004-degraded-out-of-scope` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-005-degraded-routed-elsewhere` | `coverage-inflate` | `policy` | `S3b/S4` |
| `ok-005-degraded-routed-elsewhere` | `coverage-inflate` | `verdict` | `S3b/S4` |
| `ok-005-degraded-routed-elsewhere` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-008-artifact-fail-closed-method` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-009-artifact-oov-label-fail` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-010-artifact-retired-basis-fail` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-014-three-record-odd-split` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-014-three-record-odd-split` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-014-three-record-odd-split` | `drop-interception` | `policy` | `S6` |
| `ok-014-three-record-odd-split` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-015-four-record-tree` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-015-four-record-tree` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-015-four-record-tree` | `drop-interception` | `policy` | `S6` |
| `ok-015-four-record-tree` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-016-caught-actuallayer-none` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-016-caught-actuallayer-none` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-017-method-weakening-allowed` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-017-method-weakening-allowed` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-020-non-pae-signature` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-020-non-pae-signature` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-021-producer-extra-members` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-021-producer-extra-members` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-024-mixed-basis-rows` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-024-mixed-basis-rows` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-024-mixed-basis-rows` | `refs-splice` | `tier` | `U7` |
| `ok-026-five-record-tree` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-026-five-record-tree` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-026-five-record-tree` | `drop-interception` | `policy` | `S6` |
| `ok-026-five-record-tree` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-027-artifact-missing-method` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-030-method-min-multirecord` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-030-method-min-multirecord` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-031-caught-reconstructed` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-031-caught-reconstructed` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-031-caught-reconstructed` | `coverage-suppress` | `caught-label` | `S3a` |
| `ok-031-caught-reconstructed` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-031-caught-reconstructed` | `relabel-clean` | `caught-label` | `S1` |
| `ok-031-caught-reconstructed` | `relabel-clean` | `verdict` | `S1` |
| `ok-032-method-inferred-retired` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-046-seal-attacks-lower-bound` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-046-seal-attacks-lower-bound` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-048-attribution-paired-despite-expectation` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-048-attribution-paired-despite-expectation` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-049-seal-names-caught-attack` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-049-seal-names-caught-attack` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-053-liveness-probe-uncaught-on-one-channel` | `issuedat-future` | `temporal-distance` | `S7` |
| `ok-054-producer-ordered-axis-inert` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-054-producer-ordered-axis-inert` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-900-fail-outranks-degraded` | `artifact-downgrade` | `caught-label` | `S10` |
| `ok-900-fail-outranks-degraded` | `artifact-downgrade` | `verdict` | `S10` |
| `ok-900-fail-outranks-degraded` | `coverage-suppress` | `caught-label` | `S3a` |
| `ok-900-fail-outranks-degraded` | `coverage-suppress` | `verdict` | `S3a` |
| `ok-900-fail-outranks-degraded` | `relabel-clean` | `caught-label` | `S1` |
| `ok-900-fail-outranks-degraded` | `relabel-clean` | `verdict` | `S1` |
| `ok-900-fail-outranks-degraded` | `vocab-narrow` | `caught-label` | `S2` |
| `ok-900-fail-outranks-degraded` | `vocab-narrow` | `verdict` | `S2` |
| `ok-901-row-missing-basis` | `coverage-suppress` | `verdict` | `S3a` |

Re-derive with `scripts/ratchet_report.py --ledger <ratchet ledger>`. A count in this document that the script does not reproduce is a defect in the document.
