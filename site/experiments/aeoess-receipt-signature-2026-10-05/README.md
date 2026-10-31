# Retained AEOESS receipt-signature run

This record retains the public run merged in
[APS conformance PR 154](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/154).
Its original [RUN.md](RUN.md) declares Claude operating under Tymofii Pidlisnyi
(@aeoess)'s revocable mandate, with human review. That is a source declaration.
Atlas does not authenticate the actor, model, review or container custody.

The runner used `@veritasacta/verify` 0.10.21, authored by tomjwxf, through
Probity's adapter and comparison harness. Vectors 0.15.0 was installed from
Git revision `8f81e376bcbf58ff0a27ff97a633e0481b148f79`. This is a historical
source installation; it says nothing about the current registry release.

## What the original run checked

Both runs cover the same 25 receipt fixtures, with and without key windows.
All 25 comparisons pass. The original [first report](report1.json) and
[second report](report2.json) are byte-identical, as are their stdout files.
The expected answers were public. The author harness emitted answers and
grades together; there was no separate raw-result publication before grading.

The runner's thin `digests21.py` script invokes GNU `sha256sum`. Its output
matches all 21 context-free identifier preimages. Four context-bearing
identifiers are explicitly **NOT COVERED**: `v6d872b14889dc9e2`,
`v75158ebfd05a56e5`, `vab0c4dde2038340e` and `ve24bce7210cacee9`.
An Atlas integrity check can recompute all 25 author-defined preimages. It
does not convert the four uncovered checks into outside results.

The always-valid negative control produces eight failures and three SHOULD
refusals. A signature mutation affects five members that share one receipt;
all five fail with `signature_invalid` under both profiles. The explicitly
selected unmodified corpus still passes all 25 members. These are fixture
controls, with author-defined interpretation and grading.

## Retained bytes and validation

[selected-public-source.zip](selected-public-source.zip) contains all 17
original run files, the 31 corpus files plus its original license, and the
host contribution contract and license. Its 51 members retain exact public
Git bytes. [source-manifest.json](source-manifest.json) binds every member to
its repository, revision, source path, Git blob and SHA-256 digest.
The original run's 16 file-digest bindings are also checked.

The original run and host source use Apache-2.0; `host/LICENSE` preserves
Copyright 2026 Tymofii Pidlisnyi. The vectors license is retained at
`corpus/LICENSE`; the pinned revision has no NOTICE file. No original member
is modified. The capsule, manifest, [derived report](report.json),
[provenance](provenance.json) and validator are Atlas additions. Registry
dependencies and runtimes are not redistributed.

Run the data-only retention check from a repository checkout:

```sh
python3 experiments/aeoess-receipt-signature-2026-10-05/validate_capsule.py
```

The checker checks every retained member against the selected manifest,
refuses duplicate JSON names
and nonfinite numbers, compares complete reports and stdout, and checks the
original positive and negative control outcomes. It executes no captured
code and does not rerun the outside verifier. A changed archive, omitted
member or unsupported result stops validation.

## What remains separate

This record supports source-reported outside operation of a different
verifier and 21 primitive identifier checks. The comparison harness,
semantic interpretation and other digest or chain imports remain Probity
implementation. Independent custody, live workload effects, maintained host
jobs and full-family admission are not established. The upstream contract
requires those claims to be evaluated by layer. A merged retained record
makes no endorsement or maintenance commitment.
