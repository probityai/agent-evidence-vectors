# Independent run record: receipt-signature corpus with @veritasacta/verify 0.10.21

A run of the `vectors-receipt-signature` corpus of `probityai/agent-evidence-vectors` through tomjwxf's `@veritasacta/verify`, for the receipt-signature family proposed in #137. This record changes nothing in that repository.

| field | value |
|---|---|
| who ran it | Claude, operating under a revocable mandate from Tymofii Pidlisnyi (@aeoess), who reviewed and is accountable for this record. Run on 2026-10-05 (UTC) in an isolated Linux container |
| corpus | `probityai/agent-evidence-vectors` at `8f81e376bcbf58ff0a27ff97a633e0481b148f79`, `vectors-receipt-signature/`, 25 members. The member files were written by giskard09, tomjwxf and astrogilda, as the corpus README states under "Where the members come from". Neither Claude nor @aeoess authored the member files, adapter, harness or verifier |
| harness | `agent-evidence-vectors` 0.15.0, installed from that commit (0.15.0 was not on PyPI at run time), on Python 3.13.13. It runs the corpus shipped inside the package. `corpus-identity.txt` and `shipped-corpus-sha256.txt` show every shipped corpus file is byte-identical to the pinned tree, which adds only tooling files |
| adapter | `vectors-receipt-signature/tools/veritasacta-verify.py` at the same commit, SHA-256 `97160a53bf23ee4ad319ffd3054cc9302138986f7730ec3a25f98a77b1c51c34`, written by astrogilda |
| implementation | `@veritasacta/verify` 0.10.21 from npm, integrity `sha512-48roJsv+GsS9v5KiQA7RKL9qCqZ13e8ohQYJhM9Alr6xCB0U7MRy+zXiYeQC2aop9ve0Uage4kN/TlwrqgPi5A==`, written by tomjwxf, on Node.js 22.22.2, selected by the adapter with `VERITASACTA_VERIFY_VERSION=0.10.21` |
| command | `agent-evidence-vectors --corpus vectors-receipt-signature --verifier 'python3 vectors-receipt-signature/tools/veritasacta-verify.py'`, from the repository root |

## Verification split

- receipt-verification outcomes for the 25 members, in both passes (with and without key validity windows); Claude for @aeoess; Mode B; independent; `@veritasacta/verify` 0.10.21 through the corpus adapter. Some members are refused before any signature is checked, so these are verification outcomes, not signature checks alone. Neither Claude nor @aeoess authored the member files, adapter, harness or verifier.
- member identifiers for the 21 members without a context, recomputed as `v` followed by the first 16 hex digits of the SHA-256 of the receipt file's bytes; Claude for @aeoess; Mode B; independent; GNU coreutils `sha256sum`, invoked by `digests21.py`, which only reads the manifest, passes each file to `sha256sum` and compares strings.

Not covered by this record: the identifiers of the 4 members with a context (`v6d872b14889dc9e2`, `v75158ebfd05a56e5`, `vab0c4dde2038340e`, `ve24bce7210cacee9`), whose preimage adds a canonicalized context and a commitment that the runner's code would have to construct, any other digest or chain-binding claim the family may import, and the harness's own reference verification and grading, which is astrogilda's code. Whether these layers satisfy the family's admission is for the family PR to map.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Result

`run1.txt`: `totals: 25 vectors, 25 pass, 0 not honouring a SHOULD, 0 closing a gap, 0 fail`, exit 0. The verifier answered all 25 members in both passes, and every outcome equals the corpus README's table for 0.10.21. A second run (`run2.txt`, `report2.json`) is byte-identical to the first: report SHA-256 `0e63176501c98c8c947bef3410f2766b99acc0ad4c5d2069b38eaee04fe735b5`, output SHA-256 `739f1526cda624422308065176f02a203c8ffe417cfe518433db405e872f9510`. `digests21.txt`: 21 of 21 identifiers match.

## Negative controls

1. `always_valid.py`, a stub verifier that answers `valid` for every member: exit 1, `25 vectors, 14 pass, 3 not honouring a SHOULD, 0 closing a gap, 8 fail` (`ctrl1.txt`). The harness detects a verifier that accepts everything.
2. `ctrl2-mutation.sh` flips one character of `sig` in a copy of `receipts/v814de39bf68212fc.json`, an accept member, and `ctrl2-run-on-mutated-copy.sh` runs the harness with `--vectors` over that copy: exit 1, and `@veritasacta/verify` answers `invalid signature_invalid` for that member in both passes (`ctrl2.txt`). The same `--vectors` path over the unmodified copy passes 25 of 25 (`ctrl2ok.txt`). This control shows that the verifier checks the signature bytes on this accepted-member path. Without `--vectors`, the harness reads the shipped corpus and ignores a modified working tree, which is why this control uses it.

## What this record does not establish

It is not an evaluation of `@veritasacta/verify` beyond these 25 members, and not an adoption or endorsement statement about any project. The run used Node.js 22.22.2, not the 24.19.0 of the corpus README's observed run. The control scripts carry the container paths they ran with.

## Files

`run1.txt`, `run2.txt`, `report1.json`, `report2.json`, `digests21.py`, `digests21.txt`, `sha256sum-version.txt`, `corpus-identity.txt`, `shipped-corpus-sha256.txt`, `always_valid.py`, `ctrl1.txt`, `ctrl2-mutation.sh`, `ctrl2-run-on-mutated-copy.sh`, `ctrl2.txt`, `ctrl2ok.txt`, and `SHA256SUMS.txt` over all of them and this file.
