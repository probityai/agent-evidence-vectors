# W3C intake criteria checker

The W3C public-agent-conformance community group set intake criteria for a submitted conformance result: version 2 in [2026Oct/0067](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0067.html), with wording changes accepted in [0070](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0070.html) and [0075](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0075.html) and the explicit field announced in [0073](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0073.html). The criterion-6 consumed state was proposed in [0090](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0090.html) and measured in [0091](https://lists.w3.org/Archives/Public/public-agent-conformance/2026Oct/0091.html). This page covers the corpus that turns those criteria into tests and the reader that applies them.

## The corpus

[`vectors-w3c-intake/`](../../vectors-w3c-intake/INDEX.md) holds 48 rejection grounds, `W3C-I-001` to `W3C-I-048`. The manifest binds each ground by sha256 to the exact sentence of the list message it comes from. The corpus has 137 members: 53 records an intake reader must admit and 84 it must refuse. Every ground has at least one of each. Criterion 13 ("the criteria name no implementation") has no ground: an intake reader shows that it applies the criteria by giving the expected answer on every member, whatever its code.

Three grounds come from the criterion-6 consumed state. W3C-I-046 refuses a record that does not say, for every file of the package beside its members and manifest, whether a check consumed it. W3C-I-047 refuses a consumed state the swap-and-re-pin test contradicts: replace the file's bytes, move every pin that covers it, rerun the checker, and compare the complete native result with the baseline. A file whose swap leaves that result unchanged is unconsumed, however often it was opened. W3C-I-048 refuses an unconsumed file whose record does not name the ground that refuses its swap while its pin stays.

Criterion 7's anchor can be a signed digest list. The record then names the signature file, the public key file and its sha256, and the scheme (`ed25519`). The reader verifies the signature over the list's exact bytes with no library installed. Locating the anchor line is not checking the anchor. A missing signature or key is an availability failure (W3C-I-023). A signature that does not verify, or a key that is not the pinned one, is an integrity failure (W3C-I-024). The corpus refuses three consistent rewrites under W3C-I-024: a member edited, a member deleted, and the list re-signed under another key, each with every digest re-pinned to match.

## The readers

Two readers in this repository judge the corpus. They print byte-identical output, and `scripts/w3c-intake-parity-test.py` holds them together over the committed corpus and mutated copies of it.

```sh
PYTHONPATH=packaging python -m agent_evidence_vectors.w3cintake --judge vectors-w3c-intake
GOWORK=off go build -o aee-verify ./cmd/aee-verify && ./aee-verify vectors-w3c-intake
```

To check a single record: `python -m agent_evidence_vectors.w3cintake <record.json> --root <dir>`. Exit `0` means admitted, `1` refused (each ground is named), and `2` means the record could not be read. Checks that read bytes on disk run only with `--root`. The output says which ran.

## Intake records for every corpus here

`scripts/gen-intake-records.py` runs each corpus's own checker and writes [`release/intake/<corpus>.intake.json`](../../release/intake/), one record per corpus in `release/CORPUS-DIGESTS.txt`, keeping the checker's native output under `release/intake/native/`. Each record declares the relationship of the reader that ran it. The relationship is the same implementation for our own runner, with the expected answers visible. A non-author reader is declared where one has been run: DSHCorrectover/independent-reader, which derived its rules from this repository's source, ran on release 0.17.6. Each record also lists the corpus's other tracked files as artifacts, each with the consumed state that the swap-and-re-pin test measures. Its anchor names the digest routine's file and becomes a signed digest list exactly when `release/CORPUS-DIGESTS.txt` verifies under `release/cosign.pub`. On a candidate tree the list has changed since the last release signed it, so the records say the anchor is a located line, not a verified one. The release commit regenerates them after signing ([RELEASING.md](../../RELEASING.md)). `--check` reruns every checker and refuses any difference, and CI runs it.

A rerun by anyone else, with the reader's relationship stated, can be reported through the [independent-run form](../guides/report-run.md).
