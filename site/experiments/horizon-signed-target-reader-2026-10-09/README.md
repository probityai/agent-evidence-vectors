# What did the outside host CI establish about the supplied signed records and exact endpoint, and what remained unobserved?

[Report](report.json) · [Original source and output](provenance.json) · [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-horizon-signed-target-reader-2026-10-09)

This packet retains historical evidence from `ogasurfproject-jpg/horizon-shield` at
`c71095f3062c7411b3a7ed5c628733daf004ba9b`. The [original host run](https://github.com/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273)
keeps its own date, command and result. The report reads that original output.
The Atlas reader repeats no original workload.

## What the evidence supports

The [complete report](report.json) keeps the measured fields separate from source
assertions and author reports. The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-horizon-signed-target-reader-2026-10-09)
shows each claim result, the operator roles and the unexercised claims.

- Host CI actor is separately established by GitHub metadata; the output operator string is caller-declared and unauthenticated
- The original signed-record assertions remain producer-declared: pair A has seven true assertions and one unevaluated assertion.
- Both ledger fetches returned HTTP 403. A successful job does not establish successful ledger acquisition.
- No new walk, response correctness, historical key control, independent custody, production effect or paid use established

## Original result

| Retained read | Result |
|---|---|
| Ten recorded command exits | Every actual exit matched its expected exit, including the refusal controls. |
| A record, exact A2A target | Signature verifies under the pinned key; target matches. Seven assertions are true and one is unevaluated. |
| B record, selected A2A target | Signature verifies; its signed purpose names MCP, so the reader reports `TARGET_MISMATCH`. |
| Ledger fetches | Both returned HTTP 403. The successful job does not establish successful ledger acquisition. |

## Retained bodies

| Body | Source | Stored bytes |
|---|---|---:|
| [repository.json](repository.json) | [Original source](https://api.github.com/repos/ogasurfproject-jpg/horizon-shield) | 6,354 |
| [run.json](run.json) | [Original source](https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273) | 14,877 |
| [jobs.json](jobs.json) | [Original source](https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273/jobs?per_page=100) | 2,942 |
| [workflow.yml](workflow.yml) | [Original source](https://raw.githubusercontent.com/ogasurfproject-jpg/horizon-shield/c71095f3062c7411b3a7ed5c628733daf004ba9b/.github/workflows/probity-witness-reader.yml) | 4,168 |
| [artifact.zip](artifact.zip) | [Original source](https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/artifacts/11616887017/zip) | 13,061 |
| [job-log.zip](job-log.zip) | [Original source](https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/jobs/113824012738/logs) | 6,835 |

Every body has a fixed SHA-256 in [provenance](provenance.json) and in the reader.
The provider ZIP artifact keeps its original bytes. The separate job-log ZIP preserves the original log byte for byte, including whitespace. Its decoded SHA-256 is explicit; its fixed 1980 container timestamp is packaging, not execution time.

## Check this packet

```sh
python3 experiments/horizon-signed-target-reader-2026-10-09/validate_capsule.py
python3 tools/check_lab.py
```

The first command derives the full report from the retained bodies. It refuses
changed source, changed provenance, duplicate JSON keys and report substitutions.
It executes none of the captured source code. The original pinned workflow and
source keep the procedure for a separate native reproduction.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-horizon-signed-target-reader-2026-10-09)
returns to this packet. New evidence uses the existing
[question and claim intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting).
