# Which structural and rule-mutation checks actually ran for the pinned NIST AI300-1 extraction?

[Report](report.json) · [Original source and output](provenance.json) · [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-nist-ai300-1-checker-2026-10-13)

This packet retains historical evidence from `probityai/agent-evidence-vectors` at
`2212fe0fb413003b1b329e4c4b034c45746f571d`. The [original host run](https://github.com/probityai/agent-evidence-vectors/actions/runs/38361073429)
keeps its own date, command and result. The report reads that original output.
The Atlas reader repeats no original workload.

## What the evidence supports

The [complete report](report.json) keeps the measured fields separate from source
assertions and author reports. The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-nist-ai300-1-checker-2026-10-13)
shows each claim result, the operator roles and the unexercised claims.

- The original Python 3.13.15 host output is retained. This packet does not repeat the checker workload.
- Structural extraction and mutation sensitivity do not establish semantic completeness, NIST certification or compliance
- The population of 235 members over 139 rules comes from the actual checker output. Another current corpus count cannot replace it.
- Reviewer ambiguities and requirements beyond structural checks stay open

## Original result

| Original checker output | Count |
|---|---:|
| Native tests passed | 13 |
| Rows found by both extractions | 157 |
| Members / rules | 235 / 139 |
| Bindings re-derived | 9 |
| Deletion / dropped-condition controls | 143 / 50 |

The original job also records regeneration and a clean source comparison. These are structural and rule controls, with no certification claim.

## Retained bodies

| Body | Source | Stored bytes |
|---|---|---:|
| [jobs.json](jobs.json) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/38361073429/jobs?per_page=100) | 5,905 |
| [job-log.zip](job-log.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/jobs/115175144532/logs) | 6,622 |
| [source/workflows/nist-ai-300-1.yml](source/workflows/nist-ai-300-1.yml) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/.github/workflows/nist-ai-300-1.yml) | 2,361 |
| [source/interop/nist-ai-300-1/README.md](source/interop/nist-ai-300-1/README.md) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/interop/nist-ai-300-1/README.md) | 5,032 |
| [source/interop/nist-ai-300-1/check_vectors.py](source/interop/nist-ai-300-1/check_vectors.py) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/interop/nist-ai-300-1/check_vectors.py) | 14,667 |

Every body has a fixed SHA-256 in [provenance](provenance.json) and in the reader.
The lossless ZIP keeps the complete original public job output, including its original whitespace. The provenance binds the decoded body size and SHA-256. The fixed 1980 container timestamp records packaging, not execution time.

## Check this packet

```sh
python3 experiments/nist-ai300-1-checker-2026-10-13/validate_capsule.py
python3 tools/check_lab.py
```

The first command derives the full report from the retained bodies. It refuses
changed source, changed provenance, duplicate JSON keys and report substitutions.
It executes none of the captured source code. The original pinned workflow and
source keep the procedure for a separate native reproduction.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-nist-ai300-1-checker-2026-10-13)
returns to this packet. New evidence uses the existing
[question and claim intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting).
