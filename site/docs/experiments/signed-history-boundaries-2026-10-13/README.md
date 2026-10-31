# Did the pinned signed-history tests expose genuine signed histories that a signature-only or unanchored reader would accept incorrectly?

[Report](report.json) · [Original source and output](provenance.json) · [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-signed-history-boundaries-2026-10-13)

This packet retains historical evidence from `probityai/agent-evidence-vectors` at
`33d545104ff2f8c124cff465c96c013eeb809156`. The [original host run](https://github.com/probityai/agent-evidence-vectors/actions/runs/38353256915)
keeps its own date, command and result. The report reads that original output.
The Atlas reader repeats no original workload.

## What the evidence supports

The [complete report](report.json) keeps the measured fields separate from source
assertions and author reports. The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-signed-history-boundaries-2026-10-13)
shows each claim result, the operator roles and the unexercised claims.

- Public deterministic test keys and author-generated synthetic histories; independently controlled anchors and custody remain unestablished
- The original output for the case-specific job and the exact executed tests bind the control claims. The default artifact of 285 cases does not.
- Fourteen is the fixture population declared by the source. Fifteen is the actual pytest result, not fifteen independent reproductions.
- No continuous operation, real-world rollback prevention or commercial effect inferred

## Original result

| Executed source control | Result |
|---|---|
| Case-specific native tests | 15 passed |
| Rejected stores whose record signatures remain genuine | 8 |
| Rejections missed by the signature-only reader | 7 |
| Rejections missed without the anchor | 3 |
| Each check disabled, reject-all reader, missing verifier and changed fixture | The selected source tests exercise their required refusals. |

The source declares 14 fixtures. That population stays separate from the 15 executed pytest tests. The unrelated default-corpus artifact is excluded.

## Retained bodies

| Body | Source | Stored bytes |
|---|---|---:|
| [jobs.json](jobs.json) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/38353256915/jobs?per_page=100) | 39,203 |
| [job-log.zip](job-log.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/jobs/115150232069/logs) | 57,609 |
| [source/workflows/ci.yml](source/workflows/ci.yml) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/.github/workflows/ci.yml) | 83,481 |
| [source/vectors-anchored-chain/README.md](source/vectors-anchored-chain/README.md) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/README.md) | 4,332 |
| [source/vectors-anchored-chain/check_vectors.py](source/vectors-anchored-chain/check_vectors.py) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/check_vectors.py) | 466 |
| [source/vectors-anchored-chain/tests/test_corpus.py](source/vectors-anchored-chain/tests/test_corpus.py) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/tests/test_corpus.py) | 5,449 |

Every body has a fixed SHA-256 in [provenance](provenance.json) and in the reader.
The lossless ZIP keeps the complete original public job output, including its original whitespace. The provenance binds the decoded body size and SHA-256. The fixed 1980 container timestamp records packaging, not execution time.

## Check this packet

```sh
python3 experiments/signed-history-boundaries-2026-10-13/validate_capsule.py
python3 tools/check_lab.py
```

The first command derives the full report from the retained bodies. It refuses
changed source, changed provenance, duplicate JSON keys and report substitutions.
It executes none of the captured source code. The original pinned workflow and
source keep the procedure for a separate native reproduction.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-signed-history-boundaries-2026-10-13)
returns to this packet. New evidence uses the existing
[question and claim intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting).
