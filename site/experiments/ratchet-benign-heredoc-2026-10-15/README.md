# Did the public guard correct a benign document-writing false alarm while keeping destructive-push controls, and which broader replay counts remain author reports?

[Report](report.json) · [Original source and output](provenance.json) · [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ratchet-benign-heredoc-2026-10-15)

This packet retains historical evidence from `probityai/ratchet` at
`b2800b26ec6cf60fee8e95682660846f674f97c2`. The [original host run](https://github.com/probityai/ratchet/actions/runs/38783949790)
keeps its own date, command and result. The report reads that original output.
The Atlas reader repeats no original workload.

## What the evidence supports

The [complete report](report.json) keeps the measured fields separate from source
assertions and author reports. The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ratchet-benign-heredoc-2026-10-15)
shows each claim result, the operator roles and the unexercised claims.

- The 13,739 sessions and 632,126 tool calls are the author's pinned report. They are not an independent measured Atlas run.
- The first reported run had one false alarm: a Python heredoc wrote documentation naming a force push; no push occurred
- The corrected source treats heredoc data separately, handles --mirror and ignores a dry run. The public test source and the default pytest selection bind the regression.
- The hosted suite reports 1,431 tests passed, one skipped and nine deselected. It is not a fresh replay of private historical transcripts.
- This packet copies no private transcript or private source. It does not establish production prevention or revenue.

## Original result

The original public CI reports **1,431 passed, 1 skipped and 9 deselected**.
Its default test source checks the benign document heredoc and the distinct destructive-push controls.

The following counts are the author's dated replay report. Atlas did not repeat the private transcript replay.

| Author report | First run | Corrected guard |
|---|---:|---:|
| Sessions | 13,712 | 13,739 |
| Tool calls | 629,192 | 632,126 |
| Real force pushes / false alarms | 6 / 1 | 6 / 0 |
| Checker crashes | 0 | 0 |

The false alarm was a Python heredoc that wrote documentation containing a force-push command. It made no push. The corrected guard separates data from a shell script, handles `--mirror` and ignores a dry run. The report also counts one unreadable transcript and 118 malformed lines as skipped.

## Retained bodies

| Body | Source | Stored bytes |
|---|---|---:|
| [job.json](job.json) | [Original source](https://api.github.com/repos/probityai/ratchet/actions/jobs/116591068820) | 2,986 |
| [job-log.zip](job-log.zip) | [Original source](https://api.github.com/repos/probityai/ratchet/actions/jobs/116591068820/logs) | 719,825 |
| [source/docs/results/hooks-replay.md](source/docs/results/hooks-replay.md) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/docs/results/hooks-replay.md) | 1,795 |
| [source/pyproject.toml](source/pyproject.toml) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/pyproject.toml) | 3,800 |
| [source/workflows/ci.yml](source/workflows/ci.yml) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/.github/workflows/ci.yml) | 9,335 |
| [source/tests/export/test_example.py](source/tests/export/test_example.py) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/tests/export/test_example.py) | 8,328 |
| [source/examples/claude-code/no_force_push_main.py](source/examples/claude-code/no_force_push_main.py) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/examples/claude-code/no_force_push_main.py) | 13,020 |
| [source/examples/claude-code/hooks/ratchet_no_force_push_main.py](source/examples/claude-code/hooks/ratchet_no_force_push_main.py) | [Original source](https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/examples/claude-code/hooks/ratchet_no_force_push_main.py) | 63,391 |

Every body has a fixed SHA-256 in [provenance](provenance.json) and in the reader.
The original public log uses a lossless ZIP. Its decoded body has 8,008,375 bytes and SHA-256 `e98010c7bfa4ae18e1f8fccc72da7307681ab6833e9ff2ee3b1cf6f2272fce2e`. The fixed 1980 ZIP timestamp records packaging, not execution time. No private transcript is included.

## Check this packet

```sh
python3 experiments/ratchet-benign-heredoc-2026-10-15/validate_capsule.py
python3 tools/check_lab.py
```

The first command derives the full report from the retained bodies. It refuses
changed source, changed provenance, duplicate JSON keys and report substitutions.
It executes none of the captured source code. The original pinned workflow and
source keep the procedure for a separate native reproduction.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ratchet-benign-heredoc-2026-10-15)
returns to this packet. New evidence uses the existing
[question and claim intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting).
