# Original tool-argument CPU evidence

This directory retains the exact native provider ZIP for Observer run
[37116827382](https://github.com/probityai/agent-evidence-observer/actions/runs/37116827382),
its byte-identical report, a selected source contract and complete native member
inventory. [Claims P-51–P-56](../../CLAIMS.md) record the sources and limits.

All 128 planned calls started and scored. The 24-token cap reaches length in
all 64 calls; none of those outputs is valid JSON. All 64 outputs at the
96-token cap satisfy their selected schema. At the long cap, the smaller model
scores 0/16 in each mode; the larger model scores 7/16 in each mode. Every row
has zero correct abstentions and zero fully correct pairs. All eight strict
quality rows hold. Scoped evidence publication is a separate decision.

Re-derive the retained population, raw-response verdicts and source selection
from the repository root:

```sh
python3 tools/check_lab.py
python3 -m pytest -q tests/test_tool_argument_retention.py
```

These commands read selected data only. They do not import packet code, load
weights, install its runtime or make model calls. The retention tests also
check every earlier Lab record and artifact byte against the Atlas baseline.

The original ZIP is 2,639,358 bytes, SHA-256
`67ef1e638e814c71bbf354fe9895ea0faf5d9ef11eae2ff76b10b065bd7a7e54`.
All 331 members are retained without omission. The full preparation provider
artifact is 1,051,848,146 bytes and is not retained here; it includes the
selected archive, extracted model/dependency/source payloads and installed
environment. Its provider metadata and hash are recorded in provenance.
Hashes cannot reconstruct those omitted preparation bytes. Provider artifacts
expire on 2027-01-01 at 10:33:56 UTC. Git retains this native original separately.

Authored tasks, answers and thresholds are exposed. Native measurement,
selected source custody, quality acceptance, model-action authority, outside
producer acceptance, recurring adoption and independent effect custody remain
separate. This Atlas record establishes none of the outside acceptance or
custody axes.
