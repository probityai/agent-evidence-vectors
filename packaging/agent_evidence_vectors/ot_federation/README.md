# Building-control decision trails: six claims, 42 cases

This corpus judges decision trails of the `ot-federation-case/v1` shape, the format the
[autonomous-ot-control](https://github.com/darklordVirtual/autonomous-ot-control) testbed uses
for its sealed fixture sets. Each trail records one proposed setpoint change for a zone of a
simulated building: the proposal, the decision, the dispatch, the twin's own operation record, an
observation, and an evidence bundle with its digest. It is for anyone who writes or accepts a
verifier for those trails and wants to know which wrong trails the verifier lets through.

```
pip install agent-evidence-vectors==X.Y.Z
agent-evidence-vectors-ot-federation --output ./ot-federation-run
agent-evidence-vectors-ot-federation --emit-fixtures ./aev-ot-federation
```

The first command judges every case and exits 1 on any answer that differs from the frozen one.
The second writes the cases as an `ot-federation-fixtures/v1` set (a manifest with per-file
SHA-256, a package digest and each case's expected verdict, plus one file per case), so any
verifier that reads that layout runs against them unchanged.

| Claim | ESTABLISHED means |
| --- | --- |
| `decision_correspondence` | The dispatch happened under an approved ACCEPT, or an approved VERIFY or ESCALATE whose reviewer approved, and the envelope or the evidence binds the decision to this proposal. |
| `single_dispatch` | The recorded execution count is exactly one. |
| `call_binding` | The twin's operation record is for this proposal and for the claimed value. |
| `declared_effect_observed` | The twin recorded APPLIED for the claimed zone and value, and the observation shows that value. Each is checked on its own. |
| `observation_after_dispatch` | The observation was made at or after the dispatch, both times recorded. |
| `evidence_digest_integrity` | `evidence_sha256` is the digest the case contract defines (sorted keys, compact separators, `ensure_ascii=False`). |

Missing evidence is `NOT_ESTABLISHED`, never an assumed value. A trail that disagrees with itself is
`CONTRADICTED`. A trail that is not of the schema's shape is `NOT_ESTABLISHED` as malformed, and the
reader never raises on one. Four properties are never established here: that the decision was
authentic, that the capture was complete, that the observer was independent of the deployment
(`--strict-vantage` in the reader leaves the effect unestablished unless the trail records a
separate deployment), and the state of any physical plant.

## Why these cases

A sealed set exercises only the checks its faults touch. A second implementation run against a
12-positive, 10-negative sealed set showed eleven checks that a verifier could drop and still agree
on every case: the reviewer's answer, the envelope and evidence bindings to the proposal, the
twin's status, zone and applied value apart from the observation, a missing observation, the
`ensure_ascii` and `sort_keys` parts of the digest rule, and malformed input. Every one of those has
a case here, and so do the faults the sealed sets already carry.

`scripts/ot-federation-test.py` holds the corpus to that standard. It seeds 33 faults into the
reader, one at a time, and fails unless each is caught by at least one case.

## Files

| File | Purpose |
| --- | --- |
| `corpus/cases.json` | The frozen cases, each with its trail, fault shape and expected answers. Written without sorting keys, so one control keeps its evidence keys unsorted on disk. |
| `corpus/manifest.json` | The sha256 of each corpus member; the runner refuses a changed member. |
| `reader.py` | The reader. Standard library only, importing nothing else from the package, so a network-less sandbox can carry the file alone, checked by its SHA-256. |
| `run.py` | The command-line runner and the fixture-set writer. |

The corpus is written by `scripts/ot-federation-build.py`, never edited by hand; `--check` fails when
it is stale, and the builder refuses to write a case the reader answers differently.

Status: corpus schema `aev-ot-federation-cases/v1`, shipped with the package version above.
