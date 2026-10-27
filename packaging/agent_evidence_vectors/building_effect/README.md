# Building-automation effect evidence: four fault shapes, six axes

This corpus judges one commanded change to a building plant point (an air-handler setpoint, a chilled-water valve position, a heat-pump start) from the trail a verifier would read. It is for people who accept or build verifiers for building and industrial control agents and want to know which wrong trails their verifier lets through.

Install it as a pinned dependency and run it:

```
pip install agent-evidence-vectors==X.Y.Z
agent-evidence-vectors-building-effect --output ./building-effect-run
```

The command prints the case count and the ids of any case whose answer differs from the frozen one, and exits 1 on a mismatch.

Each trail is judged on six axes. An answer is `ESTABLISHED`, `CONTRADICTED` or `NOT_ESTABLISHED`.

| Axis | ESTABLISHED means | Fault shape it catches |
| --- | --- | --- |
| `dispatch_count` | Exactly one dispatch began. | A retried command: the state cannot be attributed to one act. |
| `authority_at_dispatch` | An approval was in force at the latest dispatch. | An approval that survives a pause. |
| `observation_after_dispatch` | A read was sampled at or after the latest dispatch. | An observation that predates a retried dispatch. |
| `observation_freshness` | The confirming read is live and recorded close to when it was taken. | A stale or cached read counted as confirmation. |
| `observed_effect` | A live read after the latest dispatch shows the declared value. | A missing observation read as clean. |
| `observation_vantage` | The read came from a reader other than the dispatcher. | A read from the same deployment, under `strict_vantage`. |

`effect_confirmed` is derived: `ESTABLISHED` only when every axis is, `CONTRADICTED` when any axis is. A trail's own `claimed_clean` field is never read. Times are integer seconds and the files are strict JSON with no floats.

The vantage axis carries a finding from a public edge run: every trail it produced declares `same_deployment` for its reader, so under `strict_vantage` the `declared_effect_observed` property is `NOT_ESTABLISHED`. The case `vantage_same_deployment_strict` holds that shape, and `vantage_same_deployment_lenient` shows the same trail passing when the verifier does not ask for a separate deployment.

Three properties are never established here: sensor calibration, the physical state beyond the point, and the reader's independence from the building itself.

Status: corpus schema `aev-building-effect-cases/v1`, shipped with the package version above.

## Files

| File | Purpose |
| --- | --- |
| `corpus/cases.json` | The frozen cases, each with its trail, fault shape and expected answers. |
| `corpus/manifest.json` | The sha256 of each corpus member; the runner refuses a changed member. |
| `reader.py` | The pure-Python reader. |
| `run.py` | The command-line runner. |

The corpus is written by `scripts/building-effect-build.py`, never edited by hand, and `--check` fails when it is stale.
