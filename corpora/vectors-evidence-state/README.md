# Evidence-state vectors

Cases for `evidence-state/v1`: one record declares where the evidence about one system
stands, as one of nine codes from the vocabulary term
[`evidence_state`](https://w3id.org/agent-evidence/vocab/v1/evidence_state), beside the
observations that ground it. The reader derives the code from the observations and
refuses a declared code that differs. The headline case is a recurring misreading in incident
records: a silence declared clean (`ES1`) over monitors whose coverage nobody
measured (`ES0`).

| Code | Observable entry condition |
| --- | --- |
| `ES0` | No anomaly recorded; monitor coverage not measured |
| `ES1` | No anomaly recorded; coverage measured |
| `ES2` | At least one anomaly recorded; no declared change-detection threshold crossed |
| `ES3` | Recorded anomalies past a declared change-detection threshold |
| `ES4` | Propagation observed; pathway not identified |
| `ES5` | Pathway identified; scope not yet bounded with containment verified |
| `ES6` | Scope bounded; containment verified |
| `ES7` | Effects confirmed outside the organisation |
| `ES8` | Containment recorded; restart requested |

A record's state is the highest code whose entry condition its observations meet.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who writes incident, monitoring or restart records and wants CI to refuse a
declared state its own observations do not support.

```sh
pip install agent-evidence-vectors
python -m agent_evidence_vectors.evidencestate your-record.json --json
agent-evidence-vectors --corpus vectors-evidence-state
python3 corpora/vectors-evidence-state/check_vectors.py --verifier './verifier'
```

The second line judges your own records, one JSON line each with `decision`, `reason`
and `derivedState`; it exits 1 when any record is denied. The third replays this corpus
through the packaged reader, the fourth through your verifier. A verifier takes
`record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0 for `allow`,
1 for `deny`.

## The record

```json
{
  "assessedAt": "2026-11-02T09:00:00Z",
  "contractId": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evidence-state",
  "evidenceState": "ES1",
  "observations": {
    "anomaliesRecorded": 0, "changeThreshold": 5, "containmentRecorded": false,
    "containmentVerified": false, "coverageMeasured": true,
    "externalEffectsConfirmed": false, "pathwayIdentified": false,
    "propagationObserved": false, "restartRequested": false, "scopeBounded": false
  },
  "recordId": "record-1",
  "system": "agent-system-1"
}
```

`changeThreshold` is a count of at least one, or `null` when none is declared.

## What the cases force

The reader applies eight checks in order and names the first that fails:
`contract_id_missing`, `contract_id_unknown`, `record_malformed`,
`evidence_state_unregistered`, `observations_inconsistent` (a pathway with no observed
propagation, propagation beside no anomaly, containment verified but never recorded),
`clean_without_coverage`, `evidence_state_unsupported` (a code higher than the
observations reach) and `evidence_state_understated` (a code lower than they reach).
Each denied case fails exactly its named check, and every code from `ES0` to `ES8` has
an accepting control. Counts are in `MANIFEST.json`.

## Synthetic, and labelled so

Every member is synthetic. Systems are fixed labels, and no member records a real system
or incident. The manifest says so in `synthetic`.

## What it does not test

Whether the observations are true, which response a state calls for, or whether a
restart should be admitted. The code says what was observed; a relying party decides what
to do with it. Regenerate with `python3 corpora/vectors-evidence-state/gen_vectors.py`.
