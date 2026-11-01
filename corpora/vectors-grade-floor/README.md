# Evidence grade floor vectors

Cases for `evidence-grade-floor/v1`: the E0-E4 evidence ladder in
[AAIF Observability WG issue #37](https://github.com/aaif/wg-observability-and-traceability/issues/37)
(E0 Declared, E1 Observed, E2 Enforced, E3 Corroborated, E4 Anchored), with
the grade **derived by the consumer** from what the record shows. A grade the
producer declares, and integrity booleans the producer sets about its own
record, never raise it.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Replay from the installed package:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-grade-floor
```

## The rule under test

The reader derives the grade from each observation's `source`,
`relationship`, `observation_vantage` (`substrate` or `artifact`),
`observation_directness` (`intercepted` or `reconstructed`) and
`witness_scope` (`SELF`, `PEER`, `EXTERNAL`), the last three as defined in
[agent-evidence-vocabulary](https://github.com/probityai/agent-evidence-vocabulary).
It also reads the distinct basis engines, the reconciliation state
(`agreement`, `contradiction`, `no_independent_evidence`) and the integrity
marker objects.

| Rung | Requires | Refusal code when missing |
| --- | --- | --- |
| E1 | a `framework` or `gateway` observation not scoped `SELF` | `e1_no_external_observer` |
| E2 | policy enforced at the boundary and a denial recorded by a `substrate`, `intercepted` observer | `e2_no_recorded_denial` |
| E3 | two or more distinct `independent` basis engines, neither a self report nor `SELF` scoped | `e3_insufficient_independent_engines` |
| E4 | external timestamp, chain link and independent verification markers, each an object with its own fields | `e4_missing_external_timestamp`, `e4_missing_chain_link`, `e4_missing_independent_verification` |

The claim floor: an `operationally-conformant` claim needs a derived grade of
E3 or higher (`claim_floor_below_e3`) and a reconciliation state other than
`contradiction` (`claim_floor_contradiction`).

A record is accepted when the derived grade reaches the declared grade and the
claim floor holds. A rejected record names its accepted twin and the rule that
refused it. [INDEX.md](INDEX.md) lists all thirteen members; `MANIFEST.json`
holds the expected `decision`, `derivedGrade` and `reason` for each.

## Tools

- `gen_vectors.py` writes every case, `MANIFEST.json` and `INDEX.md`
  deterministically.
- `check_vectors.py` runs the packaged reference reader, or a named verifier
  with `--verifier "<cmd>"`. The contract: `<cmd> <case-dir>/case.json --json`
  prints `decision`, `derivedGrade` and `reason`, and exits 0 for `accepted`
  and 1 for `rejected`.
- `mutation_check.py` switches off each rule in turn and fails unless some
  rejected member changes its answer, and no accepted member is refused.
