# vectors-done-probes

Suite `done-probes/v1`. What a grader runs beside the acceptance commands: an import probe that reads no answer, the visible test run again inside the candidate's own process, and detectors over the visible test. Every member declares the five checks' verdicts and the outcome and integrity verdicts over them.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Follows the Done Receipt predicate (spec/predicates/done-receipt.md). The rules and the members are recorded from probity-verify's tests at probityai/probity@932c1e3 (`packages/probity-verify/tests/test_out_of_tree_tamper.py` and `test_probe_observed.py`).

## Run it

```sh
aee-verify vectors-done-probes
python -m agent_evidence_vectors.donerun done-probes/v1 vectors-done-probes
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-done-probes/gen_vectors.py`.

Every member is also replayed through probity-verify: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-done-probes`. CI runs it on every push.

## Members

- A probe counts only on a split whose behavioural commands all passed. The import probe reads no answer, so it also counts when its own comparison failed (`failure_kind: assertion`); an import that crashes stays gated, because an honest module can raise on import.
- An in-process twin (`in_process_twin_of`) that exits zero where its isolated run failed on an assertion or on the candidate's own exit contradicts as `in_process_exit_subverted`, a tamper finding. A failure of another kind, a failing twin and a run stopped at its limit are honest divergences, each a member.
- A detector finding that refuses contradicts under its own reason; a measured finding travels as evidence.

Members fall into the verdict classes `supported`, `contradicted` and `not_established`. Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts a reader must reach.
