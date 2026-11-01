# vectors-test-tampering

Suite `test-tampering/v2`. Edits of the files an agent is judged by, the ones an observer sees and the ones it loses: the protected-path check, with controls, edit-and-restore, links in the final tree, and the changes only the final tree shows.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Follows `protected_paths/v1` of the Done Receipt predicate (spec/predicates/done-receipt.md).

## Run it

```sh
aee-verify vectors-test-tampering
python -m agent_evidence_vectors.donerun test-tampering/v2 vectors-test-tampering
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-test-tampering/gen_vectors.py`.

Every member is also replayed through probity-verify, the implementation the rules come from: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-test-tampering`. CI runs it on every push.

## Members

Members fall into the verdict classes `supported`, `contradicted` and `not_established`. The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
