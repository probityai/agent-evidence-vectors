# Source-coverage vectors

Eight synthetic cases for `source_text_coverage/v1`. Each case has a separate
consumer policy, a source capture binding, and a report binding. The expected
decision and reason are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

| Case | Expected decision | Distinction |
| --- | --- | --- |
| complete | supported | The selected passage appears in both bound artifacts. |
| self-hashed-truncation | contradicted | A valid report hash covers truncated bytes. |
| middle-omission | contradicted | A middle passage is absent from an otherwise intact report. |
| returned-after-requested-window | not_established | A June capture cannot establish an April source state. |
| capture-absent | not_established | The named source bytes were never supplied. |
| hidden-script-only | not_established | Script text is outside the selected article. |
| scanner-truncation-reported-clean | contradicted | A scanner prints that it did not open five repositories, then reports a clean account; the last repository's line is not in the record. |
| scanner-complete-scan | supported | The control: the same scan with every repository read. |

Run a verifier that accepts `case.json --policy policy.json --json`:

```sh
python3 vectors-source-coverage/check_vectors.py --verifier './verifier'
```

The wheel supports the same corpus:
`agent-evidence-vectors --corpus vectors-source-coverage --verifier './verifier'`.
The checker verifies fixture bytes and compares each decision and reason.
Regenerate the cases with `python3 vectors-source-coverage/gen_vectors.py`.

CI runs [probity-verify](https://github.com/probityai/probity-verify)
against this corpus. Both are maintained by Probity AI.

The last two cases are a defect and control pair contributed by sushant-me from
[`sushant-me/reputation`](https://github.com/sushant-me/reputation/blob/95717bd/case2_truncation_exit_code.py)
(pinned at `95717bd`), reduced to this contract. The defect arm is not silent: the
record states `truncated: 5 repo(s) not opened` and still ends with the clean
claim, so a verifier that stops at the notice or at the exit status misses the
shape. The pair shares one source and one selected passage.

Passing these synthetic cases does not establish source authority, passage
materiality, or report completeness.
