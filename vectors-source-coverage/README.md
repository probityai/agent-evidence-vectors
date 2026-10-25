# Source-coverage vectors

Eight synthetic cases for `source_text_coverage/v1`. Each case has a separate
consumer policy, a source capture binding, and a report binding. The expected
decision and reason are in `MANIFEST.json`.

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
