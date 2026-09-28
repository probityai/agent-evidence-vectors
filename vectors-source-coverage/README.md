# Source-coverage vectors

Six synthetic cases for `source_text_coverage/v1`. Each case has a separate
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

Run a verifier through the CLI contract:

```sh
python3 vectors-source-coverage/check_vectors.py --verifier 'probity-verify'
```

The checker executes the named program for every vector and reports the count.
It checks the committed fixture bytes before invoking the verifier. Regenerate
the cases with `python3 vectors-source-coverage/gen_vectors.py`.

This corpus was authored by the same team as `probity-verify`. Passing it
demonstrates these cases, not independent corroboration of the archive, source
authority, materiality of selected passages, or general completeness.
