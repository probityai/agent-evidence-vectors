# vectors-test-tampering

Suite `test-tampering/v1`. Edits of the files an agent is judged by, the ones an observer sees and the ones it loses: the protected-path check, with controls, edit-and-restore, and the changes only the final tree shows. The members whose id starts `recorded-` are read from runs of a real launcher, kept in `vectors-done-receipt/recorded/`.

Follows the protected_paths/v1 of the Done Receipt predicate (spec/predicates/done-receipt.md).

## Run it

```sh
aee-verify vectors-test-tampering
python -m agent_evidence_vectors.donerun test-tampering/v1 vectors-test-tampering
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-test-tampering/gen_vectors.py`.

The checks are also replayed through an independent implementation: `python vectors-done-receipt/crosscheck_probity_verify.py vectors-test-tampering` with `probity-verify` installed.

## Members

| verdict | count |
| --- | --- |
| `contradicted` | 23 |
| `not_established` | 6 |
| `supported` | 9 |

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
