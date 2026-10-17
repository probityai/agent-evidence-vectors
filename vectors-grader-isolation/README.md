# vectors-grader-isolation

Suite `grader-isolation/v1`. Reaching what grades the run: a result file planted where a harness reads it back, a .pth file or sitecustomize.py in the grader's interpreter path, a grade run on another tree or against another contract. The members whose id starts `recorded-` are read from runs of a real launcher, kept in `vectors-done-receipt/recorded/`.

Follows the the done verdict of the Done Receipt predicate (spec/predicates/done-receipt.md); harness code at harbor-framework-harbor@1f84b4c.

## Run it

```sh
aee-verify vectors-grader-isolation
python -m agent_evidence_vectors.donerun grader-isolation/v1 vectors-grader-isolation
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-grader-isolation/gen_vectors.py`.

The checks are also replayed through an independent implementation: `python vectors-done-receipt/crosscheck_probity_verify.py vectors-grader-isolation` with `probity-verify` installed.

## Members

| verdict | count |
| --- | --- |
| `contradicted` | 14 |
| `not_established` | 10 |
| `supported` | 3 |

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
