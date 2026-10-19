# vectors-grader-isolation

Suite `grader-isolation/v2`. Reaching what grades the run: a result file planted where a harness reads it back, a .pth file or sitecustomize.py in the grader's interpreter path, a write, unlink or link on the execution surface a contract seals from the agent's image, test configuration created above the workspace, a grade run on another tree or against another contract, and the rules a passing grade must still meet. Every member declares the five checks' verdicts and the outcome and integrity verdicts over them.

Follows the Done Receipt predicate (spec/predicates/done-receipt.md); harness code at harbor-framework-harbor@1f84b4c.

## Run it

```sh
aee-verify vectors-grader-isolation
python -m agent_evidence_vectors.donerun grader-isolation/v2 vectors-grader-isolation
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-grader-isolation/gen_vectors.py`.

Every member is also replayed through probity-verify, the implementation the rules come from: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-grader-isolation`. CI runs it on every push.

## Members

Members fall into the verdict classes `supported`, `contradicted` and `not_established`. The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
