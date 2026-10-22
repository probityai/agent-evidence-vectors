# vectors-test-tampering

Suite `test-tampering/v2`. Edits of the files an agent is judged by, the ones an observer sees and the ones it loses: the protected-path check, with controls, edit-and-restore, links in the final tree, and the changes only the final tree shows.

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
