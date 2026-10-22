# vectors-done-contract

Suite `done-contract/v2`. A sealed contract for a coding agent's task, carried by an unsigned in-toto Statement under the done-contract predicate: valid contracts, one for each optional member the contract may seal, and one invalid contract for every rule of the record and of the statement.

Follows the Done Contract predicate (spec/predicates/done-contract.md) and the record rules (spec/predicates/done-records.md).

## Run it

```sh
aee-verify vectors-done-contract
python -m agent_evidence_vectors.donerun done-contract/v2 vectors-done-contract
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-done-contract/gen_vectors.py`.

Every member is also replayed through probity-verify, the implementation the rules come from: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-done-contract`. CI runs it on every push.

## Members

Members fall into the verdict classes `valid` and `invalid`. The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
