# vectors-done-contract

Suite `done-contract/v1`. A sealed contract for a coding agent's task, carried by an unsigned in-toto Statement under the done-contract predicate: valid contracts and one invalid contract for every rule of the record and of the statement.

Follows the Done Contract predicate (spec/predicates/done-contract.md) and the record rules (spec/predicates/done-records.md).

## Run it

```sh
aee-verify vectors-done-contract
python -m agent_evidence_vectors.donerun done-contract/v1 vectors-done-contract
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-done-contract/gen_vectors.py`.

## Members

| verdict | count |
| --- | --- |
| `invalid` | 40 |
| `valid` | 6 |

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
