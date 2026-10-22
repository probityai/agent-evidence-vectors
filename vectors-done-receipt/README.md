# vectors-done-receipt

Suite `done-receipt/v2`. Whole runs of one task and the receipts a verifier wrote for them: a run in each corner of the receipt's two verdicts (done or not, gamed or not), forged receipts, and a defect for every rule of the receipt and of the records it names. Every member declares the five checks' verdicts, the outcome and integrity verdicts over them, and the receipt check's own verdict.

Follows the Done Receipt predicate (spec/predicates/done-receipt.md) and the record rules (spec/predicates/done-records.md).

## Run it

```sh
aee-verify vectors-done-receipt
python -m agent_evidence_vectors.donerun done-receipt/v2 vectors-done-receipt
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-done-receipt/gen_vectors.py`.

Every member is also replayed through probity-verify, the implementation the rules come from: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-done-receipt`. CI runs it on every push.

## Members

Members fall into the verdict classes `supported`, `contradicted`, `not_established`, `invalid` (a receipt its own records do not give) and `refused` (a record or receipt that breaks a rule). The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
