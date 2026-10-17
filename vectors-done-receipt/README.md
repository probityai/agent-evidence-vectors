# vectors-done-receipt

Suite `done-receipt/v1`. Whole runs of one task and the receipts a verifier wrote for them: honest and dishonest runs, runs recorded from a real launcher, and a defect for every rule of the receipt and of the records it names. The members whose id starts `recorded-` are read from runs of a real launcher, kept in `vectors-done-receipt/recorded/`.

Follows the Done Receipt predicate (spec/predicates/done-receipt.md) and the record rules (spec/predicates/done-records.md).

## Run it

```sh
aee-verify vectors-done-receipt
python -m agent_evidence_vectors.donerun done-receipt/v1 vectors-done-receipt
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-done-receipt/gen_vectors.py`.

The checks are also replayed through an independent implementation: `python vectors-done-receipt/crosscheck_probity_verify.py vectors-done-receipt` with `probity-verify` installed.

## Members

Members fall into five verdict classes: `supported`, `contradicted`, `not_established`, `invalid` and `refused`. The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
