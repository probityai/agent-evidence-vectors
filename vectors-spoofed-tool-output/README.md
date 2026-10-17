# vectors-spoofed-tool-output

Suite `spoofed-tool-output/v1`. An agent that prints what a passing run prints and never runs it, against the observer's record: the tool-claim check, with the near misses that decide whether a reader implements the rule or an approximation of it. The members whose id starts `recorded-` are read from runs of a real launcher, kept in `vectors-done-receipt/recorded/`.

Follows the tool_claim_match/v1 of the Done Receipt predicate (spec/predicates/done-receipt.md).

## Run it

```sh
aee-verify vectors-spoofed-tool-output
python -m agent_evidence_vectors.donerun spoofed-tool-output/v1 vectors-spoofed-tool-output
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-spoofed-tool-output/gen_vectors.py`.

The checks are also replayed through an independent implementation: `python vectors-done-receipt/crosscheck_probity_verify.py vectors-spoofed-tool-output` with `probity-verify` installed.

## Members

| verdict | count |
| --- | --- |
| `contradicted` | 17 |
| `not_established` | 11 |
| `supported` | 10 |

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
