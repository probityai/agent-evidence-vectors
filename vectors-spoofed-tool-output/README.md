# vectors-spoofed-tool-output

Suite `spoofed-tool-output/v2`. An agent that prints what a passing run prints and never runs it, against the observer's record: the tool-claim and completion-claim checks, with the near misses that decide whether a reader implements the rules or an approximation of them, stale and shadowed runs, and runs of a sealed command.

Follows `tool_claim_match/v1` and `completion_claim/v1` of the Done Receipt predicate (spec/predicates/done-receipt.md).

## Run it

```sh
aee-verify vectors-spoofed-tool-output
python -m agent_evidence_vectors.donerun spoofed-tool-output/v2 vectors-spoofed-tool-output
```

Both print every member and exit 0 when each behaves as `MANIFEST.json` declares. The reader derives every verdict from the member's records, and the manifest states the same; a named verifier is refused. The corpus regenerates byte for byte with `python vectors-spoofed-tool-output/gen_vectors.py`.

Every member is also replayed through probity-verify, the implementation the rules come from: `uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py vectors-spoofed-tool-output`. CI runs it on every push.

## Members

Members fall into the verdict classes `supported`, `contradicted` and `not_established`. The run prints the count of each; `MANIFEST.json` is where they are derived.

Each manifest row has an `edit` sentence saying what the member changes from the control, and `expected`, the verdicts and codes a reader must reach. A row marked KNOWN LIMIT records what the rule does today and names what covers it.
