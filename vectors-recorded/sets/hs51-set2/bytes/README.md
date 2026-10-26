# #51 set 2: the companion log, its anchor and the settlement (2026-10-22)

The run of 2026-10-22 00:00 to 03:00 UTC (horizon-shield #51): calls A, B and C from the buyer
`4c3b54ac…` to the responder `7b1ada68…`, each priced at 7000 JPY-testnet against a budget of 20000.

| file | what it is |
|---|---|
| `log/entries.jsonl`, `log/entries/` | the 13 companion log entries, in order (budget, criteria A, B, C, then use, payment and receipt for A, B and C) |
| `log/checkpoint.json` | the signed checkpoint: size 13, head `746eba10…`, as_of 2026-10-22T00:11:06Z |
| `log/checkpoint.stamp`, `log/checkpoint.stamp.ots` | the same bytes as the checkpoint, and their OpenTimestamps proof (Bitcoin blocks 972551 and 972552) |
| `bundle.json` | the companion v0.1 bundle built from the files above, the witness acknowledgements and a header view of blocks 972238 to 972559 |
| `settlement.json` | `pilot_v0.py --settle bundle.json`, without the trailing newline |

Recompute the settlement with your own copy of the code (Python 3.11 or later; ca2a-runtime 0.4.0 brings rfc8785
and cryptography):

    cd workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0 && python3 -m venv /tmp/p51 && /tmp/p51/bin/pip install ca2a-runtime==0.4.0 && /tmp/p51/bin/python pilot_v0.py --settle pilot51/set2/bundle.json | shasum -a 256

The expected sha256 of that output (with its newline) is
`18a19f8a1eb62593b857241f34c07b1d96550b93d5c9ea17184b2ac695818fbd`.
The settlement says: the log verifies (anchored at 972551, depth 9 in this view), payments A and B have no
reasons, payment C has `budget_exceeded` (total 21000 against 20000), and the three executions are
`within_delegation`.

The raw call files (request bodies, responses and the audit bytes) are not here. Their sha256 values are in
the log entries. The audit bytes are shared privately with the acceptance checker, and nothing more is
published until everyone in #51 agrees.

The header view in `bundle.json` was taken from mempool.space on 2026-10-22 at 03:2x UTC. Each header's hash
was recomputed and equals its block id, and the top hash was checked against blockstream.info. Build your own
view from your own node to check it independently.
