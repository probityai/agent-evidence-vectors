# #51 set 2: the trusted witness acknowledgements and their complete OpenTimestamps proofs

The eight acknowledgements under trust `d132fe72…` (threshold 2) for the #51 set 2 run of 2026-10-22, with their
upgraded OpenTimestamps proofs. The same acknowledgements, with the proof paths reduced to their Bitcoin
attestation, are inside `../set2/bundle.json`. The optional acknowledgements by giskard09 are in `../witness-giskard09/`.

| witness | key | ack seen_block | Bitcoin attestations of each `.ots` (header time, UTC) |
|---|---|---|---|
| astrogilda | `58c98ed4…` | 972388 (2026-10-20T22:47:31Z) | 972403 (2026-10-21T02:01:04Z), 972405 (02:14:41Z) |
| Poke-nushi | `d6f6ca92…` | 972415 (2026-10-21T04:03:21Z) | 972423 (2026-10-21T05:46:32Z), 972425 (05:51:23Z) |

Each `.jcs` file is the RFC 8785 bytes of one acknowledgement (statements: budget `bde88678…`, criteria A
`d5d272d6…`, B `baebf8aa…`, C `759d8cf2…`). The witnesses signed them; we stamped them. Every anchor height is
above the ack's seen_block and below 972546, the seen_block of the first call. Check a proof with
`ots verify -f ack_budget.jcs ack_budget.jcs.ots` against your own node, or read its attestations with `ots info`.
The header times above are the nTime field of the headers in `../set2/bundle.json`.
