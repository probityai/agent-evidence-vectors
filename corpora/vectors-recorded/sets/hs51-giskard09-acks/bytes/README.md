# Optional witness acknowledgements from giskard09 (pilot51, set 2)

giskard09 posted four witness acknowledgements in #51 on 2026-10-20 10:49 UTC
(issuecomment-6289198580), signed with the key published for this role
(`cf3fba883807e4af50522e7d2d80d923445323cee30ef1021002f52f3ec209a1`, argentum-core `387faa8`,
`docs/interop/horizon51-witness/public-key.json`). The key is outside the trust configuration
`d132fe72` (astrogilda and Poke-nushi, threshold 2). These acknowledgements are recorded here
and are not counted toward that threshold. They do not change when call A may start.

| file | item | sha256 of the file |
|---|---|---|
| `ack_budget.jcs` | budget `bde88678…` | `e4026d721866b91165a4039f3059b5eded64ea2f134511baaa98b62e0b6db641` |
| `ack_criteria_A.jcs` | criteria A `d5d272d6…` | `b857f63e73c252e96e1bd31ae672f24c056521bf1a569dcc89f5d74234434711` |
| `ack_criteria_B.jcs` | criteria B `baebf8aa…` | `a711715494c4672c30b0f3fced820edca8ff4dddb4a9f8609aa8f1e4a2474234` |
| `ack_criteria_C.jcs` | criteria C `759d8cf2…` | `4a00d5d67e90ba89dda717f2f91a07e4c686044e3bfc1c62ea24bfb9c5d260c3` |

Each `.jcs` file is the RFC 8785 form of the JSON posted in the issue, with no trailing newline.
Each `.jcs.ots` is giskard09's OpenTimestamps proof from `giskard09/argentum-core@0aa0a37`
(`docs/interop/horizon51-witness/ots/`), upgraded here with the attestation the
alice.btc.calendar.opentimestamps.org calendar served on 2026-10-20. The other three calendars'
pending attestations are kept as they were.

All four proofs reach Bitcoin block 972311:

    hash         00000000000000000000d730593a11364a91a283e4677878b3959906a07ae3c0
    merkle root  665649252a96c48eb1564eb2f9f54f8b77c77fab1bac042cefc36a1a0c5cc248
    time         2026-10-20 11:25:27 UTC

## Check it

    shasum -a 256 ack_*.jcs                 # equals the table, and the "File sha256 hash" ots info prints
    ots info ack_budget.jcs.ots             # BitcoinBlockHeaderAttestation(972311)
    ots verify ack_budget.jcs.ots           # needs a Bitcoin node

## What this shows and does not

The acknowledgements existed no later than 2026-10-20 11:25:27 UTC. The block each one names inside
(`seen_block` 972307) bounds when it was signed from below, as far as the signer chose to read it.
A signature shows which key signed. It does not show that the signer checked anything beyond what
the acknowledgement states.
