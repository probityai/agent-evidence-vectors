# IETF agent-record drafts conformance vectors

Emitted by `gen_vectors.py`. Do not edit: the next build overwrites it.

Corpus digest: `b080bfb0df5a6929d83d5b94cd6654fe4c05945f12df37d8dbe03d9253d39468`

## draft-emirdag-scitt-ai-agent-execution-01

| member | verdict | code | under the draft's own steps | what it carries | parent |
| --- | --- | --- | --- | --- | --- |
| [`air-genesis`](cases/v619036653b6d7369.json) | valid |  | valid | the first record of agent-pay-01's chain: sequence 0, prev_chain_hash all zero |  |
| [`air-follows`](cases/v8eb997c4e82b6312.json) | valid |  | valid | record 1, whose prev_chain_hash is record 0's chain_hash |  |
| [`air-third-follows`](cases/v059494e0bdc24d98.json) | valid |  | valid | record 2 after records 0 and 1, timestamped one minute after record 1 |  |
| [`air-prev-chain-hash-mismatch`](cases/vab2f9e4fc1ca6b44.json) | invalid | `prev-chain-hash-mismatch` | valid | record 1 whose prev_chain_hash is the chain_hash of another agent's record, not record 0's; Section 5.8 takes the preceding chain_hash as input and never compares it | `air-follows` |
| [`air-two-records-one-position`](cases/v1c3e1aeefe89445a.json) | invalid | `chain-position-equivocation` | valid | two records, completed and failed, both at sequence 1 over record 0 and both signed by the Issuer; each passes Section 5.8 on its own | `air-follows` |
| [`air-timestamp-before-predecessor`](cases/v7ed4d3fdd37eef96.json) | invalid | `timestamp-regression` | valid | record 2 whose action_timestamp_ms, in the header and the payload alike, is one day before record 0's; Section 6.3 checks only captured time against action time | `air-third-follows` |
| [`air-header-payload-time-differ`](cases/v27bcb59c03bb551a.json) | invalid | `header-payload-disagree` | valid | record 2 whose header action_timestamp_ms, the value bound into chain_hash, is a minute before the payload's | `air-third-follows` |
| [`air-content-hash-mismatch`](cases/v8e112d2716472d27.json) | invalid | `content-hash-mismatch` | invalid | record 1 whose header content_hash is the hash of a payload it does not carry | `air-follows` |
| [`air-chain-hash-mismatch`](cases/vd3794ac0671808f2.json) | invalid | `chain-hash-mismatch` | invalid | record 1 whose chain_hash takes action_timestamp_ms little-endian, against the big-endian encoding Section 5.7 pins | `air-follows` |
| [`air-sequence-gap`](cases/vdc35eea744fd7224.json) | invalid | `sequence-gap` | invalid | a record at sequence 2 directly after record 0 | `air-follows` |
| [`air-signed-by-other-key`](cases/v9af0955e6f118541.json) | invalid | `signature-invalid` | invalid | record 1 signed by a P-256 key other than the operator's registered one | `air-follows` |
| [`air-cwt-sub-missing`](cases/veb528a11595d1920.json) | malformed | `cose-malformed` | malformed | record 0 whose CWT Claims carry iss and no sub, which Section 5.5 requires | `air-genesis` |

| rule | what it requires |
| --- | --- |
| `cose-shape` | COSE_Sign1 under tag 18, alg -7, a kid, and CWT Claims carrying iss and sub (Section 5.5) |
| `signature` | the ES256 signature verifies under the operator's registered key |
| `content-hash` | content_hash is SHA-256 over the payload bytes (Section 5.7) |
| `chain-hash` | chain_hash is SHA-256 over the 76 + len(agent_id) byte pre-image of Section 5.7 |
| `sequence` | sequence_number is one more than the preceding record's, or zero first (Section 5.8 step 4) |
| `header-payload` | the header's action_timestamp_ms and agent_id equal the payload's [corpus] |
| `prev-chain-link` | prev_chain_hash equals the preceding record's chain_hash, or all zero first [corpus] |
| `time-order` | action_timestamp_ms is not below the preceding record's [corpus] |
| `position-unique` | no two records claim one (agent_id, sequence_number) [corpus] |

## draft-mih-scitt-checkpointed-local-log-02

| member | verdict | code | under the draft's own steps | what it carries | parent |
| --- | --- | --- | --- | --- | --- |
| [`cll-cp1-first`](cases/vd2a07f2769aca84f.json) | valid |  | valid | the published cp1, registered as the first checkpoint of the log |  |
| [`cll-cp2-continuous`](cases/va16f8ecfd7c4bf12.json) | valid |  | valid | the published cp2 after cp1, with its consistency proof |  |
| [`cll-cp3-continuous`](cases/v41c9ac27ed7f9e37.json) | valid |  | valid | the published cp3, no growth since cp2 |  |
| [`cll-cp4-on-time`](cases/v7e6c2a0f4349a03c.json) | valid |  | valid | the published cp4 after cp3, registered thirty seconds after its issued_at |  |
| [`cll-cp3-reissued`](cases/vaef5b4a3f78e4f85.json) | valid |  | valid | cp3's claims issued again at 02:30, after cp3, with no growth |  |
| [`cll-cp1-at-second-service`](cases/v5d18ac5ccc2f020b.json) | valid |  | valid | the published cp1 registered first-seen at ts2, while ts1, also named by the producer, holds cp1 to cp4 |  |
| [`cll-cp4-registered-two-weeks-late`](cases/v30fe94ad421269f8.json) | invalid | `registration-late` | valid | the published cp4, unchanged, registered on 27 October, two weeks after its issued_at and its declared cadence of 3600 seconds; Sections 4.3 and 4.5 read neither time | `cll-cp4-on-time` |
| [`cll-issued-at-regression`](cases/v396893a5747f2d4e.json) | invalid | `issued-at-regression` | valid | cp3's claims issued again at 01:45, before cp3's 02:00, registered after cp3 | `cll-cp3-reissued` |
| [`cll-second-history-same-identity`](cases/v7799ec7b1c4bf125.json) | invalid | `history-fork` | valid | a first checkpoint for the same (iss, sub) over three other entries, registered first-seen at ts2 while ts1 holds cp1 to cp4; Section 4.5 lets ts2 start a history and nothing compares the two services | `cll-cp1-at-second-service` |
| [`cll-commitment-key-repeated`](cases/vb8b2caa513c47af8.json) | malformed | `cbor-not-deterministic` | valid | a first checkpoint whose payload map writes commitment twice, cp1's then a forked one; a last-wins decoder reads the fork, a first-wins decoder reads cp1, and each reading passes Section 4.3 | `cll-cp1-first` |
| [`cll-signed-by-other-key`](cases/vbf1554388dcfa67b.json) | invalid | `signature-invalid` | invalid | cp1's claims and header, signed by another Ed25519 key | `cll-cp1-first` |
| [`cll-kind-wrong`](cases/v82b42bf6b7a52249.json) | malformed | `claims-malformed` | malformed | cp1 with kind cll-checkpoint-v1, which Table 1 does not allow | `cll-cp1-first` |
| [`cll-not-continuous`](cases/v94c5e9a4ad1e0bd0.json) | invalid | `not-continuous` | invalid | the published cp4 at a service whose last registration is cp1 | `cll-cp4-on-time` |
| [`cll-sub-missing`](cases/v955ebd7f6716690b.json) | malformed | `cose-malformed` | malformed | cp1 signed under CWT Claims with iss and no sub, the log name Section 4.5 needs | `cll-cp1-first` |

| rule | what it requires |
| --- | --- |
| `deterministic-encoding` | the checkpoint, its protected header and its payload are core deterministic CBOR, so no map repeats a key [corpus; Section 4.2 binds only the producer] |
| `cose-shape` | COSE_Sign1 under tag 18, alg -19, and CWT Claims whose (iss, sub) is the case's log identity |
| `signature` | the Ed25519 signature verifies under the producer key |
| `claims` | kind is cll-checkpoint and the required claims carry Table 1's types (Section 4.3 step 2) |
| `continuity` | prev_size and prev_commitment equal the service's last registration, or the service holds none and prev_size is 0 (Section 4.5) |
| `issued-at-order` | issued_at is not earlier than the service's last registered issued_at [corpus] |
| `registration-time` | the service's clock is within the declared cadence of issued_at [corpus] |
| `history-fork` | no other named service holds a registration of the same log_size with another commitment [corpus] |

## draft-gruszka-scitt-statement-identification-02

| member | verdict | code | under the draft's own steps | what it carries | parent |
| --- | --- | --- | --- | --- | --- |
| [`sid-statement-01`](cases/va96badd9df6ce030.json) | valid |  | valid | statement 01 of Appendix A as printed, against the reference statement 02 carries |  |
| [`sid-header-keys-reordered`](cases/v1ab8391a77ee6b5e.json) | valid or malformed |  | invalid | statement 01 re-signed by its own issuer seed, the decoded protected header and payload unchanged, the header keys written 15, 4, 3, 1; the draft's ToBeSigned rule reports NO_MATCH with a valid signature | `sid-statement-01` |
| [`sid-different-payload`](cases/vbf32fe6235ed3d69.json) | invalid | `reference-mismatch` | invalid | statement 01's protected header over a payload whose license is Apache-2.0, signed by the issuer: a different statement | `sid-statement-01` |
| [`sid-signature-other-key`](cases/v009ee09f1bd85876.json) | invalid | `signature-invalid` | invalid | statement 01's ToBeSigned signed with the auditor seed in place of the issuer's | `sid-statement-01` |
| [`sid-protected-header-key-repeated`](cases/vacb161d3ce78204d.json) | malformed | `cbor-duplicate-key` | malformed | statement 01's protected header with label 3 written twice, signed by the issuer; Section 6 refuses a map with two equal keys | `sid-statement-01` |

| rule | what it requires |
| --- | --- |
| `duplicate-key` | no map in the protected header repeats a key (Section 6) |
| `signature` | the Ed25519 signature verifies under the issuer key |
| `identity` | SHA-256 over ToBeSigned, with the protected header in its deterministic encoding, equals the reference digest [corpus; the draft hashes the header bytes as written] |
