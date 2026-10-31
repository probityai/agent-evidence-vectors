# Revocation trace — testnet — 2026-10-05T02:29:48.990Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261005T022948Z.jsonl`. Decision log: verifier console /console/decisions (MINT-307).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | issuer `9ddd3b08a70e3506`; verifier engine `proof-core 0.3.0`, SDK 0.1.0, SPEC-1 v3.1 |
| Status/root | before: epoch 1305, finalized height 18517; after: epoch 1318, finalized height 18688 |
| Observation time | before 2026-10-05T02:29:51.000Z; after 2026-10-05T02:35:53.000Z (verifier `/v1/status`) |
| Actual age | before 23 s; after 22 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-10-05T02:31:31.213Z — the issuer's removal of the agent (revoke response) | current root epoch 1309 (finalized height 18573, generated 2026-10-05T02:31:28.000Z) | none after t0 (—) | t0 + 185 s (t0 + A + K) = 2026-10-05T02:34:36.213Z | 2026-10-05T02:31:45.372Z (+14.2 s), `status_root_stale` | epoch 1310, finalized height 18587 at 2026-10-05T02:31:56.817Z |
| kill_switch | 2026-10-05T02:32:28.736Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 1312 (finalized height 18616, generated 2026-10-05T02:32:58.000Z) | 2026-10-05T02:33:04.076Z (+35.3 s) | t0 + 245 s (t0 + G + A + K) = 2026-10-05T02:36:33.736Z | 2026-10-05T02:33:11.981Z (+43.2 s), `status_root_stale` | epoch 1312, finalized height 18616 at 2026-10-05T02:32:58.475Z |
| cascade (cascade_agent_1) | 2026-10-05T02:33:58.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 1315 (finalized height 18658, generated 2026-10-05T02:34:28.000Z) | 2026-10-05T02:34:16.883Z (+18.9 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-05T02:40:33.000Z | 2026-10-05T02:34:36.011Z (+38.0 s), `status_root_stale` | trigger root epoch 1314, finalized height 18644 at 2026-10-05T02:33:57.924Z |
| cascade (cascade_agent_2) | 2026-10-05T02:33:58.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 1316 (finalized height 18672, generated 2026-10-05T02:34:58.000Z) | 2026-10-05T02:34:56.143Z (+58.1 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-05T02:40:33.000Z | 2026-10-05T02:35:06.384Z (+68.4 s), `status_root_stale` | trigger root epoch 1314, finalized height 18644 at 2026-10-05T02:33:57.924Z |
| emergency | 2026-10-05T02:35:32.289Z — the emergency root's submission (the issuer's answer; the bound itself is block-based) | current root epoch 1318 (finalized height 18688, generated 2026-10-05T02:35:31.000Z) EMERGENCY | none after t0 (—) | t0 + 0 s (the emergency root's finalisation: measured in blocks below) = 2026-10-05T02:35:32.289Z | 2026-10-05T02:35:39.459Z (+7.2 s), `status_root_stale` | epoch 1318, finalized height 18688 at 2026-10-05T02:35:31.360Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 14.2 s | 185 s | yes |
| kill_switch | 43.2 s | 245 s | yes |
| cascade/cascade_agent_1 | 38.0 s | 395 s | yes |
| cascade/cascade_agent_2 | 68.4 s | 395 s | yes |
| emergency | 7.2 s after the submission; last accepted at node head None, first refused at node head 18690; the emergency root entered block 18688 | the block of the emergency root (+1 header to prove it) | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer first refused | 2026-10-05T02:31:45.372Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-05 02:31:44Z root_epoch=1309 root_height=18573 root_age_seconds=16` |
| kill_switch last accepted | 2026-10-05T02:33:04.076Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-05 02:33:01Z root_epoch=1311 root_height=18601 root_age_seconds=33` |
| kill_switch first refused | 2026-10-05T02:33:11.981Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-05 02:33:10Z root_epoch=1312 root_height=18616 root_age_seconds=12` |
| cascade/cascade_agent_1 last accepted | 2026-10-05T02:34:16.883Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-05 02:34:14Z root_epoch=1314 root_height=18644 root_age_seconds=16` |
| cascade/cascade_agent_1 first refused | 2026-10-05T02:34:36.011Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-05 02:34:34Z root_epoch=1315 root_height=18658 root_age_seconds=6` |
| cascade/cascade_agent_2 last accepted | 2026-10-05T02:34:56.143Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-05 02:34:52Z root_epoch=1315 root_height=18658 root_age_seconds=24` |
| cascade/cascade_agent_2 first refused | 2026-10-05T02:35:06.384Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-05 02:35:04Z root_epoch=1316 root_height=18672 root_age_seconds=6` |
| emergency first refused | 2026-10-05T02:35:39.459Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-05 02:35:38Z root_epoch=1318 root_height=18688 root_age_seconds=7` |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted —, first refused 2026-10-05T02:31:38.794Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Rule

- **issuer**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1309 (finalized height 18573, 16 s old at the decision).
- **issuer control (never revoked)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1309 (finalized height 18573, 9 s old at the decision).
- **kill_switch**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1312 (finalized height 18616, 12 s old at the decision).
- **cascade (cascade_agent_1)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1315 (finalized height 18658, 6 s old at the decision).
- **cascade (cascade_agent_2)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1316 (finalized height 18672, 6 s old at the decision).
- **emergency**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 1318 (finalized height 18688, 7 s old at the decision).

Condition 5 verifies every agent proof against the issuer material — definition, BBS key and accumulator, scope anchors — that the newest provable root anchors (issuer metadata `anchoring`). A refusal there with `status_root_stale` means the material had moved to a newer root than the one the proof was made against and the proof was not accepted against it; the root named is the root the proof was checked against. The ring rule of condition 7 is not reached. An honest client refreshes its witness and retries; a revoked one cannot obtain a newer witness. The SPEC-1 §9.1 bound is what every conforming verifier guarantees (one that accepts a ring root inside its validity window); condition 5 is this verifier's stricter check, so its deny point can come before the bound.

