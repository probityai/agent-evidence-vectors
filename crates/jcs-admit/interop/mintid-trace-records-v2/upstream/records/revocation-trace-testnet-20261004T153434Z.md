# Revocation trace — testnet — 2026-10-04T15:34:34.487Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261004T153434Z.jsonl`. Decision log: verifier console /console/decisions (MINT-307).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | issuer `9ddd3b08a70e3506`; verifier engine `proof-core 0.3.0`, SDK 0.1.0, SPEC-1 v3.1 |
| Status/root | before: epoch 12, finalized height 163; after: epoch 23, finalized height 308 |
| Observation time | before 2026-10-04T15:34:38.000Z; after 2026-10-04T15:39:40.000Z (verifier `/v1/status`) |
| Actual age | before 23 s; after 17 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-10-04T15:36:12.053Z — the issuer's removal of the agent (revoke response) | current root epoch 16 (finalized height 219, generated 2026-10-04T15:36:15.000Z) | none after t0 (—) | t0 + 185 s (t0 + A + K) = 2026-10-04T15:39:17.053Z | 2026-10-04T15:36:22.578Z (+10.5 s), `status_root_stale` | epoch 16, finalized height 219 at 2026-10-04T15:36:14.038Z |
| kill_switch | 2026-10-04T15:37:00.768Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 18 (finalized height 248, generated 2026-10-04T15:37:15.000Z) | 2026-10-04T15:37:20.886Z (+20.1 s) | t0 + 245 s (t0 + G + A + K) = 2026-10-04T15:41:05.768Z | 2026-10-04T15:37:27.316Z (+26.5 s), `status_root_stale` | epoch 18, finalized height 248 at 2026-10-04T15:37:15.643Z |
| cascade (cascade_agent_1) | 2026-10-04T15:38:15.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 21 (finalized height 290, generated 2026-10-04T15:38:45.000Z) | 2026-10-04T15:38:44.749Z (+29.8 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-04T15:44:50.000Z | 2026-10-04T15:39:04.463Z (+49.5 s), `status_root_stale` | trigger root epoch 20, finalized height 276 at 2026-10-04T15:38:15.197Z |
| cascade (cascade_agent_2) | 2026-10-04T15:38:15.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 21 (finalized height 290, generated 2026-10-04T15:38:45.000Z) | 2026-10-04T15:38:35.520Z (+20.5 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-04T15:44:50.000Z | 2026-10-04T15:38:51.470Z (+36.5 s), `status_root_stale` | trigger root epoch 20, finalized height 276 at 2026-10-04T15:38:15.197Z |
| emergency | 2026-10-04T15:39:23.865Z — the emergency root's submission (the issuer's answer; the bound itself is block-based) | current root epoch 23 (finalized height 308, generated 2026-10-04T15:39:23.000Z) EMERGENCY | none after t0 (—) | t0 + 0 s (the emergency root's finalisation: measured in blocks below) = 2026-10-04T15:39:23.865Z | 2026-10-04T15:39:28.497Z (+4.6 s), `status_root_stale` | epoch 23, finalized height 308 at 2026-10-04T15:39:23.277Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 10.5 s | 185 s | yes |
| kill_switch | 26.5 s | 245 s | yes |
| cascade/cascade_agent_1 | 49.5 s | 395 s | yes |
| cascade/cascade_agent_2 | 36.5 s | 395 s | yes |
| emergency | 4.6 s after the submission; last accepted at node head None, first refused at node head 309; the emergency root entered block 308 | the block of the emergency root (+1 header to prove it) | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer first refused | 2026-10-04T15:36:22.578Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=2026-10-04 15:36:21Z root_epoch=None root_height=None root_age_seconds=None` |
| kill_switch last accepted | 2026-10-04T15:37:20.886Z | `accepted` | `accepted=True reason=accepted decided_at_unix=2026-10-04 15:37:19Z root_epoch=17 root_height=233 root_age_seconds=34` |
| kill_switch first refused | 2026-10-04T15:37:27.316Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=2026-10-04 15:37:26Z root_epoch=None root_height=None root_age_seconds=None` |
| cascade/cascade_agent_1 last accepted | 2026-10-04T15:38:44.749Z | `accepted` | `accepted=True reason=accepted decided_at_unix=2026-10-04 15:38:43Z root_epoch=20 root_height=276 root_age_seconds=28` |
| cascade/cascade_agent_1 first refused | 2026-10-04T15:39:04.463Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=2026-10-04 15:39:03Z root_epoch=None root_height=None root_age_seconds=None` |
| cascade/cascade_agent_2 last accepted | 2026-10-04T15:38:35.520Z | `accepted` | `accepted=True reason=accepted decided_at_unix=2026-10-04 15:38:33Z root_epoch=20 root_height=276 root_age_seconds=18` |
| cascade/cascade_agent_2 first refused | 2026-10-04T15:38:51.470Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=2026-10-04 15:38:50Z root_epoch=None root_height=None root_age_seconds=None` |
| emergency first refused | 2026-10-04T15:39:28.497Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=2026-10-04 15:39:27Z root_epoch=None root_height=None root_age_seconds=None` |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted 2026-10-04T15:36:17.573Z, first refused 2026-10-04T15:36:33.904Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Rule

A forced proof over the witness the agent held before the trigger is refused, `status_root_stale`, at the first attempt after the next root is finalized **and provable** (finalized height ≤ latest − 1), by condition 5 (proof verification), not by the ring rule of condition 7: the verifier verifies every agent proof against the issuer definition — BBS key and accumulator — that the newest provable root anchors (issuer metadata `anchoring`, MINT-323/344), read at the decision. The agent accumulator moves at every root (MINT-369 cover traffic: a never-issued element when no agent left), so a non-revocation witness of an older root no longer verifies; `verify_agent_presentation` then raises the plain stale refusal without a verified result, and condition 7 (the MINT-345 ring acceptance) is never reached — hence the decision-log line carries no root evidence (MINT-425: refused before the status read). The control shows the same refusal for a sibling that was never revoked, and its acceptance once it refreshes: an honest client refreshes and retries; a revoked one can no longer refresh. The SPEC-1 §9.1 bound is what every conforming verifier guarantees (a verifier that accepts a ring root inside its validity window); this verifier denies earlier because it rejects any agent proof over a superseded accumulator.

