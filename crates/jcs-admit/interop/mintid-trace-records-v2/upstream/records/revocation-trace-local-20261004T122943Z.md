# Revocation trace — local — 2026-10-04T12:29:43.869Z

Chain `mintid-anchor-local`, issuer `860bc22e30e395a8…`, verifier `fe70f0d05c0ca3c5…`. Raw events: `revocation-trace-local-20261004T122943Z.jsonl`. Decision log: verifier volume /var/lib/verifier/decisions.jsonl (docker exec mintid-anchor-verifier-1).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-anchor-local`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | issuer `bc172b91b6295b73`; verifier engine `proof-core 0.3.0`, SDK 0.1.0, SPEC-1 v3.1 |
| Status/root | before: epoch 5482, finalized height 81585; after: epoch 5490, finalized height 81693 |
| Observation time | before 2026-10-04T12:29:43.000Z; after 2026-10-04T12:33:10.000Z (verifier `/v1/status`) |
| Actual age | before 15 s; after 4 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-10-04T12:30:02.257Z — the issuer's removal of the agent (revoke response) | current root epoch 5484 (finalized height 81615, generated 2026-10-04T12:30:28.000Z) | 2026-10-04T12:30:30.407Z (+28.2 s) | t0 + 185 s (t0 + A + K) = 2026-10-04T12:33:07.257Z | 2026-10-04T12:30:33.536Z (+31.3 s), `status_root_stale` | epoch 5484, finalized height 81615 at 2026-10-04T12:30:27.176Z |
| kill_switch | 2026-10-04T12:30:37.242Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 5485 (finalized height 81630, generated 2026-10-04T12:30:58.000Z) | 2026-10-04T12:30:59.780Z (+22.5 s) | t0 + 245 s (t0 + G + A + K) = 2026-10-04T12:34:42.242Z | 2026-10-04T12:31:02.096Z (+24.9 s), `status_root_stale` | epoch 5485, finalized height 81630 at 2026-10-04T12:30:57.381Z |
| cascade (cascade_agent_1) | 2026-10-04T12:31:28.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 5489 (finalized height 81690, generated 2026-10-04T12:32:58.000Z) | 2026-10-04T12:32:59.562Z (+91.6 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-04T12:38:03.000Z | 2026-10-04T12:33:02.410Z (+94.4 s), `status_root_stale` | trigger root epoch 5486, finalized height 81645 at 2026-10-04T12:31:27.575Z |
| cascade (cascade_agent_2) | 2026-10-04T12:31:28.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 5488 (finalized height 81675, generated 2026-10-04T12:32:28.000Z) | 2026-10-04T12:32:28.632Z (+60.6 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-04T12:38:03.000Z | 2026-10-04T12:32:32.411Z (+64.4 s), `status_root_stale` | trigger root epoch 5486, finalized height 81645 at 2026-10-04T12:31:27.575Z |
| emergency | 2026-10-04T12:33:06.202Z — the emergency root's submission (the issuer's answer; the bound itself is block-based) | current root epoch 5490 (finalized height 81693, generated 2026-10-04T12:33:06.000Z) EMERGENCY | 2026-10-04T12:33:07.103Z (+0.9 s) | t0 + 0 s (the emergency root's finalisation: measured in blocks below) = 2026-10-04T12:33:06.202Z | 2026-10-04T12:33:08.922Z (+2.7 s), `status_root_stale` | epoch 5490, finalized height 81693 at 2026-10-04T12:33:04.251Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 31.3 s | 185 s | yes |
| kill_switch | 24.9 s | 245 s | yes |
| cascade/cascade_agent_1 | 94.4 s | 395 s | yes |
| cascade/cascade_agent_2 | 64.4 s | 395 s | yes |
| emergency | 2.7 s after the submission; last accepted at node head 81693, first refused at node head 81694; the emergency root entered block 81693 | the block of the emergency root (+1 header to prove it) | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer last accepted | 2026-10-04T12:30:30.407Z | `accepted` | `accepted=True reason=accepted decided_at_unix=1791117030 root_epoch=5483 root_height=81600 root_age_seconds=32` |
| issuer first refused | 2026-10-04T12:30:33.536Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=1791117033 root_epoch=None root_height=None root_age_seconds=None` |
| kill_switch last accepted | 2026-10-04T12:30:59.780Z | `accepted` | `accepted=True reason=accepted decided_at_unix=1791117059 root_epoch=5484 root_height=81615 root_age_seconds=31` |
| kill_switch first refused | 2026-10-04T12:31:02.096Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=1791117062 root_epoch=None root_height=None root_age_seconds=None` |
| cascade/cascade_agent_1 last accepted | 2026-10-04T12:32:59.562Z | `accepted` | `accepted=True reason=accepted decided_at_unix=1791117179 root_epoch=5488 root_height=81675 root_age_seconds=31` |
| cascade/cascade_agent_1 first refused | 2026-10-04T12:33:02.410Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=1791117182 root_epoch=None root_height=None root_age_seconds=None` |
| cascade/cascade_agent_2 last accepted | 2026-10-04T12:32:28.632Z | `accepted` | `accepted=True reason=accepted decided_at_unix=1791117148 root_epoch=5487 root_height=81660 root_age_seconds=30` |
| cascade/cascade_agent_2 first refused | 2026-10-04T12:32:32.411Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=1791117152 root_epoch=None root_height=None root_age_seconds=None` |
| emergency last accepted | 2026-10-04T12:33:07.103Z | `accepted` | `accepted=True reason=accepted decided_at_unix=1791117186 root_epoch=5489 root_height=81690 root_age_seconds=8` |
| emergency first refused | 2026-10-04T12:33:08.922Z | `status_root_stale` | `accepted=False reason=status_root_stale decided_at_unix=1791117188 root_epoch=None root_height=None root_age_seconds=None` |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted 2026-10-04T12:30:29.513Z, first refused 2026-10-04T12:30:32.736Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Rule

A forced proof over the witness the agent held before the trigger is refused, `status_root_stale`, at the first attempt after the next root is finalized **and provable** (finalized height ≤ latest − 1), by condition 5 (proof verification), not by the ring rule of condition 7: the verifier verifies every agent proof against the issuer definition — BBS key and accumulator — that the newest provable root anchors (issuer metadata `anchoring`, MINT-323/344), read at the decision. The agent accumulator moves at every root (MINT-369 cover traffic: a never-issued element when no agent left), so a non-revocation witness of an older root no longer verifies; `verify_agent_presentation` then raises the plain stale refusal without a verified result, and condition 7 (the MINT-345 ring acceptance) is never reached — hence the decision-log line carries no root evidence (MINT-425: refused before the status read). The control shows the same refusal for a sibling that was never revoked, and its acceptance once it refreshes: an honest client refreshes and retries; a revoked one can no longer refresh. The SPEC-1 §9.1 bound is what every conforming verifier guarantees (a verifier that accepts a ring root inside its validity window); this verifier denies earlier because it rejects any agent proof over a superseded accumulator.

