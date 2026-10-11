#!/usr/bin/env python3
"""Generate two worked Observed Effect receipts for MCP tool calls.

Regenerate byte-identically:

    uv run --extra generators python examples/mcp-receipts/gen_examples.py

Check them:

    uv run --extra generators python examples/mcp-receipts/check_examples.py

WHAT THESE ARE
--------------
A trace is written by the parties it describes and reassembled afterwards. A
receipt here is the other shape: one signed record per tool call, sealed by an
observer below the call (a proxy or sandbox host the agent cannot address),
whose commitment to the authority and the starting state is signed BEFORE the
call opens. Each record verifies offline with the observed-effect reference
verifier, from the record alone.

Two topologies, the two where a propagated thread id is known to break:

chain/   three tool calls in sequence. Each call's beforeRoot is the previous
         call's afterRoot, so the session is the chain of records, and a record
         dropped or reordered breaks the chain visibly.
fanout/  three tool calls dispatched in parallel, each into its own fork of one
         parent state. All three share a beforeRoot and differ in intervalId.
         The commitment preimage carries intervalId, so a commitment signed for
         one branch does not verify on another (attack A9 in the predicate).

In both, every record carries the SAME authorityDigest: the digest of one
authority document naming the originating intent, the requester and the
executor. That digest is inside the observer's prior commitment, so the intent
a call ran under is fixed before the call starts and survives fan-out, retries
and hops as signed content rather than as a header somebody has to propagate.

The keys are the corpus's PUBLISHED TEST KEYS, so anyone can rebuild every byte.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "vectors-observed-effect")
sys.path.insert(0, CORPUS)

import gen_vectors as oe  # noqa: E402
from canonical import canonical_bytes  # noqa: E402

AUTHORITY = {
    "intent": "intent-0001",
    "requester": "user:alice",
    "executor": "agent:release-bot",
    "grant": "write:/srv/app/",
    "tools": ["fs.read_file", "fs.write_file"],
}
AUTHORITY_DIGEST = hashlib.sha256(canonical_bytes(AUTHORITY)).hexdigest()


def at(second: int) -> str:
    return f"2026-10-07T00:00:{second:02d}Z"


def receipt(
    interval_id: str,
    before: str,
    after: str,
    opened: int,
    sealed: int,
    writes: list[dict[str, Any]],
) -> dict[str, Any]:
    pred = oe.predicate(
        intervalId=interval_id,
        mutation="observed" if writes else "none",
        interval={
            "beforeRoot": before,
            "afterRoot": after,
            "baseResolution": "supplied",
            "openedAt": at(opened),
            "sealedAt": at(sealed),
        },
        authorityDigest=AUTHORITY_DIGEST,
        reads=[oe.read_row(pre=before)],
        writes=writes,
        dualValues=[oe.dual("writes.count", str(len(writes)), str(len(writes)), "agree")],
        issuedAt=at(sealed + 1),
    )
    pred["observation"]["priorCommitment"] = oe.commitment(
        before_root=before,
        authority_digest=AUTHORITY_DIGEST,
        interval_id=interval_id,
        committed_at=at(opened - 1),
    )
    return oe.envelope(oe.statement(pred))


def root(label: str) -> str:
    return hashlib.sha256(f"mcp-receipts/root/{label}".encode()).hexdigest()


def chain() -> list[tuple[str, dict[str, Any]]]:
    s0, s1, s2 = root("session-start"), root("after-main"), root("after-handler")
    return [
        ("1-read-config", receipt("chain-call-1", s0, s0, 2, 3, [])),
        (
            "2-write-main",
            receipt("chain-call-2", s0, s1, 5, 6, [oe.write_row("/srv/app/main.py", s0, s1)]),
        ),
        (
            "3-write-handler",
            receipt(
                "chain-call-3", s1, s2, 8, 9, [oe.write_row("/srv/app/handler.py", s1, s2)]
            ),
        ),
    ]


def fanout() -> list[tuple[str, dict[str, Any]]]:
    parent = root("fanout-parent")
    out = []
    for n, name in enumerate(("orders", "billing", "notify"), start=1):
        after = root(f"fanout-branch-{name}")
        path = f"/srv/app/{name}.json"
        out.append(
            (
                f"branch-{n}-{name}",
                receipt(
                    f"fanout-call-{n}", parent, after, 12, 14, [oe.write_row(path, parent, after)]
                ),
            )
        )
    return out


def write(rel: str, obj: Any) -> None:
    path = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(json.dumps(obj, indent=2, sort_keys=True).encode() + b"\n")


def emit() -> None:
    write("authority.json", AUTHORITY)
    for folder, members in (("chain", chain()), ("fanout", fanout())):
        keep = set()
        for slug, env in members:
            write(f"{folder}/{slug}.json", env)
            keep.add(f"{slug}.json")
        for stale in sorted(os.listdir(os.path.join(HERE, folder))):
            if stale.endswith(".json") and stale not in keep:
                os.remove(os.path.join(HERE, folder, stale))


if __name__ == "__main__":
    emit()
