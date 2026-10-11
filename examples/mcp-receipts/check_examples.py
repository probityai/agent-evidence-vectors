#!/usr/bin/env python3
"""Check the MCP receipt examples: each record alone, then the topology.

    uv run --extra generators python examples/mcp-receipts/check_examples.py

Per record: the observed-effect reference verifier must return valid.
Chain: each call starts from the state the previous one sealed, in time order.
Fan-out: every branch starts from one parent state under distinct interval ids.
Both: every record names the published authority document by digest.

Two controls must FAIL, or a pass above means nothing:
  - a branch's prior commitment moved onto a sibling branch is refused, because
    intervalId is in the commitment preimage;
  - the chain read with two calls swapped does not link.
Exit 0 when everything holds, 1 otherwise.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "vectors-observed-effect")
sys.path.insert(0, CORPUS)

import check_vectors as cv  # noqa: E402
from canonical import canonical_bytes  # noqa: E402

FAILURES: list[str] = []


def load(folder: str) -> list[tuple[str, bytes, dict[str, Any]]]:
    out = []
    directory = os.path.join(HERE, folder)
    for name in sorted(os.listdir(directory)):
        raw = open(os.path.join(directory, name), "rb").read()
        stmt = json.loads(base64.b64decode(json.loads(raw)["payload"]))
        out.append((name, raw, stmt["predicate"]))
    return out


def public_key() -> str:
    manifest = json.load(open(os.path.join(CORPUS, "MANIFEST.json")))
    return manifest["keys"]["observer"]["publicKey"]


def links(preds: list[dict[str, Any]]) -> bool:
    return all(
        a["interval"]["afterRoot"] == b["interval"]["beforeRoot"]
        and a["interval"]["sealedAt"] <= b["interval"]["openedAt"]
        for a, b in zip(preds, preds[1:])
    )


def main() -> int:
    key = public_key()
    authority = json.load(open(os.path.join(HERE, "authority.json")))
    authority_digest = hashlib.sha256(canonical_bytes(authority)).hexdigest()
    chain, fan = load("chain"), load("fanout")

    for name, raw, pred in chain + fan:
        verdict, codes = cv.verify(raw, key, cv.BLOBS)
        if verdict != "valid":
            FAILURES.append(f"{name}: reference verifier says {verdict} {codes}")
        if pred["authorityDigest"] != authority_digest:
            FAILURES.append(f"{name}: authorityDigest is not the published authority.json")

    chain_preds = [p for _, _, p in chain]
    if not links(chain_preds):
        FAILURES.append("chain: a call does not start from the state the previous call sealed")
    if links([chain_preds[1], chain_preds[0], chain_preds[2]]):
        FAILURES.append("control: a reordered chain still links")

    fan_preds = [p for _, _, p in fan]
    if len({p["interval"]["beforeRoot"] for p in fan_preds}) != 1:
        FAILURES.append("fanout: branches do not share one parent state")
    if len({p["intervalId"] for p in fan_preds}) != len(fan_preds):
        FAILURES.append("fanout: interval ids repeat")

    replayed = json.loads(base64.b64decode(json.loads(fan[1][1])["payload"]))
    replayed["predicate"]["observation"]["priorCommitment"] = copy.deepcopy(
        fan_preds[0]["observation"]["priorCommitment"]
    )
    env = {"payload": base64.b64encode(canonical_bytes(replayed)).decode(),
           "payloadType": "application/vnd.in-toto+json", "signatures": []}
    verdict, codes = cv.verify(json.dumps(env).encode(), key, cv.BLOBS)
    if verdict == "valid" or codes != ["commitment-digest-mismatch"]:
        FAILURES.append(f"control: a commitment replayed across branches gave {verdict} {codes}")

    for line in FAILURES:
        print("FAIL", line)
    print(f"{len(chain) + len(fan)} records checked, {len(FAILURES)} failures")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
