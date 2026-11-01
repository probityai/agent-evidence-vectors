"""Grade the candidate cases without sending expectations to the reader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prior_witness import RECORD_DIGEST, digest, evaluate

ROOT = Path(__file__).resolve().parent
RECORD = ROOT.parent.parent / "corpora/vectors-observed-effect/statements/v162352770f2f6c1c.json"


def read_pinned() -> tuple[bytes, dict[str, bytes]]:
    raw = RECORD.read_bytes()
    if digest(raw) != RECORD_DIGEST:
        raise ValueError("the pinned Observed Effect record differs")
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    files = {}
    for name, expected in manifest["fixtureSha256"].items():
        data = (ROOT / "fixtures" / name).read_bytes()
        if digest(data) != expected:
            raise ValueError(f"fixture differs: {name}")
        files[name] = data
    return raw, files


def run_cases() -> dict[str, Any]:
    record, files = read_pinned()
    expected_bytes = (ROOT / "EXPECTED.json").read_bytes()
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    if digest(expected_bytes) != manifest["expectedSha256"]:
        raise ValueError("expected answers differ from their pin")
    expected = json.loads(expected_bytes)
    found = {}
    for name, policy_file, witness_file, action_file in (
        ("claimed", "claimed-policy.json", None, "action-at-window.json"),
        ("witnessed", "witnessed-policy.json", "witness.jsonl", "action-at-window.json"),
        (
            "pending-after-window",
            "witnessed-policy.json",
            "witness.jsonl",
            "action-after-window.json",
        ),
    ):
        policy = json.loads(files[policy_file])
        action = json.loads(files[action_file])
        witness = files[witness_file] if witness_file else None
        found[name] = evaluate(record, policy, witness, action)
    compared = {
        name: {
            **expected["cases"][name],
            "binding": {**expected["binding"], "witnessHead": expected["witnessHeads"][name]},
        }
        for name in found
    }
    if found != compared:
        raise ValueError(f"candidate cases differ: {json.dumps(found, sort_keys=True)}")
    return found


if __name__ == "__main__":
    print(json.dumps(run_cases(), indent=2, sort_keys=True))
