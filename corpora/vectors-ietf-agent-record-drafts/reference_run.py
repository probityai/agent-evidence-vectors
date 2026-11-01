#!/usr/bin/env python3
"""Run every checkpointed-local-log member through the draft's own reference verifier.

    uv run --extra generators python vectors-ietf-agent-record-drafts/reference_run.py \\
        <clone of action-state-group/checkpointed-local-log>

The reference verifier is `cll-02-vectors/cll02.py` in the draft's vector
repository. This script checks the clone is at the commit the manifest names,
loads `cll02.py` by path, and for each member runs `parse_and_verify_signature`,
then `check_claims` (Section 4.3), then `registration_continuity` (Section 4.5)
against the service the case registers at. It compares the outcome with the
`referenceVerifier` record in MANIFEST.json and exits 1 on any difference, so
that record is the output of a run and not a statement about one.

It needs the clone, which CI does not fetch, so it is run by hand when the
corpus or the upstream commit changes.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))


def load(clone: str) -> Any:
    vectors = os.path.join(clone, "cll-02-vectors")
    sys.path.insert(0, vectors)
    spec = importlib.util.spec_from_file_location("cll02", os.path.join(vectors, "cll02.py"))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load cll02.py from {vectors}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome(cll02: Any, case: dict[str, Any], kid: bytes) -> dict[str, str]:
    cose = bytes.fromhex(case["checkpoint"])
    try:
        identity, claims = cll02.parse_and_verify_signature(cose, kid)
        cll02.check_claims(claims)
    except cll02.CheckpointError as exc:
        return {"checkClaims": exc.code, "registration": ""}
    target = next(s for s in case["services"] if s["name"] == case["registerAt"])
    registered = {}
    if target["history"]:
        last = target["history"][-1]
        registered[identity] = (last["log_size"], bytes.fromhex(last["commitment"]))
    try:
        result = cll02.registration_continuity(identity, claims, registered)
    except cll02.CheckpointError as exc:
        return {"checkClaims": "pass", "registration": exc.code}
    return {"checkClaims": "pass", "registration": result}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    clone = sys.argv[1]
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    want = manifest["upstream"]["cll-02-vectors.json"]["commit"]
    head = subprocess.run(
        ["git", "-C", clone, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != want:
        print(f"FAIL the clone is at {head}, the manifest names {want}")
        return 1
    cll02 = load(clone)
    kid = bytes.fromhex(manifest["keys"]["cll-producer"]["publicKey"])
    findings = []
    ran = 0
    for entry in manifest["vectors"]:
        if "referenceVerifier" not in entry:
            continue
        with open(os.path.join(HERE, entry["file"]), encoding="utf-8") as fh:
            case = json.load(fh)
        got = outcome(cll02, case, kid)
        ran += 1
        recorded = {k: entry["referenceVerifier"][k] for k in ("checkClaims", "registration")}
        line = (
            f"{entry['slug']}: checkClaims={got['checkClaims']} registration={got['registration']}"
        )
        print(line)
        if got != recorded:
            findings.append(
                f"{entry['slug']}: the run gives {got}, the manifest records {recorded}"
            )
    for finding in findings:
        print(f"FAIL {finding}")
    if ran == 0:
        print("FAIL no member carries a referenceVerifier record")
        return 1
    if findings:
        return 1
    print(f"reference verifier at {head}: {ran} members, every outcome as recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
