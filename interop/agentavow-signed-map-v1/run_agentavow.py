"""Evaluate a separately supplied, byte-pinned native AgentAvow packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from map_reader import (
    ROOT,
    capture_digest,
    decode_base64url,
    evaluate,
    extract_pin,
    load_json,
    read_jws,
    refuse,
    tool_key,
)


def selected_fixture(path: Path) -> tuple[dict, dict, dict]:
    """Verify native and shared-reader bytes before decoding the supplied packet.

    The native file remains outside this source tree. Its revision and raw
    digest are selected by source-lock.json; the caller-selected key and issuer
    are in selection.json and never taken from a packet-controlled key hint.
    """
    lock = load_json((ROOT / "source-lock.json").read_bytes())
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != lock["fixture"]["sha256"]:
        refuse("native fixture digest differs from the selected source")
    for entry in lock["files"]:
        digest = hashlib.sha256((ROOT / entry["file"]).read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            refuse(f"shared source digest mismatch: {entry['file']}")
    return load_json(raw), lock, load_json((ROOT / "selection.json").read_bytes())


def check_population(fixture: dict, lock: dict) -> None:
    """Refuse a packet whose key pairs, served tools or cases differ in count.

    The counts belong to the selected revision, so they live in
    source-lock.json beside its digest: a producer revision that adds a case
    is selected by editing the lock, never by editing this driver.
    """
    expected = lock["population"]
    found = {
        "key_pairs": len(fixture["key_encoding"]),
        "definitions": len(fixture["observed_tools"]),
        "cases": len(fixture["vectors"]),
    }
    if found != expected:
        refuse(f"native population {found} differs from the selected {expected}")


def run(path: Path) -> dict:
    """Recompute the key pairs, definition digests and native cases.

    The original expected outcomes are compared after evaluating all axes.
    The report retains original packet and implementation selection digests,
    native case names, extra issuer checks and the usable positive pin. It
    never infers an independent operator or actual tool execution.
    """
    fixture, lock, selection = selected_fixture(path)
    check_population(fixture, lock)
    jwk, issuer = selection["jwk"], selection["issuer"]
    jws = fixture["attestation"]["jws"]
    payload, _, _ = read_jws(jws, jwk)
    keys = [tool_key(pair["name"]) == pair["key"] for pair in fixture["key_encoding"]]
    definitions = [
        capture_digest(fixture["observed_tools"], tool["name"])
        == payload["scan"]["toolDigests"][tool_key(tool["name"])]
        for tool in fixture["observed_tools"]
    ]
    results = []
    for case in fixture["vectors"]:
        candidate = jws if case["jws"] == "reference" else case["jws"]
        actual = evaluate(candidate, jwk, issuer, case["gate"])
        matches = all(actual[axis] == value for axis, value in case["expect"].items())
        results.append({"name": case["name"], "axes": actual, "matches": matches})
    positive = fixture["vectors"][0]["gate"]
    extracted = extract_pin(jws, jwk, issuer, positive)
    reference_bytes = decode_base64url(jws.split(".")[1])
    payload_digest = hashlib.sha256(reference_bytes).hexdigest()
    payload_matches = payload_digest == fixture["attestation"]["payload_sha256"]
    return {
        "profile": "probity-agentavow-signed-map-extraction-v1-candidate",
        "classification": "Probity-operated reproduction using original native packet",
        "source_revision": lock["revision"],
        "fixture_sha256": lock["fixture"]["sha256"],
        "key_pair_matches": keys,
        "definition_matches": definitions,
        "payload_sha256": payload_digest,
        "payload_digest_matches": payload_matches,
        "results": results,
        "positive_pin": extracted,
        "passed": all(keys + definitions)
        and payload_matches
        and all(result["matches"] for result in results),
        "limits": [
            "static served-definition binding only",
            "same Probity operator",
            "key authority supplied by consumer selection",
            "no runtime authorization",
            "truncated keys retain a 64-bit hash suffix; no injectivity proof",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    report = run(parser.parse_args().fixture)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
