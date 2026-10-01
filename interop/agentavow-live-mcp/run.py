"""Replay synthetic captures against an independently pinned expectation file."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from definition_pin import compare

ROOT = Path(__file__).resolve().parent


def run() -> dict[str, dict[str, str]]:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    raw = (ROOT / "fixtures" / "cases.json").read_bytes()
    expected_raw = (ROOT / "EXPECTED.json").read_bytes()
    for name, body in (("cases", raw), ("expected", expected_raw)):
        if hashlib.sha256(body).hexdigest() != manifest[f"{name}Sha256"]:
            raise ValueError(f"{name} file differs from the manifest")
    fixture = json.loads(raw)
    actual = {case["name"]: compare(fixture["pin"], case["capture"])
              for case in fixture["cases"]}
    expected = json.loads(expected_raw)
    if actual != expected:
        raise ValueError(f"reader disagrees: {json.dumps(actual, sort_keys=True)}")
    return actual


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
