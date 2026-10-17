#!/usr/bin/env python3
"""Replay a done corpus through probity-verify's adapters and compare every check.

probity-verify implements the three checks independently of this repository's
readers. A member that both answer the same way is a member whose declared verdict
does not rest on one implementation. Run it with the adapters installed:

    uv run --with "probity-verify @ git+https://github.com/probityai/probity-verify@<commit>" \
        python vectors-done-receipt/crosscheck_probity_verify.py vectors-done-receipt

Exit 0 when every check agrees, 1 on a disagreement, 2 when nothing was compared.
A member whose launch record or launch receipt breaks a rule is not compared:
probity-verify does not read those. A member whose other records break a rule is expected to be
refused by probity-verify too
(it raises ``CaseError``); the codes are this repository's own and are not compared.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from probity_verify.common import MAX_ARTIFACT_BYTES  # pyright: ignore[reportMissingImports]
from probity_verify.core import CaseError, adjudicate  # pyright: ignore[reportMissingImports]
from probity_verify.json_input import parse_json  # pyright: ignore[reportMissingImports]

FILES = {"protected_paths/v1": "protected-paths", "acceptance_observed/v1": "acceptance",
         "tool_claim_match/v1": "tool-claims"}
KEYS = ("decision", "reason", "vantage", "witness_scope")


def _load(path: Path) -> object:
    """Read a control file the way probity-verify's command line does."""
    return parse_json(path.read_bytes(), max_bytes=MAX_ARTIFACT_BYTES, max_depth=32,
                      max_nodes=32768)


def answer(member: Path, claim_type: str) -> dict[str, Any] | str:
    name = FILES[claim_type]
    try:
        case = _load(member / f"{name}.case.json")
        policy = _load(member / f"{name}.policy.json")
    except (OSError, ValueError, CaseError) as exc:
        return f"refused: {exc}"
    try:
        result = adjudicate(case, policy, member)
    except CaseError as exc:
        return f"refused: {exc}"
    return {key: result[key] for key in KEYS if key in result}


def main(argv: list[str]) -> int:
    root = Path(argv[1])
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    compared, disagreements = 0, []
    for entry in manifest["vectors"]:
        expected = entry["expected"]
        member = root / entry["path"]
        declared = entry.get("checks", [])
        if not declared or ("checks" not in expected and "refused" not in expected):
            continue
        if str(expected.get("refused", "")).startswith("launch_"):
            continue  # the launch records are the observer's, not probity-verify's
        got = {claim_type: answer(member, claim_type) for claim_type in declared}
        compared += len(declared)
        if "refused" in expected:
            if not any(isinstance(item, str) for item in got.values()):
                disagreements.append(f"{entry['id']}: declared refused, no check was refused")
            continue
        for claim_type, want in expected["checks"].items():
            if got.get(claim_type) != want:
                disagreements.append(
                    f"{entry['id']} {claim_type}: declared {want}, got {got.get(claim_type)}")
    for line in disagreements:
        print(line)
    print(f"compared {compared} checks, {len(disagreements)} disagreements")
    if not compared:
        return 2
    return 1 if disagreements else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
