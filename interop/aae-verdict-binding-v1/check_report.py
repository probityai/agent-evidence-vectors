"""Require a fresh run report that matches this checkout's pins, code and outcomes.

    uv run python interop/aae-verdict-binding-v1/check_report.py DIR/report.json

Exit 0 only when the report's input digests equal the committed pins, its code
digests equal this checkout's files, all 26 vectors reproduced and all seven cases
produced their declared outcome. Anything else, a missing report included, is 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import bind
import pins
import run_binding
from strict_json import InputError, no_constant, no_float, refuse, unique_members

VECTORS = 26
CASES = 7
MAX_REPORT_BYTES = 4 * 1024 * 1024


def load_report(path: Path) -> dict[str, Any]:
    """A report is larger than an input but read under the same strict rules."""
    with path.open("rb") as stream:
        payload = stream.read(MAX_REPORT_BYTES + 1)
    if len(payload) > MAX_REPORT_BYTES:
        refuse("the report exceeds its byte budget")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_members,
                           parse_float=no_float, parse_constant=no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("the report is not well-formed JSON")
    if not isinstance(value, dict):
        refuse("the report root is not an object")
    return value


def check_counts(report: dict[str, Any]) -> None:
    """Every vector and every case, at the counts this package retains."""
    expected = {
        "vectors_total": VECTORS,
        "vectors_reproduced": VECTORS,
        "cases_total": CASES,
        "cases_as_declared": CASES,
    }
    if any(report.get(key) != value for key, value in expected.items()):
        refuse("the report does not reproduce every vector and every declared case")
    if not all(item.get("reproduced") is True for item in report.get("vectors", [])):
        refuse("a vector entry is not reproduced")
    if not all(item.get("matches_declaration") is True for item in report.get("cases", [])):
        refuse("a case entry differs from its declaration")


def check_report(path: Path) -> None:
    """Check pins, code digests, profile, counts and the claim ceiling of one report."""
    document = pins.check_pins()
    report = load_report(path)
    if report.get("profile") != run_binding.PROFILE or report.get("source") != pins.SOURCE:
        refuse("the report's profile or source differs")
    if report.get("input_sha256") != {item["path"]: item["sha256"] for item in document["files"]}:
        refuse("the report's inputs differ from the committed pins")
    code = {name: run_binding.digest_file(run_binding.HERE / name) for name in run_binding.CODE}
    code["observed_effect_verifier"] = run_binding.digest_file(bind.EVIDENCE_VERIFIER)
    if report.get("code_sha256") != code:
        refuse("the report was produced by code other than this checkout's")
    if report.get("not_established") != run_binding.NOT_ESTABLISHED:
        refuse("the report's not_established list differs")
    check_counts(report)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check an AAE verdict-binding report")
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        check_report(args.report)
    except (OSError, InputError) as exc:
        print(f"report refused: {exc}", file=sys.stderr)
        return 2
    print(f"Report checked: {VECTORS} vectors reproduced and {CASES} cases as declared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
