"""Reproduce the AAE v1.4.0 vectors, run every binding case, and retain one fresh report.

    uv run python interop/aae-verdict-binding-v1/run_binding.py --output-dir DIR

DIR must not exist; the runner creates it and never reuses an earlier report. Exit 0
means every vector reproduced and every case produced its declared outcome; 1 means a
fresh report records at least one difference; 2 means malformed input, a failed pin
or key pin, or an output failure, and no report is written by that invocation.
No network is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import bind
import kernel
import pins
from reproduce import reproduce
from strict_json import InputError, load_file, read_bounded, refuse

HERE = Path(__file__).resolve().parent
PROFILE = "aev.aae-verdict-binding.v1"
CODE = ("kernel.py", "strict_json.py", "reproduce.py", "pins.py", "bind.py", "run_binding.py")
CASE_FILES = {"verdict-record.json", "expected.json", "evidence.dsse.json", "ratification.json"}
NOT_ESTABLISHED = [
    "execution",
    "outcome",
    "completeness_of_the_decision_set",
    "freshness_at_presentation",
    "production_identity_of_any_key",
    "revocation_state",
    "independent_custody",
]


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_vectors(root: Path) -> list[dict[str, Any]]:
    """Reproduce every retained vector under the trust-key pins."""
    paths = sorted((root / pins.FIXTURE_DIR).glob("*.json"))
    return [reproduce(path.name, load_file(path), pins.trust_pins()) for path in paths]


def declared(directory: Path) -> dict[str, Any]:
    """Read and check one case's declaration."""
    document = load_file(directory / "expected.json")
    if set(document) != {"name", "role", "describe", "expect"}:
        refuse("a case declaration carries exactly name, role, describe and expect")
    if document["name"] != directory.name or document["role"] not in ("case", "control"):
        refuse("a case declaration's name or role is wrong")
    if not isinstance(document["expect"], dict) or set(document["expect"]) != set(bind.CLAIMS):
        refuse("a case declaration must state every claim and no other")
    return document


def run_case(directory: Path) -> dict[str, Any]:
    """Evaluate one case directory and compare its claims with the declaration."""
    present = {path.name for path in directory.iterdir()}
    if not present <= CASE_FILES or not {"verdict-record.json", "expected.json"} <= present:
        refuse("a case directory holds an unexpected or missing file")
    declaration = declared(directory)
    evidence = directory / "evidence.dsse.json"
    ratification = directory / "ratification.json"
    result = bind.bind(
        load_file(directory / "verdict-record.json"),
        read_bounded(evidence) if evidence.exists() else None,
        load_file(ratification) if ratification.exists() else None,
    )
    produced = bind.claim_values(result)
    return {
        "name": directory.name,
        "role": declaration["role"],
        "declared": declaration["expect"],
        "produced": produced,
        "matches_declaration": produced == declaration["expect"],
        "result": result,
    }


def build_report(root: Path) -> dict[str, Any]:
    """Check pins, reproduce vectors, run cases, and assemble the report."""
    document = pins.check_pins(root)
    vector_results = run_vectors(root)
    case_results = [run_case(path) for path in sorted((root / "cases").iterdir())]
    code = {name: digest_file(HERE / name) for name in CODE}
    code["observed_effect_verifier"] = digest_file(bind.EVIDENCE_VERIFIER)
    return {
        "profile": PROFILE,
        "source": document["source"],
        "input_sha256": {item["path"]: item["sha256"] for item in document["files"]},
        "code_sha256": code,
        "trust_keys": document["trust_keys"],
        "evidence_keys": document["evidence_keys"],
        "vectors_total": len(vector_results),
        "vectors_reproduced": sum(item["reproduced"] for item in vector_results),
        "vectors": vector_results,
        "cases_total": len(case_results),
        "cases_as_declared": sum(item["matches_declaration"] for item in case_results),
        "cases": case_results,
        "not_established": NOT_ESTABLISHED,
    }


def passed(report: dict[str, Any]) -> bool:
    return (report["vectors_reproduced"] == report["vectors_total"] > 0
            and report["cases_as_declared"] == report["cases_total"] > 0)


def write_report(directory: Path, report: dict[str, Any]) -> Path:
    """Write report.json atomically inside the directory this invocation created."""
    temporary = directory / "report.json.tmp"
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    final = directory / "report.json"
    temporary.replace(final)
    return final


def main(argv: list[str] | None = None) -> int:
    """Run once into a new output directory; see the module docstring for exit codes."""
    parser = argparse.ArgumentParser(description="AAE verdict-binding run")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--input-root", type=Path, default=HERE, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        args.output_dir.mkdir(parents=False, exist_ok=False)
        report = build_report(args.input_root)
        path = write_report(args.output_dir, report)
    except (InputError, kernel.CallerError, OSError) as exc:
        print(f"aae-verdict-binding: refused: {exc}", file=sys.stderr)
        return 2
    print(
        f"aae-verdict-binding: {report['vectors_reproduced']}/{report['vectors_total']} vectors "
        f"reproduced, {report['cases_as_declared']}/{report['cases_total']} cases as declared, "
        f"report {path}"
    )
    return 0 if passed(report) else 1


if __name__ == "__main__":
    sys.exit(main())
