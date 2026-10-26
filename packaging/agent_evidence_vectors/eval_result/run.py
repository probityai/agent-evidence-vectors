"""Evaluation result readings: read one input, or replay the frozen corpus.

    agent-evidence-vectors evalresult read --input CASE.json
    agent-evidence-vectors evalresult run --output DIR

``read`` prints the reading and exits 0 when it carries no reason, 1 when it carries at
least one, and 2 on unusable input. ``run`` replays every case of the frozen corpus without
reading its expected answer, replays every negative's twin through the repair, writes
``report.json`` and exits 1 if anything differs.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
from pathlib import Path
from typing import Any

from ..claim_record.ops import apply_ops
from ..record_paths import portable_command, write_records
from .reader import CODES, MalformedInput, parse_strict, read, sha256_tag

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_CORPUS = Path(__file__).parent / "corpus"
EXIT_CLEAN, EXIT_REASONS, EXIT_UNUSABLE = 0, 1, 2


def load_corpus(root: Path) -> dict[str, Any]:
    """Check every member against the manifest, then load the cases."""
    manifest = parse_strict((root / "manifest.json").read_bytes())
    on_disk = sorted(
        str(p.relative_to(root))
        for p in root.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    )
    if sorted(manifest["members"]) != on_disk:
        raise MalformedInput("corpus members differ from the manifest's list")
    for name, pinned in manifest["members"].items():
        actual = sha256_tag((root / name).read_bytes())
        if actual != pinned:
            raise MalformedInput(f"corpus member {name} is {actual}, manifest pins {pinned}")
    return {
        "cases": parse_strict((root / "cases.json").read_bytes()),
        "digests": dict(manifest["members"]),
    }


def run_corpus(root: Path) -> dict[str, Any]:
    """Read every case without its expected answer, then compare; replay each negative's twin."""
    corpus = load_corpus(root)
    cases = {c["id"]: c for c in corpus["cases"]["cases"]}
    results, failures = [], []
    for case in corpus["cases"]["cases"]:
        actual = read(case["input"])
        ok = actual == case["expected"]
        entry: dict[str, Any] = {
            "case_id": case["id"],
            "kind": case["kind"],
            "about": case["about"],
            "actual": actual,
            "expected": case["expected"],
        }
        if case["kind"] == "negative":
            twin = cases[case["twin"]]
            repaired = apply_ops(case["input"], case["repair"])
            entry["repaired_matches_twin"] = (
                repaired == twin["input"] and read(repaired) == (twin["expected"])
            )
            ok = ok and entry["repaired_matches_twin"]
        if not ok:
            failures.append(case["id"])
        results.append(entry)
    return {
        "schema": "aev-evaluation-result-report/v1",
        "codes": list(CODES),
        "input_digests": corpus["digests"],
        "results": results,
        "failures": failures,
    }


def _revision(explicit: str | None) -> str:
    if explicit is not None:
        return explicit
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"{DISTRIBUTION}=={version(DISTRIBUTION)}"
    except PackageNotFoundError:
        raise SystemExit(
            "pass --implementation-revision <40-character commit> when running from a checkout"
        ) from None


def _cmd_run(args: argparse.Namespace) -> int:
    if args.implementation_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", args.implementation_revision
    ):
        raise SystemExit("implementation revision must be a 40-character Git commit")
    if args.output.exists():
        raise FileExistsError(args.output)
    report = run_corpus(args.corpus)
    report["implementation_revision"] = _revision(args.implementation_revision)
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = portable_command()
    write_records(args.output, {"report.json": report})
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


def _cmd_read(args: argparse.Namespace) -> int:
    outcome = read(parse_strict(args.input.read_bytes()))
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return EXIT_REASONS if outcome["reasons"] else EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-evidence-vectors evalresult",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="replay the frozen corpus into a new directory")
    run.add_argument("--corpus", type=Path, default=PACKAGED_CORPUS)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--implementation-revision", default=None)
    run.set_defaults(func=_cmd_run)
    rd = sub.add_parser("read", help="read one evaluation result input")
    rd.add_argument("--input", type=Path, required=True)
    rd.set_defaults(func=_cmd_read)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (MalformedInput, OSError) as exc:
        print(f"evalresult: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE


if __name__ == "__main__":
    raise SystemExit(main())
