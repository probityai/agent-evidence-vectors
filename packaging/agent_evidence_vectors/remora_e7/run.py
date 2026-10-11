"""Retain an E7 evaluation and its producer-native external run record."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import re
import sys
from pathlib import Path

from .reader import CONTRACT, PACKAGE_DIGEST, REVISION, run_package, sha256

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_UPSTREAM = Path(__file__).parent / "upstream"


def _implementation_revision(explicit: str | None) -> str:
    """Name the exact reader that ran: a Git commit, or the pinned distribution.

    A checkout passes its commit. An installed wheel has no Git history, so it
    names itself as the exact pin that reproduces it; the reader source hashes in
    report.json bind the bytes either way.
    """
    if explicit is not None:
        return explicit
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"{DISTRIBUTION}=={version(DISTRIBUTION)}"
    except PackageNotFoundError:
        raise SystemExit(
            "reader revision is required when the reader is not run from an installed "
            f"{DISTRIBUTION} distribution: pass --reader-revision <40-character commit>"
        ) from None


def main(argv: list[str] | None = None) -> int:
    """Run the selected frozen package and retain an immutable output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream",
        type=Path,
        default=PACKAGED_UPSTREAM,
        help="frozen producer package root (default: the copy shipped in this distribution)",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reader-revision", default=None)
    parser.add_argument("--run-ref", required=True)
    parser.add_argument("--operator", choices=("AUTHOR", "EXTERNAL"), required=True)
    args = parser.parse_args(argv)
    if args.reader_revision is not None and not re.fullmatch(r"[0-9a-f]{40}", args.reader_revision):
        parser.error("reader revision must be a published 40-character Git commit")
    revision = _implementation_revision(args.reader_revision)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    args.output.mkdir(parents=True, exist_ok=False)
    report = run_package(args.upstream)
    report["reader_files"] = _reader_files()
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = _command()
    record = {
        "schema_version": "remora-external-run-record-v1",
        "contract_id": CONTRACT,
        "package_digest": PACKAGE_DIGEST,
        "consumed_revision": REVISION,
        "verifier": {
            "project": "Probity",
            "repository": "probityai/agent-evidence-vectors",
            "implementation_revision": revision,
            "maintained_by": "EXTERNAL",
        },
        "imports": {"remora_runtime": False, "reference_verifier": False},
        "command": report["command"],
        "environment": report["environment"],
        "input_digests": report["input_digests"],
        "implementation_diversity": "SECOND_IMPLEMENTATION",
        "operator": args.operator,
        "independence": "INDEPENDENT" if args.operator == "EXTERNAL" else "NOT_INDEPENDENT",
        "results": [
            {
                "claim_id": item["claim_id"],
                "case_id": item["case_id"],
                "result": item["claim_result"],
                "note": "Frozen fixture premise only; see report.json for ceilings and non-claims.",
            }
            for item in report["results"]
        ],
        "claim_ceiling_repeated": True,
        "non_claims_repeated": True,
        "run_ref": args.run_ref,
    }
    report["operator_scope"] = (
        "Operator is external to REMORA when EXTERNAL is selected. Reader and output are under "
        "Probity control; this proves no independent effect observation or key/store custody."
    )
    for name, value in (("report.json", report), ("external-run-record-v1.json", record)):
        (args.output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


def _reader_files() -> list[dict[str, str]]:
    """Bind the actual reader sources evaluated by this command."""
    root = Path(__file__).parent
    return [
        {"path": name, "sha256": sha256((root / name).read_bytes())}
        for name in ("reader.py", "run.py")
    ]


def _command() -> str:
    """Render the invocation as an unambiguous shell command."""
    import shlex

    return shlex.join([sys.executable, *sys.argv])


if __name__ == "__main__":
    raise SystemExit(main())
