"""Check pinned source-coverage cases through a named external verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

SUITE = "source-text-coverage/v1"
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-source-coverage" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-source-coverage")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    """Return the first byte-level fixture error, if any."""
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_digest((directory / name).read_bytes()) != digest
           for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _execute(
    command: list[str], directory: Path, expected: dict[str, str]
) -> tuple[bool, str | None]:
    """Return whether the process ran and any disagreement."""
    try:
        result = subprocess.run(
            [*command, str(directory / "case.json"), "--policy",
             str(directory / "policy.json"), "--json"],
            capture_output=True, text=True, timeout=90, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if result.returncode or observed != expected:
        return True, f"expected {expected}, got {observed} (exit {result.returncode})"
    return True, None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Check manifest commitments and return its members."""
    manifest = json.loads((root / "MANIFEST.json").read_text())
    entries = manifest["vectors"]
    if _digest(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def check(verifier: str | list[str], root: Path = ROOT) -> tuple[int, list[str]]:
    """Check every committed vector through a separately invoked process.

    Return the number of executed vectors and any corpus or verifier failures.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    executed = 0
    for entry in entries:
        name = entry["id"]
        directory = root / "cases" / name
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        ran, execution_error = _execute(command, directory, entry["expected"])
        executed += int(ran)
        if execution_error:
            errors.append(f"{name}: {execution_error}")
    return executed, errors


def run_external(root: str, verifier: list[str], report_path: str, rail_note: str) -> int:
    """Run every member, recording the executed count and all disagreements."""
    directory = Path(root)
    executed, errors = check(verifier, directory)
    manifest: dict[str, Any] = {}
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        total = 0
    for error in errors:
        print(error)
    print(f"executed {executed} of {total} vectors")
    if not executed or not total:
        print("no report written: the named verifier did not answer a vector")
        return 2
    report = {
        "suite": SUITE, "rail": "external", "verifier": {"command": verifier,
        "vectorsExecuted": executed, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors),
                   "fail": len(errors), "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or executed != total else 0


def run_or_refuse(
    root: str, verifier: list[str] | None, report_path: str, rail_note: str
) -> int:
    if verifier is None:
        print(
            "source-text-coverage/v1 requires a named external verifier; "
            "no vector was checked and no report was written.",
            file=sys.stderr,
        )
        return 2
    return run_external(root, verifier, report_path, rail_note)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", required=True,
                        help="command that accepts case, --policy and --json")
    args = parser.parse_args()
    executed, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text())["vectors"])
    print(f"executed {executed} of {total} vectors")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
