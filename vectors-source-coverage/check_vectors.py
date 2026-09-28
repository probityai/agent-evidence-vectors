"""Check corpus bytes and drive a named external source-coverage verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _fixture_error(directory: Path, entry: dict) -> str | None:
    """Return the first byte-level fixture error, if any."""
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_digest((directory / name).read_bytes()) != digest
           for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _execute(command: list[str], directory: Path, expected: dict) -> tuple[bool, str | None]:
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


def _validated_entries(root: Path) -> tuple[list[dict], str | None]:
    """Check manifest commitments and return its members."""
    manifest = json.loads((root / "MANIFEST.json").read_text())
    entries = manifest["vectors"]
    if _digest(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def check(verifier: str, root: Path = ROOT) -> tuple[int, list[str]]:
    """Check every committed vector through a separately invoked process.

    Parameters
    ----------
    verifier : str
        Command implementing the probity-verify CLI contract.
    root : Path
        Corpus directory.

    Returns
    -------
    tuple[int, list[str]]
        Number of executed vectors and any corpus or verifier failures.
    """
    entries, manifest_error = _validated_entries(root)
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier)
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
