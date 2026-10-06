#!/usr/bin/env python3
"""Capture timestamp attempt bytes before grading their review eligibility."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MEMBERS = (
    "release/CORPUS-DIGESTS.txt.sig",
    "release/CORPUS-DIGESTS.txt.sig.tsr",
    "release/CORPUS-DIGESTS.txt.sig.ots",
    "spec/tsa-roots.pem",
)
OUTCOMES = ("success", "failure", "skipped", "cancelled")
LOGS = ("upgrade.log", "verify.log")


def git(*args: str) -> bytes:
    """Read source objects without changing refs."""
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, check=True).stdout


def record(relative: str, raw: bytes | None, state: str, reason: str = "") -> dict[str, object]:
    """Describe missing and empty members without inventing bytes."""
    result: dict[str, object] = {"path": relative, "state": state}
    if raw is not None:
        result.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if reason:
        result["reason"] = reason
    return result


def snapshot(root: Path, relative: str) -> tuple[dict[str, object], bytes | None]:
    """Read regular bytes once; refuse symlinks within the selected boundary."""
    path = root
    for part in Path(relative).parts:
        path /= part
        if path.is_symlink():
            return record(relative, None, "refused", "symlink inside the retained boundary"), None
    if not path.exists():
        return record(relative, None, "missing"), None
    if not path.is_file():
        return record(relative, None, "refused", "member is not a regular file"), None
    try:
        raw = path.read_bytes()
    except OSError as error:
        return record(relative, None, "unreadable", str(error)), None
    return record(relative, raw, "present" if raw else "empty"), raw


def preflight(destination: Path) -> None:
    """Check every write target and selected log before creating any capture member."""
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("candidate destination is not a regular directory")
    for relative in ("manifest.json", "original.ots", *MEMBERS, *LOGS):
        target = destination
        for part in Path(relative).parts:
            target /= part
            if target.is_symlink():
                raise ValueError(f"candidate destination contains a symlink: {relative}")
            if target != destination / relative and target.exists() and not target.is_dir():
                raise ValueError(f"candidate destination parent is not a directory: {relative}")
        if relative not in LOGS and target.exists():
            raise ValueError(f"refuse to replace retained candidate: {relative}")


def source_snapshot() -> tuple[str | None, str | None, list[str], dict[str, bytes], list[str]]:
    """Read one immutable Git identity and its selected original blobs."""
    # Resolve mutable HEAD exactly once; every subsequent Git read uses that object.
    head = None
    tree = None
    changes: list[str] = []
    expected: dict[str, bytes] = {}
    source_errors: list[str] = []
    try:
        head = git("rev-parse", "HEAD").decode().strip()
        tree = git("rev-parse", f"{head}^{{tree}}").decode().strip()
        changes = [
            path
            for path in git("diff", "--name-only", "-z", head, "--").decode().split("\0")
            if path
        ]
        for relative in MEMBERS:
            try:
                expected[relative] = git("show", f"{head}:{relative}")
            except subprocess.CalledProcessError:
                source_errors.append(f"selected source has no readable blob: {relative}")
    except subprocess.CalledProcessError:
        source_errors.append("selected Git source could not be pinned and read")
    return head, tree, changes, expected, source_errors


def write_captures(destination: Path, copies: dict[str, bytes | None]) -> None:
    """Create only preflighted named members; never replace an existing member."""
    destination.mkdir(parents=True, exist_ok=True)
    for relative, raw in copies.items():
        if raw is not None:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)


def validation_errors(
    selected: dict[str, tuple[dict[str, object], bytes | None]], expected: dict[str, bytes]
) -> list[str]:
    """Compare the captured validation bytes with the same selected source."""
    errors = []
    for relative, (member, raw) in selected.items():
        if relative in expected:
            member["sourceSha256"] = hashlib.sha256(expected[relative]).hexdigest()
            if relative != MEMBERS[2] and raw != expected[relative]:
                errors.append(f"working validation input differs from selected source: {relative}")
    return errors


def grade(
    records: list[dict[str, object]],
    selected: dict[str, tuple[dict[str, object], bytes | None]],
    expected: dict[str, bytes],
    changes: list[str],
    outcomes: dict[str, str],
    source_errors: list[str],
) -> list[str]:
    """Grade a completed capture; outcomes are reported, not authenticated."""
    errors = source_errors + validation_errors(selected, expected)
    errors.extend(
        f"{member['path']}: {member['state']}" for member in records if member["state"] != "present"
    )
    if any(path != MEMBERS[2] for path in changes):
        errors.append("working source has changes beyond the selected proof")
    for stage, outcome in outcomes.items():
        if outcome != "success":
            errors.append(f"reported {stage} step outcome: {outcome}")
    return errors


def retain(destination: Path, upgrade_outcome: str, verify_outcome: str) -> dict[str, object]:
    """Retain available fixed inputs and logs, then grade without authenticating stages."""
    preflight(destination)
    for outcome in (upgrade_outcome, verify_outcome):
        if outcome not in OUTCOMES:
            raise ValueError(f"unrecognized reported step outcome: {outcome}")
    head, tree, changes, expected, source_errors = source_snapshot()

    # Snapshot every source before writes. Copying these bytes never follows a source symlink.
    selected = {relative: snapshot(REPO, relative) for relative in MEMBERS}
    original = expected.get(MEMBERS[2])
    original_record = record(
        "original.ots",
        original,
        "missing" if original is None else "present" if original else "empty",
    )
    original_record["role"] = (
        "original proof from the selected source commit; "
        "not an observation of pre-upgrade working bytes"
    )
    logs = {relative: snapshot(destination, relative) for relative in LOGS}

    copies = {
        "original.ots": original,
        **{relative: raw for relative, (_, raw) in selected.items()},
    }
    write_captures(destination, copies)

    records = [
        original_record,
        *(value[0] for value in logs.values()),
        *(value[0] for value in selected.values()),
    ]
    errors = grade(
        records,
        selected,
        expected,
        changes,
        {"upgrade": upgrade_outcome, "verify": verify_outcome},
        source_errors,
    )
    proof = selected[MEMBERS[2]][1]
    return {
        "schemaVersion": 1,
        "sourceCommit": head,
        "sourceTree": tree,
        "changedTrackedPaths": changes,
        "proofChanged": None if proof is None or original is None else proof != original,
        "members": records,
        "stages": {"upgrade": {"outcome": upgrade_outcome}, "verify": {"outcome": verify_outcome}},
        "decision": "capture-only-refused" if errors else "eligible-for-ordinary-review",
        "errors": errors,
        "verification": (
            "Step outcomes are supplied by the caller; no command exit code is inferred. "
            "Logs retain reported binding and chain states but do not authenticate execution. "
            "Capture and upgrade success do not establish chain validation."
        ),
        "publication": (
            "Capture only. Any proof change needs ordinary protected review. "
            "Immutable releases remain unchanged."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("upgrade_outcome", choices=OUTCOMES)
    parser.add_argument("verify_outcome", choices=OUTCOMES)
    args = parser.parse_args()
    try:
        report = retain(args.destination, args.upgrade_outcome, args.verify_outcome)
        with (args.destination / "manifest.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # A collision or hostile destination cannot safely receive a new manifest.
        print(json.dumps({"decision": "capture-only-refused", "error": str(error)}, sort_keys=True))
        print(f"timestamp capture refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    if report["decision"] != "eligible-for-ordinary-review":
        print("timestamp capture retained; review eligibility refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
