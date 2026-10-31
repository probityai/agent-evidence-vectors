"""Check every owned production module, not an aggregate coverage percentage."""

import hashlib
import json
import sys
from pathlib import Path

REQUIRED = {
    "reader.py",
    "runner.py",
    "cli.py",
    "scanner.py",
    "coverage_bridge.py",
    "frequency_claims.py",
    "distribution.py",
    "isolated.py",
    "errors.py",
}


def _has_symlink_ancestor(path: Path) -> bool:
    return any(parent.is_symlink() for parent in (path, *path.parents))


def evaluate(data: dict, qualification: dict) -> dict:
    payload = qualification["installedPayload"]
    root = Path(payload["installedRoot"]).absolute()
    selected = {row["path"]: row for row in payload["files"]}
    rows = {}
    measured = {}
    failures = []
    for name, row in data["files"].items():
        # Keep the measured lexical path until after the identity decision:
        # resolving it first could turn an outside symlink into a false match.
        path = Path(name).absolute()
        if path.name not in REQUIRED:
            continue
        if path.name in rows:
            failures.append("duplicate measured module: " + path.name)
        rows[path.name] = row["summary"]["percent_covered"]
        measured[path.name] = str(path)
        expected = selected.get("authority_effect/" + path.name)
        if (
            path != root / "authority_effect" / path.name
            or expected is None
            or _has_symlink_ancestor(path)
        ):
            failures.append("measured source differs from qualified installation: " + name)
            continue
        if not path.is_file() or path.is_symlink():
            failures.append("qualified source is missing or a symlink: " + name)
            continue
        content = path.read_bytes()
        if (
            len(content) != expected["bytes"]
            or hashlib.sha256(content).hexdigest() != expected["sha256"]
        ):
            failures.append("qualified source bytes changed: " + name)
    return {
        "threshold": 80,
        "files": rows,
        "measuredSourceFiles": measured,
        "selectedWheelSha256": payload["wheelSha256"],
        "identityFailures": failures,
        "passing": (
            not failures and set(rows) == REQUIRED and all(value >= 80 for value in rows.values())
        ),
    }


def main() -> int:
    data = json.loads(Path(sys.argv[1]).read_bytes())
    qualification = json.loads(Path(sys.argv[2]).read_bytes())
    report = evaluate(data, qualification)
    Path(sys.argv[1]).with_name("per-file-coverage.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print(json.dumps(report, sort_keys=True, indent=2))
    return int(not report["passing"])


if __name__ == "__main__":
    raise SystemExit(main())
