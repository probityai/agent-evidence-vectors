"""Run every packaged control through the API and a separate installed process."""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .isolated import command
from .reader import PROFILE, InputError, _parse, assess

ROOT = Path(__file__).resolve().parent / "fixtures"


def _manifest() -> list[dict]:
    manifest = _parse((ROOT / "manifest.json").read_bytes())
    try:
        entries = manifest["cases"]
        expected_files = {"manifest.json", "policy.json"}
        expected_files.update(entry[key] for entry in entries for key in ("path", "policy"))
        actual_files = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*.json")}
        invalid = (
            manifest["profile"] != PROFILE
            or not entries
            or len(entries) != manifest["total"]
            or len({entry["id"] for entry in entries}) != len(entries)
            or actual_files != expected_files
        )
        if invalid:
            raise InputError("incomplete, duplicate or changed fixture population")
        for entry in entries:
            if (
                re.fullmatch(r"[a-z][a-z0-9-]{0,100}", entry["id"]) is None
                or entry["path"] != f"cases/{entry['id']}.json"
                or entry["policy"] != f"policies/{entry['id']}.json"
            ):
                raise InputError("fixture path differs from identifier")
        _bound(ROOT / "policy.json", manifest["baselinePolicySha256"])
    except (KeyError, TypeError) as exc:
        raise InputError("invalid fixture manifest") from exc
    return entries


def _bound(path: Path, digest: str) -> bytes:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise InputError("fixture digest differs")
    return raw


def _control(entry: dict, output: Path, outside: str) -> dict:
    case, policy = ROOT / entry["path"], ROOT / entry["policy"]
    raw = _bound(case, entry["sha256"])
    result = assess(raw, _bound(policy, entry["policySha256"]))
    values = {name: claim["value"] for name, claim in result["claims"].items()}
    process = subprocess.run(
        [
            *command("authority_effect.cli", record=output / (entry["id"] + ".cache.json")),
            "read",
            str(case),
            "--policy",
            str(policy),
        ],
        cwd=outside,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        capture_output=True,
        timeout=30,
        check=False,
    )
    stem = output / entry["id"]
    stem.with_suffix(".stdout").write_bytes(process.stdout)
    stem.with_suffix(".stderr").write_bytes(process.stderr)
    stem.with_suffix(".exit").write_text(str(process.returncode) + "\n")
    try:
        answered = json.loads(process.stdout) == result
    except (ValueError, TypeError):
        answered = False
    matched = (
        values == entry["expected"] and process.returncode == 0 and answered and not process.stderr
    )
    return {
        "id": entry["id"],
        "matched": matched,
        "actual": values,
        "caseSha256": result["caseSha256"],
        "policySha256": result["policySha256"],
        "exit": process.returncode,
    }


def run_controls(output: Path) -> dict:
    """Keep complete process output before comparing each expected claim."""
    if output.exists() and any(output.iterdir()):
        raise InputError("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="authority-effect-outside-") as outside:
        rows = [_control(entry, output, outside) for entry in _manifest()]
    report = {
        "schema": "probity.authority-effect-controls/v1",
        "total": len(rows),
        "passed": sum(row["matched"] for row in rows),
        "rows": rows,
        "scope": "Author-operated synthetic controls; no authenticated observer or live dispatch",
    }
    (output / "controls.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report
