"""Read supplied Boolean decisions without upgrading them to authorization evidence."""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .isolated import command
from .reader import InputError, _object, _parse, _text

PROFILE = "probity.frequency-supplied-claims/v1"
ROOT = Path(__file__).resolve().parent / "frequency_fixtures"


def assess_supplied_claims(raw: bytes) -> dict:
    """Compare a supplied observation to a requested value, never a refusal policy."""
    value = _object(
        _parse(raw),
        {"profile", "id", "authorized", "executionReported", "requestedEffect", "observation"},
    )
    if value["profile"] != PROFILE:
        raise InputError("unsupported supplied-claims profile")
    _text(value["id"])
    for key in ("authorized", "executionReported"):
        if type(value[key]) is not bool:
            raise InputError(f"{key} must be a literal Boolean")
    requested = _text(value["requestedEffect"])
    observed = value["observation"]
    if observed is None:
        comparison = "NOT_ESTABLISHED"
    else:
        comparison = "MATCHES_REQUEST" if _text(observed) == requested else "DIFFERS_FROM_REQUEST"
    return {
        "profile": PROFILE,
        "id": value["id"],
        "inputSha256": hashlib.sha256(raw).hexdigest(),
        "claims": {
            "suppliedDecision": "AUTHORIZED" if value["authorized"] else "DENIED",
            "completionReport": "REPORTED" if value["executionReported"] else "NOT_REPORTED",
            "requestedEffectComparison": comparison,
        },
        "requiredPostDecisionState": "NOT_SUPPLIED",
        "scope": "Supplied assertions only; no signature, execution or observation provenance",
    }


def _entry_name(entry: dict, identifiers: set[str]) -> str:
    _object(entry, {"id", "path", "sha256", "expected"})
    name = entry["id"]
    if (
        type(name) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{0,100}", name) is None
        or name in identifiers
        or entry["path"] != name + ".json"
    ):
        raise InputError("invalid or duplicate supplied-claims control path")
    return name


def _manifest() -> list[dict]:
    manifest = _parse((ROOT / "manifest.json").read_bytes())
    entries = manifest.get("cases")
    if not isinstance(entries, list) or not entries:
        raise InputError("missing supplied-claims control population")
    expected = {"manifest.json"}
    identifiers: set[str] = set()
    for entry in entries:
        name = _entry_name(entry, identifiers)
        identifiers.add(name)
        expected.add(entry["path"])
    actual = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*.json")}
    if (
        manifest.get("profile") != PROFILE
        or manifest.get("total") != len(entries)
        or actual != expected
    ):
        raise InputError("supplied-claims control population changed")
    return entries


def _matched(
    result: dict | None, expected: dict | str, process: subprocess.CompletedProcess[bytes]
) -> bool:
    if expected == "REFUSED":
        return (
            result is None
            and process.returncode == 2
            and not process.stdout
            and process.stderr.startswith(b"refused:")
        )
    if result is None or process.returncode != 0 or process.stderr:
        return False
    try:
        return json.loads(process.stdout) == result and result["claims"] == expected
    except (ValueError, TypeError):
        return False


def _control(entry: dict, output: Path, outside: str) -> dict:
    path = ROOT / entry["path"]
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != entry["sha256"]:
        raise InputError("supplied-claims control digest differs")
    try:
        result = assess_supplied_claims(raw)
    except InputError:
        result = None
    process = subprocess.run(
        [
            *command("authority_effect.cli", record=output / (entry["id"] + ".cache.json")),
            "frequency-read",
            str(path),
        ],
        cwd=outside,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
        capture_output=True,
        check=False,
        timeout=30,
    )
    stem = output / entry["id"]
    stem.with_suffix(".stdout").write_bytes(process.stdout)
    stem.with_suffix(".stderr").write_bytes(process.stderr)
    stem.with_suffix(".exit").write_text(str(process.returncode) + "\n")
    matched = _matched(result, entry["expected"], process)
    return {
        "id": entry["id"],
        "matched": matched,
        "inputSha256": digest,
        "actual": result,
        "exit": process.returncode,
    }


def run_supplied_controls(output: Path) -> dict:
    """Retain all twelve comparison cells and each invalid-Boolean CLI refusal."""
    if output.exists() and any(output.iterdir()):
        raise InputError("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="frequency-claims-outside-") as outside:
        rows = [_control(entry, output, outside) for entry in _manifest()]
    report = {
        "profile": PROFILE,
        "total": len(rows),
        "passed": sum(row["matched"] for row in rows),
        "rows": rows,
        "scope": "Author-operated supplied-assertion controls; original fixture unchanged",
    }
    (output / "controls.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report
