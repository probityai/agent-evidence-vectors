"""Compare actual process outcomes with a bounded, producer-derived report projection."""

import json
import os
import re
import stat
import unicodedata
from datetime import datetime
from pathlib import Path

PROFILE = "frequency.external-assurance.aps-priorseal.v1"
MAX_REPORT_BYTES = 1_048_576
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
EXPECTED = json.loads((Path(__file__).parent / "expected.json").read_text())


def operator_identity(value: str) -> dict:
    """Require an explicit caller declaration without inferring authentication."""
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else None
    except UnicodeError:
        encoded = None
    if (
        not isinstance(value, str)
        or not value
        or encoded is None
        or value != value.strip()
        or value.startswith("--")
        or len(encoded) > 512
        or any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in value)
    ):
        raise ValueError(
            "operator identity must be explicit, bounded and free of control characters"
        )
    return {"identity": value, "source": "caller-declared", "authenticated": False}


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _constant(value):
    raise ValueError("non-JSON numeric constant: " + value)


def _same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same(actual[key], value) for key, value in expected.items()
        )
    return actual == expected


def _time(value):
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("expected exact UTC millisecond timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_report(path: Path) -> tuple[bytes | None, str | None]:
    """Read a bounded regular file without following a report symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, "REPORT_ABSENT"
    except OSError:
        return None, "REPORT_UNREADABLE"
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None, "REPORT_NOT_REGULAR"
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            return None, "REPORT_TOO_LARGE"
        return raw, None
    finally:
        os.close(descriptor)


def compare_report(raw: bytes, started: str, ended: str) -> str | None:
    """Check native field meanings, not signatures, execution or operator identity."""
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "REPORT_MALFORMED"
    if not isinstance(report, dict) or report.get("profile") != PROFILE:
        return "REPORT_PROFILE_MISMATCH"
    pins = report.get("pins")
    if not isinstance(pins, dict) or any(
        not _same(pins.get(key), value) for key, value in EXPECTED["pins"].items()
    ):
        return "REPORT_INPUT_MISMATCH"
    claims = report.get("claims")
    if not isinstance(claims, list) or any(not isinstance(item, dict) for item in claims):
        return "REPORT_CLAIMS_MISMATCH"
    projection = [{"id": item.get("id"), "result": item.get("result")} for item in claims]
    if projection != EXPECTED["claims"]:
        return "REPORT_CLAIMS_MISMATCH"
    summary = report.get("summary")
    if (
        not isinstance(summary, dict)
        or summary != EXPECTED["summary"]
        or any(type(value) is not int for value in summary.values())
    ):
        return "REPORT_SUMMARY_MISMATCH"
    try:
        first, last = _time(started), _time(ended)
        generated = _time(report.get("generated_at"))
    except ValueError:
        return "REPORT_TIME_INVALID"
    if last < first:
        return "OBSERVED_INTERVAL_INVALID"
    if not first <= generated <= last:
        return "REPORT_TIME_OUTSIDE_INTERVAL"
    return None


def assess(
    *,
    process_exit: int | None,
    capture_complete: bool,
    recorded_exit: int | None,
    report_before: bool,
    report_path: Path,
    started: str,
    ended: str,
) -> dict:
    """Keep actual process, recorded status and report checks as separate evidence."""
    raw, report_error = read_report(report_path)
    if report_error is None:
        report_error = compare_report(raw, started, ended)
    if capture_complete is not True or type(process_exit) is not int:
        reason = "PROCESS_NOT_COMPLETE"
    elif process_exit != 0:
        reason = "PROCESS_NONZERO"
    elif recorded_exit != process_exit or type(recorded_exit) is not int:
        reason = "RECORDED_EXIT_MISMATCH"
    elif type(report_before) is not bool:
        reason = "REPORT_PRESENCE_NOT_OBSERVED"
    elif report_before:
        reason = "REPORT_PREEXISTED"
    else:
        reason = report_error
    return {
        "accepted_projection": reason is None,
        "reason": reason,
        "process_exit": process_exit,
        "recorded_exit": recorded_exit,
        "report_check": report_error,
        "report_present_before": report_before,
        "report_bytes": len(raw) if raw is not None else None,
        "run_correlation": "not supplied by the native contract",
        "generation_time": "producer-declared; window check is not authenticity or execution proof",
    }
