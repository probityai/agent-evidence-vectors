"""Join native process retention, installed Verify, and the Vectors process rail.

Verify evaluates selected text coverage, not destination authorization or scanner
health. The owned reader evaluates the supplied exit status on a separate axis.
"""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from agent_evidence_vectors import sourcecoverage

from .isolated import command
from .reader import InputError, assess
from .runner import ROOT


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _child(command: list[str], output: Path, outside: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        cwd=outside,
        timeout=90,
        capture_output=True,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        check=False,
    )
    output.with_suffix(".stdout").write_bytes(result.stdout)
    output.with_suffix(".stderr").write_bytes(result.stderr)
    output.with_suffix(".exit").write_text(f"{result.returncode}\n")
    return result


def _document(name: str, stdout: bytes, captured: str, source_available: bool) -> dict[str, bytes]:
    case_id = f"authority-effect-{name}"
    source = b"selected unit: unit-a\nselected unit: unit-b\nselected unit: unit-c\n"

    def metadata(path: str, raw: bytes) -> dict:
        return {"path": path, "sha256": _sha(raw), "length": len(raw)}

    case = {
        "schema_version": "source-coverage-case/v1",
        "case_id": case_id,
        "artifacts": {
            "source": metadata("source.txt", source),
            "record": metadata("report.txt", stdout),
        },
    }
    policy = {
        "schema_version": "source-coverage-policy/v1",
        "witnesses": {
            "capture": {
                "artifact": "source",
                "sha256": _sha(source),
                "captured_at": captured,
                "source_url": "https://fixture.example/selected-inventory",
                "authority": "Caller-selected synthetic inventory; no independent capture",
                "source_format": "text_utf8/v1",
            }
        },
        "assessments": {
            case_id: {
                "claim_type": "source_text_coverage/v1",
                "source_witness": "capture",
                "record_artifact": "record",
                "record_sha256": _sha(stdout),
                "record_version": "synthetic-process/v1",
                "source_window": {"start": "2026-10-09T00:00:00Z", "end": "2026-10-09T23:59:59Z"},
                "required_spans": [
                    {"id": unit, "text": f"selected unit: {unit}"}
                    for unit in ("unit-a", "unit-b", "unit-c")
                ],
            }
        },
    }
    files = {"case.json": _json(case), "policy.json": _json(policy), "report.txt": stdout}
    if source_available:
        files["source.txt"] = source
    return files


def _scanner_claims(mode: str, process: subprocess.CompletedProcess) -> dict:
    case = json.loads((ROOT / "cases" / "matching-supplied-records.json").read_bytes())
    complete = mode == "complete"
    case["scan"] = {
        "scanned": ["unit-a", "unit-b", "unit-c"] if complete else ["unit-a"],
        "skipped": [] if complete else ["unit-b", "unit-c"],
        "findings": [],
        "stdout": process.stdout.decode("utf-8"),
        "exitCode": process.returncode,
    }
    claims = assess(_json(case), (ROOT / "policy.json").read_bytes())["claims"]
    return {
        key: claims[key]
        for key in (
            "coverageComplete",
            "noFindingReported",
            "processExitMatchesCoverage",
            "truncationNoticePresent",
        )
    }


def run_bridge(output: Path) -> dict:
    """Retain process bytes, then bind and check every generated coverage case."""
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise InputError("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    entries, rows = [], []
    specifications = [
        ("complete", "complete", "supported", "all_selected_spans_present", True, False),
        (
            "truncation-zero",
            "truncation-zero",
            "contradicted",
            "selected_span_missing_from_record",
            True,
            False,
        ),
        (
            "truncation-one",
            "truncation-one",
            "contradicted",
            "selected_span_missing_from_record",
            True,
            False,
        ),
        (
            "silent-truncation",
            "silent-truncation",
            "contradicted",
            "selected_span_missing_from_record",
            True,
            False,
        ),
        (
            "inventory-unavailable",
            "complete",
            "not_established",
            "artifact_unavailable_or_unbound",
            False,
            False,
        ),
        (
            "stale-capture",
            "complete",
            "not_established",
            "witness_outside_source_window",
            True,
            True,
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="coverage-bridge-outside-") as outside:
        for name, mode, decision, reason, available, stale in specifications:
            directory = output / "cases" / name
            directory.mkdir(parents=True)
            process = _child(
                [
                    *command(
                        "authority_effect.scanner", record=output / f"scanner-{name}.cache.json"
                    ),
                    mode,
                ],
                output / f"scanner-{name}",
                outside,
            )
            if process.stderr or process.returncode != int(mode == "truncation-one"):
                raise InputError("scanner process did not meet its explicit process contract")
            capture = "2026-10-10T00:00:00Z" if stale else "2026-10-09T12:00:00Z"
            files = _document(name, process.stdout, capture, available)
            for file, raw in files.items():
                (directory / file).write_bytes(raw)
            expected = {"decision": decision, "reason": reason}
            entries.append(
                {
                    "id": name,
                    "path": f"cases/{name}",
                    "expected": expected,
                    "files": {file: _sha(raw) for file, raw in files.items()},
                }
            )
            verifier = _child(
                [
                    *command("probity_verify.cli", record=output / f"verify-{name}.cache.json"),
                    str(directory / "case.json"),
                    "--policy",
                    str(directory / "policy.json"),
                    "--json",
                ],
                output / f"verify-{name}",
                outside,
            )
            try:
                answer = json.loads(verifier.stdout)
                observed = {key: answer[key] for key in expected}
            except (ValueError, KeyError, TypeError) as exc:
                raise InputError("installed Verify did not return its decision contract") from exc
            rows.append(
                {
                    "id": name,
                    "expected": expected,
                    "observed": observed,
                    "matched": observed == expected
                    and verifier.returncode == 0
                    and not verifier.stderr,
                    "nativeProcessExit": process.returncode,
                    "scannerClaims": _scanner_claims(mode, process),
                }
            )
        manifest = {
            "suite": sourcecoverage.SUITE,
            "vectors": entries,
            "corpusDigest": _sha(_json(entries)),
            "verifierContract": "verifier case.json --policy policy.json --json",
        }
        (output / "MANIFEST.json").write_bytes(_json(manifest))
        executed, failures = sourcecoverage.check(command("probity_verify.cli"), output)
    report = {
        "schema": "probity.authority-effect-coverage-bridge/v1",
        "total": len(rows),
        "passed": sum(row["matched"] for row in rows),
        "vectorsExecuted": executed,
        "vectorsFailures": failures,
        "corpusDigest": manifest["corpusDigest"],
        "rows": rows,
        "scope": "Reduced synthetic process fixture; Verify checks selected text coverage only",
    }
    (output / "bridge.json").write_bytes(_json(report))
    return report
