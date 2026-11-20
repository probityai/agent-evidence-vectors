"""Drive a runtime's spend ledger through the execution-billing-finality scenarios.

The runtime contract: the adapter is run as ``<runtime> <scenario.json> --json``.
The scenario carries ``id``, ``budget``, ``steps`` and ``probes`` and no expected
value. The adapter reserves attempt A for two units on a fresh account under
the scenario's budget, runs the steps through its own ledger, reopens the
ledger in a fresh process, runs the probes there, and prints one
execution-billing-finality record (see ``executionbilling``) as its last stdout
line. It exits 0 for a completed observation and nonzero for an operational
failure, which is never read as a verdict.

A scenario passes when the adapter exited 0, its record echoes the scenario it
was given, and the reference reader allows the record. Every shipped scenario
is one a conforming ledger leaves allowed, so a ledger that frees a reservation
because a call succeeded, reads a final invoice as an execution, opens the
dispatch gate after billing settles, or leaves an invoiced attempt RESERVED
fails the scenario that shows it. The corpus's own reference adapter, over an
unmodified copy of the P04 ledger, is ``tests/billing_adapter.py``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from agent_evidence_vectors import executionbilling as reader

TIMEOUT_SECONDS = 120


def judge(scenario: dict[str, Any], record: object) -> list[str]:
    """The problems with one runtime's record of one scenario; empty when it passes."""
    if not isinstance(record, dict):
        return ["the runtime printed no record object"]
    if record.get("scenario") != scenario:
        return ["the record does not echo the scenario it was given"]
    verdict = reader.decide(record)
    if verdict["decision"] != reader.ALLOW:
        return [f"the reader denies the record: {verdict['reason']}"]
    return []


def drive(command: list[str], scenario: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    """Run the adapter through one scenario: whether it ran, its failures and what it left."""
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / "scenario.json"
        path.write_text(json.dumps(scenario, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                    text=True, timeout=TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, [f"runtime did not run: {exc}"], {}
    lines = result.stdout.strip().splitlines()
    try:
        record = json.loads(lines[-1]) if lines else None
    except ValueError:
        record = None
    if result.returncode != 0 or record is None:
        return True, [f"runtime exited {result.returncode} without printing a record"], {}
    problems = judge(scenario, record)
    kept = reader.retained(record) if not reader.malformed(record) else {}
    return True, problems, kept


def check_runtime(runtime: str | list[str], root: Path = reader.ROOT) -> dict[str, Any]:
    """Drive the runtime through every scenario and return the report body."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    command = shlex.split(runtime) if isinstance(runtime, str) else runtime
    if not command:
        raise ValueError("runtime command is empty")
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    executed = 0
    for scenario in reader.scenarios(manifest["vectors"]):
        ran, problems, kept = drive(command, scenario)
        executed += int(ran)
        failures.extend(f"{scenario['id']}: {problem}" for problem in problems)
        rows.append({"id": scenario["id"], "kind": "runtime", "observed": kept,
                     "reasons": problems, "status": "FAIL" if problems else "PASS"})
    failed = len({failure.split(":")[0] for failure in failures})
    return {
        "suite": reader.SUITE, "rail": "external", "unit": "runtime scenario",
        "verifier": {"command": command, "vectorsExecuted": executed,
                     "note": "runtime contract: <runtime> <scenario.json> --json"},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": len(rows), "conform": len(rows) - failed, "fail": failed,
                   "suiteRefusals": 0},
        "vectors": rows, "failures": failures,
    }


def run_runtime(runtime: str | list[str], report_path: str, root: Path = reader.ROOT) -> int:
    """Write the runtime report; exit 0 only when every scenario ran and passed."""
    report = check_runtime(runtime, root)
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    for failure in report["failures"]:
        print(failure)
    totals = report["totals"]
    executed = report["verifier"]["vectorsExecuted"]
    print(f"{reader.SUITE}: runtime ran {executed} of {totals['vectors']} scenarios, "
          f"{totals['fail']} failed")
    if not executed:
        return 2
    return 1 if totals["fail"] or executed != totals["vectors"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or reader.SUITE).splitlines()[0])
    parser.add_argument("--runtime", required=True,
                        help="adapter command, run as <runtime> <scenario.json> --json")
    parser.add_argument("--report", default="execution-billing-runtime-report.json")
    parser.add_argument("--vectors", default=None, help="corpus directory (default: shipped)")
    args = parser.parse_args(argv)
    root = Path(args.vectors) if args.vectors else reader.ROOT
    return run_runtime(args.runtime, args.report, root)


if __name__ == "__main__":
    raise SystemExit(main())
