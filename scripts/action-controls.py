#!/usr/bin/env python3
"""Replay the corpus through the always-accept and always-reject controls.

This is the body of the "Score the null controls" step of `action.yml`. It runs
the same harness command the replay ran, on the same corpus, with
scripts/action-control-verifier.py standing in for the verifier, and writes one
report per control into CONTROLS_DIR. The job summary reads them and prints
what each control scored against the corpus's must-accept and must-reject
shares (scripts/action_checks.py `controls`).

A control the harness refused (exit 2, or no report) is recorded as not scored,
never as zero: zero would read as a corpus that discriminates. The step never
fails the job; what the controls show is a fact about the corpus, reported
beside the verifier's own verdict.

Variables:

    CONTROLS_DIR   where the two reports go (required)
    CORPUS_ARGS    the harness's corpus arguments, as JSON list (required)
    HARNESS        the harness command (default: agent-evidence-vectors)
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL = HERE / "action-control-verifier.py"


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"action-controls: ${name} is not set; refusing to score nothing.")
    return value


def control_command(mode: str) -> str:
    """The control as a command line, run with -S so it costs one interpreter start."""
    return shlex.join([sys.executable, "-S", str(CONTROL), mode])


def run_control(
    harness: list[str], corpus_args: list[str], mode: str, out: Path
) -> dict[str, object]:
    report = out / f"always-{mode}.json"
    report.unlink(missing_ok=True)
    command = [*harness, *corpus_args, "--verifier", control_command(mode), "--report", str(report)]
    done = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    passed = None
    if report.is_file():
        try:
            totals = json.loads(report.read_text(encoding="utf-8"))["totals"]
            passed = int(totals.get("pass", 0))
        except (ValueError, KeyError, TypeError):
            passed = None
    return {"mode": mode, "exit": done.returncode, "report": str(report), "passed": passed}


def main() -> int:
    out = Path(required("CONTROLS_DIR"))
    out.mkdir(parents=True, exist_ok=True)
    corpus_args = json.loads(required("CORPUS_ARGS"))
    harness = shlex.split(os.environ.get("HARNESS") or "agent-evidence-vectors")
    results = [run_control(harness, corpus_args, mode, out) for mode in ("accept", "reject")]
    (out / "controls.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    for result in results:
        scored = "not scored" if result["passed"] is None else f"passed {result['passed']}"
        print(f"always-{result['mode']}: harness exit {result['exit']}, {scored}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
