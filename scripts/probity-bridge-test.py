#!/usr/bin/env python3
"""The Probity bridge line is in the Action summary and in every spec README.

Ruling P-54 puts one line on every spec README and on the Action's job summary:
"Checked with Probity" with the link to the offline verifier and its pinned
install. This test holds each copy to `BRIDGE` in scripts/action-summary.py:

1. A passing run's summary carries the line once, after the result table.
2. A failing run's summary, with or without a report, carries the offline
   verifier line (`OFFLINE`) and not the "Checked with Probity" statement.
3. Every vectors-*/README.md, spec/README.md and the main README carry BADGE
   once and no text line beside it.
4. Removing the line from the summary script turns check 1 red, so the check
   cannot pass while the summary has lost the line.

Run with: python3 scripts/probity-bridge-test.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SUMMARY = HERE / "action-summary.py"

_spec = importlib.util.spec_from_file_location("action_summary", SUMMARY)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
BRIDGE: str = _module.BRIDGE
OFFLINE: str = _module.OFFLINE

# The README badge: shields.io with the probityai org avatar (a small PNG) as the
# logo, linking the verifier repository. Every README carries this exact text.
BADGE = (
    "[![Checked with Probity]("
    "https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D"
    ")](https://github.com/probityai/probity)"
)

REPORT = {
    "rail": "external",
    "railNote": "synthetic",
    "totals": {"vectors": 3, "pass": 3, "fail": 0, "conform": 3,
               "reasonParityMismatch": 0, "suiteRefusals": 0},
    "vectors": [],
    "verifier": {"command": "x", "vectorsExecuted": 3},
}


def run_summary(script: Path, status: str, work: Path, with_report: bool = True) -> str:
    report = work / "report.json"
    report.unlink(missing_ok=True)
    if with_report:
        report.write_text(json.dumps(REPORT), encoding="utf-8")
    summary = work / "summary.md"
    summary.write_text("", encoding="utf-8")
    outputs = work / "outputs.txt"
    outputs.write_text("", encoding="utf-8")
    env = dict(os.environ, REPORT=str(report), STATUS=status, CORPUS="vectors",
               GITHUB_STEP_SUMMARY=str(summary), GITHUB_OUTPUT=str(outputs))
    subprocess.run([sys.executable, str(script)], env=env, check=True, capture_output=True)
    return summary.read_text(encoding="utf-8")


def summary_errors(script: Path, work: Path) -> list[str]:
    errors: list[str] = []
    passed = run_summary(script, "0", work)
    if passed.count(BRIDGE) != 1:
        errors.append(f"pass summary carries the bridge {passed.count(BRIDGE)} times, expected 1")
    elif passed.index(BRIDGE) < passed.index("| ---: |"):
        errors.append("pass summary puts the bridge before the result table")
    for label, text in (
        ("failing", run_summary(script, "1", work)),
        ("no-report", run_summary(script, "2", work, with_report=False)),
    ):
        if text.count(OFFLINE) != 1:
            errors.append(f"{label} summary carries the offline line {text.count(OFFLINE)} times")
        if "Checked with Probity" in text:
            errors.append(f"{label} summary says Checked with Probity")
    return errors


def readme_errors() -> list[str]:
    paths = sorted(REPO_ROOT.glob("vectors-*/README.md"))
    paths += [REPO_ROOT / "spec" / "README.md", REPO_ROOT / "README.md"]
    errors = []
    for p in paths:
        text = p.read_text(encoding="utf-8")
        name = p.relative_to(REPO_ROOT)
        if text.count(BADGE) != 1:
            errors.append(f"{name} lacks the Probity badge exactly once (BADGE in this test)")
        if "Checked with Probity (github.com" in text:
            errors.append(f"{name} still carries the old text line beside the badge")
    return errors


def mutation_errors(work: Path) -> list[str]:
    source = SUMMARY.read_text(encoding="utf-8")
    anchor = 'summary.append(f"{BRIDGE if result == \'pass\' else OFFLINE}\\n\\n")'
    if source.count(anchor) != 1:
        return ["mutation: the bridge append is not present exactly once; it would prove nothing"]
    mutant = work / "action-summary-mutant.py"
    mutant.write_text(source.replace(anchor, "pass"), encoding="utf-8")
    if not summary_errors(mutant, work):
        return ["mutation: the summary check stayed GREEN with the bridge line removed"]
    return []


def main() -> int:
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aev-bridge-") as tmp:
        work = Path(tmp)
        errors += summary_errors(SUMMARY, work)
        errors += mutation_errors(work)
    errors += readme_errors()
    if errors:
        print(f"FAIL: the Probity bridge line ({len(errors)}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("OK: the Action summary and every spec README carry the Probity bridge line, "
          "and removing it from the summary turns this test red.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
