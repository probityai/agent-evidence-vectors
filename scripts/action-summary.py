#!/usr/bin/env python3
"""Turn a conformance report into the composite action's summary and outputs.

This is the body of the "Write the job summary" step of `action.yml`. It lives
in a file rather than in a heredoc inside that step for one reason: the local
workflow mirror (`scripts/workflow-steps-gate.py`) has to produce the same
outputs the runner does, and the only way for a mirror to be certain it agrees
with the thing it mirrors is for both to run the same code. A second copy of
this arithmetic inside the gate would agree on the day it was written and drift
afterwards, and the drift would surface as a consumer's job disagreeing with a
gate that had just passed.

It reads three variables and writes two files, all of them the ones GitHub
Actions already defines:

    REPORT   path of the report JSON the harness wrote, which may not exist
    STATUS   the harness's exit status, as a string
    CORPUS   the corpus name that was replayed, for the heading

    GITHUB_STEP_SUMMARY   the job summary, appended to
    GITHUB_OUTPUT         the step's outputs, appended to

Both output paths are required. A summary writer that silently discarded its
summary when a variable was missing would report success for having written
nothing, which is the failure mode every gate in this repository exists to
refuse.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# A failing verifier can disagree on every vector, and a table with one row per
# vector is not read, it is scrolled past. The rest stay in the report, which is
# uploaded whole, and the count below says how many were elided.
MAX_ROWS = 50


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"action-summary: ${name} is not set; refusing to write a summary nowhere.")
    return value


def main() -> int:
    report_path = required("REPORT")
    summary_path = required("GITHUB_STEP_SUMMARY")
    output_path = required("GITHUB_OUTPUT")
    status = os.environ.get("STATUS", "1")
    corpus = os.environ.get("CORPUS", "vectors")

    summary: list[str] = []
    outputs: list[str] = []

    if not Path(report_path).is_file():
        # The harness refused before it could write anything. That is a result,
        # and it is reported as one rather than as a zero-vector pass.
        summary.append(
            f"## agent-evidence-vectors: no report\n\n"
            f"The harness exited {status} before writing `{report_path}`. "
            "Read the step log for the refusal.\n"
        )
        outputs.append("vectors=0\nconform=0\nresult=fail\n")
        _write(summary_path, summary, output_path, outputs)
        return 0

    with open(report_path, encoding="utf-8") as handle:
        report: dict[str, Any] = json.load(handle)
    totals = report["totals"]

    # The verdict is the harness's exit status AND proof that the named
    # verifier answered every vector. The status alone is not enough: harness
    # releases up to v0.12.0 ran their own reference rail whenever a probe of
    # the named verifier failed, and exited 0 on that rail's pass. The `tag`
    # input can still install one of those, so the report is read for which
    # rail ran and how many vectors the verifier answered, and a report that
    # cannot show both is a failure.
    refusal = verifier_refusal(report)
    result = "pass" if status == "0" and refusal is None else "fail"
    executed = (report.get("verifier") or {}).get("vectorsExecuted")
    outputs.append(f"vectors={totals['vectors']}\n")
    outputs.append(f"conform={totals['conform']}\n")
    outputs.append(f"executed={executed if executed is not None else ''}\n")
    outputs.append(f"result={result}\n")

    # railNote since the fix; externalVerifierProbe is what older harness
    # releases wrote, and the `tag` input can install one of them.
    note = report.get("railNote", report.get("externalVerifierProbe", ""))
    summary.append(f"## agent-evidence-vectors: {result}\n\n")
    summary.append(f"Corpus `{corpus}`, rail `{report['rail']}`. {note}\n\n")
    if refusal is not None:
        summary.append(f"**The verifier under test did NOT answer this run:** {refusal}\n\n")
    elif executed is not None:
        summary.append(f"The verifier ran on {executed} of {totals['vectors']} vectors.\n\n")
    summary.append(
        "| vectors | pass | fail | conform | reason-parity mismatches | suite refusals |\n"
    )
    summary.append("| ---: | ---: | ---: | ---: | ---: | ---: |\n")
    summary.append(
        f"| {totals['vectors']} | {totals['pass']} | {totals['fail']} | {totals['conform']} "
        f"| {totals['reasonParityMismatch']} | {totals['suiteRefusals']} |\n\n"
    )

    failed = [row for row in report.get("vectors", []) if row.get("status") == "FAIL"]
    if failed:
        summary.append("| vector | kind | reasons |\n| --- | --- | --- |\n")
        for row in failed[:MAX_ROWS]:
            reasons = "; ".join(str(reason) for reason in row.get("reasons", []))[:300]
            summary.append(f"| `{row.get('id')}` | {row.get('kind')} | {reasons} |\n")
        if len(failed) > MAX_ROWS:
            summary.append(f"\n{len(failed) - MAX_ROWS} more failing vectors are in the report.\n")

    notes = report.get("notes", [])
    if notes:
        summary.append("\n<details><summary>suite notes</summary>\n\n")
        for note in notes:
            summary.append(f"- {note}\n")
        summary.append("\n</details>\n")

    _write(summary_path, summary, output_path, outputs)
    return 0


def verifier_refusal(report: dict[str, Any]) -> str | None:
    """Why this report does not show the named verifier answering every vector."""
    if report.get("rail") != "external":
        return (
            f"the report's rail is {report.get('rail')!r}, so the harness judged the "
            "corpus with its own reference rail and never ran the verifier named"
        )
    vectors = report["totals"]["vectors"]
    if not vectors:
        return "the report holds no vectors"
    verifier = report.get("verifier")
    if verifier is None:
        # A harness older than the executed count: an external rail there ran
        # every vector through the named command, which is all it could say.
        return None
    executed = verifier.get("vectorsExecuted")
    if executed != vectors:
        return f"it ran on {executed} of {vectors} vectors"
    return None


def _write(summary_path: str, summary: list[str], output_path: str, outputs: list[str]) -> None:
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("".join(summary))
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write("".join(outputs))


if __name__ == "__main__":
    raise SystemExit(main())
