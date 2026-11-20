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

and five more the action passes, each optional so the local mirror runs as before:

    CORPUS_DIR            the corpus directory, for the case count and the profile
    PROFILE               a profile name or file (scripts/action_checks.py)
    FAIL_ON_NO_VECTORS    `false` makes an empty corpus `no-verdict` rather than `fail`
    FAIL_ON_MISSING_CASE  `false` reports a listed case that went missing without failing
    CONTROLS_DIR          the always-accept and always-reject reports

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import action_checks  # noqa: E402

# A failing verifier can disagree on every vector, and a table with one row per
# vector is not read, it is scrolled past. The rest stay in the report, which is
# uploaded whole, and the count below says how many were elided.
MAX_ROWS = 50

# The line that points a reader at the offline verifier. A failing run carries
# OFFLINE alone, because a maintainer reading a red run is who wants the tool;
# a passing run, and every corpus README, carry BRIDGE, which adds the "Checked with
# Probity" statement a failing run cannot make. scripts/probity-bridge-test.py holds
# every copy to these constants, so a release of probityai changes the pin here
# and the test names every README still on the old one.
OFFLINE = "Check evidence offline with probity-verify: `pip install probityai==0.1.0`."
BRIDGE = (
    "Checked with Probity ([github.com/probityai/probity](https://github.com/probityai/probity)). "
    + OFFLINE
)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"action-summary: ${name} is not set; refusing to write a summary nowhere.")
    return value


def _flag(name: str) -> bool:
    """A true/false input; anything but `false` keeps the strict default."""
    return os.environ.get(name, "true").strip().lower() != "false"


def main() -> int:
    report_path = required("REPORT")
    summary_path = required("GITHUB_STEP_SUMMARY")
    output_path = required("GITHUB_OUTPUT")
    status = os.environ.get("STATUS", "1")
    corpus = os.environ.get("CORPUS", "vectors")
    corpus_dir = os.environ.get("CORPUS_DIR", "")

    summary: list[str] = []
    outputs: list[str] = []

    if not Path(report_path).is_file():
        # The harness refused before it could write anything. That is a result,
        # and it is reported as one rather than as a zero-vector pass.
        summary.append(
            f"## agent-evidence-vectors: no report\n\n"
            f"The harness exited {status} before writing `{report_path}`. "
            "Read the step log for the refusal.\n\n"
            f"{OFFLINE}\n"
        )
        result = "fail"
        if corpus_dir:
            counted = action_checks.count_cases(corpus_dir)
            summary.append(_count_line(counted) + "\n\n")
            outputs.append(f"vectors-found={counted['present']}\n")
            if counted["present"] == 0 and not _flag("FAIL_ON_NO_VECTORS"):
                result = "no-verdict"
        summary.append(action_checks.controls_line(action_checks.controls([], None, None)) + "\n")
        outputs.append(f"vectors=0\nconform=0\nresult={result}\n")
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
    gates, gate_rows, gate_outputs = _gates(report, corpus_dir)
    outputs.extend(gate_outputs)
    # The profile split and the controls go into the uploaded report too, so a
    # scoreboard reading the artifact sees the same counts as the summary.
    Path(report_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    profile_ok = gates["profileExcusesFailures"] and status == "1"
    result = "pass" if (status == "0" or profile_ok) and refusal is None else "fail"
    if gates["blocking"]:
        result = "fail"
    if gates["noVectors"] and not _flag("FAIL_ON_NO_VECTORS"):
        result = "no-verdict"
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
    provenance = report.get("corpus") or {}
    summary.append(
        f"Release `{provenance.get('release') or 'none (source checkout)'}`, "
        f"suiteRevision `{provenance.get('suiteRevision') or 'none'}`, "
        f"corpus digest `{provenance.get('corpusDigest') or 'not declared'}`, "
        f"manifest sha256 `{provenance.get('manifestSha256') or 'unread'}`.\n\n"
    )
    header = report.get("verifierResult")
    if isinstance(header, dict):
        summary.append(
            f"Verifier result: package `{header.get('package')}` "
            f"`{header.get('version') or 'unknown'}` ({header.get('versionSource')}), "
            f"corpus `{header.get('corpus')}`, "
            f"input digest `{header.get('corpusDigest') or 'not declared'}`, "
            f"corpus revision `{header.get('corpusRevision') or 'unknown'}` "
            f"({header.get('corpusRevisionKind')}).\n\n"
        )
    if refusal is not None:
        summary.append(f"**The verifier under test did NOT answer this run:** {refusal}\n\n")
    elif executed is not None:
        summary.append(f"The verifier ran on {executed} of {totals['vectors']} vectors.\n\n")
    summary.append(
        "| vectors | pass | fail | conform | reason-parity mismatches | suite refusals |\n"
    )
    summary.append("| ---: | ---: | ---: | ---: | ---: | ---: |\n")
    # Not every reader reports every column: the source-coverage contract has no
    # pass or reason-parity count. A column the report does not carry is shown
    # as absent rather than read as zero, and never stops the summary from
    # being written; the verdict above does not depend on it.
    columns = ("vectors", "pass", "fail", "conform", "reasonParityMismatch", "suiteRefusals")
    cells = " | ".join(str(totals[c]) if c in totals else "n/a" for c in columns)
    summary.append(f"| {cells} |\n\n")

    summary.extend(gate_rows)

    summary.append(f"{BRIDGE if result == 'pass' else OFFLINE}\n\n")

    summary.extend(_failure_rows(report))

    notes = report.get("notes", [])
    if notes:
        summary.append("\n<details><summary>suite notes</summary>\n\n")
        for note in notes:
            summary.append(f"- {note}\n")
        summary.append("\n</details>\n")

    _write(summary_path, summary, output_path, outputs)
    return 0


def _count_line(counted: dict[str, Any]) -> str:
    if not counted["manifest"]:
        return "No MANIFEST.json was found, so no case was counted on this runner."
    return (
        f"Cases counted on this runner (os.name `{counted['os']}`): {counted['present']} of "
        f"{counted['listed']} listed are on disk."
    )


class _Gates:
    """What the case count, the profile and the controls found: rows, outputs, verdict inputs."""

    def __init__(self) -> None:
        self.rows: list[str] = []
        self.outputs: list[str] = []
        self.blocking: list[str] = []
        self.no_vectors = False
        self.profile_excuses = False


def _gates(report: dict[str, Any], corpus_dir: str) -> tuple[dict[str, Any], list[str], list[str]]:
    """The case count, the missing cases, the profile split and the null controls.

    Returns what decides the result, the summary rows and the step outputs.
    """
    gates = _Gates()
    if corpus_dir:
        _count_gate(gates, action_checks.count_cases(corpus_dir, report))
    if not report["totals"].get("vectors", 0):
        gates.no_vectors = True
        if _flag("FAIL_ON_NO_VECTORS"):
            gates.blocking.append("no vectors")
    if os.environ.get("PROFILE", "").strip():
        _profile_gate(gates, report, corpus_dir, os.environ["PROFILE"].strip())
    _control_gate(gates, report)
    if gates.blocking:
        gates.rows.append(f"**Failed by:** {', '.join(gates.blocking)}.\n\n")
    decided = {
        "blocking": gates.blocking,
        "noVectors": gates.no_vectors,
        "profileExcusesFailures": gates.profile_excuses,
    }
    return decided, gates.rows, gates.outputs


def _count_gate(gates: _Gates, counted: dict[str, Any]) -> None:
    gates.rows.append(_count_line(counted) + "\n\n")
    gates.outputs.append(f"vectors-found={counted['present']}\n")
    if counted["manifest"] and counted["listed"] and counted["present"] == 0:
        gates.no_vectors = True
    missing = counted["missingOnDisk"] + counted["missingFromReport"]
    gates.outputs.append(f"missing-cases={len(counted['missingOnDisk']) + counted['reportGap']}\n")
    if not (missing or counted["reportGap"]):
        return
    gates.rows.append(
        f"**Missing cases:** {len(counted['missingOnDisk'])} listed and not on disk, "
        f"{counted['reportGap']} listed and not scored by the replay.\n\n"
    )
    gates.rows.extend(f"- `{name}`\n" for name in missing[:MAX_ROWS])
    gates.rows.append("\n")
    if _flag("FAIL_ON_MISSING_CASE"):
        gates.blocking.append("missing cases")


def _profile_gate(gates: _Gates, report: dict[str, Any], corpus_dir: str, spec: str) -> None:
    try:
        profile = action_checks.load_profile(spec)
        features = action_checks.member_features(corpus_dir) if corpus_dir else {}
    except (OSError, ValueError) as exc:
        gates.rows.append(f"**Profile `{spec}` could not be read:** {exc}\n\n")
        gates.blocking.append("unreadable profile")
        return
    split = action_checks.split_by_profile(report, features, profile)
    inside, outside = split["inProfile"], split["outOfProfile"]
    excluded = ", ".join(split["excludes"]) or "named ids"
    gates.rows.append(
        f"Profile `{split['profile']}` (out of profile: {excluded}): "
        f"in profile {inside['pass']} of {inside['vectors']} pass; "
        f"out of profile {outside['pass']} of {outside['vectors']} pass, counted on their own "
        "and not failing the job.\n\n"
    )
    gates.outputs.append(f"in-profile={inside['vectors']}\nin-profile-pass={inside['pass']}\n")
    gates.outputs.append(
        f"out-of-profile={outside['vectors']}\nout-of-profile-pass={outside['pass']}\n"
    )
    # Failures excused only when every in-profile member passed and the suite refused nothing.
    clean = not report["totals"].get("suiteRefusals") and bool(inside["vectors"])
    gates.profile_excuses = clean and inside["fail"] == 0
    report["profile"] = split


def _control_gate(gates: _Gates, report: dict[str, Any]) -> None:
    kinds = [str(row.get("kind")) for row in report.get("vectors") or []]
    accept_passed, reject_passed = _control_scores()
    control = action_checks.controls(kinds, accept_passed, reject_passed)
    gates.rows.append(action_checks.controls_line(control) + "\n\n")
    verdict = control["discriminates"]
    gates.outputs.append(
        f"control-always-accept={'' if accept_passed is None else accept_passed}\n"
        f"control-always-reject={'' if reject_passed is None else reject_passed}\n"
        f"discriminates={'' if verdict is None else str(verdict).lower()}\n"
    )
    report["controls"] = control


def _control_scores() -> tuple[int | None, int | None]:
    """What the two controls passed, from the reports the controls step wrote."""
    directory = os.environ.get("CONTROLS_DIR", "")
    scores: list[int | None] = []
    for mode in ("accept", "reject"):
        path = Path(directory) / f"always-{mode}.json" if directory else None
        try:
            totals = json.loads(path.read_text(encoding="utf-8"))["totals"] if path else None
            scores.append(int(totals["pass"]) if totals else None)
        except (OSError, ValueError, KeyError, TypeError):
            scores.append(None)
    return scores[0], scores[1]


def _failure_rows(report: dict[str, Any]) -> list[str]:
    """Tables of the failing vectors and of the reader's own failures list."""
    rows: list[str] = []
    failed = [row for row in report.get("vectors", []) if row.get("status") == "FAIL"]
    if failed:
        rows.append("| vector | kind | reasons |\n| --- | --- | --- |\n")
        for row in failed[:MAX_ROWS]:
            reasons = "; ".join(str(reason) for reason in row.get("reasons", []))[:300]
            rows.append(f"| `{row.get('id')}` | {row.get('kind')} | {reasons} |\n")
        if len(failed) > MAX_ROWS:
            rows.append(f"\n{len(failed) - MAX_ROWS} more failing vectors are in the report.\n")
    # The source-coverage reader reports a list of failure strings instead of
    # per-vector rows.
    failures = report.get("failures") or []
    if failures:
        rows.append("| failure |\n| --- |\n")
        for failure in failures[:MAX_ROWS]:
            rows.append(f"| {str(failure)[:300]} |\n")
        if len(failures) > MAX_ROWS:
            rows.append(f"\n{len(failures) - MAX_ROWS} more failures are in the report.\n")
    return rows


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
