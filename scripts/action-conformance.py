#!/usr/bin/env python3
"""Conformance mode: run a verifier over your own cases and hold it to an expected-verdicts file.

    python -S scripts/action-conformance.py --expected verify-expected.txt \\
        --cases test-vectors --verifier "./my-verifier --json" [--report report.json] [--github]

A project that already keeps cases and a list of the verdict each must get (a
`valid/` and `invalid/` tree with a `verify-expected.txt`, an examples
directory with an expectations table) needs no corpus of ours to be checked
against them: it needs the case it forgot to count. This walks the cases
directory, runs the verifier once per listed case (`<verifier> <case>`: exit 0
means valid, exit 1 invalid; a last stdout line that is a JSON object with a
`verdict` must agree with the exit), and compares each answer with the file.

It fails the run on four things, each named in the summary:

* a listed case the verifier judged the other way;
* a listed case the verifier did not answer (exit other than 0 or 1, a timeout,
  a verdict that contradicts the exit);
* a listed case that is not on disk (`--fail-on-missing-case`, the default);
* no case found at all (`--fail-on-no-vectors`, the default), counted with
  `os.walk` so a Windows runner counts what a Linux one does.

It prints what an always-accept and an always-reject verifier would score on
the same file, so a cases tree with only valid members is shown for what it is.

This runs under `python -S` with nothing installed: the action calls it before
any setup step, the way a zero-dependency conformance CLI runs in the projects
it was learned from. Exit 0 pass, 1 fail, 2 no verdict (unreadable expected
file, no case found, a verifier that answered nothing).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import action_checks  # noqa: E402

TIMEOUT_S = 60
MAX_ROWS = 50


def ask(verifier: list[str], case: Path) -> tuple[str, str]:
    """The verifier's verdict on one case: valid, invalid or notrun, and how."""
    try:
        done = subprocess.run(  # noqa: S603 -- the consumer's own verifier, on its own cases
            [*verifier, str(case)], capture_output=True, text=True, timeout=TIMEOUT_S, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "notrun", f"did not run: {exc}"
    if done.returncode not in (0, 1):
        return "notrun", f"exit {done.returncode}: {(done.stderr or done.stdout).strip()[-200:]}"
    verdict = "valid" if done.returncode == 0 else "invalid"
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    if lines:
        try:
            answer = json.loads(lines[-1])
        except ValueError:
            answer = None
        if isinstance(answer, dict) and "verdict" in answer:
            said = str(answer["verdict"]).lower()
            said = "valid" if said in ("valid", "accept", "pass", "ok") else "invalid"
            if said != verdict:
                return "notrun", f"exit {done.returncode} but verdict {answer['verdict']!r}"
    return verdict, f"exit {done.returncode}"


def run(
    expected_path: str, cases_root: str, verifier: list[str], fail_on_missing: bool, fail_on_none: bool
) -> dict[str, Any]:
    expected = action_checks.read_expected(expected_path)
    root = Path(cases_root)
    on_disk = action_checks.files_on_disk(root) if root.is_dir() else set()
    expected_rel = None
    try:
        expected_rel = PurePosixPath(*Path(os.path.relpath(expected_path, root)).parts).as_posix()
    except ValueError:
        expected_rel = None
    rows: list[dict[str, Any]] = []
    executed = 0
    missing = sorted(c for c in expected if c not in on_disk)
    for case, want in sorted(expected.items()):
        if case in missing:
            continue
        got, how = ask(verifier, root / case)
        if got != "notrun":
            executed += 1
        status = "PASS" if got == want else "FAIL"
        rows.append({"id": case, "kind": want, "observed": got, "status": status,
                     "reasons": [] if status == "PASS" else [f"expected {want}, got {got} ({how})"]})
    unlisted = sorted(on_disk - set(expected) - ({expected_rel} if expected_rel else set()))
    kinds = list(expected.values())
    valid = sum(1 for k in kinds if k == "valid")
    control = action_checks.controls(kinds, valid, len(kinds) - valid)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    blocking = []
    if not rows and fail_on_none:
        blocking.append("no case found")
    if missing and fail_on_missing:
        blocking.append("missing cases")
    if passed != len(rows):
        blocking.append("verdict mismatches")
    if executed != len(rows):
        blocking.append("cases the verifier did not answer")
    if blocking:
        result = "fail"
    elif not rows:
        result = "no-verdict"  # nothing found and the caller chose not to fail on that
    else:
        result = "pass"
    return {
        "mode": "conformance",
        "rail": "external",
        "expected": {"path": expected_path,
                     "sha256": hashlib.sha256(Path(expected_path).read_bytes()).hexdigest()},
        "casesRoot": cases_root,
        "os": os.name,
        "verifier": {"command": shlex.join(verifier), "vectorsExecuted": executed, "vectors": len(rows)},
        "totals": {"vectors": len(rows), "listed": len(expected), "pass": passed,
                   "fail": len(rows) - passed, "conform": passed, "missing": len(missing),
                   "notRun": len(rows) - executed, "unlisted": len(unlisted), "suiteRefusals": 0},
        "missing": missing,
        "unlisted": unlisted,
        "controls": control,
        "blocking": blocking,
        "result": result,
        "vectors": rows,
    }


def summary_markdown(report: dict[str, Any]) -> str:
    t = report["totals"]
    lines = [
        f"## agent-evidence-vectors conformance mode: {report['result']}\n\n",
        f"Expected verdicts `{report['expected']['path']}` (sha256 `{report['expected']['sha256']}`), "
        f"cases under `{report['casesRoot']}`, verifier `{report['verifier']['command']}`.\n\n",
        f"Cases counted on this runner (os.name `{report['os']}`): {t['vectors']} of {t['listed']} "
        f"listed are on disk; the verifier answered {report['verifier']['vectorsExecuted']} and "
        f"{t['pass']} match the expected verdict.\n\n",
        action_checks.controls_line(report["controls"]) + "\n\n",
    ]
    if report["blocking"]:
        lines.append(f"**Failed by:** {', '.join(report['blocking'])}.\n\n")
    if report["missing"]:
        lines.append("| listed and not on disk |\n| --- |\n")
        lines.extend(f"| `{case}` |\n" for case in report["missing"][:MAX_ROWS])
        lines.append("\n")
    bad = [r for r in report["vectors"] if r["status"] != "PASS"]
    if bad:
        lines.append("| case | expected | got | why |\n| --- | --- | --- | --- |\n")
        lines.extend(
            f"| `{r['id']}` | {r['kind']} | {r['observed']} | {r['reasons'][0][:200]} |\n"
            for r in bad[:MAX_ROWS]
        )
        lines.append("\n")
    if report["unlisted"]:
        lines.append(f"{len(report['unlisted'])} files under the cases root are not in the expected file.\n")
    return "".join(lines)


def write_github(report: dict[str, Any], report_path: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        t = report["totals"]
        c = report["controls"]
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(
                f"report={report_path}\nresult={report['result']}\nvectors={t['vectors']}\n"
                f"conform={t['conform']}\nexecuted={report['verifier']['vectorsExecuted']}\n"
                f"vectors-found={t['vectors']}\nmissing-cases={t['missing']}\n"
                f"control-always-accept={c['alwaysAccept']}\ncontrol-always-reject={c['alwaysReject']}\n"
                f"discriminates={str(c['discriminates']).lower()}\n"
            )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(summary_markdown(report))


def _flag(value: str) -> bool:
    return value.strip().lower() != "false"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="action-conformance", description=__doc__.split("\n")[0])
    parser.add_argument("--expected", required=True, help="expected-verdicts file")
    parser.add_argument("--cases", required=True, help="directory the case paths are relative to")
    parser.add_argument("--verifier", required=True, help="verifier command line")
    parser.add_argument("--report", default="agent-evidence-vectors-conformance.json")
    parser.add_argument("--fail-on-missing-case", default="true")
    parser.add_argument("--fail-on-no-vectors", default="true")
    parser.add_argument("--github", action="store_true", help="write step outputs and summary")
    args = parser.parse_args(argv)
    try:
        report = run(args.expected, args.cases, shlex.split(args.verifier, posix=os.name != "nt"),
                     _flag(args.fail_on_missing_case), _flag(args.fail_on_no_vectors))
    except (OSError, ValueError) as exc:
        print(f"no verdict: {exc}", file=sys.stderr)
        if args.github and os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
                handle.write("result=no-verdict\nvectors=0\nconform=0\n")
        return 2
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for row in report["vectors"]:
        if row["status"] != "PASS":
            print(f"FAIL {row['id']}: {row['reasons'][0]}")
    for case in report["missing"]:
        print(f"MISSING {case}: listed in {args.expected} and not under {args.cases}")
    t = report["totals"]
    print(f"conformance {t['pass']} of {t['listed']} listed cases match; {t['missing']} missing; "
          f"result {report['result']}")
    print(action_checks.controls_line(report["controls"]))
    if args.github:
        write_github(report, args.report)
    return {"pass": 0, "fail": 1}.get(report["result"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
