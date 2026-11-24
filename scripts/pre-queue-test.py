#!/usr/bin/env python3
"""Tests for scripts/pre-queue.py and its wiring in .github/workflows/ci.yml.

The pre-queue run exists so that a pull request which would fail a cheap batch check
never takes a queue slot. Three ways it could look green and enforce nothing are held
here: a check that names a step ci.yml no longer carries would be skipped; a failing
check that stopped the run would hide the ones after it; and a job that is not wired
into the required aggregator would run and block nothing. The first case below is
the one that cost a queue slot on 19 Nov 2026: a squash subject of 75 characters.

The derived-file cases build a small repository with one generator (out.txt is
in.txt upper-cased, plus a flag that reads two of its lines together) and judge it the
way a plain pull request does. A pull request that changes only the input is stale and
passes with a notice; one that regenerated and then merged main cleanly is stale and
passes; a hand-edited or hand-merged output fails; and the batch command (--check)
refuses the very file the pull request run lets through.

Usage: python3 scripts/pre-queue-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pre_queue", ROOT / "scripts" / "pre-queue.py")
assert spec is not None and spec.loader is not None
pre_queue: Any = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pre_queue)

regen_spec = importlib.util.spec_from_file_location(
    "regenerate_derived", ROOT / "scripts" / "regenerate-derived.py"
)
assert regen_spec is not None and regen_spec.loader is not None
regen: Any = importlib.util.module_from_spec(regen_spec)
regen_spec.loader.exec_module(regen)

FAILURES: list[str] = []


def check(ok: bool, what: str) -> None:
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        FAILURES.append(what)


def subject_status(title: str, number: str) -> int:
    """Exit status of the real merge-subject check for one pull request title."""
    jobs = pre_queue.load_jobs()
    command = pre_queue.find_command(
        jobs, "commit_message_lint", "Lint the prospective merge subject", None
    )
    env = dict(os.environ, PR_TITLE=title, PR_NUMBER=number)
    return subprocess.run(
        ["bash", "-e", "-c", command], cwd=ROOT, env=env, capture_output=True
    ).returncode


def test_every_check_resolves() -> None:
    jobs = pre_queue.load_jobs()
    for label, job, step, only in pre_queue.CHECKS:
        try:
            text = pre_queue.find_command(jobs, job, step, only)
        except pre_queue.MissingStep as exc:
            check(False, f"{label}: {exc}")
            continue
        check(bool(text.strip()), f"{label}: ci.yml declares the step and it carries a command")


def test_missing_step_is_a_failure_not_a_skip() -> None:
    jobs: dict[str, Any] = {"j": {"steps": [{"name": "other", "run": "true"}]}}
    real = pre_queue.CHECKS
    pre_queue.CHECKS = (("gone", "j", "renamed step", None),)
    try:
        results = pre_queue.run_checks(jobs, dict(os.environ))
    finally:
        pre_queue.CHECKS = real
    check(
        results == [("gone", 2)], "a check whose step was renamed fails with status 2, never passes"
    )


def test_failure_does_not_hide_later_checks() -> None:
    jobs: dict[str, Any] = {
        "j": {
            "steps": [
                {"name": "a", "run": "exit 3"},
                {"name": "b", "run": "true"},
                {"name": "c", "run": 'test "$X" = y'},
            ]
        }
    }
    real = pre_queue.CHECKS
    pre_queue.CHECKS = (("a", "j", "a", None), ("b", "j", "b", None), ("c", "j", "c", None))
    try:
        results = pre_queue.run_checks(jobs, dict(os.environ, X="y"))
    finally:
        pre_queue.CHECKS = real
    check(
        results == [("a", 3), ("b", 0), ("c", 0)],
        "a failing check is reported and the later checks still run with the environment",
    )


def test_line_filter_runs_only_the_named_line() -> None:
    jobs: dict[str, Any] = {"j": {"steps": [{"name": "s", "run": "echo one\nexit 9\n"}]}}
    check(
        pre_queue.find_command(jobs, "j", "s", "echo") == "echo one\n",
        "a line filter keeps only the matching lines",
    )
    try:
        pre_queue.find_command(jobs, "j", "s", "nothing-here")
        check(False, "a line filter that matches nothing is refused")
    except pre_queue.MissingStep:
        check(True, "a line filter that matches nothing is refused")


def test_squash_subject_limit() -> None:
    title = "feat(audit-record): add an external-verifier contract for the corpus"
    check(
        len(title) + len(" (#575)") == 75,
        "the 19 Nov title is the 75-character subject that failed the queue",
    )
    check(
        subject_status(title, "575") != 0,
        "the 75-character squash subject is refused before the queue",
    )
    check(
        subject_status("feat(audit-record): add a verifier contract", "575") == 0,
        "a squash subject within 72 characters passes",
    )


def test_dependabot_subject_is_left_out() -> None:
    jobs: dict[str, Any] = {"j": {"steps": [{"name": "s", "run": "exit 1"}]}}
    real = pre_queue.CHECKS
    pre_queue.CHECKS = ((pre_queue.SUBJECT_CHECK, "j", "s", None), ("other", "j", "s", None))
    try:
        results = pre_queue.run_checks(jobs, dict(os.environ, PR_AUTHOR="dependabot[bot]"))
        human = pre_queue.run_checks(jobs, dict(os.environ, PR_AUTHOR="astrogilda"))
    finally:
        pre_queue.CHECKS = real
    check(results == [("other", 1)], "a Dependabot pull request skips only the subject check")
    check(
        human == [(pre_queue.SUBJECT_CHECK, 1), ("other", 1)],
        "every other author keeps the subject check",
    )


def test_wiring_into_the_required_aggregator() -> None:
    jobs = pre_queue.load_jobs()
    job = jobs.get("pre_queue", {})
    check("pre_queue" in jobs, "ci.yml declares the pre_queue job")
    check(
        "pull_request" in str(job.get("if", "")) and "merge-train/" in str(job.get("if", "")),
        "pre_queue runs on a plain pull request only",
    )
    check(
        any("scripts/pre-queue.py" in str(s.get("run", "")) for s in job.get("steps", [])),
        "pre_queue runs scripts/pre-queue.py",
    )
    env = {k for s in job.get("steps", []) for k in (s.get("env") or {})}
    check(
        {"PR_TITLE", "PR_NUMBER", "PR_AUTHOR"} <= env,
        "pre_queue passes the pull request title, number and author to the checks",
    )
    aggregator = jobs["ci-ok"]
    check(
        "pre_queue" in aggregator["needs"],
        "ci-ok waits for pre_queue, so a failed pre-queue check blocks the enqueue",
    )
    cond = str(aggregator.get("if", ""))
    check(
        "always()" in cond and "github.event_name != 'pull_request'" not in cond,
        "ci-ok runs on a plain pull request too",
    )
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    check(
        "pull_request" in (document.get("on") or document.get(True) or {}),
        "ci.yml triggers on pull_request",
    )


#: The stand-in generator committed in the scratch repository, at the path the real
#: one has. out.txt upper-cases in.txt line by line and ends with a flag that reads
#: the x and y lines together, so two clean edits on different lines can merge into an
#: out.txt that no tree generates.
GENERATOR = """\
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
lines = (root / "in.txt").read_text().splitlines()
values = dict(line.split("=") for line in lines if "=" in line)
flag = int(values["x"]) > int(values["y"])
text = "".join(line.upper() + "\\n" for line in lines) + f"FLAG={flag}\\n"
out = root / "out.txt"
if sys.argv[1:] == ["--check"]:
    raise SystemExit(0 if out.read_text() == text else 1)
out.write_text(text)
"""


def sh(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout


def write_input(root: Path, x: int, y: int) -> None:
    (root / "in.txt").write_text(f"x={x}\na\nb\nc\ny={y}\nd\ne\nf\n")


def generate(root: Path) -> None:
    subprocess.run(
        [sys.executable, str(root / "scripts" / "regenerate-derived.py")], check=True
    )


def scratch_repo(root: Path) -> None:
    """main: x=1, y=2 and an exact out.txt; the pull request branch `pr` starts there."""
    sh(root, "init", "-q", "-b", "main")
    sh(root, "config", "user.email", "t@example.org")
    sh(root, "config", "user.name", "t")
    sh(root, "config", "commit.gpgsign", "false")
    (root / ".gitattributes").write_text("out.txt derived\n")
    (root / "scripts").mkdir()
    (root / "scripts" / "regenerate-derived.py").write_text(GENERATOR)
    write_input(root, 1, 2)
    generate(root)
    sh(root, "add", "-A")
    sh(root, "commit", "-q", "-m", "base")
    sh(root, "switch", "-q", "-c", "pr")


def judge(root: Path) -> tuple[int, str]:
    """The plain pull request's verdict on the scratch repository's HEAD, and what it printed."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            status = regen.stale_ok(root, "main")
        except SystemExit as exc:
            status = 2
            print(exc)
    return status, out.getvalue()


def strict(root: Path) -> int:
    """The batch run's verdict: the generator's --check on the same HEAD."""
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "regenerate-derived.py"), "--check"]
    ).returncode


def test_stale_receipt_passes_with_a_notice() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scratch_repo(root)
        write_input(root, 1, 3)
        sh(root, "commit", "-q", "-am", "change the input, not the output")
        status, text = judge(root)
        check(status == 0, "a derived file the pull request only left stale passes")
        check(
            "::notice" in text and "out.txt" in text,
            "the stale file is named in a notice, not hidden",
        )
        check(strict(root) == 1, "the batch run's --check refuses the same stale file")


def test_hand_edited_receipt_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scratch_repo(root)
        (root / "out.txt").write_text("X=1\nA\nB\nC\nY=2\nD\nE\nF\nFLAG=True\n")
        sh(root, "commit", "-q", "-am", "edit the output by hand")
        status, text = judge(root)
        check(status == 1, "a derived file edited by hand fails on a plain pull request")
        check("::error file=out.txt" in text, "the hand-edited file is named in an error")

        write_input(root, 1, 3)
        sh(root, "commit", "-q", "-am", "then change the input")
        status, _ = judge(root)
        check(status == 1, "a later commit that leaves the hand edit in place does not clear it")


def test_regenerated_then_merged_main_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scratch_repo(root)
        write_input(root, 1, 4)
        generate(root)
        sh(root, "commit", "-q", "-am", "pr: y=4, regenerated")
        sh(root, "switch", "-q", "main")
        write_input(root, 3, 2)
        generate(root)
        sh(root, "commit", "-q", "-am", "main: x=3, regenerated")
        sh(root, "switch", "-q", "pr")
        sh(root, "merge", "-q", "--no-edit", "main")
        check(strict(root) == 1, "the clean merge left out.txt stale (FLAG reads both sides)")
        status, text = judge(root)
        check(status == 0, "a regenerated pull request that merged main cleanly passes")
        check("::notice" in text, "and its stale file is named in a notice")


def test_hand_resolved_merge_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scratch_repo(root)
        write_input(root, 5, 2)
        generate(root)
        sh(root, "commit", "-q", "-am", "pr: x=5, regenerated")
        sh(root, "switch", "-q", "main")
        write_input(root, 4, 2)
        generate(root)
        sh(root, "commit", "-q", "-am", "main: x=4, regenerated")
        sh(root, "switch", "-q", "pr")
        merged = subprocess.run(
            ["git", "-C", str(root), "merge", "-q", "--no-edit", "main"], capture_output=True
        )
        check(merged.returncode != 0, "both sides changed the x line, so the merge conflicts")
        write_input(root, 5, 2)
        (root / "out.txt").write_text("X=5\nA\nB\nC\nY=2\nD\nE\nF\nFLAG=False\n")
        sh(root, "add", "-A")
        sh(root, "commit", "-q", "--no-edit")
        status, _ = judge(root)
        check(status == 1, "an output resolved by hand in a merge fails")


def test_pull_request_runs_the_lenient_form_and_the_batch_the_strict() -> None:
    jobs = pre_queue.load_jobs()
    _, job, step, only = next(c for c in pre_queue.CHECKS if c[0] == pre_queue.DERIVED_CHECK)
    batch = pre_queue.find_command(jobs, job, step, only)
    check(
        batch.strip().endswith("scripts/regenerate-derived.py --check"),
        "the batch step (merge group, merge-train) runs the strict --check",
    )
    gate = str(jobs["changes"].get("if", ""))
    check(
        "changes" in jobs[job].get("needs", [])
        and "github.event_name != 'pull_request'" in gate
        and "merge-train/" in gate,
        "the job carrying the strict step runs in the merge group and on merge-train/* only",
    )
    lenient = pre_queue.stale_ok_command(batch, {"GITHUB_BASE_REF": "main"})
    check(
        lenient.strip().endswith("scripts/regenerate-derived.py --stale-ok origin/main"),
        "the plain pull request runs the same command with --stale-ok against its base",
    )
    check(
        "--group crosscheck" in batch and "--group crosscheck" in lenient,
        "both forms run where the reference coverage step can import the reference verifier",
    )
    check(
        "reference coverage" in step,
        "the step's name says the reference coverage is one of the derived families it holds",
    )
    try:
        pre_queue.stale_ok_command("python3 scripts/regenerate-derived.py", {})
        check(False, "a derived step that no longer ends in --check is refused")
    except pre_queue.MissingStep:
        check(True, "a derived step that no longer ends in --check is refused")
    probe = (
        'python3 -c \'import sys; sys.exit(0 if sys.argv[-1] == "origin/main" else 5)\' --check'
    )
    fake: dict[str, Any] = {"j": {"steps": [{"name": "s", "run": probe}]}}
    real = pre_queue.CHECKS
    pre_queue.CHECKS = ((pre_queue.DERIVED_CHECK, "j", "s", None), ("other", "j", "s", None))
    try:
        results = pre_queue.run_checks(fake, dict(os.environ, GITHUB_BASE_REF="main"))
    finally:
        pre_queue.CHECKS = real
    check(
        results == [(pre_queue.DERIVED_CHECK, 0), ("other", 5)],
        "only the derived check runs in its lenient form; every other check runs as declared",
    )


def main() -> int:
    test_every_check_resolves()
    test_missing_step_is_a_failure_not_a_skip()
    test_failure_does_not_hide_later_checks()
    test_line_filter_runs_only_the_named_line()
    test_squash_subject_limit()
    test_dependabot_subject_is_left_out()
    test_wiring_into_the_required_aggregator()
    test_stale_receipt_passes_with_a_notice()
    test_hand_edited_receipt_fails()
    test_regenerated_then_merged_main_passes()
    test_hand_resolved_merge_fails()
    test_pull_request_runs_the_lenient_form_and_the_batch_the_strict()
    print(f"pre-queue-test: {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
