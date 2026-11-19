#!/usr/bin/env python3
"""Tests for scripts/pre-queue.py and its wiring in .github/workflows/ci.yml.

The pre-queue run exists so that a pull request which would fail a cheap batch check
never takes a queue slot. Three ways it could look green and enforce nothing are held
here: a check that names a step ci.yml no longer carries would be skipped; a failing
check that stopped the run would hide the ones after it; and a job that is not wired
into the required aggregator would run and block nothing. The first case below is
the one that cost a queue slot on 19 Nov 2026: a squash subject of 75 characters.

Usage: python3 scripts/pre-queue-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pre_queue", ROOT / "scripts" / "pre-queue.py")
assert spec is not None and spec.loader is not None
pre_queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pre_queue)

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


def main() -> int:
    test_every_check_resolves()
    test_missing_step_is_a_failure_not_a_skip()
    test_failure_does_not_hide_later_checks()
    test_line_filter_runs_only_the_named_line()
    test_squash_subject_limit()
    test_dependabot_subject_is_left_out()
    test_wiring_into_the_required_aggregator()
    print(f"pre-queue-test: {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
