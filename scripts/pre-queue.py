#!/usr/bin/env python3
"""Run the cheap checks that decide a pull request's batch run before it takes a queue slot.

CI runs once per batch (a merge-train pull request, the merge queue, main), so a plain
pull request starts none of the heavy jobs. That left four cheap failures to be found
only inside the queue, each one costing a queue slot and a full batch of runner time:
a squash subject over 72 characters, a ruff or mypy finding, a count the prose states
and the gate does not declare, and a generated file (digest list, intake records,
shared-source lock) that no longer matches the tree it was generated from.

This script runs exactly those checks, on a plain pull request, in the `pre_queue` job
of .github/workflows/ci.yml, which the required `ci-ok` aggregator waits for. It does
not repeat their commands: each check is a step that ci.yml already declares, found by
its job and its step name, so the pre-queue run and the batch run cannot drift apart.
A renamed or removed step is refused here and in scripts/pre-queue-test.py, never
skipped.

One check is run in its lenient form. The batch step refuses any derived file that
is not what a run writes now; here the same command runs with `--stale-ok` in place
of `--check`, which passes a derived file that is only stale (with a notice) and
still refuses one that no generator run wrote, such as a hand edit or a hand-resolved
merge. A pull request goes stale whenever it touches a corpus or a checker, or merges
main; the batch run regenerates it (merge-train, before the queue) and the merge
group stays strict, so main is always exact. The derived check judges the committed
HEAD, not uncommitted edits.

    python3 scripts/pre-queue.py            run every check, past failures
    python3 scripts/pre-queue.py --list     print the checks and the step each one runs

Exit 0 when every check passed; 1 when any failed or any step could not be found.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

#: (label, job, step name, run only the lines containing this text or None for the whole step)
CHECKS: tuple[tuple[str, str, str, str | None], ...] = (
    ("merge subject", "commit_message_lint", "Lint the prospective merge subject", None),
    ("ruff", "ci__python", "ruff", None),
    ("mypy --strict", "ci__python", "mypy --strict", None),
    (
        "count gate",
        "ci__python",
        "every published count is derived, and no new one is hand-written",
        "scripts/count-gate.py",
    ),
    (
        "derived files",
        "ci__go",
        "every derived file is what a fresh run writes (intake records, digest list, source lock)",
        None,
    ),
)


#: Dependabot writes its own pull request title, which runs past 72 characters, and its
#: pull requests are merged with a subject written by hand. The step this check runs
#: carries that exemption in its `if:`, which a run of the step's text cannot see.
DEPENDABOT = "dependabot[bot]"
SUBJECT_CHECK = "merge subject"

#: The check that runs in its pull-request form: the step's trailing STRICT flag is
#: replaced by --stale-ok against the base branch (see the module docstring).
DERIVED_CHECK = "derived files"
STRICT = "--check"


class MissingStep(Exception):
    """A check names a step the workflow does not carry."""


def load_jobs(path: Path = WORKFLOW) -> dict[str, Any]:
    """The `jobs` mapping of a workflow file."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs: dict[str, Any] = document["jobs"]
    return jobs


def find_command(jobs: dict[str, Any], job: str, step: str, only: str | None) -> str:
    """The shell text of one declared step, narrowed to `only` when given."""
    matches = [
        s for s in jobs.get(job, {}).get("steps", []) if s.get("name") == step and "run" in s
    ]
    if len(matches) != 1:
        raise MissingStep(f"{job}: {len(matches)} steps named {step!r}, expected exactly one")
    text: str = matches[0]["run"]
    if only is None:
        return text
    lines = [line for line in text.splitlines() if only in line]
    if not lines:
        raise MissingStep(f"{job}: step {step!r} has no line containing {only!r}")
    return "\n".join(lines) + "\n"


def stale_ok_command(command: str, env: dict[str, str] | None) -> str:
    """The strict derived-file step as a plain pull request runs it: stale passes, hand-made fails."""
    text = command.strip()
    if "\n" in text or not text.endswith(" " + STRICT):
        raise MissingStep(f"the derived-file step no longer ends in {STRICT}: {text!r}")
    base = (env or {}).get("GITHUB_BASE_REF") or "main"
    return text[: -len(STRICT)] + "--stale-ok " + shlex.quote("origin/" + base) + "\n"


def run_checks(jobs: dict[str, Any], env: dict[str, str] | None = None) -> list[tuple[str, int]]:
    """Run every check past failures and return (label, exit status) for each."""
    results: list[tuple[str, int]] = []
    author = (env or {}).get("PR_AUTHOR", "")
    for label, job, step, only in CHECKS:
        if label == SUBJECT_CHECK and author == DEPENDABOT:
            print(
                f"pre-queue: {label}: left out, a Dependabot pull request "
                "(merged with a hand-written subject)"
            )
            continue
        try:
            command = find_command(jobs, job, step, only)
            if label == DERIVED_CHECK:
                command = stale_ok_command(command, env)
        except MissingStep as exc:
            print(f"pre-queue: {label}: {exc}", file=sys.stderr)
            results.append((label, 2))
            continue
        print(f"::group::pre-queue: {label}", flush=True)
        status = subprocess.run(
            ["bash", "-e", "-c", command], cwd=ROOT, env=env, stdin=subprocess.DEVNULL
        ).returncode
        print("::endgroup::", flush=True)
        print(
            f"pre-queue: {label}: {'ok' if status == 0 else f'FAILED (exit {status})'}", flush=True
        )
        results.append((label, status))
    return results


def main(argv: list[str]) -> int:
    jobs = load_jobs()
    if argv == ["--list"]:
        for label, job, step, only in CHECKS:
            lenient = f" ({STRICT} run as --stale-ok)" if label == DERIVED_CHECK else ""
            print(f"{label}: {job} / {step}" + (f" (lines with {only})" if only else "") + lenient)
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 1
    results = run_checks(jobs, dict(os.environ))
    failed = [label for label, status in results if status]
    print(
        f"pre-queue: {len(results) - len(failed)} of {len(results)} checks passed"
        + (f"; failed: {', '.join(failed)}" if failed else "")
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
