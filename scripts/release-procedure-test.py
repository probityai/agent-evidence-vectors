#!/usr/bin/env python3
"""Refuse a release procedure that asks for a full local mirror of the CI jobs.

Ruling of 2026-10-07: the local gate is a fast subset (identity and leak scan,
size, secrets, runner labels), and remote CI is the proof. On 2026-10-29 the
release procedure still told the releaser to run scripts/workflow-steps-gate.py,
a serial mirror of every CI job. On one shared box it ran about 15 hours (job 41
of about 220 after three and a half hours) and held v0.30.0 back, while the same
jobs ran in parallel on GitHub in under 40 minutes.

Three statements are checked:

1. RELEASING.md, outside this test's own mention, never tells the releaser to run
   scripts/workflow-steps-gate.py or to set AEV_PRE_PUSH_VENUE to local or pool.
2. The pre-push hook defaults to the leak tier.
3. The Go race test in ci.yml carries an explicit -timeout, so Go's 10 minute
   default is never the limit on a slow machine (the corpora package took 281 s
   on a GitHub runner and exceeded 600 s on a shared box).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = (
    re.compile(r"workflow-steps-gate\.py"),
    re.compile(r"AEV_PRE_PUSH_VENUE\s*=\s*(local|pool)"),
)


def releasing_violations(text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for pattern in FORBIDDEN:
            if pattern.search(line):
                found.append(f"RELEASING.md:{number}: {line.strip()}")
    return found


def hook_default_violations(text: str) -> list[str]:
    if 'venue="${AEV_PRE_PUSH_VENUE-leak}"' not in text:
        return [".githooks/pre-push: the default venue is not leak"]
    return []


def go_timeout_violations(text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if "go test" in line and "-race" in line and "-timeout" not in line:
            found.append(f".github/workflows/ci.yml:{number}: {line.strip()}")
    return found


def _run_text(step: dict) -> str:
    return str(step.get("run", ""))


def release_workflow_violations(text: str) -> list[str]:
    """The tag-ancestry check and the token check are separate, each with its own error.

    Releases v0.34.0, v0.36.0 and v0.36.1 failed one step that held both checks. The
    ancestry check printed nothing and the token check printed "HF_TOKEN is not set",
    so the failure read as a missing secret while the secret was set. So: ancestry is
    a step of its own in a job with no environment (it runs before anyone approves),
    publish never runs it, and the token check has one condition and its own error.
    """
    jobs = (yaml.safe_load(text) or {}).get("jobs", {})
    found = []
    verify, publish = jobs.get("verify", {}), jobs.get("publish", {})
    if "environment" in verify:
        found.append("release.yml: verify declares an environment, so the ancestry check waits for approval")
    ancestry = [s for s in verify.get("steps", []) if "merge-base --is-ancestor" in _run_text(s)]
    if len(ancestry) != 1:
        found.append(f"release.yml: verify has {len(ancestry)} ancestry steps, want exactly 1")
    else:
        run = _run_text(ancestry[0])
        if "::error::" not in run or "GITHUB_REF_NAME" not in run or "origin/main" not in run:
            found.append("release.yml: the ancestry step does not print the tag, the sha and origin/main in its error")
        if "token" in run.lower():
            found.append("release.yml: the ancestry step mentions a token")
    if "environment" not in publish:
        found.append("release.yml: publish has no environment")
    for step in publish.get("steps", []):
        run = _run_text(step)
        if "merge-base" in run:
            found.append(f"release.yml: publish step {step.get('name')!r} runs the ancestry check after approval")
        if "HF_TOKEN" in run and run.count("if [") != 1:
            found.append(f"release.yml: publish step {step.get('name')!r} holds more than the one token condition")
    token = [s for s in publish.get("steps", []) if "::error::" in _run_text(s) and "HF_TOKEN" in _run_text(s)]
    if len(token) != 1:
        found.append(f"release.yml: publish has {len(token)} token-check steps, want exactly 1")
    elif " and " in str(token[0].get("name", "")):
        found.append("release.yml: the token step name joins two checks")
    return found


GOOD_WORKFLOW = """
jobs:
  verify:
    steps:
      - name: the tagged commit is on main
        run: |
          git merge-base --is-ancestor a origin/main || echo "::error::${GITHUB_REF_NAME} origin/main"
  publish:
    environment: public-release
    steps:
      - name: the dataset token is set
        run: |
          if [ -z "$HF_TOKEN" ]; then echo "::error::the HF_TOKEN secret is not set"; fi
"""
# The shape that failed three releases: both checks in one publish step.
MERGED_CHECKS_WORKFLOW = GOOD_WORKFLOW.replace(
    "run: |\n          if [ -z",
    "run: |\n          git merge-base --is-ancestor a b\n          if [ -z",
)


def main() -> int:
    problems = (
        releasing_violations((ROOT / "RELEASING.md").read_text(encoding="utf-8"))
        + hook_default_violations((ROOT / ".githooks/pre-push").read_text(encoding="utf-8"))
        + go_timeout_violations((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        + release_workflow_violations((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    )
    if release_workflow_violations(GOOD_WORKFLOW):
        print("FAIL: the known-good workflow fixture is refused", file=sys.stderr)
        return 1
    # Controls: each rule must fire on a known-bad input, or the test checks nothing.
    controls = (
        releasing_violations("uv run python -B scripts/workflow-steps-gate.py"),
        releasing_violations("AEV_PRE_PUSH_VENUE=pool git push"),
        hook_default_violations('venue="${AEV_PRE_PUSH_VENUE-local}"'),
        go_timeout_violations("go test ./... -race -count=1"),
        release_workflow_violations(MERGED_CHECKS_WORKFLOW),
        release_workflow_violations(GOOD_WORKFLOW.replace("environment: public-release", "")),
    )
    if not all(controls):
        print("FAIL: a control did not fire; the checker is blind", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print("ok: release procedure runs the leak tier only; Go race test has an explicit timeout")
    return 0


if __name__ == "__main__":
    sys.exit(main())
