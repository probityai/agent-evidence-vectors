#!/usr/bin/env python3
"""Refuse a workflow set that piles up runs or can leave a required check unreported.

The defect this exists for, measured 2026-10-31. Each push started about 18
workflows and none of them cancelled the run an earlier push had started, so 84
runs were waiting on GitHub-hosted runners and every pull request, ours and an
outside contributor's, waited hours for CI.

Rules, each a refusal:
  1. A workflow that runs on push, pull_request or pull_request_target declares
     a concurrency group, so a newer push supersedes the older run.
  2. No such workflow cancels in progress unconditionally on push. The group
     names the commit for a main push, so two main pushes never share it.
  3. A job a ruleset requires reports on every pull request: its workflow has no
     workflow-level path filter on pull_request, and the job exists under the
     name the ruleset requires. A path-filtered workflow never starts, and a
     required check that never starts stays pending forever.

Exit 0 when the set is sound, 1 on a finding, 2 when a file could not be read.
Usage: python3 scripts/workflow-concurrency-gate.py [--workflows DIR]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_DIR = HERE.parent / ".github" / "workflows"

# The contexts the main-protection ruleset requires, and the workflow that
# reports each. Read from `gh api repos/probityai/agent-evidence-vectors/rulesets`
# on 2026-10-31; change this table in the same pull request as the ruleset.
REQUIRED: dict[str, str] = {
    "release-integrity": "ci.yml",
    "go": "ci.yml",
    "python": "ci.yml",
    "forcing": "ci.yml",
    "action": "ci.yml",
    "dispositions": "governance.yml",
    "guard": "no-internal-drafts.yml",
    "code-digest": "observed-code-digest.yml",
    "push-range": "identity-scan.yml",
}

# pages.yml deploys the newest commit, so superseding an older deploy is the point.
CANCEL_ON_PUSH_ALLOWED = {"pages.yml"}

# Workflows owned by the site move; they come under rule 1 when they leave this directory.
RULE1_EXEMPT_PREFIX = "site"

RUN_EVENTS = {"push", "pull_request", "pull_request_target"}


def triggers(doc: dict[str, Any]) -> dict[str, Any]:
    on = doc.get(True, doc.get("on"))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return dict(on or {})


def check_file(name: str, doc: dict[str, Any]) -> list[str]:
    found: list[str] = []
    on = triggers(doc)
    conc = doc.get("concurrency")
    if set(on) & RUN_EVENTS and not name.startswith(RULE1_EXEMPT_PREFIX) and not conc:
        found.append(f"{name}: no concurrency group, so superseded runs keep running")
    if isinstance(conc, dict) and "push" in on and name not in CANCEL_ON_PUSH_ALLOWED:
        if str(conc.get("cancel-in-progress", False)).strip().lower() == "true":
            found.append(f"{name}: cancel-in-progress is unconditionally true and the workflow runs on push")
    return found


def check_required(docs: dict[str, dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for context, wf in REQUIRED.items():
        doc = docs.get(wf)
        if doc is None:
            found.append(f"required check {context!r}: workflow {wf} is missing")
            continue
        names = {str(j.get("name") or k) for k, j in (doc.get("jobs") or {}).items()}
        if context not in names:
            found.append(f"required check {context!r}: no job of that name in {wf}")
        on = triggers(doc)
        if "pull_request" not in on:
            found.append(f"required check {context!r}: {wf} does not run on pull_request")
        elif isinstance(on["pull_request"], dict) and (
            "paths" in on["pull_request"] or "paths-ignore" in on["pull_request"]
        ):
            found.append(f"required check {context!r}: {wf} path-filters pull_request, so it can stay pending")
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflows", type=Path, default=DEFAULT_DIR)
    args = ap.parse_args(argv)
    docs: dict[str, dict[str, Any]] = {}
    try:
        for path in sorted(args.workflows.glob("*.yml")):
            docs[path.name] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"could not read the workflows: {exc}", file=sys.stderr)
        return 2
    if not docs:
        print("no workflows found; nothing was verified", file=sys.stderr)
        return 2
    findings = [f for n, d in docs.items() for f in check_file(n, d)]
    findings += check_required(docs)
    for f in findings:
        print(f"FINDING: {f}")
    print(f"checked {len(docs)} workflows, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
