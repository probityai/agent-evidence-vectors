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
  4. The required aggregator runs always() and needs every other job of its
     workflow, so no job can fail or be cancelled without failing it, and it
     also runs in the merge queue (merge_group trigger).
  5. One workflow asks for no more macOS jobs than the free plan runs at once
     (five). Measured 2026-11-24: a batch run asked for 22, nine of them were
     never given a runner ("not acquired by Runner of type hosted even after
     multiple attempts", run 45429763085) and the required check failed on a
     queue, not on code. A matrix or expression this gate cannot expand counts
     nothing, so it reads low, never high.

Exit 0 when the set is sound, 1 on a finding, 2 when a file could not be read.
Usage: python3 scripts/workflow-concurrency-gate.py [--workflows DIR]
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_DIR = HERE.parent / ".github" / "workflows"

# The context the main-protection ruleset requires, and the workflow that
# reports it. ci-ok is the one aggregator: it needs every other job of ci.yml, so
# a path-skipped job reports nothing and a failed one fails ci-ok. Read from
# `gh api repos/probityai/agent-evidence-vectors/rulesets`; change this table in
# the same pull request as the ruleset.
REQUIRED: dict[str, str] = {"ci-ok": "ci.yml"}

# pages.yml deploys the newest commit, so superseding an older deploy is the point.
CANCEL_ON_PUSH_ALLOWED = {"pages.yml"}

# Workflows owned by the site move; they come under rule 1 when they leave this directory.
RULE1_EXEMPT_PREFIX = "site"

RUN_EVENTS = {"push", "pull_request", "pull_request_target"}

# GitHub Free runs five macOS jobs at a time per account.
MACOS_SLOTS = 5
MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}")


def triggers(doc: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 parses the bare key "on" as boolean True.
    raw: dict[Any, Any] = dict(doc)
    on = raw.get(True, raw.get("on"))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return dict(on or {})


def literal_entries(value: Any) -> list[dict[str, Any]]:
    """The mappings of a literal list, and nothing for an expression GitHub resolves at run time."""
    return [e for e in value if isinstance(e, dict)] if isinstance(value, list) else []


def expand_matrix(matrix: Any) -> list[dict[str, Any]]:
    """The combinations GitHub builds from a literal matrix: the product of its
    list axes, minus `exclude`, with each `include` merged into the combinations
    it matches (never overwriting an axis) or added as a combination of its own."""
    if not isinstance(matrix, dict):
        return [{}]
    axes = {
        k: v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)
    }
    combos = (
        [dict(zip(axes, values, strict=True)) for values in itertools.product(*axes.values())]
        if axes
        else []
    )
    excludes = literal_entries(matrix.get("exclude"))
    combos = [
        c for c in combos if not any(all(c.get(k) == v for k, v in ex.items()) for ex in excludes)
    ]
    includes = literal_entries(matrix.get("include"))
    for inc in includes:
        hits = [c for c in combos if all(c.get(k) == v for k, v in inc.items() if k in axes)]
        for c in hits:
            for k, v in inc.items():
                c.setdefault(k, v)
        if not hits:
            combos.append(dict(inc))
    return combos or [{}]


def macos_jobs(doc: dict[str, Any]) -> int:
    """How many jobs of one workflow run on a macOS label, matrix legs counted."""
    total = 0
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        strategy = job.get("strategy")
        for combo in expand_matrix(strategy.get("matrix") if isinstance(strategy, dict) else None):
            label = MATRIX_REF.sub(
                lambda m, c=combo: str(c.get(m.group(1), "")), str(job.get("runs-on", ""))
            )
            total += label.startswith("macos-")
    return total


def check_file(name: str, doc: dict[str, Any]) -> list[str]:
    found: list[str] = []
    on = triggers(doc)
    conc = doc.get("concurrency")
    if set(on) & RUN_EVENTS and not name.startswith(RULE1_EXEMPT_PREFIX) and not conc:
        found.append(f"{name}: no concurrency group, so superseded runs keep running")
    if isinstance(conc, dict) and "push" in on and name not in CANCEL_ON_PUSH_ALLOWED:
        if str(conc.get("cancel-in-progress", False)).strip().lower() == "true":
            found.append(
                f"{name}: cancel-in-progress is unconditionally true and the workflow runs on push"
            )
    macos = macos_jobs(doc)
    if macos > MACOS_SLOTS:
        found.append(
            f"{name}: {macos} macOS jobs in one run, and the free plan runs {MACOS_SLOTS} at a "
            "time; the rest queue until GitHub drops them unserved. Give macOS one job that runs "
            "every row"
        )
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
            found.append(
                f"required check {context!r}: {wf} path-filters pull_request, so it can pend"
            )
    return found


def check_aggregator(context: str, wf: str, doc: dict[str, Any]) -> list[str]:
    jobs = doc.get("jobs") or {}
    job = jobs.get(context)
    if not isinstance(job, dict):
        return []
    found: list[str] = []
    if "always()" not in str(job.get("if", "")):
        found.append(f"required check {context!r}: {wf} does not run it with always()")
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    missing = sorted(set(jobs) - set(needs) - {context})
    if missing:
        found.append(f"required check {context!r}: it does not need {', '.join(missing)}")
    if "merge_group" not in triggers(doc):
        found.append(f"required check {context!r}: {wf} does not run on merge_group")
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
    findings += [
        f
        for context, wf in REQUIRED.items()
        if wf in docs
        for f in check_aggregator(context, wf, docs[wf])
    ]
    for f in findings:
        print(f"FINDING: {f}")
    print(f"checked {len(docs)} workflows, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
