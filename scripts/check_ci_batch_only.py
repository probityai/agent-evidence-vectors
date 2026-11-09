#!/usr/bin/env python3
"""Check that no workflow job takes a runner on a plain pull request.

CI runs once per batch: on a merge-train/* pull request, in the merge queue, on main,
on a schedule or by hand. A plain pull request run must start no job. So in every
workflow that a pull request triggers, each job must either carry the batch gate in its
`if:`, or need (directly or through other jobs) a job that does and use no status
function (always(), failure(), cancelled()) that would make it run after a skipped need.
Skipped jobs count as passed for a required check, so the required aggregator stays
satisfied on a plain pull request.

Usage: check_ci_batch_only.py [WORKFLOW_DIR]   (default .github/workflows)
Exit 0 clean, 1 with findings printed one per line.
Dependency-free: it reads the small subset of YAML that workflow files use for the
top-level `on:` and `jobs:` keys.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

GATE = "github.event_name != 'pull_request' || startsWith(github.head_ref, 'merge-train/')"
STATUS_FN = re.compile(r"\b(always|failure|cancelled)\s*\(")
# Workflows that must run on every pull request, with the reason.
EXEMPT = {
    "dco.yml": "posts the required dco/sign-off commit status, which a skipped job never posts",
}


def _top_block(lines: list[str], names: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    inside = False
    for line in lines:
        if line and not line[0].isspace() and not line.startswith("#"):
            key = line.split(":", 1)[0].strip().strip("'\"")
            inside = key in names
            continue
        if inside:
            out.append(line)
    return out


def triggers(text: str) -> set[str]:
    lines = text.splitlines()
    for line in lines:
        m = re.match(r"""^['"]?on['"]?:\s*(\S.*)?$""", line)
        if m and m.group(1):
            value = m.group(1).split("#", 1)[0].strip()
            return {v.strip() for v in value.strip("[]").split(",") if v.strip()}
    keys = set()
    for line in _top_block(lines, ("on",)):
        m = re.match(r"^  ([A-Za-z_]+):", line)
        if m:
            keys.add(m.group(1))
    return keys


def jobs(text: str) -> dict[str, dict]:
    """Map job id -> {"needs": [ids], "if": str}."""
    out: dict[str, dict] = {}
    cur = None
    in_needs = False
    for line in _top_block(text.splitlines(), ("jobs",)):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if m:
            cur = out.setdefault(m.group(1), {"needs": [], "if": ""})
            in_needs = False
            continue
        if cur is None:
            continue
        m = re.match(r"^    (needs|if):\s*(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).split(" #", 1)[0].strip()
            in_needs = key == "needs" and val == ""
            if key == "needs" and val:
                cur["needs"] = [v.strip().strip("'\"") for v in val.strip("[]").split(",") if v.strip()]
            elif key == "if":
                cur["if"] = val
            continue
        if in_needs:
            m = re.match(r"^    \s*- \s*(\S+)", line)
            if m:
                cur["needs"].append(m.group(1).strip("'\""))
                continue
        if re.match(r"^    \S", line):
            in_needs = False
    return out


def check_text(name: str, text: str) -> list[str]:
    on = triggers(text)
    if not on & {"pull_request", "pull_request_target"} or name in EXEMPT:
        return []
    js = jobs(text)
    gated = {j for j, v in js.items() if GATE in v["if"]}
    findings = []
    if not any(not js[j]["needs"] for j in gated):
        findings.append(f"{name}: no job without needs carries the batch gate")

    reach: dict[str, bool] = {}

    def reaches(j: str, seen: frozenset = frozenset()) -> bool:
        if j in reach:
            return reach[j]
        if j in gated:
            return True
        if j in seen or j not in js:
            return False
        ok = (not STATUS_FN.search(js[j]["if"])
              and any(reaches(n, seen | {j}) for n in js[j]["needs"]))
        reach[j] = ok
        return ok

    for j in js:
        if not reaches(j):
            findings.append(f"{name}: job {j} can run on a plain pull request "
                            "(add the batch gate or need the gated select job)")
    return findings


def check_dir(path: Path) -> list[str]:
    findings: list[str] = []
    for wf in sorted([*path.glob("*.yml"), *path.glob("*.yaml")]):
        findings += check_text(wf.name, wf.read_text())
    return findings


def main(argv: list[str]) -> int:
    findings = check_dir(Path(argv[1] if len(argv) > 1 else ".github/workflows"))
    for f in findings:
        print(f)
    print(f"ci batch-only: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
