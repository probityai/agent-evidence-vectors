#!/usr/bin/env python3
"""Run every declared repair to a fixed point, and refuse a gate that has none.

WHAT THIS IS. `scripts/repairs.toml` names, for each gate that compares a
committed artifact against a regenerable one, the command that regenerates it.
This runs them. It is deliberately small: a fuller version of this idea reads a
gate manifest carrying subjects, jobs, costs and dependencies, and a runner needs
four fields of that. Building one here would have been several hundred lines to
serve three rows, so the registry below is the four fields and nothing else.

WHY A FIXED POINT RATHER THAN A SEQUENCE. The repairs are not independent.
Regenerating the coverage matrix can move a figure the forcing document derives,
so a single pass in a guessed order leaves a second artifact stale and the next
push refuses on a gate that was green a moment ago. Running to convergence
removes the ordering question entirely: repeat until a pass changes nothing.

CONVERGENCE IS OBSERVED, NEVER ASSUMED. Generators are idempotent by intent and
not by proof, and two that disagree would oscillate forever. So the loop is
bounded and REFUSES at the bound rather than reporting the last pass as a
success -- a repair loop that quietly gives up is the failure this file exists
to remove, arriving one level up.

ONE FAILING REPAIR DOES NOT CANCEL THE OTHERS. Each is run independently and its
failure is collected, so a run reports every repair that could not complete
rather than stopping at the first. A gate whose repair needs an argument only the
operator can supply is declared `needs_operator` and is REPORTED, never invented:
running it without that argument would either fail or, worse, write a record of
something nobody measured.

SOME COMPARING GATES HAVE NO REPAIR, ON PURPOSE. A gate that compares a reader
against hand-authored expected answers must never be "repaired": regenerating the
expected file from the reader would make the check compare the reader with itself.
Such a row carries `not_regenerable = "<why>"` in place of `fix`. The audit counts
it as declared, and the repair loop reports it and never runs anything for it.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = REPO_ROOT / "scripts" / "repairs.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: A gate COMPARES when its argv carries one of these as a WHOLE argument.
#: Matching on a prefix would sweep in `--check-baseline` and `--check-live`,
#: which compare against live external state rather than a regenerable artifact.
COMPARING_FLAGS = frozenset({"--check", "--verify"})

#: Generators are idempotent by intent, not by proof. Refuse at the bound.
MAX_PASSES = 3


class Refused(RuntimeError):
    """The registry could not be READ. Never a statement about the repairs."""


def load() -> list[dict[str, Any]]:
    if not REGISTRY.is_file():
        raise Refused(f"no repair registry at {REGISTRY}")
    try:
        doc = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise Refused(f"{REGISTRY} is not readable TOML: {exc}") from exc
    gates = doc.get("gate")
    if not isinstance(gates, list) or not gates:
        raise Refused(f"{REGISTRY} declares no [[gate]] rows")
    for g in gates:
        for field in ("ident", "argv"):
            if not g.get(field):
                raise Refused(f"a [[gate]] row is missing {field!r}: {g!r}")
        has_fix, has_reason = bool(g.get("fix")), bool(g.get("not_regenerable"))
        if has_fix == has_reason:
            raise Refused(
                f"a [[gate]] row needs exactly one of 'fix' or 'not_regenerable': {g!r}"
            )
    return gates


def is_comparing(argv: list[str]) -> bool:
    return bool(COMPARING_FLAGS.intersection(argv))


def ci_comparing_steps() -> list[str]:
    """Every comparing invocation the workflow actually runs.

    Read from the workflow rather than from the registry, because the question
    the audit asks is whether the registry has fallen BEHIND what CI enforces.
    Comparing the registry against itself would answer nothing.
    """
    if not WORKFLOW.is_file():
        raise Refused(f"no workflow at {WORKFLOW}")
    found: list[str] = []
    for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s.startswith(("run:", "python3 ", "- run:")):
            continue
        parts = s.split()
        if is_comparing(parts) and any(p.endswith(".py") for p in parts):
            found.append(next(p for p in parts if p.endswith(".py")))
    return sorted(set(found))


def audit(gates: list[dict[str, Any]]) -> list[str]:
    """Every comparing gate CI runs is declared here, with a repair."""
    declared = {
        next((a for a in g["argv"] if str(a).endswith(".py")), "")
        for g in gates
        if is_comparing(list(g["argv"]))
    }
    problems = [
        f"{script} is run with a comparing flag in the workflow and declares no repair "
        f"in {REGISTRY.name}; add a [[gate]] row or state why it is not regenerable"
        for script in ci_comparing_steps()
        if script not in declared
    ]
    for g in gates:
        if not is_comparing(list(g["argv"])):
            problems.append(
                f"{g['ident']} declares a repair but its argv carries no whole-word "
                f"{' or '.join(sorted(COMPARING_FLAGS))}, so nothing here compares an artifact"
            )
    return problems


def run_one(gate: dict[str, Any]) -> tuple[bool, str]:
    """(changed_something, message). Never raises on the repair's own failure."""
    cwd = REPO_ROOT / gate.get("workdir", ".")
    before = subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout
    proc = subprocess.run(list(gate["fix"]), cwd=cwd, capture_output=True, text=True)
    after = subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True
    ).stdout
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        return False, f"FAILED {gate['ident']}: {tail[-1] if tail else 'no output'}"
    return after != before, f"ok {gate['ident']}"


def regenerate(gates: list[dict[str, Any]]) -> int:
    fixed = [g for g in gates if not g.get("not_regenerable")]
    runnable = [g for g in fixed if not g.get("needs_operator")]
    deferred = [g for g in fixed if g.get("needs_operator")]

    for g in gates:
        if g.get("not_regenerable"):
            print(f"NOT REGENERABLE {g['ident']}: {g['not_regenerable']}")

    for g in deferred:
        print(
            f"SKIPPED {g['ident']}: declared needs_operator, so its repair takes an "
            "argument this runner cannot supply. Run it by hand; it is not reported "
            "as repaired.",
            file=sys.stderr,
        )

    for attempt in range(1, MAX_PASSES + 1):
        failures, changed = [], False
        for g in runnable:
            moved, msg = run_one(g)
            changed = changed or moved
            if msg.startswith("FAILED"):
                failures.append(msg)
            print(f"  pass {attempt}: {msg}")
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        if failures:
            print(
                f"{len(failures)} repair(s) could not complete; the tree may be "
                "partly regenerated. Nothing above claims a repair that failed.",
                file=sys.stderr,
            )
            return 1
        if not changed:
            print(f"converged after {attempt} pass(es); nothing left to regenerate")
            return 0

    print(
        f"REFUSED: still changing after {MAX_PASSES} passes. Two generators disagree, "
        "so this is not a fixed point and the last pass is not a result. Read what each "
        "pass rewrote before running again.",
        file=sys.stderr,
    )
    return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--audit",
        action="store_true",
        help="check every comparing gate in CI declares a repair; write nothing",
    )
    ap.add_argument("--list", action="store_true", help="print the registry and exit")
    args = ap.parse_args(argv[1:])

    try:
        gates = load()
    except Refused as exc:
        print(f"regen: REFUSED to run -- {exc}", file=sys.stderr)
        return 2

    if args.list:
        for g in gates:
            flag = " [needs operator]" if g.get("needs_operator") else ""
            print(f"{g['ident']}{flag}")
            print(f"    gate   {' '.join(g['argv'])}")
            if g.get("not_regenerable"):
                print(f"    repair none: {g['not_regenerable']}")
            else:
                print(f"    repair {' '.join(g['fix'])}")
        return 0

    if args.audit:
        try:
            problems = audit(gates)
        except Refused as exc:
            print(f"regen: REFUSED to audit -- {exc}", file=sys.stderr)
            return 2
        for p in problems:
            print(f"regen audit: {p}", file=sys.stderr)
        if problems:
            return 1
        n = sum(1 for g in gates if is_comparing(list(g["argv"])))
        none = sum(1 for g in gates if g.get("not_regenerable"))
        print(f"All {n} comparing gate(s) declare a repair or, for {none} of them, "
              "why none exists.")
        return 0

    return regenerate(gates)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
