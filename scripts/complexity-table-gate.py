#!/usr/bin/env python3
"""Accepted-complexity gate, for both rails.

Two files record the functions whose cyclomatic complexity is accepted as
inherent, each entry pairing a measured number with a hand-written rationale.
``docs/architecture/DESIGN_DECISIONS.md`` carries the Go table;
``docs/complexity-rationales.toml`` carries the Python entries, one per function
marked ``# noqa: C901``. The rationale is the point of both: it is the argument
that a branch-heavy function mirrors a branch-heavy specification rather than
tangled structure. That argument is only worth reading if the number attached to
it is the number a reader gets when they measure.

The numbers drift because nothing checks them, and they have now drifted on both
rails. On the Go side, as gocyclo measured them at suiteRevision 15, ``Gate0``
grew from 33 to 34 and ``evaluateKind`` from 24 to 28 without a check going red,
and two functions crossed the inclusion
threshold without ever being written down. The Python side was described here and
in ``DESIGN_DECISIONS.md`` as already covered, on the reasoning that ruff's C901
fails the build; that reasoning was wrong, and the correction is the reason this
gate now spans both rails. C901 fires on functions above the threshold, and the
recorded functions are exactly the ones carrying ``# noqa: C901``, which silences
it. Nothing then read the recorded number at all: ``verify`` grew from 38 to 45
and ``second_fault_absence`` from 11 to 12 under a linter that was, correctly,
saying nothing about either.

It fails closed on all three ways a record can go out of sync with the source,
identically on both rails:

  - an entry whose number no longer matches what the analyzer measures;
  - a function at or above the inclusion threshold with no entry (an unreviewed
    accepted-complexity function, which is exactly what these records exist to
    prevent);
  - an entry for a function that no longer exists, or that has been refactored
    back below the threshold (a rationale for complexity that is no longer
    there).

On the Python rail it also fails when a recorded function has lost its
``# noqa: C901`` marker, so the source comment and the record keep pointing at
each other.

Scope and threshold are stated for each rail rather than inferred from the
records, so the rule is checkable instead of archaeological:

  - GO SCOPE -- every non-test Go function in the four source trees. Test helpers
    are excluded: they are not the shipped verifier, and their branch count is
    driven by the number of cases they enumerate.
  - GO THRESHOLD -- complexity 18 and above. Below that, a function is ordinary
    and needs no defence.
  - PYTHON SCOPE -- every function in the three trees ruff lints in CI.
  - PYTHON THRESHOLD -- one above ``max-complexity`` in ``pyproject.toml``, read
    from that file rather than repeated here, because the threshold that matters
    is the one the linter enforces and two copies of it would be one more number
    free to drift.

``--sync`` rewrites the numbers from a fresh measurement and touches nothing
else, so a legitimate complexity change is one command rather than a hand edit
that can typo a digit. It deliberately cannot add or remove an entry: a new
accepted-complexity function needs a rationale a script has no way to write, and
inventing a placeholder would defeat the record. Membership stays a human
decision; only the arithmetic is automated.

``--rail`` selects which half to run, because the two analyzers come from
different toolchains and CI splits the work across two jobs: the Go job has
gocyclo and the Python job has ruff. A bare run does both, which is what a
developer with the full toolchain wants.

Note the argument convention is the majority one in this directory (bare run =
check, fail closed), not ``coverage-matrix-gate.py``'s (bare run = regenerate),
because this is a gate that can regenerate rather than a generator that can
check.

Usage: python3 scripts/complexity-table-gate.py
           [--rail go|python|both] [--sync] [--gocyclo PATH] [--ruff PATH]
Exit 0 when every record matches its source; 1 on any drift.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "architecture" / "DESIGN_DECISIONS.md"
RATIONALES = REPO_ROOT / "docs" / "complexity-rationales.toml"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Every Go source tree in the repository: the stdlib-only core, the fixture
# builder, the commands, and the separate go-witness attestor module. gocyclo is
# purely syntactic, so the second module needs no separate invocation. aeetest/
# is included deliberately -- its files are not `_test.go`, so they are ordinary
# compiled source, and `Build` sits at 17, one step below the threshold.
GO_SCOPE = ("aee", "aeetest", "cmd", "corpusreaders", "witnessattestor")
GO_THRESHOLD = 18

# The three trees the CI ruff step lints, so the gate's scope and the linter's
# cannot come apart.
PY_SCOPE = ("packaging", "vectors", "scripts")

# Pinned to the version CI installs. Complexity counting is the tool's whole
# output and it is committed in the table, so a local/CI version skew would show
# up as a table that passes on one machine and fails on the other.
GOCYCLO_HINT = "go install github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0"
# ruff needs no pin here: uv.lock resolves it to one version, and CI installs
# from that lock, so the number this gate reads is the number the linter that
# defines the threshold produced.
RUFF_HINT = "uv sync --extra dev"

# `37 aee checkSubstrateRow aee/validity.go:456:1`
STAT_RE = re.compile(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+):(\d+):(\d+)$")
# `| `aee/validity.go` `checkSubstrateRow` | 37 | Per-row coverage: ... |`
ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s+`([^`]+)`\s*\|\s*(\d+)\s*\|")
HEADER = "| Function | Cyclo | Why it is inherent |"

# `packaging/run_vectors.py:161:5: C901 `jcs_dumps` is too complex (10 > 1)`
RUFF_RE = re.compile(r"^(\S+):\d+:\d+: C901 `([^`]+)` is too complex \((\d+) > \d+\)$")
# `["vectors/accept/gen_valid_vectors.py::verify"]` and its `complexity = 38`.
SECTION_RE = re.compile(r'^\["([^"]+)"\]\s*$')
COMPLEXITY_RE = re.compile(r"^complexity\s*=\s*(\d+)\s*$")

Key = tuple[str, str]  # (file path relative to repo root, function name)
Rows = dict[Key, tuple[int, int]]  # key -> (line index to rewrite, recorded value)


def _missing(tool: str, hint: str, flag: str, env: str) -> None:
    """Report an absent analyzer and exit non-zero.

    A missing analyzer must never degrade into a pass. An unmeasured record is
    exactly the state this gate exists to end, so absence of the tool is a
    failure of the gate, not an excuse to skip it.
    """
    print(
        f"FAIL: {tool} is not installed, so the accepted-complexity records "
        "cannot be checked.\n"
        f"  install it with: {hint}\n"
        f"  or point the gate at it with {flag} PATH / {env}=PATH\n"
        "This gate does not skip when the analyzer is missing: an unchecked "
        "record is the defect it exists to catch.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def _explicit_path(tool: str, candidates: tuple[str | None, ...]) -> str | None:
    for candidate in candidates:
        if candidate:
            if Path(candidate).is_file():
                return candidate
            print(f"FAIL: {tool} not found at {candidate}", file=sys.stderr)
            raise SystemExit(1)
    return None


def resolve_gocyclo(explicit: str | None) -> str:
    """Locate the gocyclo binary, or exit non-zero saying how to install it."""
    chosen = _explicit_path("gocyclo", (explicit, os.environ.get("GOCYCLO")))
    if chosen:
        return chosen

    found = shutil.which("gocyclo")
    if found:
        return found

    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    fallback = Path(gopath) / "bin" / "gocyclo"
    if fallback.is_file():
        return str(fallback)

    _missing("gocyclo", GOCYCLO_HINT, "--gocyclo", "GOCYCLO")
    raise AssertionError("unreachable")


def resolve_ruff(explicit: str | None) -> str:
    """Locate the ruff binary, or exit non-zero saying how to install it."""
    chosen = _explicit_path("ruff", (explicit, os.environ.get("RUFF")))
    if chosen:
        return chosen

    found = shutil.which("ruff")
    if found:
        return found

    venv = REPO_ROOT / ".venv" / "bin" / "ruff"
    if venv.is_file():
        return str(venv)

    _missing("ruff", RUFF_HINT, "--ruff", "RUFF")
    raise AssertionError("unreachable")


def _run_analyzer(argv: list[str], tool: str, allowed: tuple[int, ...]) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=REPO_ROOT, check=False)
    if proc.returncode not in allowed:
        print(
            f"FAIL: {tool} exited {proc.returncode}:\n{proc.stderr.strip()}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return proc.stdout


def _require_measurements(out: dict[Key, int], tool: str, scope: tuple[str, ...]) -> dict[Key, int]:
    if not out:
        print(
            f"FAIL: {tool} reported no functions; the scope paths "
            f"{list(scope)} are wrong or the trees are empty.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return out


def measure_go(binary: str) -> dict[Key, int]:
    """Cyclomatic complexity of every in-scope non-test Go function."""
    paths = [str(REPO_ROOT / d) for d in GO_SCOPE]
    out: dict[Key, int] = {}
    for line in _run_analyzer([binary, *paths], "gocyclo", (0,)).splitlines():
        m = STAT_RE.match(line.strip())
        if not m:
            continue
        complexity, _pkg, func, path = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        rel = str(Path(path).resolve().relative_to(REPO_ROOT))
        if rel.endswith("_test.go"):
            continue
        out[(rel, func)] = complexity
    return _require_measurements(out, "gocyclo", GO_SCOPE)


def measure_python(binary: str) -> dict[Key, int]:
    """Cyclomatic complexity of every in-scope Python function.

    Two flags carry the whole point of this measurement. ``--ignore-noqa`` is
    what makes it possible at all: every recorded function carries a
    ``# noqa: C901``, so a plain ruff run reports nothing about exactly the
    functions whose numbers are written down. Setting the threshold to 1 turns
    the linter's pass/fail into a reading, since ruff prints the measured value
    in the message it would otherwise only print above ``max-complexity``.
    ``--isolated`` keeps the run independent of the project configuration so the
    threshold override is the only one in force.
    """
    argv = [
        binary,
        "check",
        "--isolated",
        "--no-cache",
        "--select",
        "C901",
        "--config",
        "lint.mccabe.max-complexity = 1",
        "--ignore-noqa",
        "--output-format",
        "concise",
        *PY_SCOPE,
    ]
    out: dict[Key, int] = {}
    # ruff exits 1 when it has findings, and findings are the measurement.
    for line in _run_analyzer(argv, "ruff", (0, 1)).splitlines():
        m = RUFF_RE.match(line.strip())
        if m:
            out[(m.group(1), m.group(2))] = int(m.group(3))
    return _require_measurements(out, "ruff", PY_SCOPE)


def python_threshold() -> int:
    """One above the ruff mccabe ceiling, read from the linter's own config."""
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    try:
        ceiling = config["tool"]["ruff"]["lint"]["mccabe"]["max-complexity"]
    except (KeyError, TypeError):
        print(
            "FAIL: pyproject.toml has no [tool.ruff.lint.mccabe] max-complexity, "
            "so the Python inclusion threshold cannot be read from the linter "
            "that enforces it.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    if not isinstance(ceiling, int):
        print("FAIL: max-complexity in pyproject.toml is not an integer.", file=sys.stderr)
        raise SystemExit(1)
    return ceiling + 1


def parse_table(lines: list[str]) -> Rows:
    """Map each table row to its (line index, recorded complexity)."""
    try:
        start = lines.index(HEADER)
    except ValueError:
        print(
            f"FAIL: {DOC.relative_to(REPO_ROOT)} has no accepted-complexity "
            f"table (expected a header line {HEADER!r}).",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    rows: Rows = {}
    for idx in range(start + 2, len(lines)):  # +2 skips the |---| separator
        m = ROW_RE.match(lines[idx])
        if not m:
            break
        rows[(m.group(1), m.group(2))] = (idx, int(m.group(3)))
    return rows


def parse_rationales(lines: list[str]) -> Rows:
    """Map each TOML entry to its (line index of `complexity`, recorded value).

    The file is read twice on purpose: tomllib for validity and for the presence
    of a rationale, and this line scan for the one line ``--sync`` may rewrite.
    Round-tripping the parsed document would reflow the multi-line rationale
    strings, and the rationale is the part of the record worth keeping byte for
    byte.
    """
    document = tomllib.loads("\n".join(lines))
    rows: Rows = {}
    current: str | None = None
    for idx, line in enumerate(lines):
        section = SECTION_RE.match(line)
        if section:
            current = section.group(1)
            continue
        value = COMPLEXITY_RE.match(line)
        if value and current:
            path, _, func = current.partition("::")
            rows[(path, func)] = (idx, int(value.group(1)))
            current = None
    for name, entry in document.items():
        if not str(entry.get("rationale", "")).strip():
            print(
                f"FAIL: {RATIONALES.relative_to(REPO_ROOT)} entry {name!r} has no "
                "rationale, which is the only part of the entry a reader needs.",
                file=sys.stderr,
            )
            raise SystemExit(1)
    return rows


def drift(measured: dict[Key, int], rows: Rows, threshold: int, tool: str) -> list[str]:
    """Every disagreement between the record and the source, worst first."""
    accepted = {k: c for k, c in measured.items() if c >= threshold}
    errors: list[tuple[int, str]] = []

    for key, complexity in accepted.items():
        recorded = rows.get(key)
        if recorded is None:
            errors.append(
                (
                    complexity,
                    f"`{key[0]}` `{key[1]}`: measures {complexity} "
                    f"(>= {threshold}) but has no entry -- add one with a "
                    "rationale, or refactor it below the threshold",
                )
            )
        elif recorded[1] != complexity:
            errors.append(
                (
                    complexity,
                    f"`{key[0]}` `{key[1]}`: the record says {recorded[1]}, "
                    f"{tool} measures {complexity}",
                )
            )

    for key in rows:
        if key in accepted:
            continue
        now = measured.get(key)
        why = (
            "the function no longer exists"
            if now is None
            else f"it now measures {now}, below the {threshold} threshold"
        )
        errors.append((0, f"`{key[0]}` `{key[1]}`: has an entry but {why} -- drop the entry"))

    return [msg for _, msg in sorted(errors, key=lambda e: (-e[0], e[1]))]


def missing_markers(rows: Rows) -> list[str]:
    """Recorded Python functions whose ``# noqa: C901`` marker has gone.

    The marker is what makes the record findable from the source. Without it a
    reader meets a branch-heavy function with nothing pointing at the argument
    for why it is allowed to be one, and ruff has no reason to stay quiet about
    it either.
    """
    errors: list[str] = []
    for path, func in sorted(rows):
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        marked = any(
            re.match(rf"\s*def {re.escape(func)}\b", line) and "# noqa: C901" in line
            for line in source.splitlines()
        )
        if not marked:
            errors.append(
                f"`{path}` `{func}`: has an entry but its definition carries no "
                "`# noqa: C901`, so nothing in the source points at the rationale"
            )
    return errors


def sync_table(lines: list[str], measured: dict[Key, int], rows: Rows) -> int:
    """Rewrite the numeric column of existing table rows. Returns the count."""
    changed = 0
    for key, (idx, recorded) in rows.items():
        now = measured.get(key)
        if now is None or now == recorded:
            continue
        # `| `file` `func` | 37 | prose |` splits into
        # ['', ' `file` `func` ', ' 37 ', ' prose ', ''] -- only field 2 moves,
        # so the rationale survives byte for byte.
        fields = lines[idx].split("|")
        fields[2] = f" {now} "
        lines[idx] = "|".join(fields)
        changed += 1
    return changed


def sync_rationales(lines: list[str], measured: dict[Key, int], rows: Rows) -> int:
    """Rewrite the ``complexity`` value of existing TOML entries. Returns the count."""
    changed = 0
    for key, (idx, recorded) in rows.items():
        now = measured.get(key)
        if now is None or now == recorded:
            continue
        lines[idx] = f"complexity = {now}"
        changed += 1
    return changed


def _report(errors: list[str], record: Path, rail: str) -> int:
    print(
        f"FAIL: the accepted-complexity record in {record.relative_to(REPO_ROOT)} "
        f"has drifted from the source ({len(errors)} disagreement(s)):",
        file=sys.stderr,
    )
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    print(
        f"\nRun `python3 scripts/complexity-table-gate.py --rail {rail} --sync` to "
        "rewrite the numbers; add or drop an entry by hand, because an entry's "
        "rationale is the part worth having and no script can write it.",
        file=sys.stderr,
    )
    return 1


def check_go(args: argparse.Namespace) -> int:
    measured = measure_go(resolve_gocyclo(args.gocyclo))
    lines = DOC.read_text(encoding="utf-8").splitlines()
    rows = parse_table(lines)

    if args.sync:
        changed = sync_table(lines, measured, rows)
        if changed:
            DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"synced {changed} complexity value(s) in {DOC.relative_to(REPO_ROOT)}")
        else:
            print(f"no numeric drift to sync in {DOC.relative_to(REPO_ROOT)}")
        rows = parse_table(lines)

    errors = drift(measured, rows, GO_THRESHOLD, "gocyclo")
    if errors:
        return _report(errors, DOC, "go")
    print(
        f"OK: {len(rows)} accepted-complexity row(s) match gocyclo, and no "
        f"non-test function in {'/'.join(GO_SCOPE)} reaches {GO_THRESHOLD} unrecorded."
    )
    return 0


def check_python(args: argparse.Namespace) -> int:
    measured = measure_python(resolve_ruff(args.ruff))
    threshold = python_threshold()
    lines = RATIONALES.read_text(encoding="utf-8").splitlines()
    rows = parse_rationales(lines)

    if args.sync:
        changed = sync_rationales(lines, measured, rows)
        if changed:
            RATIONALES.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"synced {changed} complexity value(s) in {RATIONALES.relative_to(REPO_ROOT)}")
        else:
            print(f"no numeric drift to sync in {RATIONALES.relative_to(REPO_ROOT)}")
        rows = parse_rationales(lines)

    errors = drift(measured, rows, threshold, "ruff") + missing_markers(rows)
    if errors:
        return _report(errors, RATIONALES, "python")
    print(
        f"OK: {len(rows)} accepted-complexity entr(ies) match ruff, and no "
        f"function in {'/'.join(PY_SCOPE)} reaches {threshold} unrecorded."
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate the accepted-complexity records.")
    ap.add_argument(
        "--rail",
        choices=("go", "python", "both"),
        default="both",
        help="which rail to check (default: both, which needs both analyzers)",
    )
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the numbers from a fresh measurement (prose untouched)",
    )
    ap.add_argument("--gocyclo", default=None, help="path to the gocyclo binary")
    ap.add_argument("--ruff", default=None, help="path to the ruff binary")
    args = ap.parse_args(argv[1:])

    status = 0
    if args.rail in ("go", "both"):
        status |= check_go(args)
    if args.rail in ("python", "both"):
        status |= check_python(args)
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
