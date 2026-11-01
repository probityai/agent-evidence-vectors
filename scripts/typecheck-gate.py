#!/usr/bin/env python3
"""Type-check every Python file in the repository, and prove it checked them.

This repository asks a stranger to run its gates and reach the same answer, so
a gate that dies partway is worse than one that answers wrongly: a crash and a
never-wired check produce the same thing, which is no finding at all. The lint
pass covers the compiled rail. Nothing covered the interpreted one.

Three properties, and each exists because its absence is a way this gate could
report a clean result it did not earn.

FIRST, coverage is by directory and is checked, not assumed. The other type
pass runs from a list of files spelled out by hand at its call site, so a file
is covered only if somebody remembered to add it; four had accumulated that no
checker had ever read, including this directory's own workflow runner and the
locking primitive under it. Here the checked set comes from the directories in
[tool.pyright].include, and any Python file in the repository that falls
outside them is a CONFIGURATION error -- the gate refuses rather than quietly
checking less than it appears to.

SECOND, an unresolved import is a CONFIGURATION error, never a finding. It
means the environment lacks a package or the search path is short, and it is
reported against the file doing the importing, where it reads exactly like a
real undefined name. A gate that emits a page of that on every run is a gate
its readers learn to scroll past, and the genuine findings underneath go with
it. So they exit separately, with the command that fixes them.

THIRD, a run that analysed nothing is not a pass. Point a checker at a path
that does not resolve and it reports zero problems, cheerfully, in
milliseconds -- the same output as a clean tree. So the analysed-file count is
compared against the files this repository actually has, and a shortfall fails.

    uv run python scripts/typecheck-gate.py           # check
    uv run python scripts/typecheck-gate.py --list    # show the set, check nothing

Exits: 0 clean, 1 type findings, 2 configuration error.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tomllib
from typing import NoReturn

REPO = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"

FINDINGS = 1
CONFIG = 2

# Reported against the importing file, but never a fact about that file: each
# says the checker could not find a module, which is a statement about the
# environment it was run in. Kept as a set rather than a prefix test so that a
# new rule has to be classified deliberately rather than swept in by its name.
IMPORT_RULES = frozenset(
    {
        "reportMissingImports",
        "reportMissingModuleSource",
        "reportMissingTypeStubs",
    }
)


def fail(message: str) -> NoReturn:
    """Print a configuration refusal and exit. Never used for a finding.

    Declared NoReturn so callers are understood to stop here. Without it every
    name bound after a refusal reads as possibly-unbound, which is six findings
    that describe the annotation rather than the code -- and a reader who has
    dismissed six of those will dismiss the seventh without reading it.
    """
    print(f"typecheck-gate: {message}", file=sys.stderr)
    raise SystemExit(CONFIG)


def included_dirs() -> list[str]:
    """The directories the checker is configured to read, or refuse."""
    try:
        config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read {PYPROJECT}: {exc}")
    dirs = config.get("tool", {}).get("pyright", {}).get("include")
    if not dirs:
        fail(
            "pyproject.toml declares no [tool.pyright].include.\n"
            "  Refusing to run: without it the checker decides its own scope, and\n"
            "  this gate cannot report what was covered."
        )
    return list(dirs)


def held_elsewhere_dirs() -> list[str]:
    """Directories whose Python is checked by the workflow that owns them.

    The trees imported from the sibling specification repository carry their
    own lint and test jobs (parts.yml and the crate, package and site
    workflows). They are named here, in pyproject.toml, so the exclusion is
    visible and reviewed; a Python file outside both lists is still an error.
    """
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    held = config.get("tool", {}).get("typecheck-gate", {}).get("held-elsewhere", [])
    return list(held)


def repository_python_files() -> list[pathlib.Path]:
    """Every Python file git knows about, tracked or not yet added.

    Untracked files count. The work most likely to carry a fresh defect is the
    work that has not been committed yet, and a gate that only reads committed
    files reports clean on precisely the change being written.
    """
    found: set[pathlib.Path] = set()
    for extra in ([], ["--others", "--exclude-standard"]):
        proc = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", *extra, "*.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            fail(f"git ls-files failed: {proc.stderr.strip()}")
        found.update(pathlib.Path(line) for line in proc.stdout.split() if line)
    return sorted(found)


def uncovered(files: list[pathlib.Path], dirs: list[str]) -> list[pathlib.Path]:
    """Files that exist but sit outside every configured directory."""
    roots = [pathlib.Path(d) for d in dirs]
    return [f for f in files if not any(r == f or r in f.parents for r in roots)]


def run_checker() -> dict:
    """Run the checker over the configured tree and return its report."""
    try:
        proc = subprocess.run(
            [
                "pyright",
                "--project",
                str(REPO),
                # Bind the analysis to the interpreter running this gate, so the
                # packages it can see are the ones the caller actually has. Left
                # to its own discovery the checker may pick an unrelated
                # interpreter and report imports as missing that are installed.
                "--pythonpath",
                sys.executable,
                "--outputjson",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        fail(
            "pyright is not on PATH.\n"
            "  It is declared in the dev extra; install it with:\n"
            "    uv sync --extra dev --extra generators\n"
            "  and run this gate as: uv run python scripts/typecheck-gate.py"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail(
            "the checker produced no readable report.\n"
            f"  exit {proc.returncode}\n"
            f"  {(proc.stderr or proc.stdout).strip()[:2000]}"
        )


def show(diagnostics: list[dict], heading: str) -> None:
    print(f"\n{heading}")
    for d in diagnostics:
        path = pathlib.Path(d.get("file", "?"))
        try:
            path = path.relative_to(REPO)
        except ValueError:
            pass
        start = d.get("range", {}).get("start", {})
        line = start.get("line", 0) + 1
        col = start.get("character", 0) + 1
        rule = d.get("rule") or d.get("severity", "error")
        print(f"  {path}:{line}:{col}  [{rule}]")
        for text in d.get("message", "").splitlines():
            print(f"      {text}")


def main() -> int:
    ap = argparse.ArgumentParser(description="type-check every Python file")
    ap.add_argument(
        "--list",
        action="store_true",
        help="print the covered set and the configured directories, run nothing",
    )
    args = ap.parse_args()

    dirs = included_dirs()
    held = [pathlib.Path(d) for d in held_elsewhere_dirs()]
    files = [
        f
        for f in repository_python_files()
        if not any(r == f or r in f.parents for r in held)
    ]
    if not files:
        fail(
            "git reported no Python files in this repository.\n"
            "  That is not a clean result; this repository has them. Refusing to\n"
            "  pass on a listing that cannot be right."
        )

    stray = uncovered(files, dirs)
    if stray:
        print(
            "typecheck-gate: these Python files sit outside every checked directory:",
            file=sys.stderr,
        )
        for f in stray:
            print(f"  {f}", file=sys.stderr)
        fail(
            "add the directory to [tool.pyright].include in pyproject.toml.\n"
            "  A file no checker reads is the case this gate exists to prevent."
        )

    if args.list:
        print(f"configured directories: {', '.join(dirs)}")
        print(f"python files in the repository: {len(files)}")
        for f in files:
            print(f"  {f}")
        return 0

    report = run_checker()
    summary = report.get("summary", {})
    analysed = summary.get("filesAnalyzed", 0)

    # The positive control. Zero problems from zero files is the signature of a
    # checker pointed somewhere that does not exist, and it is indistinguishable
    # from a clean tree in every other respect.
    if analysed < len(files):
        fail(
            f"the checker analysed {analysed} files; this repository has {len(files)}.\n"
            "  A check that did not read the code cannot report it clean."
        )

    diagnostics = report.get("generalDiagnostics", [])
    import_problems = [d for d in diagnostics if d.get("rule") in IMPORT_RULES]
    findings = [d for d in diagnostics if d.get("rule") not in IMPORT_RULES]

    if import_problems:
        show(import_problems, "CONFIGURATION: the checker could not resolve these imports.")
        print(
            "\nThis is the environment, not the code. Every third-party import in\n"
            "this repository is declared in pyproject.toml; install them and run\n"
            "the gate through the same environment:\n"
            "    uv sync --extra dev --extra generators\n"
            "    uv run python scripts/typecheck-gate.py\n"
            "If the module is genuinely new, declare it in the dev extra first.",
            file=sys.stderr,
        )
        return CONFIG

    if findings:
        show(findings, f"FAIL: {len(findings)} type finding(s).")
        return FINDINGS

    print(f"OK: {analysed} Python files type-check clean across {', '.join(dirs)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
