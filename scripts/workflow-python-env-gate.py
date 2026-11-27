#!/usr/bin/env python3
"""Refuse a workflow step that runs a Python script where the script's imports are missing.

The defect this exists for, measured 27 Nov 2026. The `resolve` job of pages.yml ran
`python3 scripts/identifier-pages-gate.py --live` on a bare runner. That gate builds the site by
launching docs/site/build.py, which imports `markdown`, and a bare python3 sees only the standard
library, so the job failed with `ModuleNotFoundError: No module named 'markdown'` on every main push
from 24 Nov 2026 and nothing said so until a person read the run. The same file's build job had
installed `markdown` from the lock and run green, so the dependency was declared and locked; only
the job that ran the script never installed it.

The rule, for every job of every workflow: each step that runs a repository Python script (python,
python3, pytest, with or without `uv run` or `.venv/bin/`) gets an environment, and every
third-party package that script imports, directly or through a local module it imports or a script
it launches with sys.executable, is in that environment.

  * `uv run [flags] ...` has the project dependencies, the default `dev` group and the extras and
    groups its flags name (`--extra`, `--all-extras`, `--group`, `--only-group`, `--no-dev`), or,
    with `--no-project`, only what `--with` names.
  * `.venv/bin/python ...` has what the job's `uv sync` steps installed.
  * a bare `python` or `python3` has the standard library plus what a `pip install` or
    `uv pip install` step of the same job names. `uv sync` does not help a bare python3: it fills
    `.venv`, which a bare python3 never reads.
  * a script run under any other interpreter path (a venv built in the job) is not checked.

A step is refused with the package, the script that imports it and the fix. Dependencies are read
from pyproject.toml, so the lock-file side is the one `uv sync --locked` already enforces.

Exit 0 when sound, 1 on a finding, 2 when a file could not be read.
Usage: python3 scripts/workflow-python-env-gate.py [--workflows DIR] [--root DIR]
"""

from __future__ import annotations

import argparse
import ast
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent

# Import name to distribution name, for the packages whose two differ. Any other third-party
# import is taken to be its own distribution, lowercased, with underscores as hyphens.
IMPORT_TO_DIST = {
    "yaml": "pyyaml",
    "Crypto": "pycryptodome",
    "fitz": "pymupdf",
    "pymupdf": "pymupdf",
    "cose": "pycose",
    "pytest_cov": "pytest-cov",
    "OpenSSL": "pyopenssl",
}

SKIPPED_DIRS = {".venv", "venv", "node_modules", "_site", "target", ".git", "__pycache__", ".build"}

# uv run and uv sync flags that take a value, so the value is not mistaken for the command.
UV_VALUE_FLAGS = {
    "--with", "--extra", "--group", "--only-group", "--no-group", "--python", "-p", "--project",
    "--directory", "--with-requirements", "--with-editable", "--env-file", "--package",
    "--isolated-env", "--config-file", "--index-url", "--refresh-package", "--no-install-package",
}  # fmt: skip

PYTHON_NAMES = re.compile(r"^python(3(\.\d+)?)?$")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def req_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    return norm(match.group(1)) if match else ""


@dataclass
class Project:
    """What `uv sync` installs, by flag, read from pyproject.toml."""

    root: Path = field(default_factory=Path)
    base: set[str] = field(default_factory=set)
    extras: dict[str, set[str]] = field(default_factory=dict)
    groups: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> Project:
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        proj = data.get("project", {})
        out = cls(root=root, base={req_name(r) for r in proj.get("dependencies", [])})
        for name, reqs in proj.get("optional-dependencies", {}).items():
            out.extras[name] = {req_name(r) for r in reqs}
        for name, reqs in data.get("dependency-groups", {}).items():
            out.groups[name] = {req_name(r) for r in reqs if isinstance(r, str)}
        return out

    def installed(self, extras: set[str], groups: set[str], all_extras: bool) -> set[str]:
        have = set(self.base)
        for name in self.extras if all_extras else extras:
            have |= self.extras.get(name, set())
        for name in groups:
            have |= self.groups.get(name, set())
        return have

    def declared_in(self, dist: str) -> list[str]:
        where = [f"--extra {n}" for n, d in self.extras.items() if dist in d]
        return where + [f"--group {n}" for n, d in self.groups.items() if dist in d]


class RepoIndex:
    """The repository's own modules, and the third-party imports of a script and what it reaches."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.local_names: set[str] = set()
        self.by_stem: dict[str, list[Path]] = {}
        for path in root.rglob("*.py"):
            if SKIPPED_DIRS & set(path.relative_to(root).parts):
                continue
            self.local_names.add(path.stem)
            self.by_stem.setdefault(path.stem, []).append(path)
            if path.name == "__init__.py":
                self.local_names.add(path.parent.name)
        self._cache: dict[Path, list[tuple[str, Path]]] = {}
        self._files: dict[Path, tuple[list[str], list[Path]]] = {}

    @staticmethod
    def _guarded(tree: ast.AST) -> set[int]:
        """Ids of import nodes in a try catching ImportError, under TYPE_CHECKING, in a function."""
        skip: set[int] = set()
        for node in ast.walk(tree):
            guarded = False
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    names = ast.dump(handler.type) if handler.type else "ImportError"
                    guarded |= "ImportError" in names or "ModuleNotFoundError" in names
                body: list[ast.stmt] = node.body
            elif isinstance(node, ast.If) and "TYPE_CHECKING" in ast.dump(node.test):
                guarded, body = True, node.body
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                # An import inside a function runs only when that path is called; the gate
                # cannot know which paths a step takes, so it asks only for module-level imports.
                guarded, body = True, node.body
            else:
                continue
            if guarded:
                skip |= {id(n) for stmt in body for n in ast.walk(stmt)}
        return skip

    @staticmethod
    def _div_chain(node: ast.expr) -> list[str] | None:
        parts: list[str] = []
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if not (isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                return None
            parts.append(node.right.value)
            node = node.left
        return parts[::-1] if parts else None

    def _launched(self, tree: ast.AST, script: Path) -> list[Path]:
        """Scripts this one starts with sys.executable, named by a literal path."""
        out: list[Path] = []
        for node in ast.walk(tree):
            rel: str | None = None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                rel = node.value if node.value.endswith(".py") else None
            elif isinstance(node, ast.BinOp):
                chain = self._div_chain(node)
                rel = "/".join(chain) if chain and chain[-1].endswith(".py") else None
            if rel:
                for base in (self.root, script.parent):
                    if (base / rel).is_file():
                        out.append(base / rel)
                        break
        return out

    def _file_info(self, path: Path) -> tuple[list[str], list[Path]]:
        """The non-standard-library import names of one file, and the scripts it launches."""
        if path in self._files:
            return self._files[path]
        names: list[str] = []
        launched: list[Path] = []
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeDecodeError):
            self._files[path] = (names, launched)
            return self._files[path]
        skip = self._guarded(tree)
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            if isinstance(node, ast.Import):
                names += [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.append(node.module.split(".")[0])
        names = [n for n in names if n not in sys.stdlib_module_names]
        if "sys.executable" in source:
            launched = self._launched(tree, path)
        self._files[path] = (names, launched)
        return self._files[path]

    def third_party(self, script: Path) -> list[tuple[str, Path]]:
        """(import name, file that imports it) for the script and everything it reaches."""
        key = script.resolve()
        if key in self._cache:
            return self._cache[key]
        found: list[tuple[str, Path]] = []
        seen: set[Path] = set()
        stack = [key]
        while stack:
            path = stack.pop()
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            names, launched = self._file_info(path)
            for name in names:
                if name in self.local_names:
                    near = [p for p in self.by_stem.get(name, []) if p.parent == path.parent]
                    stack.extend((near or self.by_stem.get(name, []))[:1])
                else:
                    found.append((name, path))
            stack.extend(p.resolve() for p in launched)
        self._cache[key] = found
        return found


@dataclass
class Env:
    label: str
    dists: set[str] | None  # None: an interpreter this gate cannot see into
    fix: str = ""


def flag_values(tokens: list[str], flag: str) -> list[str]:
    out = []
    for i, tok in enumerate(tokens):
        if tok == flag and i + 1 < len(tokens):
            out.append(tokens[i + 1])
        elif tok.startswith(flag + "="):
            out.append(tok.split("=", 1)[1])
    return out


def commands(run: str) -> list[list[str]]:
    """The shell commands of a run block, split on newlines, && || ; and pipes."""
    text = re.sub(r"\\\n", " ", run)
    out = []
    for line in text.splitlines():
        for part in re.split(r"&&|\|\||;|\|", line):
            try:
                tokens = shlex.split(part, comments=True)
            except ValueError:
                tokens = part.split()
            while tokens and re.match(r"^[A-Za-z_]\w*=", tokens[0]):  # leading NAME=value prefixes
                tokens = tokens[1:]
            if tokens:
                out.append(tokens)
    return out


def sync_flags(project: Project, tokens: list[str]) -> set[str]:
    extras = set(flag_values(tokens, "--extra"))
    groups = set(flag_values(tokens, "--group")) | set(flag_values(tokens, "--only-group"))
    if (
        "--no-dev" not in tokens
        and "--only-group" not in tokens
        and "--no-default-groups" not in tokens
    ):
        groups.add("dev")
    only = "--only-group" in tokens
    have = project.installed(extras, groups, "--all-extras" in tokens)
    if only:
        have -= project.base
    return have


def with_names(tokens: list[str]) -> set[str]:
    return {req_name(v) for v in flag_values(tokens, "--with")}


def requirements_names(root: Path, workdir: Path, rel: str, depth: int = 0) -> set[str]:
    """The distributions a requirements file names, following `-r` includes. The path is read
    from the step's working directory first and the repository root second, as a shell would."""
    out: set[str] = set()
    for base in (root / workdir, root):
        path = base / rel
        if path.is_file():
            break
    else:
        return out
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith(("-r ", "--requirement ")) and depth < 4:
            inc = path.parent / line.split(None, 1)[1].strip()
            out |= requirements_names(root, Path("."), str(inc.relative_to(root)), depth + 1)
        elif line and not line.startswith("-"):
            out.add(req_name(line))
    return out


def pip_names(tokens: list[str], root: Path, workdir: Path) -> set[str]:
    out: set[str] = set()
    for i, tok in enumerate(tokens):
        if tok in ("-r", "--requirement") and i + 1 < len(tokens):
            out |= requirements_names(root, workdir, tokens[i + 1])
            continue
        if tok.startswith("-") or tok in {"pip", "install", "uv", "python", "python3"}:
            continue
        if i and tokens[i - 1] in ("-r", "--requirement"):
            continue
        if "/" in tok or tok.endswith((".whl", ".txt", ".lock")) or "$" in tok:
            continue
        name = req_name(tok)
        if name:
            out.add(name)
    return out


def job_environments(job: dict[str, Any], project: Project) -> tuple[set[str] | None, set[str]]:
    """What the job's `uv sync` steps put in .venv (None when it never syncs), and what its
    pip steps put in the system interpreter."""
    venv: set[str] | None = None
    system: set[str] = set()
    default_dir = str((job.get("defaults") or {}).get("run", {}).get("working-directory", ""))
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        workdir = Path(str(step.get("working-directory") or default_dir or "."))
        for tokens in commands(str(step.get("run", ""))):
            if tokens[:2] == ["uv", "sync"]:
                venv = (venv or set()) | sync_flags(project, tokens)
            elif tokens[:3] == ["uv", "pip", "install"] and "--python" not in tokens:
                venv = (venv or set()) | pip_names(tokens[3:], project.root, workdir)
            elif "pip" in tokens and "install" in tokens and "-m" in tokens:
                after = tokens[tokens.index("install") + 1 :]
                if not any(t.startswith("--target") for t in after):
                    system |= pip_names(after, project.root, workdir)
            elif tokens[:2] == ["pip", "install"]:
                system |= pip_names(tokens[2:], project.root, workdir)
    return venv, system


def python_targets(tokens: list[str]) -> tuple[str, list[str]] | None:
    """(interpreter token, repository .py arguments) when the command runs a Python script."""
    exe = Path(tokens[0]).name
    if PYTHON_NAMES.match(exe) or exe == "pytest":
        rest = tokens[1:]
        if "-c" in rest:
            return None
        return tokens[0], [t for t in rest if t.endswith(".py")]
    return None


def nearest_project(project: Project, workdir: Path) -> Project:
    """The project `uv run` resolves from a step's working directory: the nearest pyproject.toml
    at or above it, up to the repository root. A directory with a pyproject.toml of its own is
    its own locked environment."""
    here = (project.root / workdir).resolve()
    while here != project.root and project.root in here.parents:
        if (here / "pyproject.toml").is_file():
            return Project.load(here)
        here = here.parent
    return project


def environment_for(
    tokens: list[str],
    project: Project,
    venv: set[str] | None,
    system: set[str],
    workdir: Path = Path("."),
) -> tuple[Env, list[str]] | None:
    if tokens[:2] == ["uv", "run"]:
        i = 2
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 2 if tokens[i] in UV_VALUE_FLAGS else 1
        flags, command = tokens[2:i], tokens[i:]
        target = python_targets(command) if command else None
        if target is None:
            return None
        if "--no-project" in flags:
            dists, fix = with_names(flags), ""
        else:
            local = nearest_project(project, workdir)
            if local is not project:
                dists, fix = sync_flags(local, flags) | with_names(flags), ""
            else:
                # `uv run` syncs inexactly: what an earlier `uv sync` of the job installed stays.
                dists = (venv or set()) | sync_flags(project, flags) | with_names(flags)
                fix = "uv run --locked --extra <extra>"
        return Env("`uv run` as written", dists, fix), target[1]
    target = python_targets(tokens)
    if target is None:
        return None
    exe, scripts = target
    if (
        exe.endswith(".venv/bin/python")
        or exe.endswith(".venv/bin/pytest")
        or exe == ".venv/bin/python"
    ):
        if venv is None:
            return Env("`.venv/bin/python` in a job that never runs `uv sync`", set()), scripts
        return Env("the `.venv` the job's `uv sync` builds", venv), scripts
    if "/" in exe:
        return None
    return Env(
        "a bare interpreter (the standard library plus the job's `pip install`s)", system
    ), scripts


def check_job(
    name: str, jname: str, job: dict[str, Any], project: Project, index: RepoIndex
) -> list[str]:
    if not isinstance(job, dict):
        return []
    venv, system = job_environments(job, project)
    found: list[str] = []
    default_dir = str((job.get("defaults") or {}).get("run", {}).get("working-directory", ""))
    for step in job.get("steps") or []:
        if not isinstance(step, dict) or "run" not in step:
            continue
        workdir = Path(str(step.get("working-directory") or default_dir or "."))
        label = str(step.get("name") or "an unnamed step")
        for tokens in commands(str(step["run"])):
            got = environment_for(tokens, project, venv, system, workdir)
            if got is None:
                continue
            env, scripts = got
            if env.dists is None:
                continue
            for rel in scripts:
                path = index.root / workdir / rel
                if path.is_file():
                    where = f"{name} job {jname!r} step {label!r}"
                    found += missing_imports(where, rel, path, env, project, index)
    return found


def missing_imports(
    where: str, rel: str, path: Path, env: Env, project: Project, index: RepoIndex
) -> list[str]:
    """One finding for each package the script reaches that its environment lacks."""
    missing: dict[str, Path] = {}
    for imp, origin in index.third_party(path):
        dist = norm(IMPORT_TO_DIST.get(imp, imp))
        if env.dists is not None and dist not in env.dists:
            missing.setdefault(dist, origin)
    found = []
    for dist, origin in sorted(missing.items()):
        extra = project.declared_in(dist)
        fix = (
            f"run it with `uv run --locked {extra[0]} python ...` "
            f"after `uv sync --locked {extra[0]}`"
            if extra
            else "declare it in pyproject.toml, lock it, and install it in this job"
        )
        found.append(
            f"{where}: {rel} needs {dist} (imported by {origin.relative_to(index.root)}) "
            f"but runs under {env.label}; {fix}"
        )
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--workflows", type=Path, default=None)
    args = ap.parse_args(argv)
    workflows = args.workflows or args.root / ".github" / "workflows"
    try:
        project = Project.load(args.root)
        docs = {
            p.name: yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for p in sorted(workflows.glob("*.yml"))
        }
    except (OSError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        print(f"could not read the repository: {exc}", file=sys.stderr)
        return 2
    if not docs:
        print("no workflows found; nothing was verified", file=sys.stderr)
        return 2
    index = RepoIndex(args.root)
    findings = []
    steps = 0
    for name, doc in docs.items():
        for jname, job in (doc.get("jobs") or {}).items():
            findings += check_job(name, jname, job, project, index)
            steps += len((job or {}).get("steps") or []) if isinstance(job, dict) else 0
    for f in findings:
        print(f"FINDING: {f}")
    print(f"checked {steps} steps in {len(docs)} workflows, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
