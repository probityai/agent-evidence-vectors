#!/usr/bin/env python3
"""Independent producibility: a second generator, sharing no code, re-mints a corpus byte for byte.

    python3 scripts/independent-producibility.py              # every minter
    python3 scripts/independent-producibility.py vectors-open-weight-art53

The regenerability gate proves that a corpus is what ITS generator writes. That is one
implementation agreeing with itself: a defect in the generator, or a rule it encodes that
the README does not state, is reproduced every time. A vector set is a unit of conformance
only when a second implementer, reading the published case table and file layout, writes
the same bytes. This gate runs that second implementer.

Each corpus with a second generator has one file, ``tools/independent-mint/<corpus>.py``.
Before it runs, it is copied into an empty directory together with the helper modules in
``tools/independent-mint/_*.py`` and nothing else, and it is started with ``python -E -s -S -B``
and an empty environment: no environment paths, no user or site packages, no variable such as
``PWD`` or ``GITHUB_WORKSPACE`` that names the checkout. Its imports are also read from its
source and refused when they name anything else, which states the reason before the run
would fail on it.

An empty directory and a clean path do not stop a minter that opens the committed corpus by
an absolute path and copies it: such a minter writes the same bytes and proves nothing. So
the minter runs under a standard-library audit hook (``sys.addaudithook``, which cannot be
removed once added) that refuses, and ends the run on:

* opening a file outside the minter's own directory, the output directory and the
  interpreter's standard library, and writing anywhere but the output directory;
* a relative path, whose target the hook cannot pin;
* listing a directory outside those roots;
* making a symbolic or hard link, starting a process, opening a socket, loading ``ctypes``,
  walking the garbage collector's objects, and rewriting a function's attributes.

The written files are read without following links, and a link among them is refused. The
hook is a guard against a minter that copies its answer, not a sandbox against an attacker;
it closes every route a copying minter needs in the standard library.

Sharing no code is also read from the source. A minter or helper that is a symbolic link is
refused (copying it would carry the generator's file in). Every function of the minter and its
helpers with at least ``MIN_SHARED_STATEMENTS`` statements is compared, with names, argument
names, annotations and docstrings erased, against every function of the corpus's own Python
files and of the ``agent_evidence_vectors`` modules they import; a match is named and FAILS,
because a pasted function reproduces the generator's defects as faithfully as an import does.

It must write exactly the files the corpus holds as minted output: ``MANIFEST.json`` and
every file of every case directory the manifest lists. A file it does not write, a file it
writes that the corpus lacks, and a byte that differs are each named.

The census line counts the corpora with a second generator against every corpus with a
manifest. It is a report and not a refusal: corpora arrive in parallel pull requests, and a
census that refused would fail each of them for a file no one of them owns. The burn-down is
the board row the README names.

Exit 0 when every minter reproduces its corpus; 1 when one does not; 2 when a minter is
named that does not exist.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MINTERS = ROOT / "tools" / "independent-mint"
CORPORA = ROOT / "corpora"
PACKAGE = ROOT / "packaging" / "agent_evidence_vectors"
MIN_SHARED_STATEMENTS = 4


def minters(directory: Path = MINTERS) -> dict[str, Path]:
    """Return every second generator, keyed by the corpus id its file is named for."""
    return {
        path.stem: path for path in sorted(directory.glob("*.py")) if not path.name.startswith("_")
    }


def helpers(directory: Path = MINTERS) -> list[Path]:
    """Return the helper modules a minter may import."""
    return sorted(directory.glob("_*.py"))


def foreign_imports(source: str, allowed_local: set[str]) -> list[str]:
    """Return each imported top-level module that is neither standard library nor a helper."""
    tree = ast.parse(source)
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names.append("." * node.level + (node.module or ""))
            elif node.module:
                names.append(node.module.split(".")[0])
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    return sorted({name for name in names if name not in stdlib and name not in allowed_local})


class _Erase(ast.NodeTransformer):
    """Erase what a paste can rename: names, argument names, annotations, docstrings."""

    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id="_", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg, node.annotation = "_", None
        return node

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.name, node.returns, node.decorator_list = "_", None, []
        first = node.body[0] if node.body else None
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
        return node

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function


def function_shapes(source: str, minimum: int = MIN_SHARED_STATEMENTS) -> dict[str, str]:
    """Return each function of ``source`` with at least ``minimum`` statements, by erased shape."""
    shapes: dict[str, str] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            size = sum(isinstance(inner, ast.stmt) for inner in ast.walk(node)) - 1
            if size >= minimum:
                shapes.setdefault(ast.dump(_Erase().visit(copy.deepcopy(node))), node.name)
    return shapes


def first_sources(corpus: Path, package: Path = PACKAGE) -> list[Path]:
    """Return the corpus's own Python files and the package modules they import."""
    own = sorted(path for path in corpus.glob("*.py") if path.is_file())
    found = list(own)
    for path in own:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module == "agent_evidence_vectors":
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                head, _, rest = node.module.partition(".")
                modules = [rest.split(".")[0]] if head == "agent_evidence_vectors" and rest else []
            for name in modules:
                for candidate in (package / f"{name}.py", package / name / "__init__.py"):
                    if candidate.is_file() and candidate not in found:
                        found.append(candidate)
    return found


def shared_code(sources: Sequence[Path], corpus: Path, package: Path = PACKAGE) -> list[str]:
    """Return each function of ``sources`` whose erased shape is one of the first generator's."""
    theirs: dict[str, tuple[str, Path]] = {}
    for path in first_sources(corpus, package):
        for shape, name in function_shapes(path.read_text(encoding="utf-8")).items():
            theirs.setdefault(shape, (name, path))
    found = []
    for path in sources:
        for shape, name in function_shapes(path.read_text(encoding="utf-8")).items():
            if shape in theirs:
                other, where = theirs[shape]
                found.append(f"{path.name} {name}() has the body of {where.name} {other}()")
    return found


def minted_files(corpus: Path) -> dict[str, bytes]:
    """Return the corpus's minted output: MANIFEST.json and every file of every listed case."""
    manifest_path = corpus / "MANIFEST.json"
    files = {"MANIFEST.json": manifest_path.read_bytes()}
    manifest = json.loads(files["MANIFEST.json"])
    for entry in manifest["vectors"]:
        directory = corpus / entry["path"]
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                files[path.relative_to(corpus).as_posix()] = path.read_bytes()
    return files


def written_files(out: Path) -> tuple[dict[str, bytes], list[str]]:
    """Return every regular file under ``out`` by relative path, and each link found there."""
    files: dict[str, bytes] = {}
    links: list[str] = []
    for path in sorted(out.rglob("*")):
        name = path.relative_to(out).as_posix()
        if path.is_symlink():
            links.append(name)
        elif path.is_file():
            files[name] = path.read_bytes()
    return files, links


# Run inside the minter's interpreter before the minter: install the audit hook, then run it.
# argv: -c BOOT <source dir> <minter file> <out dir>. Every name the hook needs is bound as a
# default argument, so nothing it reads can be reached through a module global.
BOOT = r"""
import os, sys
_source, _minter, _out = (os.path.realpath(p) for p in sys.argv[1:4])
_read_roots = tuple(
    os.path.realpath(p) for p in [_source, _out, *sys.path] if p and os.path.isabs(p)
)
_write_roots = (_out,)
_W = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
_BLOCKED = (
    "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork",
    "os.forkpty", "os.startfile", "pty.spawn", "socket.", "ctypes.", "os.symlink", "os.link",
    "gc.get_", "sys.remote_exec", "_posixsubprocess",
)
_ONE_PATH = {
    "os.listdir": False, "os.scandir": False, "os.mkdir": True, "os.remove": True,
    "os.rmdir": True, "os.truncate": True, "os.chmod": True, "os.chown": True,
    "os.utime": True, "os.chflags": True, "os.setxattr": True, "os.removexattr": True,
}
_TWO_PATHS = ("os.rename", "os.replace")


def _hook(event, args, _rp=os.path.realpath, _abs=os.path.isabs, _sep=os.sep,
          _fs=os.fspath, _rr=_read_roots, _wr=_write_roots, _w=_W, _blocked=_BLOCKED,
          _one=_ONE_PATH, _two=_TWO_PATHS, _err=PermissionError, _str=str, _bytes=bytes,
          _int=int, _type=type, _fn=type(lambda: None), _dec=os.fsdecode):
    def inside(path, roots):
        if _type(path) is _int:
            return True  # an open descriptor: its path was checked when it was opened
        path = _fs(path)
        if _type(path) is _bytes:
            path = _dec(path)
        if not _abs(path):
            raise _err(f"independent-mint: relative path refused: {path!r}")
        real = _rp(path)
        return any(real == root or real.startswith(root + _sep) for root in roots)

    if event.startswith(_blocked):
        raise _err(f"independent-mint: {event} refused")
    if event == "import" and args[0] in ("ctypes", "_ctypes", "_posixsubprocess"):
        raise _err(f"independent-mint: import {args[0]} refused")
    if event == "object.__setattr__" and _type(args[0]) is _fn:
        raise _err("independent-mint: rewriting a function refused")
    if event == "open":
        path, mode, flags = args
        if path is None:
            return
        writes = (mode is not None and any(c in _str(mode) for c in "wax+")) or (
            mode is None and _int(flags or 0) & _w
        )
        if not inside(path, _wr if writes else _rr):
            raise _err(f"independent-mint: {'writing' if writes else 'reading'} {path!r} refused")
    elif event in _one:
        path = args[0]
        if path is None:
            return
        if not inside(path, _wr if _one[event] else _rr):
            raise _err(f"independent-mint: {event} {path!r} refused")
    elif event in _two:
        if not (inside(args[0], _wr) and inside(args[1], _wr)):
            raise _err(f"independent-mint: {event} outside the output refused")


sys.argv = [_minter, _out]
sys.path[:] = [_source, *(p for p in sys.path if p and os.path.isabs(p))]
import runpy
sys.addaudithook(_hook)
del _hook
runpy.run_path(_minter, run_name="__main__")
"""


def check_minter(
    corpus_id: str, minter: Path, corpora: Path = CORPORA, package: Path = PACKAGE
) -> list[str]:
    """Run one minter in isolation and return each difference from the committed corpus."""
    helper_paths = helpers(minter.parent)
    links = [path.name for path in [minter, *helper_paths] if path.is_symlink()]
    if links:
        return [
            f"{corpus_id}: {name} is a link; a minter and its helpers are files" for name in links
        ]
    local = {path.stem for path in helper_paths}
    foreign = foreign_imports(minter.read_text(encoding="utf-8"), local)
    for helper in helper_paths:
        foreign += foreign_imports(helper.read_text(encoding="utf-8"), local)
    if foreign:
        return [
            f"{corpus_id}: imports {', '.join(sorted(set(foreign)))}; a minter may import the "
            "standard library and tools/independent-mint/_*.py only"
        ]
    corpus = corpora / corpus_id
    if not (corpus / "MANIFEST.json").is_file():
        return [f"{corpus_id}: no corpora/{corpus_id}/MANIFEST.json to compare with"]
    pasted = shared_code([minter, *helper_paths], corpus, package)
    if pasted:
        return [f"{corpus_id}: shares code with the first generator: {line}" for line in pasted]
    with tempfile.TemporaryDirectory(prefix="independent-mint-") as scratch:
        source = Path(scratch) / "src"
        out = Path(scratch) / "out"
        source.mkdir()
        out.mkdir()
        for path in [*helper_paths, minter]:
            shutil.copy2(path, source / path.name)
        command = [sys.executable, "-E", "-s", "-S", "-B", "-c", BOOT]
        command += [str(source), str(source / minter.name), str(out)]
        try:
            run = subprocess.run(
                command,
                cwd=source,
                env={},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            return [f"{corpus_id}: the minter ran past 600 s and was stopped"]
        if run.returncode != 0:
            return [
                f"{corpus_id}: the minter exited {run.returncode}: {run.stderr.strip()[-2000:]}"
            ]
        written, links = written_files(out)
    if links:
        return [f"{corpus_id}: the minter wrote a link, not a file: {name}" for name in links]
    committed = minted_files(corpus)
    problems = [
        f"{corpus_id}: not written by the minter: {name}"
        for name in sorted(committed.keys() - written.keys())
    ]
    problems += [
        f"{corpus_id}: written by the minter, absent from the corpus: {name}"
        for name in sorted(written.keys() - committed.keys())
    ]
    problems += [
        f"{corpus_id}: bytes differ: {name}"
        for name in sorted(committed.keys() & written.keys())
        if committed[name] != written[name]
    ]
    return problems


def census(corpora: Path = CORPORA, minted: Sequence[str] = ()) -> tuple[int, int, list[str]]:
    """Return (corpora with a second generator, corpora with a manifest, the ids without one)."""
    every = sorted(path.parent.name for path in corpora.glob("*/MANIFEST.json"))
    missing = [name for name in every if name not in set(minted)]
    return len(every) - len(missing), len(every), missing


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("corpora", nargs="*", help="corpus ids (default: every minter)")
    parser.add_argument(
        "--list-missing", action="store_true", help="name every corpus with no second generator"
    )
    args = parser.parse_args(argv)
    available = minters()
    names = args.corpora or sorted(available)
    unknown = [name for name in names if name not in available]
    if unknown:
        print(f"no tools/independent-mint/<id>.py for: {', '.join(unknown)}", file=sys.stderr)
        return 2
    problems: list[str] = []
    for name in names:
        found = check_minter(name, available[name])
        print(f"{name}: {'reproduced byte for byte' if not found else f'{len(found)} differences'}")
        problems += found
    covered, total, missing = census(minted=sorted(available))
    print(f"census: {covered} of {total} corpora have a second generator")
    if args.list_missing:
        for name in missing:
            print(f"  no second generator: {name}")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
