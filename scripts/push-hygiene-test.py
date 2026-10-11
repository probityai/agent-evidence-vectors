#!/usr/bin/env python3
"""Suite for push-hygiene.py, against scratch repositories.

The size limit is lowered through main's limit argument so a test does not
write 100 MiB; the comparison under test is the same one production runs.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "push_hygiene", Path(__file__).resolve().parent / "push-hygiene.py"
)
assert _SPEC is not None and _SPEC.loader is not None
lph = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lph)


def sh(cwd: Path, *args: str) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


@contextlib.contextmanager
def repo() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        env = {"GIT_CONFIG_GLOBAL": str(root / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1"}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        cwd = os.getcwd()
        try:
            work = root / "work"
            work.mkdir()
            sh(work, "git", "init", "-q", "-b", "main")
            sh(work, "git", "config", "user.email", "t@test.invalid")
            sh(work, "git", "config", "user.name", "t")
            sh(work, "git", "config", "commit.gpgsign", "false")
            (work / "a.txt").write_text("small\n")
            sh(work, "git", "add", ".")
            sh(work, "git", "commit", "-q", "-m", "base")
            sh(work, "git", "update-ref", "refs/remotes/origin/main", "HEAD")
            os.chdir(work)
            yield work
        finally:
            os.chdir(cwd)
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def run(limit: int = 64) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = lph.main([], limit=limit)
    return code, buf.getvalue()


def commit(work: Path, name: str, data: str, message: str) -> None:
    (work / name).write_text(data)
    sh(work, "git", "add", "-A")
    sh(work, "git", "commit", "-q", "-m", message)


def test_clean_tree_passes_and_says_what_it_covered() -> None:
    with repo():
        code, out = run()
        assert code == 0, out
        assert "the commits not on origin/main" in out, out


def test_a_large_blob_in_the_tree_is_refused() -> None:
    with repo() as work:
        commit(work, "big.bin", "x" * 100, "add big")
        code, out = run()
        assert code == 1, out
        assert "big.bin" in out, out


def test_a_large_blob_added_and_deleted_inside_the_range_is_refused() -> None:
    with repo() as work:
        commit(work, "big.bin", "x" * 100, "add big")
        (work / "big.bin").unlink()
        sh(work, "git", "add", "-A")
        sh(work, "git", "commit", "-q", "-m", "drop big")
        code, out = run()
        assert code == 1, out
        assert "big.bin" in out, out


def test_a_blob_just_under_the_limit_passes() -> None:
    with repo() as work:
        commit(work, "edge.bin", "x" * 63, "edge")
        code, out = run()
        assert code == 0, out


def test_no_origin_main_says_the_range_was_not_checked() -> None:
    with repo() as work:
        sh(work, "git", "update-ref", "-d", "refs/remotes/origin/main")
        code, out = run()
        assert code == 0, out
        assert "was NOT checked" in out, out


def test_a_conflict_marker_is_refused() -> None:
    with repo() as work:
        commit(work, "m.txt", "ok\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> b\n", "conflict")
        code, out = run()
        assert code == 1, out
        assert "conflict marker" in out, out


def test_a_named_revision_is_checked_not_the_working_head() -> None:
    with repo() as work:
        commit(work, "big.bin", "x" * 100, "add big")
        bad = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True, check=True
        ).stdout.strip()
        sh(work, "git", "reset", "-q", "--hard", "HEAD~1")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = lph.main(["--rev", bad], limit=64)
        assert code == 1, buf.getvalue()


def test_outside_a_repository_the_check_refuses_rather_than_passing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            code, out = run()
        finally:
            os.chdir(cwd)
        assert code == 2, out


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - a test that ERRORS must not abort the suite
            failures += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        else:
            print(f"ok   {name}")
    print(f"\n{'FAILED' if failures else 'passed'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
