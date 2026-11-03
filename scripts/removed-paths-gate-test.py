#!/usr/bin/env python3
"""The removed-paths gate refuses a returned file and passes the current tree."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("removed_paths_gate", HERE / "removed-paths-gate.py")
if spec is None or spec.loader is None:
    raise SystemExit("cannot load scripts/removed-paths-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def check() -> None:
    assert gate.entries("# c\n a/ \n\nb.py # why\n") == ["a/", "b.py"]
    found = gate.matches(["a/x.py", "ab/x.py", "b.py", "c/b.py"], ["a/", "b.py"])
    assert found == [("a/x.py", "a/"), ("b.py", "b.py")]
    assert gate.main(["--root", str(HERE.parent)]) == 0
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "release").mkdir()
        (root / "release/removed-paths.txt").write_text("gone/\n")
        (root / "gone").mkdir()
        (root / "gone/x.py").write_text("x = 1\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        assert gate.main(["--root", str(root)]) == 0
        tracked = ["gone/x.py", "release/removed-paths.txt"]
        subprocess.run(["git", "add", *tracked], cwd=root, check=True)
        assert gate.main(["--root", str(root)]) == 1
        (root / "release/removed-paths.txt").write_text("# nothing\n")
        assert gate.main(["--root", str(root)]) == 2


if __name__ == "__main__":
    check()
    print("removed-paths gate test passed")
    sys.exit(0)
