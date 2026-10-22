#!/usr/bin/env python3
"""The predicate URI gate passes on this tree and refuses an unregistered URI.

The refusal is proved on a copy of the tree: a URI is removed from the
registry, and separately a new URI is planted only inside a base64 payload,
where a text search cannot see it. Both must fail, and the tree as committed
must pass.

    python3 scripts/predicate-uri-gate-test.py
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "predicate-uri-gate.py"
HOST = "https://probityai.github.io/agent-evidence-vectors"


def gate(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def stage(work: Path) -> Path:
    copy = work / "repo"
    # The copy gets a git repository of its own. Copying .git would copy a
    # linked worktree's pointer file, and `git add` in the copy would then write
    # into the index of the checkout under test.
    shutil.copytree(
        ROOT, copy, ignore=shutil.ignore_patterns(".git", ".venv", "node_modules", "_site")
    )
    subprocess.run(["git", "init", "-q", str(copy)], check=True, capture_output=True)
    return copy


def commit_all(repo: Path) -> None:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)


def main() -> int:
    failures = []
    code, out = gate(ROOT)
    if code != 0:
        failures.append(f"the committed tree fails the gate:\n{out}")
    else:
        print("PASS the committed tree resolves every predicate URI it names")

    with tempfile.TemporaryDirectory() as tmp:
        repo = stage(Path(tmp))
        registry = repo / "spec" / "predicates" / "REGISTRY.md"
        text = registry.read_text(encoding="utf-8")
        start = text.index("### `predicate/v1/self-reported-record`")
        end = text.index("## Registered here")
        registry.write_text(text[:start] + text[end:], encoding="utf-8")
        commit_all(repo)
        code, out = gate(repo)
        if code != 1 or "predicate/v1/self-reported-record is named in" not in out:
            failures.append(
                f"an unregistered, referenced URI was not refused (exit {code}):\n{out}"
            )
        else:
            print("PASS control: a referenced URI missing from the registry is refused")

    with tempfile.TemporaryDirectory() as tmp:
        repo = stage(Path(tmp))
        planted = f'{{"predicateType":"{HOST}/predicate/v9/only-in-a-payload"}}'
        envelope = {"payload": base64.b64encode(planted.encode()).decode(), "signatures": []}
        (repo / "docs" / "planted-envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
        commit_all(repo)
        code, out = gate(repo)
        if code != 1 or "predicate/v9/only-in-a-payload" not in out:
            failures.append(f"a URI inside a base64 payload was not found (exit {code}):\n{out}")
        else:
            print("PASS control: a URI only inside a signed payload is found and refused")

    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
