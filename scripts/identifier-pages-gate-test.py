#!/usr/bin/env python3
"""The identifier gate passes on this tree and refuses an identifier with no page.

The refusal is proved on a copy of the tree: a URI is removed from the
registry, a schema identifier is planted with no schema behind it, and a new
URI is planted only inside a base64 payload, where a text search cannot see
it, also in a document nested too deep to parse. Each must fail, and the tree
as committed must pass. Set IDENTIFIER_GATE_ALSO to a checkout of the public
probity repository, which the gate scans with this one.

    python3 scripts/identifier-pages-gate-test.py
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "identifier-pages-gate.py"
HOST = "https://probityai.github.io/agent-evidence-vectors"
#: Nesting a vector may legitimately carry. 3000 levels parses but outruns a recursive walk of the
#: parsed value; 20000 is past what the interpreter parses at all. The public repository holds a
#: depth-bomb card of the second kind, which crashed the gate with an unhandled RecursionError.
DEEP_DEPTHS = ((3000, "only-in-a-3000-deep-payload"), (20000, "only-in-a-20000-deep-payload"))


def gate(root: Path, *extra: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "identifier-pages-gate.py"), *extra],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _link_or_copy(src: str, dst: str) -> str:
    """Hard-link a file into the copy so the tree costs no disk; copy when linking is refused."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return dst


def rewrite(path: Path, text: str) -> None:
    """Replace a file in the copy without writing through a hard link to the real tree."""
    path.unlink()
    path.write_text(text, encoding="utf-8")


def stage(work: Path) -> Path:
    copy = work / "repo"
    # The copy gets a git repository of its own. Copying .git would copy a
    # linked worktree's pointer file, and `git add` in the copy would then write
    # into the index of the checkout under test. Files are hard-linked, not
    # copied: a runner holds the whole tree three times over otherwise.
    shutil.copytree(
        ROOT,
        copy,
        ignore=shutil.ignore_patterns(".git", ".venv", "node_modules", "_site", "probity-public"),
        copy_function=_link_or_copy,
    )
    subprocess.run(["git", "init", "-q", str(copy)], check=True, capture_output=True)
    return copy


def commit_all(repo: Path) -> None:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)


def main() -> int:
    failures = []
    also = os.environ.get("IDENTIFIER_GATE_ALSO")
    extra = ("--also", str(ROOT / also)) if also else ()
    code, out = gate(ROOT, *extra)
    if code != 0:
        failures.append(f"the committed tree fails the gate:\n{out}")
    else:
        print("PASS the committed tree resolves every identifier it names")

    with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
        repo = stage(Path(tmp))
        registry = repo / "spec" / "predicates" / "REGISTRY.md"
        text = registry.read_text(encoding="utf-8")
        start = text.index("### `predicate/v1/self-reported-record`")
        end = text.index("## Registered here")
        rewrite(registry, text[:start] + text[end:])
        commit_all(repo)
        code, out = gate(repo)
        if code != 1 or "predicate/v1/self-reported-record is named in" not in out:
            failures.append(
                f"an unregistered, referenced URI was not refused (exit {code}):\n{out}"
            )
        else:
            print("PASS control: a referenced URI missing from the registry is refused")

    with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
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

    for depth, name in DEEP_DEPTHS:
        with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
            repo = stage(Path(tmp))
            planted = f'{{"predicateType":"{HOST}/predicate/v9/{name}"}}'
            inner = json.dumps({"payload": base64.b64encode(planted.encode()).decode()})
            deep = '{"a":' * depth + inner + "}" * depth
            (repo / "docs" / "planted-deep.json").write_text(deep, encoding="utf-8")
            commit_all(repo)
            code, out = gate(repo)
            if code != 1 or f"predicate/v9/{name}" not in out or "Traceback" in out:
                failures.append(
                    f"a URI in a payload {depth} levels deep was not found and refused "
                    f"cleanly (exit {code}):\n{out}"
                )
            else:
                print(f"PASS control: a payload {depth} levels deep is found and refused")

    with tempfile.TemporaryDirectory(dir=ROOT.parent) as tmp:
        repo = stage(Path(tmp))
        (repo / "docs" / "planted-schema.md").write_text(
            f"A record names {HOST}/schema/ghost-schema/v1 and no schema backs it.\n",
            encoding="utf-8",
        )
        commit_all(repo)
        code, out = gate(repo)
        if code != 1 or "schema/ghost-schema/v1" not in out:
            failures.append(
                f"a schema identifier with no schema was not refused (exit {code}):\n{out}"
            )
        else:
            print("PASS control: a schema identifier no schema backs is refused")

    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
