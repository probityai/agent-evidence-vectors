#!/usr/bin/env python3
"""The two readers of vectors-w3c-intake/ print the same bytes, intact and mutated.

``aee-verify vectors-w3c-intake`` judges the corpus through corpora/w3cintake.go
and ``python -m agent_evidence_vectors.w3cintake --judge vectors-w3c-intake``
through packaging/agent_evidence_vectors/w3cintake.py, whose judge this test
calls in process (the command line prints exactly ``render(judge(dir))``). Both state the 45
grounds of the intake criteria, and two statements of one set of rules drift
unless something holds them together. This holds them together.

A corpus that every reader judges clean says little about the cases where the
two would part, so most copies here are mutated, and every mutation reaches
every member at once: each copy removes one field of every member's record, or
replaces it with a value of another JSON type, so the checker's refusal set is
printed for all members and compared line by line. Further copies flip a byte
in each kind of file a member's root holds, and one flips a byte in a member
file. A reader that cannot be built fails the test; none is skipped.

Usage: python3 scripts/w3c-intake-parity-test.py
Exit 0 when every copy prints identically on both readers; 1 otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "vectors-w3c-intake"
REPLACEMENTS: tuple[Any, ...] = (None, "x", 7, [], {})


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def paths(value: Any, prefix: tuple[Any, ...] = (), depth: int = 0) -> list[tuple[Any, ...]]:
    """Every key path in a record down to depth three, the first list item included."""
    out: list[tuple[Any, ...]] = []
    if depth >= 3:
        return out
    if isinstance(value, dict):
        for key in sorted(value):
            out.append(prefix + (key,))
            out.extend(paths(value[key], prefix + (key,), depth + 1))
    elif isinstance(value, list) and value:
        out.append(prefix + (0,))
        out.extend(paths(value[0], prefix + (0,), depth + 1))
    return out


def apply(record: Any, path: tuple[Any, ...], replacement: Any, delete: bool) -> None:
    node = record
    for key in path[:-1]:
        if isinstance(key, int):
            if not isinstance(node, list) or len(node) <= key:
                return
        elif not isinstance(node, dict) or key not in node:
            return
        node = node[key]
    last = path[-1]
    if isinstance(last, int):
        if isinstance(node, list) and len(node) > last:
            if delete:
                node.pop(last)
            else:
                node[last] = replacement
    elif isinstance(node, dict) and last in node:
        if delete:
            node.pop(last)
        else:
            node[last] = replacement


def mutate_records(corpus: Path, path: tuple[Any, ...], replacement: Any, delete: bool) -> None:
    for member in sorted((corpus / "vectors").glob("*.json")):
        document = json.loads(member.read_text(encoding="utf-8"))
        apply(document["record"], path, replacement, delete)
        member.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def flip_tree_files(corpus: Path, name: str) -> None:
    """Flip the middle byte of every file of this name under every member root."""
    for target in sorted((corpus / "trees").glob(f"*/{name}")):
        body = bytearray(target.read_bytes())
        body[len(body) // 2] ^= 0x01
        target.write_bytes(bytes(body))


def flip_member_file(corpus: Path) -> None:
    first = sorted((corpus / "vectors").glob("*.json"))[0]
    body = bytearray(first.read_bytes())
    marker = b'"cites": "'
    body[body.index(marker) + len(marker)] ^= 0x01
    first.write_bytes(bytes(body))


def snapshot(corpus: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in corpus.rglob("*") if p.is_file()}


def restore(corpus: Path, pristine: dict[Path, bytes]) -> None:
    """Put back every file a mutation touched, without copying the corpus again."""
    for path, body in pristine.items():
        if path.read_bytes() != body:
            path.write_bytes(body)


def main() -> int:
    sys.path.insert(0, str(REPO / "packaging"))
    from agent_evidence_vectors import w3cintake

    scratch = Path(tempfile.mkdtemp(prefix="w3c-intake-parity-"))
    try:
        binary = scratch / "aee-verify"
        code, out = run(["go", "build", "-o", str(binary), "./cmd/aee-verify"], REPO)
        if code != 0:
            print(f"FAIL: aee-verify did not build:\n{out}")
            return 1
        copy = scratch / "copy"
        shutil.copytree(REPO / CORPUS, copy / CORPUS)
        corpus = copy / CORPUS
        pristine = snapshot(corpus)
        base = json.loads(
            next((REPO / CORPUS / "vectors").glob("*.json")).read_text(encoding="utf-8")
        )["record"]
        cases: list[tuple[str, Any]] = [("intact", None), ("member byte flipped", flip_member_file)]
        for name in ("suite/MANIFEST.json", "suite/cases/c2.json", "out/cases.json",
                     "out/summary.txt", "anchor/DIGESTS.txt", "checker/check.py",
                     "checker/deps.lock", "helpers/fetch.sh"):
            cases.append((f"tree byte flipped in {name}",
                          lambda c, n=name: flip_tree_files(c, n)))
        for path in paths(base):
            label = ".".join(str(p) for p in path)
            cases.append((f"delete {label}",
                          lambda c, p=path: mutate_records(c, p, None, True)))
            for replacement in REPLACEMENTS:
                cases.append((f"{label} := {json.dumps(replacement)}",
                              lambda c, p=path, r=replacement: mutate_records(c, p, r, False)))
        failures = 0
        cwd = os.getcwd()
        for label, mutate in cases:
            restore(corpus, pristine)
            if mutate is not None:
                mutate(corpus)
            go_code, go_out = run([str(binary), CORPUS], copy)
            os.chdir(copy)
            try:
                judged = w3cintake.judge(CORPUS)
            finally:
                os.chdir(cwd)
            py_code, py_out = (0 if judged.ok() else 1), w3cintake.render(judged, w3cintake.SUITE)
            if (go_code, go_out) != (py_code, py_out):
                failures += 1
                print(f"FAIL {label}: aee-verify exit {go_code}, python exit {py_code}")
                go_lines, py_lines = go_out.splitlines(), py_out.splitlines()
                for line in sorted(set(go_lines) ^ set(py_lines))[:6]:
                    side = "go" if line in go_lines else "py"
                    print(f"  {side}: {line}")
            elif label == "intact" and go_code != 0:
                failures += 1
                print(f"FAIL intact: the committed corpus is not clean:\n{go_out}")
        print(f"{len(cases) - failures} of {len(cases)} copies print identically on both readers")
        return 1 if failures else 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
