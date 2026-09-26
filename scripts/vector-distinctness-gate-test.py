#!/usr/bin/env python3
"""Tests for scripts/vector-distinctness-gate.py.

Every case but two asserts a REFUSAL, and that is the point. The gate this file
tests ran green for the life of the AI Agent Action corpus while never opening
it, and a byte-identical accept pair sat in that corpus the whole time. A gate
evidenced only by a green run says nothing about what it is quantified over, and
this repository has enough documented instances of that shape to stop accepting
one more.

Each case works on a STAGED COPY of the tracked corpus, breaks it in exactly one
way, and asks the gate. Fixtures would prove the comparison functions and nothing
about whether the gate is pointed at the real corpora, which is precisely the
property that failed.

Three of the cases are worth naming before they are read.

`second corpus is read at all` reintroduces the original defect: it puts a
collision in `vectors-ai-agent-action` and nowhere else. A gate scoped back to
one manifest passes that case while every other case here still holds, so it is
the only one that can catch the narrowing returning.

`two undecodable vectors are not a collision` is a refusal-shaped case that must
NOT refuse. Two files that both fail to parse hold no common decoded value, and a
gate that grouped them would be reporting a property of its own loop. The same
trap is pinned for record payloads in `aee/duplicate_masking_test.go`, and it is
the one direction where over-firing is as bad as under-firing, because it would
make the corpus's undecodable vectors unshippable.

`a repaired collision retires its declaration` asserts the ledger cannot outlive
its subject. It fixes the open collision the ledger declares and requires the
gate to refuse the now-stale row. Without it the ledger would be an ordinary
allowance list, where a row added once quiets a pair forever including after
somebody replaces one side of it.

Usage: python3 scripts/vector-distinctness-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "vector-distinctness-gate.py"
LEDGER_REL = "docs/VECTOR-COLLISIONS.json"



def _gate_corpora() -> tuple[str, ...]:
    """The corpus directories the gate itself reads, taken from the gate."""
    spec = importlib.util.spec_from_file_location("vector_distinctness_gate", GATE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"test setup: cannot load {GATE}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return tuple(module.CORPORA)


# What the gate reads, and therefore what a copy of the tree has to carry. Named
# rather than copied wholesale: staging eight thousand files to ask a question
# about a few directories is slow enough that the cases stop being run. The
# corpus list is READ FROM THE GATE rather than restated here: when a corpus was
# registered with the gate and this list was not updated, every case failed on
# a manifest the staged tree did not carry, which is a fixture defect reading as
# a gate refusal.
STAGED = (*(f"{corpus}/" for corpus in _gate_corpora()), LEDGER_REL)

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    copied = 0
    for rel in listed.stdout.split():
        if not any(rel == p or rel.startswith(p) for p in STAGED):
            continue
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied += 1
    if copied < 2:
        raise SystemExit(
            f"test setup: staged {copied} file(s), so every case below would be "
            "asking the gate about an empty tree. Fix the case, never the gate."
        )


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def manifest(root: Path, corpus: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / corpus / "MANIFEST.json").read_text(encoding="utf-8")
    )
    return loaded


def path_of(root: Path, corpus: str, vector_id: str) -> Path:
    for entry in manifest(root, corpus)["vectors"]:
        if entry["id"] == vector_id:
            return root / corpus / str(entry["file"])
    raise SystemExit(
        f"test setup: {corpus} declares no vector {vector_id!r}, so this case would "
        "assert nothing. Fix the case, never the gate."
    )


def first_of(root: Path, corpus: str, kind: str, skip: tuple[str, ...] = ()) -> str:
    for entry in manifest(root, corpus)["vectors"]:
        if entry["kind"] == kind and entry["id"] not in skip:
            return str(entry["id"])
    raise SystemExit(
        f"test setup: {corpus} declares no {kind} vector outside {skip}. "
        "Fix the case, never the gate."
    )


def ledger(root: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (root / LEDGER_REL).read_text(encoding="utf-8")
    )
    return loaded


def write_ledger(root: Path, data: dict[str, Any]) -> None:
    (root / LEDGER_REL).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --- mutations -------------------------------------------------------------


def copy_accept_over_reject(root: Path) -> None:
    """The original defect: one statement, two identifiers, byte for byte."""
    accept = path_of(root, "vectors", first_of(root, "vectors", "accept"))
    reject = path_of(root, "vectors", first_of(root, "vectors", "reject"))
    shutil.copyfile(accept, reject)


def duplicate_member_onto_reject(root: Path) -> None:
    """A reject that decodes to an accept: different bytes, one decoded value.

    This is the shape a digest comparison cannot see. The file gains a repeated
    top-level member, which every lenient decoder resolves last-wins back to the
    accept statement, so the two carry different labels and one decoded value.
    """
    accept_id = first_of(root, "vectors", "accept")
    reject_id = first_of(
        root, "vectors", "reject", skip=("v5155dde01a4538fd",)
    )
    text = path_of(root, "vectors", accept_id).read_text(encoding="utf-8")
    lines = text.split("\n")
    lines.insert(1, '  "_type": "https://example.invalid/overwritten-by-the-next-one",')
    path_of(root, "vectors", reject_id).write_text("\n".join(lines), encoding="utf-8")


def two_rejects_decode_alike(root: Path) -> None:
    """One label, two identifiers, one decoded statement, and no declaration."""
    a = first_of(root, "vectors", "reject", skip=("v5155dde01a4538fd",))
    b = first_of(
        root, "vectors", "reject", skip=("v5155dde01a4538fd", a)
    )
    text = path_of(root, "vectors", a).read_text(encoding="utf-8")
    reflowed = json.dumps(json.loads(text), indent=6, sort_keys=True) + "\n"
    path_of(root, "vectors", b).write_text(reflowed, encoding="utf-8")


def collide_the_second_corpus(root: Path) -> None:
    """The narrowing, reintroduced. Only the AI Agent Action corpus is touched."""
    corpus = "vectors-ai-agent-action"
    accept = path_of(root, corpus, first_of(root, corpus, "accept"))
    reject = path_of(root, corpus, first_of(root, corpus, "reject"))
    shutil.copyfile(accept, reject)


def drop_a_declaration(root: Path) -> None:
    data = ledger(root)
    if not data["collisions"]:
        raise SystemExit("test setup: the ledger declares nothing to drop.")
    data["collisions"] = data["collisions"][1:]
    write_ledger(root, data)


def repair_a_declared_collision(root: Path) -> None:
    """Break a collision the ledger declares, and leave the declaration behind.

    Whichever collision is declared FIRST is the one repaired, rather than a
    named pair. An earlier version of this case named the pair that happened to
    be open at the time; that pair was then fixed for real, and the case went
    quietly vacuous -- it mutated a vector that collided with nothing, the gate
    correctly accepted, and a case asserting the ratchet turns downward was
    asserting nothing. Reading the pair out of the ledger means the case follows
    the ledger instead of a memory of it.
    """
    declared = ledger(root)["collisions"]
    if not declared:
        raise SystemExit("test setup: the ledger declares no collision to repair.")
    entry = declared[0]
    target = path_of(root, str(entry["corpus"]), str(entry["ids"][0]))
    statement = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(statement, dict):
        raise SystemExit("test setup: the declared vector is not an object.")
    # A member no other vector carries: enough to move the decoded value, and so
    # to break the collision, whatever reading the collision was declared under.
    statement["_repairedByATestCase"] = True
    target.write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def blank_a_reason(root: Path) -> None:
    data = ledger(root)
    data["collisions"][0]["reason"] = "   "
    write_ledger(root, data)


def unknown_disposition(root: Path) -> None:
    data = ledger(root)
    data["collisions"][0]["disposition"] = "acknowledged"
    write_ledger(root, data)


def remove_the_ledger(root: Path) -> None:
    (root / LEDGER_REL).unlink()


def two_undecodable_rejects(root: Path) -> None:
    """Both files stop parsing, in different ways. Neither holds a value."""
    a = first_of(root, "vectors", "reject", skip=("v5155dde01a4538fd",))
    b = first_of(
        root, "vectors", "reject", skip=("v5155dde01a4538fd", a)
    )
    path_of(root, "vectors", a).write_bytes(b'{"a": \xc0\xaf}')
    path_of(root, "vectors", b).write_bytes(b'{"b": \xed\xa0\x80')


def reformat_a_reject(root: Path) -> None:
    """A vector reserialized with different whitespace and nothing else.

    The control for the decode reading: this file's bytes move, it decodes to
    exactly what it decoded to before, and it collides with nothing. A gate that
    refused here would be refusing every reformat rather than every collision.
    """
    target = path_of(
        root,
        "vectors",
        first_of(root, "vectors", "reject", skip=("v5155dde01a4538fd",)),
    )
    decoded = json.loads(target.read_text(encoding="utf-8"))
    target.write_text(json.dumps(decoded, indent=8, sort_keys=True) + "\n", encoding="utf-8")


REFUSALS: list[Case] = [
    (
        "an accept vector copied over a reject one",
        copy_accept_over_reject,
        ("byte-identical", "undeclared"),
    ),
    (
        "a reject vector that decodes to an accept one",
        duplicate_member_onto_reject,
        ("different labels", "undeclared"),
    ),
    (
        "two reject vectors that decode alike",
        two_rejects_decode_alike,
        ("same statement", "undeclared"),
    ),
    (
        "a collision in the second corpus only",
        collide_the_second_corpus,
        ("vectors-ai-agent-action", "undeclared"),
    ),
    (
        "a declared collision with its declaration removed",
        drop_a_declaration,
        ("undeclared",),
    ),
    (
        "a repaired collision retires its declaration",
        repair_a_declared_collision,
        ("stale declaration",),
    ),
    ("a declaration carrying no reason", blank_a_reason, ("declares no reason",)),
    (
        "a declaration carrying an unknown disposition",
        unknown_disposition,
        ("acknowledged",),
    ),
    ("no ledger at all", remove_the_ledger, ("is absent",)),
]

ACCEPTANCES: list[Case] = [
    ("the corpus as it stands", lambda root: None, ()),
    ("two undecodable vectors are not a collision", two_undecodable_rejects, ()),
    ("a reject vector reserialized and nothing else", reformat_a_reject, ()),
]


def check(group: str, cases: list[Case], want_refusal: bool, tmp: Path) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root)
        mutate(root)
        code, output = run(root)
        if want_refusal and code == 0:
            failures.append(f"{name}: the gate accepted it:\n{output}")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong thing sends the next "
                f"person to the wrong file.\n{output}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("refuse", REFUSALS, True, tmp))
        failures.extend(check("accept", ACCEPTANCES, False, tmp))
    total = len(REFUSALS) + len(ACCEPTANCES)
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS)} assert a refusal the gate "
        "makes and name the pair it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
