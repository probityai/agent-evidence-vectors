"""The Go refund-connected reader is held to the Python reader on mutated runs.

Each mutation is a short list of byte edits to a retained run, kept as data. This file
builds the mutations (a token of every file changed in turn, files deleted and cut, the
lines of every stream dropped and doubled, and edits aimed at single rules), judges each
mutated run with the Python reader and keeps the verdicts in
``corpora/testdata/refundconnected-differential.json``. The Go test
``TestRefundConnectedAgreesWithPython`` applies the same edits and requires the same
verdicts, or the same stop where the Python reader raises an exception it does not catch.
Regenerate with:

    AEV_WRITE_REFUND_CONNECTED=1 uv run --extra dev pytest \\
        vectors-refund-connected/tests/test_differential.py
"""

from __future__ import annotations

import base64
import functools
import json
import os
import re
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import refundconnected as reader  # noqa: E402

FIXTURE = REPO / "corpora" / "testdata" / "refundconnected-differential.json"
RUNS = {
    "r1": ROOT / "source" / "j01-connected-20261028-r1",
    "r2": ROOT / "source" / "j01-connected-20261028-r2",
}
TOKEN = re.compile(rb'"(?:[^"\\]|\\.)*"|-?\d+|\btrue\b|\bfalse\b|\bnull\b')
Op = list[Any]
Files = dict[str, bytes]


def load(run: str) -> Files:
    base = RUNS[run]
    return {
        p.relative_to(base).as_posix(): p.read_bytes()
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }


BASE = {run: load(run) for run in RUNS}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def diff_ops(before: Files, after: Files) -> list[Op]:
    """The edits that turn one tree into the other: a splice, a write or a delete per file."""
    ops: list[Op] = []
    for rel in sorted(set(before) | set(after)):
        old, new = before.get(rel), after.get(rel)
        if new is None:
            ops.append(["d", rel])
        elif old is None:
            ops.append(["w", rel, b64(new)])
        elif old != new:
            head = 0
            while head < min(len(old), len(new)) and old[head] == new[head]:
                head += 1
            tail = 0
            while tail < min(len(old), len(new)) - head and old[-1 - tail] == new[-1 - tail]:
                tail += 1
            ops.append(["s", rel, head, len(old) - head - tail, b64(new[head : len(new) - tail])])
    return ops


def apply_ops(root: Path, ops: list[Op]) -> None:
    for op in ops:
        path = root / op[1]
        if op[0] == "d":
            path.unlink()
        elif op[0] == "w":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(op[2]))
        else:
            data = path.read_bytes()
            path.write_bytes(data[: op[2]] + base64.b64decode(op[4]) + data[op[2] + op[3] :])


def accept_well_formed(pub: bytes, message: bytes, sig: bytes) -> bool:
    """The signature check of the trusting mode: any signature of the right size is good."""
    return len(pub) == 32 and len(sig) == 64


def judge(root: Path) -> dict[str, Any] | None:
    """The verdicts the Python reader derives, or None where it raises an uncaught exception."""
    try:
        result = reader.judge_run(root)
    except Exception:  # noqa: BLE001 - an uncaught exception is the answer being recorded
        return None
    return {"ok": result["ok"], "cases": result["cases"], "run_checks": result["run_checks"]}


def tweak(token: bytes, which: int) -> bytes:
    if token.startswith(b'"'):
        inner = token[1:-1]
        if which % 2 == 0 or not inner:
            return b'""'
        last = inner[-1:]
        swap = {b"9": b"0", b"f": b"0", b"z": b"a", b"Z": b"A"}.get(last)
        if swap is None:
            swap = bytes([last[0] + 1]) if last.isalnum() else b"x"
        return b'"' + inner[:-1] + swap + b'"'
    if token in (b"true", b"false"):
        return b"false" if token == b"true" else b"true"
    if token == b"null":
        return b'"x"' if which % 2 == 0 else b"0"
    count = int(token)
    return [str(count + 1).encode(), b"-1", b'"' + token + b'"'][which % 3]


def token_edits(data: bytes, cap: int, phase: int) -> Iterator[tuple[int, bytes]]:
    found = list(TOKEN.finditer(data))
    if not found:
        return
    stride = max(1, len(found) // cap)
    for number, match in enumerate(found[phase % stride :: stride][:cap]):
        yield (
            match.start(),
            data[: match.start()] + tweak(match.group(), number + phase) + data[match.end() :],
        )


Mutation = tuple[str, str, Files]


def mutations(trusting: bool) -> Iterator[Mutation]:
    """The mutations of one mode. Where the signature check accepts any well-formed
    signature, only value edits are kept, since the rest do not reach a signature."""
    for run, cap, phase in (
        (("r2", 14, 2), ("r1", 4, 3)) if trusting else (("r2", 8, 0), ("r1", 3, 1))
    ):
        base = BASE[run]
        yield f"{run}-same", run, dict(base)
        for rel, data in base.items():
            if trusting:
                for at, new in token_edits(data, cap, phase):
                    yield f"{run}-token-{rel}@{at}", run, {**base, rel: new}
                continue
            yield f"{run}-delete-{rel}", run, {k: v for k, v in base.items() if k != rel}
            yield f"{run}-cut-{rel}", run, {**base, rel: data[: len(data) // 2]}
            for at, new in token_edits(data, cap, phase):
                yield f"{run}-token-{rel}@{at}", run, {**base, rel: new}
            if rel.endswith(".jsonl"):
                lines = data.splitlines(keepends=True)
                for index in range(len(lines)):
                    yield (
                        f"{run}-drop-{rel}#{index}",
                        run,
                        {**base, rel: b"".join(lines[:index] + lines[index + 1 :])},
                    )
                    yield (
                        f"{run}-double-{rel}#{index}",
                        run,
                        {**base, rel: b"".join(lines[: index + 1] + lines[index:])},
                    )
    if not trusting:
        yield from targeted()


def edit(files: Files, rel: str, old: bytes, new: bytes) -> Files:
    assert old in files[rel], (rel, old)
    return {**files, rel: files[rel].replace(old, new, 1)}


def targeted() -> Iterator[Mutation]:
    """Edits aimed at single rules, each one the shape the corpus tests already use."""
    base = BASE["r2"]
    yield (
        "t-amount-in-proposal",
        "r2",
        edit(
            base,
            "cases/j01/inputs/pic-proposal.json",
            b'"amount_minor": 4000',
            b'"amount_minor": 4001',
        ),
    )
    yield (
        "t-amount-in-record",
        "r2",
        edit(base, "admission/state.json", b'"amount_minor":4000', b'"amount_minor":4001'),
    )
    effects = base["executor/effects.jsonl"].splitlines()
    first, second = json.loads(effects[0]), json.loads(effects[1])
    swapped = effects[0].replace(first["operation_id"].encode(), second["operation_id"].encode())
    yield (
        "t-effect-other-operation",
        "r2",
        {**base, "executor/effects.jsonl": swapped + b"\n" + effects[1] + b"\n"},
    )
    yield (
        "t-second-effect-for-key",
        "r2",
        {
            **base,
            "executor/effects.jsonl": base["executor/effects.jsonl"]
            + effects[0].replace(b'"eff-1"', b'"eff-9"')
            + b"\n",
        },
    )
    yield (
        "t-resolution-as-handoff",
        "r2",
        {**base, "signer/j01.handoff.json": base["signer/n3.resolution.json"]},
    )
    observations = base["executor/observations.jsonl"].splitlines(keepends=True)
    yield "t-one-observation", "r2", {**base, "executor/observations.jsonl": observations[0]}
    yield (
        "t-no-operations-file",
        "r2",
        {k: v for k, v in base.items() if k != "executor/operations.json"},
    )
    yield "t-empty-operations-file", "r2", {**base, "executor/operations.json": b""}
    yield "t-operations-list", "r2", {**base, "executor/operations.json": b"[]"}
    yield "t-sim-list", "r2", {**base, "sim/sim.json": b"[]"}
    yield "t-sim-not-json", "r2", {**base, "sim/sim.json": b"{"}
    yield "t-state-list", "r2", {**base, "admission/state.json": b"[]"}
    yield "t-state-not-json", "r2", {**base, "admission/state.json": b"{"}
    yield (
        "t-consumed-list",
        "r2",
        {**base, "admission/state.json": b'{"consumed":[],"decisions":{}}'},
    )
    yield "t-consumed-int", "r2", {**base, "admission/state.json": b'{"consumed":1}'}
    yield (
        "t-dispatch-times-garbage",
        "r2",
        {**base, "executor/raw/dispatch-times.jsonl": b"1\n[]\n{}\nnot json\n"},
    )
    yield (
        "t-dispatch-times-key-list",
        "r2",
        {
            **base,
            "executor/raw/dispatch-times.jsonl": (
                b'{"attempt_id":[],"at":"2026-10-28T10:00:00.000Z"}\n'
            ),
        },
    )


def table(results: list[dict[str, Any] | None], checks: list[str]) -> tuple[list[str], list[Any]]:
    """Verdicts as indexes into one table, so a mutation costs a line of numbers."""
    verdicts: dict[str, int] = {}

    def index(text: str) -> int:
        return verdicts.setdefault(text, len(verdicts))

    packed: list[Any] = []
    for result in results:
        if result is None:
            packed.append(None)
            continue
        packed.append(
            {
                "ok": result["ok"],
                "c": {
                    name: [index(steps[s]) for s in reader.STEPS]
                    for name, steps in result["cases"].items()
                },
                "k": [index(result["run_checks"][name]) for name in checks],
            }
        )
    return list(verdicts), packed


def unpack(
    verdicts: list[str], packed: dict[str, Any] | None, checks: list[str]
) -> dict[str, Any] | None:
    if packed is None:
        return None
    return {
        "ok": packed["ok"],
        "cases": {
            n: dict(zip(reader.STEPS, (verdicts[i] for i in ix), strict=True))
            for n, ix in packed["c"].items()
        },
        "run_checks": dict(zip(checks, (verdicts[i] for i in packed["k"]), strict=True)),
    }


def build() -> dict[str, Any]:
    real = reader.ed_verify
    scratch = ROOT.parent / ".differential-scratch"
    names: list[str] = []
    runs: list[str] = []
    trust: list[bool] = []
    ops: list[list[Op]] = []
    results: list[dict[str, Any] | None] = []
    try:
        for trusting in (False, True):
            reader.ed_verify = accept_well_formed if trusting else functools.cache(real)
            for name, run, files in mutations(trusting):
                edits = diff_ops(BASE[run], files)
                shutil.rmtree(scratch, ignore_errors=True)
                shutil.copytree(RUNS[run], scratch)
                apply_ops(scratch, edits)
                names.append(name)
                runs.append(run)
                trust.append(trusting)
                ops.append(edits)
                results.append(judge(scratch))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        reader.ed_verify = real
    checks = list(next(r for r in results if r is not None)["run_checks"])
    assert all(list(r["run_checks"]) == checks for r in results if r is not None)
    verdicts, packed = table(results, checks)
    return {
        "steps": list(reader.STEPS),
        "checks": checks,
        "verdicts": verdicts,
        "mutations": [
            {"id": n, "run": r, "trusting": t, "ops": o, "want": p}
            for n, r, t, o, p in zip(names, runs, trust, ops, packed, strict=True)
        ],
    }


def test_the_golden_matches_the_python_reader(tmp_path: Path) -> None:
    if os.environ.get("AEV_WRITE_REFUND_CONNECTED"):
        FIXTURE.write_text(json.dumps(build(), separators=(",", ":")) + "\n", encoding="utf-8")
    real = reader.ed_verify
    cached = functools.cache(real)
    golden = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert golden["steps"] == list(reader.STEPS)
    assert len(golden["mutations"]) > 500
    seen_fault = False
    full = bool(
        os.environ.get("AEV_REFUND_CONNECTED_FULL") or os.environ.get("AEV_WRITE_REFUND_CONNECTED")
    )
    for number, entry in enumerate(golden["mutations"]):
        # The Go test replays every mutation; here one in four is enough to catch a golden
        # that has drifted from the reader, and every stop and every aimed edit is kept.
        if (
            not full
            and number % 4
            and entry["want"] is not None
            and not entry["id"].startswith("t-")
        ):
            continue
        target = tmp_path / "run"
        shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(RUNS[entry["run"]], target)
        apply_ops(target, entry["ops"])
        want = unpack(golden["verdicts"], entry["want"], golden["checks"])
        reader.ed_verify = accept_well_formed if entry["trusting"] else cached
        try:
            assert judge(target) == want, entry["id"]
        finally:
            reader.ed_verify = real
        seen_fault = seen_fault or want is None
    assert seen_fault
    assert any(entry["trusting"] for entry in golden["mutations"])


def test_the_edits_are_data_that_reproduce_the_mutation(tmp_path: Path) -> None:
    def check(before: Files, after: Files) -> bool:
        return _roundtrip(tmp_path, before, after)

    assert check(BASE["r2"], {**BASE["r2"], "executor/attempts.jsonl": b"x"})
    assert check(
        BASE["r2"], {k: v for k, v in BASE["r2"].items() if k != "executor/attempts.jsonl"}
    )
    assert check(BASE["r2"], {**BASE["r2"], "new/file.json": b"{}"})


def _roundtrip(tmp_path: Path, before: Files, after: Files) -> bool:
    target = tmp_path / "round"
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(RUNS["r2"], target)
    apply_ops(target, diff_ops(before, after))
    got = {
        p.relative_to(target).as_posix(): p.read_bytes()
        for p in sorted(target.rglob("*"))
        if p.is_file()
    }
    return got == after
