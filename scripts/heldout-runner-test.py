#!/usr/bin/env python3
"""Tests for packaging/agent_evidence_vectors/heldout.py.

The runner's own self-test proves its controls are refused. These cases pin the
pieces the self-test leans on, each by breaking it and requiring the refusal:
a renaming that loses equality would turn a replay member into a clean one, a
short seed is a searchable one, a sealed member whose name is not its digest is
a member someone edited, and a run that scored nothing must not exit 0.

Usage: python3 scripts/heldout-runner-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packaging"))

from agent_evidence_vectors import heldout  # noqa: E402

SEED = b"a test seed that is long enough to be accepted by the runner"
CASES: list[tuple[str, Callable[[], None]]] = []


def case(fn: Callable[[], None]) -> Callable[[], None]:
    CASES.append((fn.__name__, fn))
    return fn


@case
def renaming_keeps_equality_and_changes_spelling() -> None:
    suite = heldout.load_suite("acs-core")
    question: dict[str, Any] = {
        "first": {
            "request_id": "11111111-1111-4111-8111-111111111111",
            "metadata": {"session_id": "s-1"},
        },
        "second": {
            "request_id": "11111111-1111-4111-8111-111111111111",
            "metadata": {"session_id": "s-1"},
        },
        "cites": ["s-1"],
        "method": "hooks/toolCallRequest",
    }
    out = heldout.rekey(question, SEED, "v0", suite)
    assert out["first"]["request_id"] == out["second"]["request_id"], (
        "a duplicate stopped being a duplicate"
    )
    assert out["first"]["request_id"] != question["first"]["request_id"], (
        "the request_id kept its spelling"
    )
    assert out["cites"] == [out["first"]["metadata"]["session_id"]], (
        "a citation of the session lost its target"
    )
    assert out["method"] == "hooks/toolCallRequest", "a meaningful field was renamed"
    rid = out["first"]["request_id"]
    assert len(rid) == 36 and rid[14] == "4" and rid[19] in "89ab", f"{rid} is not UUIDv4-shaped"


@case
def every_family_is_sealed_and_names_are_digests() -> None:
    suite = heldout.load_suite("acs-core")
    public, _, _ = heldout.load_public(suite)
    sealed = heldout.seal(suite, SEED, 2)
    families = {m["family"] for m in public}
    got = {item["document"]["family"] for item in sealed["members"]}
    assert got == families, f"families without a sealed member: {sorted(families - got)}"
    public_ids = {m["id"] for m in public}
    for item in sealed["members"]:
        document = item["document"]
        assert document["id"] == heldout.identify(document, suite)
        assert document["id"] not in public_ids, (
            "a sealed member is byte-identical to a published one"
        )


@case
def an_edited_sealed_member_is_refused() -> None:
    suite = heldout.load_suite("acs-core")
    sealed = heldout.seal(suite, SEED, 1)
    expected = sealed["members"][0]["document"]["expected"]
    expected["verdict"] = "deny" if expected["verdict"] != "deny" else "allow"
    with tempfile.TemporaryDirectory() as tmp:
        path = heldout.write_sealed(sealed, tmp)
        try:
            heldout.load_sealed(path, suite)
        except heldout.RunnerError:
            return
    raise AssertionError("a sealed member whose bytes no longer match its name was loaded")


@case
def a_short_seed_is_refused() -> None:
    with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
        handle.write(b"short")
    try:
        heldout.read_seed(handle.name)
    except heldout.RunnerError:
        return
    finally:
        os.unlink(handle.name)
    raise AssertionError("a five-byte seed was accepted")


@case
def a_run_that_scored_nothing_does_not_exit_zero() -> None:
    empty = {"totals": {"public": {"of": 0}, "sealed": {"of": 0}}, "rows": []}
    assert heldout.status(empty) == 2


@case
def the_command_line_refuses_a_missing_adapter() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "agent_evidence_vectors.heldout", "run", "--suite", "acs-core"],
        cwd=os.path.join(ROOT, "packaging"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, f"exit {proc.returncode}: {proc.stderr}"


@case
def the_shipped_controls_are_refused() -> None:
    assert heldout.self_test("acs-core") == 0


@case
def commit_and_reveal_round_trip_on_the_command_line() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        seed = os.path.join(tmp, "seed")
        with open(seed, "wb") as handle:
            handle.write(SEED)
        env = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "packaging")}
        base = [sys.executable, "-m", "agent_evidence_vectors.heldout"]
        sealed_dir = os.path.join(tmp, "sealed")
        subprocess.run(
            base + ["seal", "--seed-file", seed, "--out", sealed_dir],
            check=True,
            env=env,
            capture_output=True,
        )
        sealed_path = os.path.join(sealed_dir, "SEALED.json")
        committed = subprocess.run(
            base + ["commit", "--seed-file", seed],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )
        assert committed.stdout.strip() == json.load(open(sealed_path))["commitment"]
        ok = subprocess.run(
            base + ["reveal", "--seed-file", seed, "--sealed", sealed_path],
            env=env,
            capture_output=True,
        )
        assert ok.returncode == 0, ok.stderr
        with open(seed, "ab") as handle:
            handle.write(b"!")
        bad = subprocess.run(
            base + ["reveal", "--seed-file", seed, "--sealed", sealed_path],
            env=env,
            capture_output=True,
        )
        assert bad.returncode == 1, "a different seed opened the commitment"


def main() -> int:
    failed = 0
    for name, fn in CASES:
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {name}: {exc}")
    print(f"{len(CASES)} cases, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
