#!/usr/bin/env python3
"""Unit tests for rules of the v0.1 report reader that the corpus alone cannot pin.

A corpus member proves that a report is judged the way its manifest entry says.
It cannot prove what the reader does with an input no member carries, and two
of the rules here are about exactly that: a tree shape outside the closed set
must be refused rather than hashed as some other shape, and each registered
shape must be hashed by the construction its name denotes. The corpus members
of the same rules live in vectors-w3c-report/; these are the checks below them.

Usage: python3 scripts/w3c-report-rules-test.py
Exit 0 when every case holds; 1 otherwise, naming each case that did not.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import w3creport  # noqa: E402

CHECKS: list[dict[str, Any]] = [
    {"check": "c-pass", "state": "pass"},
    {"check": "c-pass-2", "state": "pass"},
    {"check": "c-pass-3", "state": "pass"},
]


def rfc9162_mth(entries: list[bytes]) -> bytes:
    """The Merkle Tree Hash of RFC 9162 section 2.1.1, written from the RFC text.

    Deliberately not the reader's own function: a test that compared the reader
    with itself would pass whatever the reader computed.
    """
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k * 2 < len(entries):
        k *= 2
    left, right = rfc9162_mth(entries[:k]), rfc9162_mth(entries[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def test_unregistered_shape_is_refused() -> None:
    """A shape outside the closed set raises; it is never hashed as another shape."""
    for shape in ("RFC 9162 SHA-256", "rfc9162", "", "FLAT"):
        try:
            w3creport.check_set_root(CHECKS, shape)
        except w3creport.UnregisteredShape:
            continue
        raise AssertionError(f"check_set_root hashed the unregistered shape {shape!r}")


def test_every_registered_shape_has_its_own_root() -> None:
    """The registry and the dispatch are one table, so no member falls through."""
    for shape in w3creport.TREE_SHAPES:
        w3creport.check_set_root(CHECKS, shape)


def test_rfc9162_sha256_is_the_rfc_9162_tree() -> None:
    """RFC9162_SHA256 (RFC 9942 section 5.1) hashes by RFC 9162 section 2.1.1."""
    if "RFC9162_SHA256" not in w3creport.TREE_SHAPES:
        raise AssertionError("RFC9162_SHA256 is not in the closed set")
    leaves = [w3creport.compact(check) for check in CHECKS]
    expected = rfc9162_mth(leaves).hex()
    got = w3creport.check_set_root(CHECKS, "RFC9162_SHA256")
    if got != expected:
        raise AssertionError(f"RFC9162_SHA256 root {got} is not the RFC 9162 tree {expected}")
    if got == w3creport.flat_root(leaves):
        raise AssertionError("RFC9162_SHA256 hashed as the flat shape")


def run(cases: list[Callable[[], None]]) -> int:
    failures = 0
    for case in cases:
        try:
            case()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {case.__name__}: {exc}")
        else:
            print(f"ok   {case.__name__}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run([
        test_unregistered_shape_is_refused,
        test_every_registered_shape_has_its_own_root,
        test_rfc9162_sha256_is_the_rfc_9162_tree,
    ]))
