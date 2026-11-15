#!/usr/bin/env python3
"""The drift family in cases.json, held to the Python RFC 8785 reference.

``driftCases`` pin bytes a producer printed and presented as canonical. This
test checks, with ``a2ajcs`` (the Python canonicalizer in this package), that:

* ``scripts/gen-jcs-drift-vectors.py --check`` finds nothing to rewrite;
* the pinned canonical bytes are what ``a2ajcs`` prints for the case's value,
  and for the presented text parsed as a value (same value, different bytes);
* the presented bytes differ from the canonical bytes, and a byte-for-byte
  comparison of the presented bytes with the canonical form refuses them;
* ``json.dumps`` with its defaults, the printer the Python-sourced cases model,
  reproduces the presented bytes where the case says that is its source.

Usage: python3 scripts/jcs-drift-vectors-test.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import a2ajcs  # noqa: E402

CORPUS = json.loads((ROOT / "corpora" / "jcs-byte-vectors" / "cases.json").read_text("utf-8"))


class DriftFamily(unittest.TestCase):
    def test_generator_has_nothing_to_rewrite(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gen-jcs-drift-vectors.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_family_size_and_coverage(self) -> None:
        cases = CORPUS["driftCases"]
        self.assertEqual(len(cases), 18)
        self.assertEqual(
            {c["family"] for c in cases}, {"html-escape", "non-ascii-escape", "number-format"}
        )

    def test_every_case_agrees_with_the_python_reference(self) -> None:
        for case in CORPUS["driftCases"]:
            with self.subTest(case["id"]):
                pinned = bytes.fromhex(case["canonicalHex"])
                presented = case["presented"].encode("utf-8")
                self.assertNotEqual(presented, pinned)
                self.assertEqual(a2ajcs.canonicalize(a2ajcs.parse(case["input"])), pinned)
                self.assertEqual(a2ajcs.canonicalize(a2ajcs.parse(case["presented"])), pinned)

    def test_python_default_printer_reproduces_its_cases(self) -> None:
        checked = 0
        for case in CORPUS["driftCases"]:
            if case["source"] != "python-json-default":
                continue
            with self.subTest(case["id"]):
                value = json.loads(case["input"])
                printed = json.dumps(value, separators=(",", ":"))
                self.assertEqual(printed, case["presented"])
                checked += 1
        self.assertGreater(checked, 0)


def strict_refuses(raw: bytes) -> bool:
    """Whether a strict RFC 8259 / I-JSON reader built from the standard library refuses raw."""

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):
            raise ValueError("duplicate member")
        return dict(pairs)

    def no_lone_surrogate(text: str) -> None:
        text.encode("utf-8")

    try:
        text = raw.decode("utf-8")
        if text.startswith("\ufeff"):
            return True
        value = json.loads(text, object_pairs_hook=no_duplicates, parse_constant=_refuse)
        no_lone_surrogate(json.dumps(value, ensure_ascii=False))
    except (UnicodeError, ValueError):
        return True
    return False


def _refuse(name: str) -> None:
    raise ValueError(name)


class InvalidInputFamily(unittest.TestCase):
    def test_family_is_nonempty_and_every_member_expects_rejection(self) -> None:
        cases = CORPUS["invalidInputCases"]
        self.assertGreaterEqual(len(cases), 15)
        self.assertEqual({c["expect"] for c in cases}, {"reject"})
        ids = [c["id"] for c in cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_strict_reference_refuses_every_member(self) -> None:
        for case in CORPUS["invalidInputCases"]:
            with self.subTest(case["id"]):
                self.assertTrue(strict_refuses(bytes.fromhex(case["inputHex"])))

    def test_the_python_rail_refuses_every_member(self) -> None:
        for case in CORPUS["invalidInputCases"]:
            raw = bytes.fromhex(case["inputHex"])
            with self.subTest(case["id"]):
                with self.assertRaises(Exception):
                    a2ajcs.canonicalize(a2ajcs.parse(raw.decode("utf-8")))


if __name__ == "__main__":
    unittest.main()
