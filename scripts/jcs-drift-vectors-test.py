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


class RefusalFamily(unittest.TestCase):
    def test_family_covers_every_refusal_class(self) -> None:
        cases = CORPUS["refusalCases"]
        self.assertEqual(
            {c["family"] for c in cases},
            {"non-finite", "trailing-content", "syntax", "invalid-unicode", "duplicate-member"},
        )
        for case in cases:
            self.assertEqual(case["expect"], "reject")
            self.assertEqual(("input" in case) + ("inputHex" in case), 1, case["id"])

    def test_python_reference_refuses_every_case(self) -> None:
        for case in CORPUS["refusalCases"]:
            with self.subTest(case["id"]):
                raw = (
                    bytes.fromhex(case["inputHex"])
                    if "inputHex" in case
                    else case["input"].encode("utf-8")
                )
                with self.assertRaises(Exception):
                    a2ajcs.canonicalize(a2ajcs.parse(raw.decode("utf-8")))


if __name__ == "__main__":
    unittest.main()
