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

import hashlib
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
                with self.assertRaises(ValueError):
                    a2ajcs.canonicalize(a2ajcs.parse(raw.decode("utf-8")))


class NoncharacterFamily(unittest.TestCase):
    """RFC 8785 prints a noncharacter as UTF-8; RFC 7493 forbids it (bounded profile)."""

    def test_python_reference_prints_the_pinned_bytes_from_both_spellings(self) -> None:
        cases = CORPUS["noncharacterCases"]
        self.assertEqual(len({c["codePoint"] for c in cases}) * 4, len(cases))
        for case in cases:
            with self.subTest(case["id"]):
                printed = a2ajcs.canonicalize(a2ajcs.parse(case["input"]))
                self.assertEqual(printed.hex(), case["canonicalHex"])
                code = int(case["codePoint"][2:], 16)
                noncharacter = code & 0xFFFE == 0xFFFE or 0xFDD0 <= code <= 0xFDEF
                self.assertEqual(case["family"] == "noncharacter", noncharacter)
                self.assertEqual(
                    case.get("boundedError"), "invalid-unicode" if noncharacter else None
                )

    def test_a_too_wide_noncharacter_test_fails_the_neighbours(self) -> None:
        """Refusing all of U+FDC0..U+FDFF and every U+nFFFx passed the family before."""

        def too_wide(code: int) -> bool:
            return code & 0xFFF0 == 0xFFF0 or 0xFDC0 <= code <= 0xFDFF

        neighbours = [
            c for c in CORPUS["noncharacterCases"] if c["family"] == "noncharacter-neighbour"
        ]
        self.assertTrue(neighbours)
        refused = {c["codePoint"] for c in neighbours if too_wide(int(c["codePoint"][2:], 16))}
        self.assertEqual(refused, {"U+FDCF", "U+FDF0", "U+FFFD", "U+1FFFD", "U+10FFFD"})

    def test_every_position_and_spelling_is_present(self) -> None:
        seen = {(c["position"], c["spelling"]) for c in CORPUS["noncharacterCases"]}
        self.assertEqual(
            seen,
            {(p, s) for p in ("value", "member-name") for s in ("raw", "escaped")},
        )


def field_digest(profile: str, value: str | None, *, json_form: bool = False) -> str:
    """The digest a reader computes for one field; ``json_form`` is the usual mistake."""
    if profile == "absent":
        return hashlib.sha256(b"null" if json_form else b"").hexdigest()
    parsed = a2ajcs.parse(value or "")
    if profile == "scalar-text" and not json_form:
        return hashlib.sha256(parsed.encode("utf-8")).hexdigest()
    return hashlib.sha256(a2ajcs.canonicalize(parsed)).hexdigest()


class PreimageFamily(unittest.TestCase):
    """Raw UTF-8 for scalar text, RFC 8785 bytes for structure, empty for absent."""

    def test_a_correct_reader_agrees_and_never_matches_the_stated_wrong_answer(self) -> None:
        for case in CORPUS["preimageCases"]:
            with self.subTest(case["id"]):
                got = field_digest(case["profile"], case.get("value"))
                self.assertEqual(got, case["sha256"])
                self.assertNotEqual(got, case["statedWrongSha256"])

    def test_a_reader_that_hashes_the_json_form_fails_every_scalar_and_absent_case(self) -> None:
        for case in CORPUS["preimageCases"]:
            if case["profile"] == "structured-json":
                continue
            with self.subTest(case["id"]):
                got = field_digest(case["profile"], case.get("value"), json_form=True)
                self.assertNotEqual(got, case["sha256"])
                self.assertEqual(got, case["statedWrongSha256"])

    def test_a_reader_that_maps_null_to_absent_fails_the_null_case(self) -> None:
        by_id = {c["id"]: c for c in CORPUS["preimageCases"]}
        null, absent = by_id["preimage-structured-null"], by_id["preimage-absent"]
        self.assertEqual(null["sha256"], absent["statedWrongSha256"])
        self.assertEqual(null["statedWrongSha256"], absent["sha256"])
        self.assertEqual(hashlib.sha256(b"").hexdigest(), null["statedWrongSha256"])

    def test_the_empty_string_collides_with_absent_and_says_so(self) -> None:
        by_id = {c["id"]: c for c in CORPUS["preimageCases"]}
        empty, absent = by_id["preimage-scalar-empty"], by_id["preimage-absent"]
        self.assertEqual(empty["sha256"], absent["sha256"])
        self.assertEqual(empty.get("collidesWith"), "preimage-absent")


if __name__ == "__main__":
    unittest.main()
