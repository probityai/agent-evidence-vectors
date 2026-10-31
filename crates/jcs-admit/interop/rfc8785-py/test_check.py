"""Meaningful failure controls for the source-pinned byte qualification."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("jcs_python_check", HERE / "check.py")
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class FailureControls(unittest.TestCase):
    def test_changed_source_byte_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source.py"
            path.write_bytes(b"original")
            entry = {"path": "source.py", "bytes": 8, "sha256": CHECK.digest(b"original")}
            CHECK.verify_files(root, [entry])
            path.write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "pinned bytes differ"):
                CHECK.verify_files(root, [entry])

    def test_changed_expected_byte_is_detected(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical bytes differ"):
            CHECK.require_bytes(b'{"a":1}', b'{"a":2}', "altered-oracle")

    def test_changed_refusal_class_is_detected(self) -> None:
        with self.assertRaisesRegex(ValueError, "boundary outcome differs"):
            CHECK.require_outcome(
                {"status": "refused", "error_class": "FloatDomainError"},
                {"status": "refused", "error_class": "IntegerDomainError"},
                "changed-class",
            )

    def test_duplicate_source_members_collapse_before_serialization(self) -> None:
        controls = json.loads((HERE / "controls.json").read_text())["cases"]
        case = next(row for row in controls if row["name"] == "escaped-duplicate-member")
        self.assertNotEqual(case["raw"], '{"a":2}')
        self.assertEqual(json.loads(case["raw"]), json.loads('{"a":2}'))
        self.assertEqual(case["rust_error"], "DuplicateMember")

    def test_unsafe_decimal_is_rounded_before_serialization(self) -> None:
        controls = json.loads((HERE / "controls.json").read_text())["cases"]
        case = next(row for row in controls if row["name"] == "unsafe-decimal-token")
        self.assertEqual(json.loads(case["raw"]), 9007199254740992.0)
        self.assertEqual(case["rust_error"], "UnsafeInteger")


if __name__ == "__main__":
    unittest.main()
