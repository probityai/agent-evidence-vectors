"""Failure controls for the pinned source, corpus and declared consumer outcome."""

import tempfile
import unittest
from pathlib import Path

import check


class TestPins(unittest.TestCase):
    def test_source_mutation_refuses_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.go").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "pinned bytes differ"):
                check.verify_files(root, [{"path": "source.go", "bytes": 8, "sha256": check.digest(b"original")}])

    def test_expected_canonical_byte_mutation_refuses(self):
        with self.assertRaisesRegex(ValueError, "consumer outcome differs"):
            check.require_outcome(check.accepted(b'[2]'), check.accepted(b'[1]'), "independent expected bytes")

    def test_later_stage_cannot_replace_raw_refusal(self):
        with self.assertRaisesRegex(ValueError, "consumer outcome differs"):
            check.require_outcome(check.refused("DuplicateMember", "go-transform"), check.refused("DuplicateMember"), "escaped duplicate")

    def test_complete_original_corpus_and_adaptations_are_accounted_for(self):
        cases = check.corpus_cases()
        self.assertEqual(len(cases), 1263)
        self.assertEqual(len({c["name"] for c in cases}), 1263)
        self.assertEqual(sum(c["name"].startswith("controls/") for c in cases), 27)


if __name__ == "__main__":
    unittest.main()
