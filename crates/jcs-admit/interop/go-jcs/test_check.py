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


class TestModulePath(unittest.TestCase):
    def test_the_harness_module_path_cannot_be_fetched(self):
        # The harness is built from this checkout only. Its earlier module path named a
        # GitHub repository that redirects to an archive, and proxy.golang.org answered
        # `@latest` for it with that archive's stale copy, so `go get` on the path the
        # README never offered still fetched the wrong code. A host under the reserved
        # .invalid domain cannot resolve anywhere.
        lines = (Path(__file__).with_name("go.mod")).read_text().splitlines()
        module = next(line.split()[1] for line in lines if line.startswith("module "))
        self.assertTrue(module.split("/")[0].endswith(".invalid"), module)
        for source in (Path(__file__).parent.glob("**/*.go")):
            text = source.read_text()
            self.assertNotIn("github.com/probityai/jcs-admit", text, str(source))


if __name__ == "__main__":
    unittest.main()
