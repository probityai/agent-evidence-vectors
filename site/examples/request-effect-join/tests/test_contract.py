"""Tests for the request/effect fixture contract and its reference reader."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run_contract  # noqa: E402  (the reader under test lives beside the fixtures)


def corpus() -> dict:
    """Return the fixture corpus."""
    return json.loads((ROOT / "fixtures" / "cases.json").read_text())


def expected() -> dict:
    """Return the expected results."""
    return json.loads((ROOT / "expected.json").read_text())


def case_by_id(case_id: str) -> dict:
    """Return one case, deep-copied so a test can mutate it."""
    return copy.deepcopy(next(c for c in corpus()["cases"] if c["case_id"] == case_id))


class ContractTest(unittest.TestCase):
    """The corpus, the expected results and the reader must agree with the contract."""

    def test_every_case_matches_expected(self) -> None:
        self.assertEqual(run_contract.main(["--check"]), 0)

    def test_expected_covers_every_case_once(self) -> None:
        ids = [c["case_id"] for c in corpus()["cases"]]
        wanted = [c["case_id"] for c in expected()["cases"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate case id in the corpus")
        self.assertEqual(sorted(ids), sorted(wanted), "expected.json does not cover the corpus")

    def test_vocabulary_is_closed(self) -> None:
        document = expected()
        for entry in document["cases"]:
            self.assertIn(entry["classification"], document["classification_values"])
            for finding in entry["findings"]:
                self.assertIn(finding, document["finding_values"])
            for finding in entry["must_not_claim"]:
                self.assertNotIn(finding, entry["findings"],
                                 f"{entry['case_id']}: a finding is also must_not_claim")

    def test_refs_recompute(self) -> None:
        for case in corpus()["cases"]:
            for name in run_contract.CHAINED:
                node = case[name]
                if node is None or case["case_id"] == "S-07":
                    continue
                with self.subTest(case=case["case_id"], field=name):
                    self.assertEqual(run_contract.computed_ref(node["preimage"]), node["ref"])

    def test_only_one_case_carries_a_broken_digest(self) -> None:
        broken = [case["case_id"] for case in corpus()["cases"]
                  if not run_contract.digests_agree(case)]
        self.assertEqual(broken, ["S-07"])

    def test_missing_later_key_is_invalid_input(self) -> None:
        with self.assertRaises(run_contract.InvalidInput):
            run_contract.classify(case_by_id("S-06"))

    def test_null_later_value_is_not_absence(self) -> None:
        null_case = run_contract.report_for(case_by_id("S-05"))
        absent_case = run_contract.report_for(case_by_id("S-06"))
        self.assertEqual(null_case["classification"], "established")
        self.assertIn("later_state_not_supplied", null_case["findings"])
        self.assertEqual(absent_case["classification"], "invalid_input")
        self.assertNotIn("not_established", absent_case["findings"])

    def test_a_refusal_does_not_establish_the_store_is_unchanged(self) -> None:
        line = run_contract.report_for(case_by_id("S-09"))
        self.assertEqual(line["classification"], "not_established")
        self.assertIn("refusal_observed", line["findings"])
        self.assertIn("store_mutation_not_established", line["findings"])
        self.assertNotIn("later_state_unchanged", line["findings"])

    def test_a_later_difference_is_not_a_digest_failure(self) -> None:
        line = run_contract.report_for(case_by_id("S-04"))
        self.assertEqual(line["classification"], "established")
        self.assertIn("later_state_differs", line["findings"])
        self.assertIn("original_result_preserved", line["findings"])
        self.assertNotIn("digest_mismatch", line["findings"])

    def test_unsupported_profile_is_not_a_digest_failure(self) -> None:
        line = run_contract.report_for(case_by_id("S-08"))
        self.assertEqual(line["classification"], "invalid_input")
        self.assertEqual(line["findings"], ["unsupported_canonical_profile"])

    def test_attempt_without_result_is_invalid_input(self) -> None:
        case = case_by_id("S-00")
        case["result"] = None
        with self.assertRaises(run_contract.InvalidInput):
            run_contract.classify(case)

    def test_unknown_key_is_invalid_input(self) -> None:
        case = case_by_id("S-00")
        case["extra"] = True
        with self.assertRaises(run_contract.InvalidInput):
            run_contract.classify(case)

    def test_a_decision_that_names_another_ref_covers_nothing(self) -> None:
        case = case_by_id("S-02")
        case["covering_decision"] = case["decision"]
        line = run_contract.report_for(case)
        self.assertEqual(line["classification"], "refused")
        self.assertEqual(line["findings"], ["effective_call_not_covered"])

    def test_manifest_pins_both_data_files(self) -> None:
        manifest = json.loads((ROOT / "fixtures" / "MANIFEST.json").read_text())
        self.assertEqual(sorted(manifest["sha256"]), ["cases.json", "expected.json"])
        for name, digest in manifest["sha256"].items():
            path = ROOT / "fixtures" / name if name == "cases.json" else ROOT / name
            actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(actual, digest, f"{name} is not the pinned file")


if __name__ == "__main__":
    unittest.main()
