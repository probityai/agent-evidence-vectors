from __future__ import annotations

import copy
import hashlib
import json
import unittest

import build_cases
import run
from definition_pin import InvalidInput, compare, definition_digest


class LiveMcpDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads((run.ROOT / "fixtures" / "cases.json").read_text())

    def test_pinned_preimage(self) -> None:
        expected = (
            b'{"profile":"agentavow.mcp-tool-definition.v1","tool":'
            b'{"annotations":{"readOnlyHint":false},'
            b'"description":"Approve a draft invoice after review.",'
            b'"inputSchema":{"properties":{"invoiceId":{"type":"string"}},"type":"object"},'
            b'"name":"approve_invoice"}}'
        )
        digest = "sha256:" + hashlib.sha256(expected).hexdigest()
        self.assertEqual(definition_digest(build_cases.PRIMARY), digest)
        self.assertEqual(self.fixture["pin"]["toolDigest"], digest)

    def test_cases_are_pinned_and_replay(self) -> None:
        self.assertEqual(build_cases.content(), (run.ROOT / "fixtures" / "cases.json").read_bytes())
        self.assertEqual(len(run.run()), 10)

    def test_target_disambiguation_and_absence(self) -> None:
        pin = self.fixture["pin"]
        capture = {"endpoint": pin["endpoint"], "tools": [build_cases.PRIMARY]}
        self.assertEqual(compare(pin, capture)["verdict"], "match")
        self.assertEqual(compare(pin, {**capture, "tools": []})["reason"], "tool_missing")
        self.assertEqual(compare(pin, {**capture, "tools": [build_cases.PRIMARY] * 2})["reason"], "name_ambiguous")

    def test_visible_change_and_out_of_contract_metadata(self) -> None:
        pin = self.fixture["pin"]
        original = {"endpoint": pin["endpoint"], "tools": [build_cases.PRIMARY]}
        changed = copy.deepcopy(original)
        changed["tools"][0]["annotations"]["readOnlyHint"] = True
        self.assertEqual(compare(pin, changed)["verdict"], "changed")
        metadata = copy.deepcopy(original)
        metadata["tools"][0]["_meta"] = {"trace": "different"}
        self.assertEqual(compare(pin, metadata)["verdict"], "match")

    def test_unsupported_numbers_and_malformed_capture(self) -> None:
        pin = self.fixture["pin"]
        for value in (0.25, 2**53, float("nan"), "\ud800"):
            tool = copy.deepcopy(build_cases.PRIMARY)
            tool["inputSchema"]["maximum"] = value
            result = compare(pin, {"endpoint": pin["endpoint"], "tools": [tool]})
            self.assertEqual(result["reason"], "definition_unreadable")
        with self.assertRaises(InvalidInput):
            compare(pin, {"endpoint": pin["endpoint"], "tools": ["tool"]})


if __name__ == "__main__":
    unittest.main()
