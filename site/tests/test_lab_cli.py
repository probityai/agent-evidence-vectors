"""Consumer CLI controls for full-register integrity and literal result output."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("atlas_cli_check_lab", ROOT / "tools" / "check_lab.py")
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class TestLabCLI(unittest.TestCase):
    """Exercise real validation through every new consumer output path."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.register = {"protocolVersion": "0.1", "records": [
            self.make_record("selected"), self.make_record("other"),
        ]}
        self.write_register()

    def make_record(self, identity: str) -> dict[str, Any]:
        """Retain independently hashed fixture bytes and all result categories."""
        raw = json.dumps({"observations": 2, "qualityAccepted": False, "identity": identity}).encode()
        reference = f"../fixtures/{identity}.json"
        target = CHECK.artifact_path(self.root, reference)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        provenance = f"../fixtures/{identity}-provenance.json"
        provenance_bytes = json.dumps({"source": "authored test fixture", "identity": identity}).encode()
        CHECK.artifact_path(self.root, provenance).write_bytes(provenance_bytes)
        return {
            "id": identity,
            "report": reference,
            "provenance": provenance,
            "artifacts": [
                {"path": reference, "sha256": hashlib.sha256(raw).hexdigest()},
                {"path": provenance, "sha256": hashlib.sha256(provenance_bytes).hexdigest()},
            ],
            "claimResults": [
                {"claim": "retained-observations", "result": "pass", "recordedField": "/observations", "expectedValue": 2},
                {"claim": "strict-task-quality", "result": "fail", "recordedField": "/qualityAccepted", "expectedValue": False},
                {"claim": "unobserved-effect", "result": "unknown"},
                {"claim": "independent-operation", "result": "not-exercised"},
                {"claim": "arbitrary-trace", "result": "out-of-scope"},
            ],
            "roles": {"independentOperation": "not-established"},
            "reviewState": "submitted",
            "evidenceClaim": "synthetic-fixture",
            "limits": ["Local authored fixture with exposed expected answers"],
        }

    def write_register(self) -> bytes:
        """Keep the exact register representation available for digest checks."""
        raw = (json.dumps(self.register, indent=2, sort_keys=True) + "\n").encode()
        target = self.root / "data" / "lab-register.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return raw

    def run_cli(self, arguments: Sequence[str]) -> str:
        """Capture actual main output without replacing any validation gate."""
        stdout = io.StringIO()
        with patch.object(CHECK, "ROOT", self.root), contextlib.redirect_stdout(stdout):
            CHECK.main(arguments)
        return stdout.getvalue()

    def assert_refuses(self, arguments: Sequence[str], reason: str) -> None:
        """Require refusal before any successful report can be emitted."""
        stdout = io.StringIO()
        with patch.object(CHECK, "ROOT", self.root), contextlib.redirect_stdout(stdout):
            with self.assertRaisesRegex(ValueError, f"^{reason}$"):
                CHECK.main(arguments)
        self.assertEqual(stdout.getvalue(), "")

    def test_default_summary_is_preserved(self) -> None:
        self.assertEqual(self.run_cli([]),
                         "lab register: 2 record(s), artifact hashes and measured bindings pass\n")

    def test_json_keeps_every_record_and_exact_register_digest(self) -> None:
        raw = self.write_register()
        output = json.loads(self.run_cli(["--json"]))
        self.assertEqual(output["format"], "probity-lab-integrity-v1")
        self.assertEqual(output["validationScope"], "complete-register")
        self.assertEqual(output["integrityStatus"], "pass")
        self.assertEqual(output["registerSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(output["records"], self.register["records"])

    def test_selected_json_preserves_results_roles_and_review_state(self) -> None:
        output = json.loads(self.run_cli(["--record", "selected", "--json"]))
        self.assertEqual(output["records"], [self.register["records"][0]])
        self.assertEqual(output["validationScope"], "complete-register")
        self.assertEqual([claim["result"] for claim in output["records"][0]["claimResults"]],
                         ["pass", "fail", "unknown", "not-exercised", "out-of-scope"])

    def test_selected_text_keeps_failed_and_unmeasured_claims_visible(self) -> None:
        output = self.run_cli(["--record", "selected"])
        self.assertIn('selected record: "selected"\n', output)
        self.assertIn('fail  "strict-task-quality"\n', output)
        self.assertIn('unknown  "unobserved-effect"\n', output)
        self.assertIn('not-exercised  "independent-operation"\n', output)

    def test_list_outputs_exact_ids(self) -> None:
        self.assertEqual([json.loads(line) for line in self.run_cli(["--list"]).splitlines()],
                         ["selected", "other"])

    def test_selected_list_outputs_one_id(self) -> None:
        self.assertEqual(self.run_cli(["--record", "other", "--list"]), '"other"\n')

    def test_list_escapes_control_characters_in_ids(self) -> None:
        identity = "candidate\x1b[31m\nsecond-line"
        self.register["records"][0]["id"] = identity
        self.write_register()
        output = self.run_cli(["--list"])
        self.assertNotIn("\x1b", output)
        self.assertEqual([json.loads(line) for line in output.splitlines()], [identity, "other"])

    def test_unknown_record_refuses_without_output(self) -> None:
        self.assert_refuses(["--record", "missing", "--json"],
                            "requested record id is not in the register")

    def test_selection_cannot_skip_changed_unselected_artifact(self) -> None:
        target = CHECK.artifact_path(self.root, self.register["records"][1]["report"])
        target.write_bytes(target.read_bytes() + b"\n")
        for arguments in (["--record", "selected"], ["--record", "selected", "--json"],
                          ["--record", "selected", "--list"], ["--json"], ["--list"]):
            with self.subTest(arguments=arguments):
                self.assert_refuses(arguments, "retained artifact differs from its SHA-256")

    def test_selection_cannot_skip_wrong_unselected_measured_binding(self) -> None:
        self.register["records"][1]["claimResults"][0]["expectedValue"] = True
        self.write_register()
        self.assert_refuses(["--record", "selected", "--json"],
                            "measured claim differs from the retained report")

    def test_duplicate_id_refuses_selected_output(self) -> None:
        self.register["records"][1]["id"] = "selected"
        self.write_register()
        self.assert_refuses(["--record", "selected", "--json"], "register repeats a record id")

    def test_json_preserves_register_and_artifact_bytes(self) -> None:
        before = copy.deepcopy(self.register)
        paths = [self.root / "data" / "lab-register.json"] + [
            CHECK.artifact_path(self.root, record["report"]) for record in self.register["records"]
        ]
        original = {path: path.read_bytes() for path in paths}
        self.run_cli(["--record", "selected", "--json"])
        self.assertEqual(self.register, before)
        self.assertEqual({path: path.read_bytes() for path in paths}, original)


class TestRetainedRegisterCLI(unittest.TestCase):
    """Exercise a real consumer selection in the complete retained CI checkout."""

    def test_original_tool_argument_record_keeps_quality_failures(self) -> None:
        raw = (ROOT / "data" / "lab-register.json").read_bytes()
        register = json.loads(raw)
        identity = "model-tool-arguments-cpu-2026-10-03"
        expected = next(record for record in register["records"] if record["id"] == identity)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            CHECK.main(["--record", identity, "--json"])
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["validationScope"], "complete-register")
        self.assertEqual(output["registerSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(output["records"], [expected])
        self.assertTrue(any(claim["result"] == "fail" for claim in expected["claimResults"]))
        self.assertEqual((ROOT / "data" / "lab-register.json").read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
