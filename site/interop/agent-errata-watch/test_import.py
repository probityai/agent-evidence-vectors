"""Finite saved-row mutations exercise the actual reader and Verify bridge."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from watch_import import InputError, compare_rows, import_watch, strict_json, write_bundle
from watch_import.reader import canonical

HERE = Path(__file__).resolve().parent


def fixture() -> tuple[dict, dict[str, bytes]]:
    row = {
        "arms": {"a": ["A", "B"], "b": ["C"], "c": [], "d": []},
        "sym": {"e": {"E": 1, "F": 2}, "f": {}},
        "tools": 2,
        "s004": {"total": 100, "tools": 40, "system": 50},
    }
    before = {"version": "fixture-before", "measured": "fixture-date", "where": "fixture-before-platform", "row": row}
    after = {**copy.deepcopy(before), "version": "fixture-after", "where": "fixture-after-platform"}
    run = {
        "harness": "fixture",
        "label": "Fixture",
        "version": after["version"],
        "previous_version": before["version"],
        "previous_measured": before["measured"],
        "date": after["measured"],
        "where": after["where"],
        "run": "fixture:run",
        "forced": False,
        "changed": False,
        "changes": [],
        "minor": [],
        "row": after["row"],
        "note": "Synthetic saved rows, not publisher execution.",
    }
    raw = {
        "baseline_state": canonical({"harnesses": {"fixture": before}}),
        "current_state": canonical({"harnesses": {"fixture": after}}),
        "run/fixture": canonical(run),
    }
    raw.update({role: b"synthetic definition\n" for role in ("registry", "comparison_source", "upstream_workflow", "tokenizer")})
    manifest = {
        "schema": "probity.watch-sources/v1",
        "repository": "fixture/saved-rows",
        "sourceRevision": "a" * 40,
        "baselineRevision": "b" * 40,
        "population": ["fixture"],
        "comparison": {"version": "watch-set-and-counts/v1"},
        "files": [],
    }
    for role, data in raw.items():
        manifest["files"].append(
            {
                "role": role,
                "repository": "fixture/saved-rows",
                "revision": "b" * 40 if role == "baseline_state" else "a" * 40,
                "path": role.replace("/", "-") + ".json",
                "retainedPath": role.replace("/", "-") + ".json",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "gitBlob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
            }
        )
    return manifest, raw


def repin(manifest: dict, raw: dict[str, bytes], role: str, value: dict) -> None:
    """Create an explicitly synthetic, newly selected input for a finite control."""
    raw[role] = (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    item = next(item for item in manifest["files"] if item["role"] == role)
    item.update(
        bytes=len(raw[role]),
        sha256=hashlib.sha256(raw[role]).hexdigest(),
        gitBlob=hashlib.sha1(b"blob " + str(len(raw[role])).encode() + b"\0" + raw[role]).hexdigest(),
    )


def materialize(root: Path, manifest: dict, raw: dict[str, bytes]) -> None:
    for item in manifest["files"]:
        target = root / item["retainedPath"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw[item["role"]])


class ImportControls(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=HERE / ".build")
        self.root = Path(self.temp.name)
        self.manifest, self.raw = fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def read(self) -> dict:
        materialize(self.root, self.manifest, self.raw)
        return import_watch(self.root, self.manifest)[0]

    def test_exact_raw_rows_bundle_and_platforms(self) -> None:
        result = self.read()
        self.assertEqual(result["summary"], {"rows": 1, "consistent_publisher_claims": 1, "adapter_changed": 0})
        output = self.root / "bundle"
        write_bundle(result, self.raw, self.manifest, output)
        self.assertEqual((output / "raw/run-fixture.json").read_bytes(), self.raw["run/fixture"])
        self.assertNotEqual(result["rows"][0]["before"]["where"], result["rows"][0]["after"]["where"])
        self.assertFalse(result["scope"]["harnesses_executed"])
        with self.assertRaises(InputError):
            write_bundle(result, self.raw, self.manifest, output)

    def test_missed_change_and_false_match(self) -> None:
        original = strict_json(self.raw["run/fixture"])
        for changed_row, reported in ((True, False), (False, True)):
            with self.subTest(changed_row=changed_row, reported=reported):
                run = copy.deepcopy(original)
                if changed_row:
                    run["row"]["arms"]["b"] = ["replacement"]
                run["changed"] = reported
                state = strict_json(self.raw["current_state"])
                state["harnesses"]["fixture"]["row"] = run["row"]
                repin(self.manifest, self.raw, "current_state", state)
                repin(self.manifest, self.raw, "run/fixture", run)
                self.assertEqual(self.read()["rows"][0]["verdict"], "contradicted")

    def test_reorder_has_a_separate_native_comparison(self) -> None:
        before = strict_json(self.raw["baseline_state"])["harnesses"]["fixture"]["row"]
        after = copy.deepcopy(before)
        after["arms"]["a"].reverse()
        after["sym"]["e"] = {"F": 2, "E": 1}
        result = compare_rows(before, after)
        self.assertFalse(result["changed"])
        self.assertTrue(result["upstream_recomputed_changed"])
        self.assertEqual(result["order_only"], ["arms/a", "sym/e"])

    def test_exact_threshold_and_zero_baseline(self) -> None:
        before = strict_json(self.raw["baseline_state"])["harnesses"]["fixture"]["row"]
        for total, changed in ((110, False), (111, True), (90, False), (89, True)):
            after = copy.deepcopy(before)
            after["s004"]["total"] = total
            self.assertEqual(compare_rows(before, after)["changed"], changed)
        before["s004"]["total"] = 0
        self.assertEqual(compare_rows(before, after)["tokens"]["comparison"], "not_established")
        before["sym"] = {}
        after["sym"] = {"e": {"observed-later": 1}, "f": {}}
        compared = compare_rows(before, after)
        self.assertEqual(compared["unavailable_fields"], ["sym/e", "sym/f"])
        self.assertFalse(compared["upstream_recomputed_changed"])

    def test_tools_and_bytes_are_not_instruction_membership(self) -> None:
        before = strict_json(self.raw["baseline_state"])["harnesses"]["fixture"]["row"]
        after = copy.deepcopy(before)
        after.update(tools=9, bytes_b=42)
        self.assertFalse(compare_rows(before, after)["changed"])

    def test_source_drift_and_missing_raw_rows(self) -> None:
        materialize(self.root, self.manifest, self.raw)
        (self.root / "registry.json").write_bytes(b"changed source\n")
        with self.assertRaises(InputError):
            import_watch(self.root, self.manifest)
        materialize(self.root, self.manifest, self.raw)
        (self.root / "run-fixture.json").unlink()
        with self.assertRaises(OSError):
            import_watch(self.root, self.manifest)

    def test_call_identity_population_and_previous_version(self) -> None:
        run = strict_json(self.raw["run/fixture"])
        for field, bad in (("harness", "other"), ("previous_version", "other-version")):
            updated = {**run, field: bad}
            repin(self.manifest, self.raw, "run/fixture", updated)
            with self.assertRaises(InputError):
                self.read()
        self.manifest["population"] = ["fixture", "fixture"]
        with self.assertRaises(InputError):
            self.read()

    def test_raw_admission_controls(self) -> None:
        bad = [
            b'{"a":1,"a":2}',
            b'{"a":1,"\\u0061":2}',
            b'{"a":"\\ud800"}',
            b"\xff",
            b'{"a":NaN}',
            b'{"a":1e999}',
            b"[]",
            b'{"a":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
            b" " * (4 * 1024 * 1024 + 1),
        ]
        for raw in bad:
            with self.subTest(raw=raw[:40]), self.assertRaises(InputError):
                strict_json(raw)
        self.assertEqual(strict_json(b'{"a":1}'), {"a": 1})

    def test_unsafe_paths_and_symlink(self) -> None:
        item = self.manifest["files"][0]
        for path in ("../outside.json", "/outside.json", "c:\\outside.json"):
            item["retainedPath"] = path
            with self.assertRaises(InputError):
                import_watch(self.root, self.manifest)
        item["retainedPath"] = "linked.json"
        target = self.root / "target.json"
        target.write_bytes(self.raw[item["role"]])
        (self.root / "linked.json").symlink_to(target)
        with self.assertRaises(InputError):
            import_watch(self.root, self.manifest)

    def test_actual_verify_support_and_mutation(self) -> None:
        # This is the installed pinned reader, not a local mock of its verdicts.
        if not os.environ.get("PROBITY_VERIFY_ROOT"):
            self.fail("PROBITY_VERIFY_ROOT is required; this gate may not skip")
        import subprocess
        import sys

        result = self.read()
        output = self.root / "bundle"
        write_bundle(result, self.raw, self.manifest, output)
        folder = output / "verify/fixture"
        env = {**os.environ, "PYTHONPATH": os.environ["PROBITY_VERIFY_ROOT"]}
        command = [
            sys.executable,
            "-m",
            "probity_verify.cli",
            str(folder / "case.json"),
            "--policy",
            str(folder / "candidate-policy.json"),
            "--json",
        ]
        observed = subprocess.run(command, cwd=output, env=env, capture_output=True, check=True)
        self.assertEqual(json.loads(observed.stdout)["decision"], "supported")
        execution = json.loads((folder / "execution.json").read_bytes())
        execution["figure"] = "999"
        (folder / "execution.json").write_bytes(canonical(execution))
        observed = subprocess.run(command, cwd=output, env=env, capture_output=True, check=True)
        self.assertEqual(json.loads(observed.stdout)["decision"], "not_established")


if __name__ == "__main__":
    (HERE / ".build").mkdir(exist_ok=True)
    unittest.main(verbosity=2)
