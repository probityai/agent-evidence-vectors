"""Fixed-byte, historical collision and actual process contract checks."""

from __future__ import annotations

import errno
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import reader

ROOT = Path(__file__).parent
MANIFEST = ROOT / "MANIFEST.json"


class CandidateTests(unittest.TestCase):
    def case(self, number: int) -> dict:
        return json.loads((ROOT / f"cases/ATF-{number:03}.json").read_bytes())

    def test_fixed_preimage_and_known_sha256(self) -> None:
        # This answer is hand-specified, not obtained from reader.encode_tuple.
        expected = bytes.fromhex(
            "50524f4249545900616374696f6e2d7475706c6500763100" + "00" * 20
        )
        empty = {"agent_id": "", "action_type": "", "scope": "", "issued_at_ms": 0}
        self.assertEqual(reader.encode_tuple(empty), expected)
        self.assertEqual(
            hashlib.sha256(expected).hexdigest(),
            "b1e9d2c00a8a6dfcc8f8f383e09e07fa0fbf3fddde0778c8f41c27b97be97f82",
        )

    def test_profile_widths_and_json_budgets_are_exercised(self) -> None:
        text = (ROOT / "PROFILE.md").read_text()
        self.assertEqual(text.count("Unsigned 32-bit big-endian UTF-8 byte count"), 3)
        match = re.search(r"depth at most (\d+) and at most ([\d,]+) value nodes", text)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(int(match.group(1)), reader.MAX_DEPTH)
        self.assertEqual(int(match.group(2).replace(",", "")), reader.MAX_NODES)
        reader.strict_json(b"[" * reader.MAX_DEPTH + b"0" + b"]" * reader.MAX_DEPTH)
        with self.assertRaisesRegex(reader.Refusal, "json-depth-or-nodes"):
            reader.strict_json(b"[" * (reader.MAX_DEPTH + 1) + b"0" + b"]" * (
                reader.MAX_DEPTH + 1))
        reader.strict_json(json.dumps([0] * (reader.MAX_NODES - 1)).encode())
        with self.assertRaisesRegex(reader.Refusal, "json-depth-or-nodes"):
            reader.strict_json(json.dumps([0] * reader.MAX_NODES).encode())

    def test_original_native_ambiguity_candidate_discriminates(self) -> None:
        first, second = self.case(1), self.case(2)

        def native(packet: dict) -> bytes:
            value = packet["tuple"]
            return (value["agent_id"] + value["action_type"] + value["scope"]).encode() + (
                struct.pack(">q", value["issued_at_ms"])
            )

        self.assertEqual(native(first), native(second))
        self.assertEqual(hashlib.sha256(native(first)).hexdigest(),
                         "6fe8b805ca46d0f71f06b1b4b3301be537ffd53cedb8726df2545c3369445ecb")
        self.assertNotEqual(first["frame_hex"], second["frame_hex"])
        self.assertNotEqual(first["digest"], second["digest"])
        for number in (1, 2):
            self.assertEqual(reader.verify((ROOT / f"cases/ATF-{number:03}.json").read_bytes())[
                "status"], "accepted")

    def test_agent_action_boundary_also_discriminates(self) -> None:
        first, second = self.case(1), self.case(9)
        self.assertEqual(
            first["tuple"]["agent_id"] + first["tuple"]["action_type"],
            second["tuple"]["agent_id"] + second["tuple"]["action_type"],
        )
        self.assertNotEqual(first["frame_hex"], second["frame_hex"])

    def test_composed_and_decomposed_unicode_are_distinct(self) -> None:
        self.assertNotEqual(self.case(5)["digest"], self.case(6)["digest"])
        for number in (4, 5, 6):
            packet = self.case(number)
            self.assertEqual(reader.decode_frame(bytes.fromhex(packet["frame_hex"])),
                             packet["tuple"])

    def test_max_utf8_bytes_and_embedded_zero_are_round_trip_values(self) -> None:
        value = {"agent_id": "é" * 32768, "action_type": "", "scope": "\0",
                 "issued_at_ms": -1}
        self.assertEqual(reader.decode_frame(reader.encode_tuple(value)), value)
        with self.assertRaisesRegex(reader.Refusal, "tuple-size"):
            reader.encode_tuple({**value, "agent_id": value["agent_id"] + "x"})

    def test_transport_budget_accepts_maximum_escaped_strings(self) -> None:
        for text in ("\0" * reader.MAX_STRING, "\x1f" * reader.MAX_STRING,
                     "😀" * (reader.MAX_STRING // 4)):
            with self.subTest(scalar=ord(text[0])):
                value: dict[str, object] = {name: text for name in reader.FIELDS}
                value["issued_at_ms"] = -(2**63)
                frame = reader.encode_tuple(value)
                packet = {"profile": reader.PROFILE, "tuple": value,
                          "frame_hex": frame.hex(), "digest": reader.sha256(frame)}
                data = json.dumps(packet, ensure_ascii=True, separators=(",", ":")).encode()
                self.assertLessEqual(len(data), reader.MAX_JSON)
                self.assertEqual(reader.verify(data)["status"], "accepted")

    def test_boundaries_and_each_refusal_class(self) -> None:
        manifest = json.loads(MANIFEST.read_bytes())
        for case in manifest["cases"]:
            with self.subTest(case=case["id"]):
                data = (ROOT / case["path"]).read_bytes()
                try:
                    result = reader.verify(data)
                except reader.Refusal as exc:
                    result = {"status": "refused", "reason": str(exc)}
                self.assertEqual({key: result[key] for key in ("status", "reason")},
                                 case["expected"])

    def test_nested_and_root_duplicates_are_refused(self) -> None:
        for data in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}'):
            with self.assertRaisesRegex(reader.Refusal, "duplicate-member"):
                reader.strict_json(data)

    def test_json_constants_invalid_utf8_depth_and_size_are_refused(self) -> None:
        for data in (b'NaN', b'Infinity', b'"\xff"'):
            with self.subTest(data_size=len(data)):
                with self.assertRaisesRegex(reader.Refusal, "json-syntax"):
                    reader.strict_json(data)
        with self.assertRaisesRegex(reader.Refusal, "json-depth-or-nodes"):
            reader.strict_json(b'[' * 40 + b']' * 40)
        with self.assertRaisesRegex(reader.Refusal, "json-size"):
            reader.strict_json(b" " * (reader.MAX_JSON + 1))

    def test_historical_files_are_unchanged(self) -> None:
        sources = json.loads((ROOT / "SOURCE-INPUTS.json").read_bytes())
        offline = ROOT.parent / "agentid-offline"
        for item in sources["files"]:
            with self.subTest(path=item["path"]):
                self.assertEqual(hashlib.sha256((offline / item["path"]).read_bytes()).hexdigest(),
                                 item["sha256"])
        self.assertEqual(hashlib.sha256((offline / "reader.py").read_bytes()).hexdigest(),
                         sources["native_reader_source"]["sha256"])

    def test_manifest_selected_bytes_and_population_use_posix_paths(self) -> None:
        manifest = json.loads(MANIFEST.read_bytes())
        members = manifest["cases"] + manifest["sources"]
        self.assertTrue(all("\\" not in item["path"] for item in members))
        report = reader.corpus(MANIFEST, reader.sha256(MANIFEST.read_bytes()))
        self.assertEqual(report["matched"], 36)
        self.assertEqual(report["planned"], 36)
        self.assertTrue(report["unsigned"])
        self.assertFalse(report["host_adoption"])
        with self.assertRaisesRegex(reader.Refusal, "manifest-pin"):
            reader.corpus(MANIFEST, "0" * 64)


    def test_autocrlf_checkout_preserves_pinned_historical_input_bytes(self) -> None:
        sources = json.loads((ROOT / "SOURCE-INPUTS.json").read_bytes())
        pinned = {item["path"]: item["sha256"] for item in sources["files"]}
        pinned["reader.py"] = sources["native_reader_source"]["sha256"]
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            relative = "interop/agentid-offline/"
            result = subprocess.run(
                ["git", "-c", "core.autocrlf=true", "checkout-index",
                 "--prefix=" + destination.as_posix() + "/",
                 *(relative + name for name in pinned)],
                cwd=ROOT.parents[1], capture_output=True, text=True, check=False,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            for name, digest in pinned.items():
                with self.subTest(path=name):
                    self.assertEqual(hashlib.sha256(
                        (destination / relative / name).read_bytes()).hexdigest(), digest)

    def test_native_windows_paths_match_posix_manifest_population(self) -> None:
        # PureWindowsPath supplies the real Windows separator semantics on any host.
        class WindowsEntry:
            def __init__(self, path: Path) -> None:
                self.relative = PureWindowsPath(path.relative_to(ROOT).as_posix())

            def relative_to(self, _root: Path) -> PureWindowsPath:
                return self.relative

        entries = [WindowsEntry(path) for path in (ROOT / "cases").iterdir()]
        self.assertTrue(all("\\" in str(item.relative) for item in entries))
        with patch.object(Path, "iterdir", return_value=iter(entries)):
            report = reader.corpus(MANIFEST, reader.sha256(MANIFEST.read_bytes()))
        self.assertEqual(report["matched"], report["planned"])


class ProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.copy = self.root / "candidate"
        shutil.copytree(ROOT, self.copy, ignore=shutil.ignore_patterns("__pycache__"))

    def command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(self.copy / "reader.py"), *args],
                              text=True, capture_output=True, check=False, timeout=20)

    def run_corpus(self, output: Path, pin: str | None = None,
                   manifest: Path | None = None) -> subprocess.CompletedProcess[str]:
        manifest = manifest or self.copy / "MANIFEST.json"
        return self.command("corpus", str(manifest), "--manifest-sha256",
                            pin or reader.sha256(manifest.read_bytes()),
                            "--output-dir", str(output))

    def assert_refused(self, result: subprocess.CompletedProcess[str], reason: str) -> None:
        # Exit 2 alone cannot tell the intended refusal from any other one.
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stderr)["status"], "refused")
        self.assertEqual(json.loads(result.stderr)["reason"], reason)

    def assert_output_exists(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stderr)["status"], "refused")
        self.assertEqual(json.loads(result.stderr)["errno"], errno.EEXIST, result.stderr)

    def test_actual_accept_and_refuse_exit_codes(self) -> None:
        self.assertEqual(self.command("check", str(self.copy / "cases/ATF-001.json")).returncode, 0)
        self.assert_refused(self.command("check", str(self.copy / "cases/ATF-010.json")),
                            "tuple-mismatch")

    def test_fresh_report_and_stale_output_refusal(self) -> None:
        output = self.root / "first"
        first = self.run_corpus(output)
        self.assertEqual(first.returncode, 0, first.stderr)
        before = (output / "report.json").read_bytes()
        self.assert_output_exists(self.run_corpus(output))
        self.assertEqual((output / "report.json").read_bytes(), before)
        empty = self.root / "empty"
        empty.mkdir()
        self.assert_output_exists(self.run_corpus(empty))
        self.assertFalse((empty / "report.json").exists())

    def test_symlinked_directory_above_the_corpus_is_not_refused(self) -> None:
        # The directories above the manifest are where a checkout lives, not
        # corpus members: macOS /tmp, a linked home or a linked TMPDIR. The
        # test makes that ancestor a symlink itself instead of relying on
        # whatever the ambient temporary directory happens to be.
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        output = self.root / "through-link"
        result = self.run_corpus(output, manifest=linked / "candidate" / "MANIFEST.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((output / "report.json").read_bytes())
        self.assertEqual(report["matched"], report["planned"])

    def test_symlinked_directory_inside_the_corpus_refuses(self) -> None:
        cases = self.copy / "cases"
        moved = self.root / "cases-elsewhere"
        cases.rename(moved)
        cases.symlink_to(moved, target_is_directory=True)
        output = self.root / "linked-cases"
        self.assert_refused(self.run_corpus(output), "pin-symlink")
        self.assertFalse((output / "report.json").exists())

    def test_wrong_selected_pin_and_changed_reader_refuse_without_report(self) -> None:
        output = self.root / "wrong-pin"
        self.assert_refused(self.run_corpus(output, "0" * 64), "manifest-pin")
        self.assertFalse((output / "report.json").exists())
        path = self.copy / "reader.py"
        path.write_bytes(path.read_bytes() + b"\n# changed source\n")
        output = self.root / "changed-reader"
        self.assert_refused(self.run_corpus(output), "pin-digest")
        self.assertFalse((output / "report.json").exists())

    def test_changed_case_extra_case_and_symlink_refuse(self) -> None:
        case = self.copy / "cases/ATF-001.json"
        original = case.read_bytes()
        case.write_bytes(original + b"\n")
        self.assert_refused(self.run_corpus(self.root / "changed-case"), "pin-digest")
        case.write_bytes(original)
        extra = self.copy / "cases/extra.json"
        extra.write_bytes(original)
        self.assert_refused(self.run_corpus(self.root / "extra-case"), "corpus-population")
        extra.unlink()
        case.unlink()
        case.symlink_to(ROOT / "cases/ATF-001.json")
        self.assert_refused(self.run_corpus(self.root / "symlink"), "pin-symlink")


if __name__ == "__main__":
    unittest.main()
