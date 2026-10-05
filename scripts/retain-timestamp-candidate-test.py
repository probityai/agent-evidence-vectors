#!/usr/bin/env python3
"""Check actual capture CLI and workflow failures without claiming cryptographic validation."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).with_name("retain-timestamp-candidate.py")
WORKFLOW = SOURCE.parents[1] / ".github/workflows/ots-upgrade.yml"
SPEC = importlib.util.spec_from_file_location("candidate", SOURCE)
assert SPEC is not None and SPEC.loader is not None
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)


def workflow_blocks() -> list[str]:
    """Read the maintained workflow's exact step blocks, not a second command implementation."""
    return WORKFLOW.read_text().split("      - ")[1:]


def workflow_command(block: str) -> str:
    lines = block.split("        run: |\n", 1)[1].splitlines()
    command = []
    for line in lines:
        if line and not line.startswith("          "):
            break
        command.append(line[10:])
    return "\n".join(command) + "\n"


class CandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        for relative in candidate.MEMBERS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode())
        (self.root / candidate.MEMBERS[0]).write_bytes(base64.b64encode(b"fixture raw signature"))
        self.script = self.root / "scripts" / SOURCE.name
        self.script.parent.mkdir()
        shutil.copyfile(SOURCE, self.script)
        shutil.copyfile(
            SOURCE.with_name("release-timestamps.sh"),
            self.script.with_name("release-timestamps.sh"),
        )
        self.git("init", "-q")
        self.git("add", ".")
        self.commit("fixture")
        self.destination = Path(self.temp.name) / "candidate"
        self.destination.mkdir()
        for name in candidate.LOGS:
            (self.destination / name).write_text("fixture output, no chain result asserted\n")
        source = patch.object(candidate, "REPO", self.root)
        source.start()
        self.addCleanup(source.stop)

    def git(self, *args: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.root), *args], capture_output=True, check=True
        ).stdout

    def commit(self, message: str) -> None:
        self.git(
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            message,
        )

    def retain(self, upgrade: str = "success", verify: str = "success") -> dict[str, object]:
        return candidate.retain(self.destination, upgrade, verify)

    def cli(
        self, upgrade: str = "success", verify: str = "success"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.script), str(self.destination), upgrade, verify],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def save_capture(
        self, name: str, result: subprocess.CompletedProcess[str], stages=None
    ) -> None:
        evidence = os.environ.get("TIMESTAMP_CAPTURE_EVIDENCE")
        if not evidence:
            return
        out = Path(evidence) / name
        out.mkdir(parents=True)
        shutil.copytree(self.destination, out / "candidate")
        (out / "stdout.json").write_text(result.stdout)
        (out / "stderr.txt").write_text(result.stderr)
        (out / "outcome.json").write_text(
            json.dumps(
                {
                    "exitCode": result.returncode,
                    "stages": stages,
                    "scope": (
                        "controlled fixture processes; "
                        "no real cryptography, GitHub upload or calendar result"
                    ),
                },
                indent=2,
            )
            + "\n"
        )
        self.git("bundle", "create", str(out / "fixture-source.bundle"), "--all")

    def test_unchanged_candidate_pins_every_byte_and_source(self) -> None:
        report = self.retain()
        self.assertEqual(report["decision"], "eligible-for-ordinary-review")
        self.assertFalse(report["proofChanged"])
        self.assertEqual(report["sourceCommit"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(len(report["members"]), 7)
        for member in report["members"]:
            raw = (self.destination / member["path"]).read_bytes()
            self.assertEqual(member["state"], "present")
            self.assertEqual(len(raw), member["bytes"])
            self.assertEqual(candidate.hashlib.sha256(raw).hexdigest(), member["sha256"])
        self.assertIn("not an observation", report["members"][0]["role"])

    def test_changed_proof_keeps_source_original_and_excludes_backup(self) -> None:
        proof = self.root / candidate.MEMBERS[2]
        original = proof.read_bytes()
        proof.write_bytes(original + b"fixture extension")
        proof.with_suffix(".ots.bak").write_bytes(original)
        report = self.retain()
        self.assertTrue(report["proofChanged"])
        self.assertEqual((self.destination / "original.ots").read_bytes(), original)
        self.assertFalse(any(member["path"].endswith(".bak") for member in report["members"]))

    def test_substituted_original_refuses_before_copy(self) -> None:
        (self.destination / "original.ots").write_bytes(b"other proof")
        with self.assertRaisesRegex(ValueError, "refuse to replace"):
            self.retain()
        self.assertEqual((self.destination / "original.ots").read_bytes(), b"other proof")
        self.assertFalse((self.destination / "release").exists())

    def test_changed_validation_input_is_retained_then_refused(self) -> None:
        (self.root / candidate.MEMBERS[0]).write_bytes(b"changed validation")
        report = self.retain()
        self.assertEqual(report["decision"], "capture-only-refused")
        self.assertEqual(
            (self.destination / candidate.MEMBERS[0]).read_bytes(), b"changed validation"
        )
        self.assertTrue(any("validation input differs" in error for error in report["errors"]))

    def test_source_symlink_refuses_copy_but_retains_other_inputs(self) -> None:
        source = self.root / candidate.MEMBERS[2]
        outside = Path(self.temp.name) / "outside.ots"
        outside.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(outside)
        report = self.retain()
        self.assertEqual(report["decision"], "capture-only-refused")
        self.assertFalse((self.destination / candidate.MEMBERS[2]).exists())
        self.assertEqual(
            next(row for row in report["members"] if row["path"] == candidate.MEMBERS[2])["state"],
            "refused",
        )
        self.assertTrue((self.destination / candidate.MEMBERS[0]).is_file())

    def test_destination_directory_symlink_refuses_without_outside_write(self) -> None:
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.destination / "release").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "destination contains a symlink"):
            self.retain()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.destination / "original.ots").exists())

    def test_checkout_ancestor_symlink_is_not_a_member(self) -> None:
        mapped = Path(self.temp.name) / "mapped-source"
        mapped.symlink_to(self.root, target_is_directory=True)
        with patch.object(candidate, "REPO", mapped):
            self.assertEqual(self.retain()["decision"], "eligible-for-ordinary-review")

    def test_repeated_retention_refuses_existing_members(self) -> None:
        first = self.retain()
        before = {
            member["path"]: (self.destination / member["path"]).read_bytes()
            for member in first["members"]
        }
        with self.assertRaisesRegex(ValueError, "refuse to replace"):
            self.retain()
        self.assertTrue(
            all((self.destination / path).read_bytes() == raw for path, raw in before.items())
        )

    def test_missing_verification_log_retains_inputs_then_refuses(self) -> None:
        (self.destination / "verify.log").unlink()
        report = self.retain()
        self.assertEqual(report["decision"], "capture-only-refused")
        self.assertTrue(
            all((self.destination / relative).exists() for relative in candidate.MEMBERS)
        )
        self.assertEqual(
            next(row for row in report["members"] if row["path"] == "verify.log")["state"],
            "missing",
        )

    def test_every_copy_collision_preflights_before_any_new_member(self) -> None:
        for index, relative in enumerate(("manifest.json", "original.ots", *candidate.MEMBERS)):
            with self.subTest(relative=relative):
                destination = Path(self.temp.name) / f"collision-{index}"
                target = destination / relative
                target.parent.mkdir(parents=True)
                target.write_bytes(b"existing")
                with self.assertRaisesRegex(ValueError, "refuse to replace"):
                    candidate.retain(destination, "success", "success")
                self.assertEqual(
                    [
                        path.relative_to(destination).as_posix()
                        for path in destination.rglob("*")
                        if path.is_file()
                    ],
                    [relative],
                )
                self.assertEqual(target.read_bytes(), b"existing")

    def test_log_symlink_refuses_all_writes(self) -> None:
        log = self.destination / "verify.log"
        outside = Path(self.temp.name) / "outside-log"
        outside.write_bytes(b"outside")
        log.unlink()
        log.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.retain()
        self.assertFalse((self.destination / "original.ots").exists())
        self.assertEqual(outside.read_bytes(), b"outside")

    def test_successful_real_cli_writes_manifest(self) -> None:
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, json.loads((self.destination / "manifest.json").read_text()))
        self.assertEqual(report["decision"], "eligible-for-ordinary-review")
        self.save_capture("cli-success", result)

    def test_failed_verification_real_cli_retains_changed_proof_and_manifest(self) -> None:
        proof = self.root / candidate.MEMBERS[2]
        proof.write_bytes(proof.read_bytes() + b"failed attempt extension")
        result = self.cli(verify="failure")
        self.assertEqual(result.returncode, 1)
        report = json.loads((self.destination / "manifest.json").read_text())
        self.assertEqual(report["stages"]["verify"]["outcome"], "failure")
        self.assertTrue(report["proofChanged"])
        self.assertEqual((self.destination / candidate.MEMBERS[2]).read_bytes(), proof.read_bytes())
        self.assertNotIn("exitCode", report["stages"]["verify"])
        self.save_capture("cli-failed-verify", result)

    def test_missing_and_empty_log_states_survive_real_cli_failure(self) -> None:
        (self.destination / "verify.log").unlink()
        (self.destination / "upgrade.log").write_bytes(b"")
        result = self.cli("failure", "skipped")
        self.assertEqual(result.returncode, 1)
        report = json.loads((self.destination / "manifest.json").read_text())
        self.assertEqual(
            {
                row["path"]: row["state"]
                for row in report["members"]
                if row["path"] in candidate.LOGS
            },
            {"upgrade.log": "empty", "verify.log": "missing"},
        )
        self.assertTrue(
            all((self.destination / relative).is_file() for relative in candidate.MEMBERS)
        )
        self.save_capture("cli-missing-log", result)

    def test_changed_validation_real_cli_retains_actual_bytes_before_nonzero(self) -> None:
        path = self.root / candidate.MEMBERS[0]
        path.write_bytes(b"changed signature input")
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["decision"], "capture-only-refused")
        self.assertEqual((self.destination / candidate.MEMBERS[0]).read_bytes(), path.read_bytes())
        self.save_capture("cli-changed-validation", result)

    def test_skipped_and_cancelled_stages_are_never_eligible(self) -> None:
        for state in ("skipped", "cancelled"):
            with self.subTest(state=state):
                destination = Path(self.temp.name) / state
                report = candidate.retain(destination, state, state)
                self.assertEqual(report["decision"], "capture-only-refused")
                self.assertEqual(report["stages"]["upgrade"]["outcome"], state)

    def test_missing_and_empty_validation_members_are_recorded_before_cli_refusal(self) -> None:
        (self.root / candidate.MEMBERS[1]).write_bytes(b"")
        (self.root / candidate.MEMBERS[3]).unlink()
        result = self.cli()
        self.assertEqual(result.returncode, 1)
        report = json.loads((self.destination / "manifest.json").read_text())
        states = {row["path"]: row["state"] for row in report["members"]}
        self.assertEqual(states[candidate.MEMBERS[1]], "empty")
        self.assertEqual(states[candidate.MEMBERS[3]], "missing")
        self.assertEqual((self.destination / candidate.MEMBERS[1]).read_bytes(), b"")
        self.assertFalse((self.destination / candidate.MEMBERS[3]).exists())
        self.assertTrue((self.destination / candidate.MEMBERS[2]).is_file())
        self.save_capture("cli-missing-validation", result)

    def test_source_identity_uses_one_head_even_when_ref_moves(self) -> None:
        initial = self.git("rev-parse", "HEAD").decode().strip()
        initial_tree = self.git("rev-parse", f"{initial}^{{tree}}").decode().strip()
        real_git = candidate.git
        calls = []

        def moving_git(*args):
            calls.append(args)
            result = real_git(*args)
            if args == ("rev-parse", "HEAD"):
                (self.root / "new-source.txt").write_bytes(b"new source")
                self.git("add", ".")
                self.commit("move HEAD during read")
            return result

        with patch.object(candidate, "git", moving_git):
            report = self.retain()
        self.assertEqual(report["sourceCommit"], initial)
        self.assertEqual(report["sourceTree"], initial_tree)
        self.assertNotEqual(self.git("rev-parse", "HEAD").decode().strip(), initial)
        self.assertEqual(calls.count(("rev-parse", "HEAD")), 1)
        self.assertTrue(all(initial in args[1] for args in calls if args[0] == "show"))
        self.assertIn(initial, next(args for args in calls if args[0] == "diff"))
        self.assertEqual(report["decision"], "capture-only-refused")

    def test_workflow_capture_runs_always_before_unique_always_upload(self) -> None:
        blocks = workflow_blocks()
        capture = next(block for block in blocks if "capture available attempt bytes" in block)
        upload = next(block for block in blocks if "actions/upload-artifact" in block)
        self.assertLess(blocks.index(capture), blocks.index(upload))
        self.assertIn("if: always()", capture)
        self.assertIn("if: always()", upload)
        self.assertIn("steps.upgrade.outcome", capture)
        self.assertIn("steps.verify.outcome", capture)
        self.assertIn("github.run_id", upload)
        self.assertIn("github.run_attempt", upload)
        self.assertIn("overwrite: false", upload)
        self.assertNotIn("continue-on-error", WORKFLOW.read_text())

    def test_actual_workflow_commands_keep_failed_upgrade_and_verify_captures(self) -> None:
        blocks = workflow_blocks()
        upgrade = next(block for block in blocks if "id: upgrade" in block)
        verify = next(block for block in blocks if "id: verify" in block)
        capture = next(block for block in blocks if "capture available attempt bytes" in block)
        stubs = Path(self.temp.name) / "stubs"
        stubs.mkdir()
        (stubs / "uv").write_text('#!/bin/sh\nwhile [ "$1" != bash ]; do shift; done\nexec "$@"\n')
        (stubs / "openssl").write_text("#!/bin/sh\nexit 0\n")
        (stubs / "ots").write_text("""#!/usr/bin/env python3
import os,sys
from pathlib import Path
command=sys.argv[1]
if command == "upgrade":
    path=Path(sys.argv[2]);raw=path.read_bytes()
    path.with_suffix(".ots.bak").write_bytes(raw)
    path.write_bytes(raw+b"controlled upgraded proof")
    print("controlled upgrade result; no calendar contacted")
    raise SystemExit(int(os.environ["FIXTURE_UPGRADE_EXIT"]))
if command == "info":
    print("File sha256 hash: mismatched-fixture-digest")
""")
        for stub in stubs.iterdir():
            stub.chmod(0o755)
        for exit_code in (0, 1):
            with self.subTest(upgradeExit=exit_code):
                runner = Path(self.temp.name) / f"runner-{exit_code}"
                environment = {
                    **os.environ,
                    "RUNNER_TEMP": str(runner),
                    "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                    "FIXTURE_UPGRADE_EXIT": str(exit_code),
                }
                result = subprocess.run(
                    ["bash", "-c", workflow_command(upgrade)],
                    cwd=self.root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, exit_code, result.stderr)
                stage_codes = {"upgrade": result.returncode, "verify": None}
                if result.returncode == 0:
                    verified = subprocess.run(
                        ["bash", "-c", workflow_command(verify)],
                        cwd=self.root,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(verified.returncode, 1)
                    stage_codes["verify"] = verified.returncode
                environment.update(
                    UPGRADE_OUTCOME="success" if exit_code == 0 else "failure",
                    VERIFY_OUTCOME="failure" if exit_code == 0 else "skipped",
                )
                captured = subprocess.run(
                    ["bash", "-c", workflow_command(capture)],
                    cwd=self.root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(captured.returncode, 1, captured.stderr)
                self.destination = runner / "timestamp-candidate"
                report = json.loads((self.destination / "manifest.json").read_text())
                self.assertEqual(report["decision"], "capture-only-refused")
                self.assertTrue(report["proofChanged"])
                self.assertEqual(
                    (self.destination / candidate.MEMBERS[2]).read_bytes(),
                    (self.root / candidate.MEMBERS[2]).read_bytes(),
                )
                self.assertFalse(
                    any(path.name.endswith(".bak") for path in self.destination.rglob("*"))
                )
                self.save_capture(f"workflow-upgrade-{exit_code}", captured, stage_codes)


if __name__ == "__main__":
    unittest.main()
