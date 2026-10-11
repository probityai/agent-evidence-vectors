"""Controls for setup-go v5's workspace file and precedence contract."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import shlex
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from _go_selector import JS_TRIM, SETUP_GO_REVISION, go_selector
from _workflow_test_fixture import fixture_git, fixture_source

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("go_selector_gate", HERE / "workflow-steps-gate.py")
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class GoSelectorControls(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.scratch.name)
        self.probe: dict[str, Any] = {}

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def select(self, inputs: dict[str, Any]) -> str:
        return go_selector(inputs, self.root, self.probe)

    def freeze(self, root: pathlib.Path) -> Any:
        fixture_git(root, "init", "-q")
        fixture_git(root, "add", ".")
        fixture_git(
            root,
            "-c",
            "user.name=Selector control",
            "-c",
            "user.email=control@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "Freeze input",
        )
        return fixture_source(GATE, root)

    def test_explicit_selector_overrides_even_a_missing_file(self) -> None:
        self.assertEqual(
            self.select({"go-version": " 1.24.x ", "go-version-file": "missing.mod"}),
            "1.24.x",
        )
        self.assertEqual(self.probe["ignored_go_version_file"], "missing.mod")
        self.assertNotIn("go_version_file", self.probe)

    def test_explicit_selector_without_file_and_missing_selection(self) -> None:
        self.assertEqual(self.select({"go-version": "1.24"}), "1.24")
        self.assertEqual(self.select({}), "")
        self.assertEqual(self.probe["selector_source"], "missing")

    def test_module_and_workspace_read_go_and_ignore_toolchain(self) -> None:
        for name in ("go.mod", "go.work"):
            with self.subTest(name=name):
                raw = (
                    b"// go 1.99\r\nmodule example.invalid/test\r\n"
                    b"go 1.24\r\ntoolchain go1.25.3\r\n"
                )
                (self.root / name).write_bytes(raw)
                self.assertEqual(self.select({"go-version-file": name}), "1.24")
                retained = self.probe["go_version_file"]
                self.assertEqual(retained["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(retained["bytes"], len(raw))
                self.assertEqual(retained["contents"], raw.decode())

    def test_version_file_trims_and_resolves_from_workspace(self) -> None:
        folder = self.root / "nested"
        folder.mkdir()
        (folder / ".go-version").write_text("\n 1.24.7 \n")
        self.assertEqual(self.select({"go-version-file": " nested/.go-version "}), "1.24.7")
        self.assertEqual(self.select({"go-version-file": str(folder / ".go-version")}), "1.24.7")

    def test_pinned_parser_uses_first_numeric_go_directive(self) -> None:
        for contents, expected in (
            ("toolchain go1.25.3\n", ""),
            (" go 1.24\n", ""),
            ("go\t1.24\n", ""),
            ("go 1.24rc1\ngo 1.25\n", "1.24"),
            ("go 1.24.7\n", "1.24.7"),
            ("go \u0661.24\n", ""),
        ):
            with self.subTest(contents=contents):
                (self.root / "go.mod").write_text(contents)
                self.assertEqual(self.select({"go-version-file": "go.mod"}), expected)

    def test_missing_file_and_directory_do_not_invent_selectors(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.select({"go-version-file": "missing.mod"})
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.select({"go-version-file": str(self.root)})

    def test_release_file_binds_fixture_go_and_runs_version_consumer(self) -> None:
        (self.root / "go.mod").write_text("go 1.24\ntoolchain go1.25.3\n", encoding="utf-8")
        source = self.freeze(self.root)
        checkout = self.root / "checkout"
        source.checkout(checkout)
        binary = self.root / "fixture-bin"
        binary.mkdir()
        executable = binary / "go"
        executable.write_text("#!/bin/sh\necho 'go version go1.24.7 linux/amd64'\n")
        executable.chmod(0o755)
        (binary / "gofmt").symlink_to(executable)
        job = GATE.JobState(str(self.root), "release", checkout)
        fixture_path = str(binary) + os.pathsep + "/usr/bin:/bin"
        job.env["PATH"] = fixture_path
        setup = GATE.Step(
            "release",
            0,
            "setup",
            None,
            f"actions/setup-go@{SETUP_GO_REVISION}",
            {"go-version-file": "go.mod"},
            workdir="nested",
        )
        (checkout / "nested").mkdir()
        sentinel = self.root / "consumer.version"
        consumer = GATE.Step(
            "release",
            1,
            "Go version consumer",
            "go version > " + shlex.quote(str(sentinel)),
            "",
            {},
            workdir="nested",
        )
        evidence = self.root / "evidence"
        evidence.mkdir()
        with patch.dict(os.environ, {"PATH": fixture_path}):
            GATE.execute_job([setup, consumer], job, source, evidence, {"PATH": fixture_path})
        GATE.retain_job(job, source, evidence)
        self.assertEqual((job.failed, job.ran), (0, 1))
        self.assertEqual(sentinel.read_text().strip(), "go version go1.24.7 linux/amd64")
        probes = json.loads((evidence / "provider-probes.json").read_text())
        self.assertEqual(probes[-1]["wanted"], "1.24")
        self.assertEqual(probes[-1]["route"], "existing PATH")
        self.assertEqual(probes[-1]["probes"][0]["stdout"].strip(), sentinel.read_text().strip())
        self.assertTrue(probes[-1]["go_version_file"]["matches_frozen_blob"])
        self.assertEqual(probes[-1]["go_version_file"]["source_commit"], source.head)
        source.verify()

    def test_javascript_line_starts_preserve_first_matching_directive(self) -> None:
        for separator in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                text = "module example.invalid/test" + separator + "go 1.24\ngo 1.25\n"
                (self.root / "go.mod").write_bytes(text.encode("utf-8"))
                self.assertEqual(self.select({"go-version-file": "go.mod"}), "1.24")

    def test_fixture_source_is_distinct_from_hosted_ci_identity(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GITHUB_SHA": "f" * 40,
                "GITHUB_HEAD_SHA": "a" * 40,
                "GITHUB_EVENT_NAME": "pull_request",
            },
        ):
            source = self.freeze(self.root)
            self.assertNotEqual(source.head, os.environ["GITHUB_SHA"])
            source.checkout(self.root / "checkout")
            source.verify()

    def test_explicit_repository_ignores_inherited_git_selectors(self) -> None:
        foreign = {
            "GIT_DIR": str(self.root / "foreign.git"),
            "GIT_WORK_TREE": str(self.root / "foreign-worktree"),
            "GIT_COMMON_DIR": str(self.root / "foreign-common"),
            "GIT_INDEX_FILE": str(self.root / "foreign-index"),
            "GIT_OBJECT_DIRECTORY": str(self.root / "foreign-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.root / "foreign-alternates"),
            "GIT_NAMESPACE": "foreign",
            "GIT_SHALLOW_FILE": str(self.root / "foreign-shallow"),
            "GIT_CEILING_DIRECTORIES": str(self.root),
            "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        }
        original = dict(os.environ)
        with patch.dict(os.environ, foreign):
            source = self.freeze(self.root)
            self.assertEqual(source.head, fixture_git(self.root, "rev-parse", "HEAD"))
            source.checkout(self.root / "checkout")
            source.verify()
            self.assertFalse(set(foreign) & GATE.git_environment().keys())
            self.assertEqual({key: os.environ[key] for key in foreign}, foreign)
            self.assertEqual(list(self.root.glob("foreign*")), [])
        self.assertEqual(dict(os.environ), original)

    def test_shared_fixture_preserves_real_authority_refusals(self) -> None:
        source = self.freeze(self.root)
        packet = source.branch_authority
        with (
            patch.dict(packet, {"selected_head": "0" * 40}),
            self.assertRaisesRegex(ValueError, "another selected source commit"),
        ):
            source.verify()
        packet["primary"]["repository"]["stdout"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "original stream hash changed"):
            source.verify()

    def test_real_job_ignores_inherited_foreign_repository(self) -> None:
        source = self.freeze(self.root)
        checkout = self.root / "checkout"
        source.checkout(checkout)
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "README.md").write_text("Foreign source must remain unchanged.\n")
        other = self.freeze(foreign)
        before = {name: (foreign / name).read_bytes() for name in ("README.md", ".git/index")}
        refs = fixture_git(foreign, "show-ref")
        poisoned = {
            "PATH": os.environ["PATH"],
            "GIT_DIR": str(foreign / ".git"),
            "GIT_WORK_TREE": str(foreign),
            "GIT_COMMON_DIR": str(foreign / ".git"),
            "GIT_INDEX_FILE": str(foreign / ".git/index"),
            "GIT_OBJECT_DIRECTORY": str(foreign / ".git/objects"),
        }
        output = self.root / "actual-child-root"
        job = GATE.JobState(str(self.root), "isolated", checkout)
        job.env.update(poisoned)
        steps = [
            GATE.Step(
                "isolated",
                0,
                "actual Git consumer",
                "git rev-parse --show-toplevel > " + shlex.quote(str(output)),
                "",
                {},
            )
        ]
        evidence = self.root / "isolated-evidence"
        with patch.dict(os.environ, poisoned):
            GATE.execute_job(steps, job, source, evidence, poisoned)
            self.assertEqual({key: os.environ[key] for key in poisoned}, poisoned)
        self.assertEqual((job.failed, job.ran), (0, 1))
        self.assertEqual(output.read_text().strip(), str(checkout))
        self.assertEqual(fixture_git(foreign, "show-ref"), refs)
        self.assertEqual({name: (foreign / name).read_bytes() for name in before}, before)
        source.verify()
        other.verify()

    def test_trim_matches_javascript_and_preserves_other_controls(self) -> None:
        path = self.root / ".go-version"
        path.write_bytes((JS_TRIM + "1.24.7" + JS_TRIM).encode("utf-8"))
        self.assertEqual(self.select({"go-version-file": path.name}), "1.24.7")
        for retained in ("\u0085", "\u001c", "\u001d", "\u001e", "\u001f"):
            with self.subTest(retained=repr(retained)):
                path.write_bytes((retained + "1.24" + retained).encode("utf-8"))
                self.assertEqual(
                    self.select({"go-version-file": path.name}), retained + "1.24" + retained
                )

    def test_non_utf8_capture_reconstructs_original_bytes(self) -> None:
        raw = b"module x\n// \xff\ngo 1.24\n"
        (self.root / "go.mod").write_bytes(raw)
        self.assertEqual(self.select({"go-version-file": "go.mod"}), "1.24")
        retained = self.probe["go_version_file"]
        self.assertFalse(retained["valid_utf8"])
        self.assertEqual(base64.b64decode(retained["contents_base64"]), raw)

    def test_null_and_boolean_inputs_use_actions_rendering(self) -> None:
        (self.root / ".go-version").write_bytes(b"1.24\n")
        self.assertEqual(
            self.select({"go-version": None, "go-version-file": ".go-version"}), "1.24"
        )
        self.assertEqual(self.select({"go-version": True}), "true")
        self.assertEqual(self.select({"go-version": False}), "false")

    def test_trailing_slash_dot_missing_and_symlink_cycle_refuse(self) -> None:
        (self.root / "go.mod").write_bytes(b"go 1.24\n")
        (self.root / "cycle").symlink_to("cycle")
        (self.root / "dangling").symlink_to("absent")
        for name in ("go.mod/", "go.mod/.", "cycle", "dangling"):
            with self.subTest(name=name), self.assertRaises(OSError):
                self.select({"go-version-file": name})
            self.assertEqual(self.probe["requested_go_version_file"], name)

    def test_fifo_and_device_refuse_without_blocking(self) -> None:
        os.mkfifo(self.root / "fifo")
        for name in ("fifo", "/dev/zero"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "regular file"):
                self.select({"go-version-file": name})

    def test_external_symlink_capture_does_not_claim_frozen_source(self) -> None:
        with tempfile.TemporaryDirectory() as external:
            target = pathlib.Path(external) / "version"
            target.write_bytes(b"1.24\n")
            (self.root / "linked").symlink_to(target)
            self.assertEqual(self.select({"go-version-file": "linked"}), "1.24")
            retained = self.probe["go_version_file"]
            self.assertEqual(retained["link_text"], str(target))
            self.assertFalse(retained["inside_workspace"])
            self.assertFalse(retained["matches_frozen_blob"])
            self.assertEqual(retained["source_class"], "external captured input")

    def test_permission_error_retains_requested_route_and_blocks_binding(self) -> None:
        job = GATE.JobState(str(self.root), "permission", self.root)
        step = GATE.Step(
            "release",
            0,
            "setup",
            None,
            f"actions/setup-go@{SETUP_GO_REVISION}",
            {"go-version-file": "go.mod"},
        )
        with (
            patch("_go_selector.os.open", side_effect=PermissionError("control permission")),
            patch.object(GATE, "ensure_provider") as provider,
        ):
            self.assertIn("control permission", GATE.provider_problem(step, job))
            provider.assert_not_called()
        self.assertEqual(job.provider_probes[-1]["requested_go_version_file"], "go.mod")

    def test_uncaptured_action_revision_refuses_before_provider(self) -> None:
        for ref in ("v5", "v4", "main", "other-commit"):
            with self.subTest(ref=ref):
                job = GATE.JobState(str(self.root), "revision", self.root)
                step = GATE.Step(
                    "release", 0, "setup", None, "actions/setup-go@" + ref, {"go-version": "1.24"}
                )
                with patch.object(GATE, "ensure_provider") as provider:
                    self.assertIn("captured action revision", GATE.provider_problem(step, job))
                    provider.assert_not_called()

    def test_inside_symlink_matches_blob_and_changed_target_is_distinguished(self) -> None:
        target = self.root / ".go-version"
        target.write_bytes(b"1.24\n")
        (self.root / "linked").symlink_to(target.name)
        source = self.freeze(self.root)
        self.assertEqual(self.select({"go-version-file": "linked"}), "1.24")
        retained = self.probe["go_version_file"]
        self.assertTrue(retained["matches_frozen_blob"])
        self.assertEqual(retained["source_commit"], source.head)
        self.assertEqual(retained["source_path"], ".go-version")
        target.write_bytes(b"1.25\n")
        self.assertEqual(self.select({"go-version-file": "linked"}), "1.25")
        self.assertFalse(self.probe["go_version_file"]["matches_frozen_blob"])

    def test_wrong_fixture_go_version_refuses_and_blocks_consumer(self) -> None:
        (self.root / "go.mod").write_bytes(b"go 1.24\ntoolchain go1.25.3\n")
        source = self.freeze(self.root)
        binary = self.root / "fixture-bin"
        binary.mkdir()
        executable = binary / "go"
        executable.write_text(
            "#!/bin/sh\necho 'go version go1.25.1 linux/amd64'\n", encoding="utf-8"
        )
        executable.chmod(0o755)
        (binary / "gofmt").symlink_to(executable)
        job = GATE.JobState(str(self.root), "wrong-go", self.root)
        fixture_path = str(binary) + os.pathsep + "/usr/bin:/bin"
        sentinel = self.root / "child.started"
        setup = GATE.Step(
            "release",
            0,
            "setup",
            None,
            f"actions/setup-go@{SETUP_GO_REVISION}",
            {"go-version-file": "go.mod"},
        )
        consumer = GATE.Step("release", 1, "child", "touch " + shlex.quote(str(sentinel)), "", {})
        with (
            patch.dict(os.environ, {"PATH": fixture_path}),
            patch("_native_provider.inventory", return_value=None),
            patch(
                "_native_provider.release", side_effect=ValueError("no matching fixture release")
            ),
        ):
            GATE.execute_job(
                [setup, consumer], job, source, self.root / "evidence", {"PATH": fixture_path}
            )
        self.assertEqual((job.failed, job.ran), (1, 0))
        self.assertFalse(sentinel.exists())
        self.assertIn("go1.25.1", job.provider_probes[-1]["probes"][0]["stdout"])
        self.assertEqual(job.provider_probes[-1]["wanted"], "1.24")

    def test_file_selection_failure_blocks_real_consumer(self) -> None:
        cases: tuple[tuple[str, str | None, dict[str, str]], ...] = (
            ("go.mod", None, {"go-version-file": "go.mod"}),
            ("go.mod", "module example.invalid/no-version\n", {"go-version-file": "go.mod"}),
            (".go-version", "stable\n", {"go-version-file": ".go-version"}),
            ("go.mod", None, {}),
        )
        for index, (filename, contents, inputs) in enumerate(cases):
            with self.subTest(contents=contents):
                root = self.root / f"case-{index}"
                root.mkdir()
                if contents is not None:
                    (root / filename).write_text(contents, encoding="utf-8")
                source = self.freeze(root)
                job = GATE.JobState(str(self.root), f"blocked-{index}", root)
                setup = GATE.Step(
                    "release",
                    0,
                    "setup",
                    None,
                    "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
                    inputs,
                )
                sentinel = self.root / f"child-{index}.started"
                child = GATE.Step(
                    "release", 1, "child", "touch " + shlex.quote(str(sentinel)), "", {}
                )
                with patch.object(GATE, "ensure_provider", wraps=GATE.ensure_provider) as provider:
                    GATE.execute_job([setup, child], job, source, root / "evidence", {})
                    if inputs and contents is None:
                        provider.assert_not_called()
                self.assertEqual(job.failed, 1)
                self.assertEqual(job.ran, 0)
                self.assertFalse(sentinel.exists())
                retained = json.loads((root / "evidence/steps/1/result.json").read_text())
                self.assertEqual(retained["status"], "NOT_RUN")
                self.assertIn("no dependent shell ran", retained["reason"])


if __name__ == "__main__":
    unittest.main()
