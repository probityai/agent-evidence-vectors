#!/usr/bin/env python3
"""Run real fixture tools against provider binding, archive and refusal controls."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import shlex
import shutil
import sys
import tarfile
import tempfile
import unittest
from collections.abc import Sequence
from typing import Any
from unittest.mock import patch

import _native_provider as P

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "native_provider_gate", HERE / "workflow-steps-gate.py"
)
assert SPEC and SPEC.loader
GATE: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def executable(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + text + "\n")
    path.chmod(0o755)


def archive(path: pathlib.Path, members: Sequence[tuple[str, bytes | str, str]]) -> None:
    with tarfile.open(path, "w:gz") as output:
        for name, data, kind in members:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            if kind == "link":
                member.type = tarfile.SYMTYPE
                assert isinstance(data, str)
                member.linkname = data
                output.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                output.addfile(member)
            else:
                assert isinstance(data, bytes)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))


class ProviderControls(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="native-provider-controls-")
        self.root = pathlib.Path(self.scratch.name)
        self.temp = self.root / "job"
        self.temp.mkdir()
        self.bin = self.root / "original-bin"
        executable(self.bin / "go", "echo go version go1.26.3 fixture")
        executable(self.bin / "gofmt", "exit 0")
        executable(self.bin / "node", "echo v20.20.2")
        executable(self.bin / "npm", "exit 0")
        executable(self.bin / "npx", "exit 0")
        self.env = {"PATH": str(self.bin), "GOROOT": "/original-scope"}
        self.ambient = dict(os.environ)
        self.payload = self.root / "fixture.tar.gz"
        self.members = [
            ("go/bin/go", b"#!/bin/sh\necho go version go1.24.13 fixture\n", "file"),
            ("go/bin/gofmt", b"#!/bin/sh\nexit 0\n", "file"),
        ]
        self.record: dict[str, Any] = {}

    def tearDown(self) -> None:
        self.assertEqual(dict(os.environ), self.ambient)
        self.assertEqual(self.env, {"PATH": str(self.bin), "GOROOT": "/original-scope"})
        self.scratch.cleanup()

    def fixture_download(self, url: str, destination: pathlib.Path, env: dict[str, str]) -> None:
        if "SHASUMS256" in url:
            destination.write_text(P.digest(self.payload) + "  node-v22.23.3-linux-x64.tar.gz\n")
        elif url.endswith("index.json"):
            destination.write_text(json.dumps([{"version": "v22.23.3"}]))
        elif "mode=json" in url:
            destination.write_text(
                json.dumps(
                    [
                        {
                            "version": "go1.24.13",
                            "stable": True,
                            "files": [
                                {
                                    "filename": "go1.24.13.linux-amd64.tar.gz",
                                    "os": "linux",
                                    "arch": "amd64",
                                    "kind": "archive",
                                    "sha256": P.digest(self.payload),
                                }
                            ],
                        }
                    ]
                )
            )
        else:
            shutil.copyfile(self.payload, destination)

    def ensure(self, kind: str = "go", wanted: str = "1.24") -> tuple[Any, Any]:
        with (
            patch.object(P, "download", self.fixture_download),
            patch.object(P.platform, "system", return_value="Linux"),
            patch.object(P.platform, "machine", return_value="x86_64"),
        ):
            return P.ensure(kind, wanted, self.env, self.temp, self.record)

    def test_real_archive_tools_and_original_mismatch_are_retained(self) -> None:
        archive(self.payload, self.members)
        binary, goroot = self.ensure()
        self.assertTrue(binary.is_relative_to(self.temp))
        self.assertEqual(goroot, binary.parent)
        self.assertTrue(self.record["archiveVerified"])
        self.assertIn("1.26.3", self.record["probes"][0]["stdout"])
        self.assertIn("1.24.13", self.record["probes"][-1]["stdout"])
        self.assertEqual(
            P.digest(self.temp / self.record["inputDirectory"] / "archive.tar.gz"),
            P.digest(self.payload),
        )
        # Repeated valid providers keep independent original inputs.
        first = self.record["inputDirectory"]
        self.ensure()
        self.assertNotEqual(self.record["inputDirectory"], first)

    def test_matching_path_needs_no_download(self) -> None:
        with patch.object(P, "download", side_effect=AssertionError("unexpected download")):
            self.assertEqual(P.ensure("go", "1.26", self.env, self.temp, self.record), (None, None))
        self.assertEqual(self.record["route"], "existing PATH")

    def test_installed_inventory_is_probed_without_installing(self) -> None:
        installed = self.root / "maintained"
        executable(installed / "bin/go", "echo go version go1.24.13 fixture")
        executable(installed / "bin/gofmt", "exit 0")
        executable(
            self.bin / "mise", f"test \"$1\" = where || exit 9\nprintf '%s\\n' '{installed}'"
        )
        with patch.object(P, "download", side_effect=AssertionError("unexpected download")):
            binary, _ = P.ensure("go", "1.24", self.env, self.temp, self.record)
        self.assertEqual(binary, installed / "bin")
        self.assertEqual(self.record["route"], "maintained installed inventory")

    def test_failed_inventory_falls_back_to_verified_archive(self) -> None:
        executable(self.bin / "mise", "exit 9")
        archive(self.payload, self.members)
        self.ensure()
        self.assertTrue(self.record["archiveVerified"])

    def test_inventory_missing_tools_wrong_version_and_relative_path_refuse_reuse(self) -> None:
        installed = self.root / "unqualified"
        for reply in ["relative/path", str(installed)]:
            with self.subTest(reply=reply):
                executable(self.bin / "mise", f"printf '%s\\n' '{reply}'")
                self.assertIsNone(P.inventory("go", "1.24", self.env, self.temp, []))
        executable(installed / "bin/go", "echo go version go1.25.1 fixture")
        executable(installed / "bin/gofmt", "exit 0")
        self.assertIsNone(P.inventory("go", "1.24", self.env, self.temp, []))

    def test_probe_nonzero_malformed_output_and_missing_tools_refuse(self) -> None:
        for text in ["echo go version go1.24.13 fixture; exit 9", "echo unrelated-v1.24.13"]:
            with self.subTest(text=text):
                executable(self.bin / "go", text)
                self.assertEqual(P.probe("go", self.env, self.temp, "invalid", []), "")
        (self.bin / "gofmt").unlink()
        self.assertEqual(P.probe("go", self.env, self.temp, "missing", []), "")

    def test_release_metadata_and_checksum_ambiguity_refuse(self) -> None:
        archive(self.payload, self.members)
        malformed = [
            {},
            ["not a record"],
            [{"version": True}],
            [],
            [{"version": "go1.24.13", "stable": False}],
            [{"version": "go1.24.13", "stable": True, "files": [True]}],
            [{"version": "go1.24.13", "stable": True, "files": []}],
            [{"version": "go1.24.13"}, {"version": "go1.24.13"}],
        ]
        for document in malformed:
            with self.subTest(document=document):

                def altered(
                    url: str,
                    destination: pathlib.Path,
                    env: dict[str, str],
                    document: Any = document,
                ) -> None:
                    self.fixture_download(url, destination, env)
                    if destination.name == "index.json":
                        destination.write_text(json.dumps(document))

                with patch.object(P, "download", altered):
                    with self.assertRaises(ValueError):
                        P.release("go", "1.24", self.temp, self.env)
        for checksum in ["malformed", "duplicate"]:
            with self.subTest(checksum=checksum):

                def altered_sum(
                    url: str,
                    destination: pathlib.Path,
                    env: dict[str, str],
                    checksum: str = checksum,
                ) -> None:
                    self.fixture_download(url, destination, env)
                    if destination.name == "SHASUMS256.txt":
                        value = "malformed" if checksum == "malformed" else "0" * 64
                        text = value + "  node-v22.23.3-linux-x64.tar.gz\n"
                        destination.write_text(text if checksum == "malformed" else text + text)

                with patch.object(P, "download", altered_sum):
                    with self.assertRaises(ValueError):
                        P.release("node", "22", self.temp, self.env)

    def test_success_without_downloaded_file_refuses(self) -> None:
        executable(self.bin / "curl", "exit 0")
        with self.assertRaisesRegex(ValueError, "regular input"):
            P.download("https://go.dev/dl/fixture", self.temp / "absent", self.env)

    def test_vendor_node_symlinks_are_contained_and_all_tools_required(self) -> None:
        root = "node-v22.23.3-linux-x64"
        archive(
            self.payload,
            [
                (root + "/bin/node", b"#!/bin/sh\necho v22.23.3\n", "file"),
                (root + "/lib/npm", b"#!/bin/sh\nexit 0\n", "file"),
                (root + "/bin/npm", "../lib/npm", "link"),
                (root + "/bin/npx", "../lib/npm", "link"),
            ],
        )
        binary, goroot = self.ensure("node", "22")
        self.assertTrue((binary / "npm").is_symlink())
        self.assertIsNone(goroot)

    def test_checksum_mismatch_refuses_before_extraction(self) -> None:
        archive(self.payload, self.members)
        with (
            patch.object(P, "release", return_value=("1.24.13", "https://go.dev/dl/a", "0" * 64)),
            patch.object(P, "download", self.fixture_download),
        ):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                P.ensure("go", "1.24", self.env, self.temp, self.record)
        self.assertFalse(self.record["archiveVerified"])
        self.assertFalse((self.temp / "provider-runtime").exists())

    def test_unsafe_archive_members_refuse(self) -> None:
        hostile = [
            ("go/../escape", b"bad", "file"),
            ("/go/absolute", b"bad", "file"),
            ("go/escape", "../../escape", "link"),
            ("go/device", b"", "fifo"),
            ("go/bin/go/", b"bad", "file"),
        ]
        for index, member in enumerate(hostile):
            with self.subTest(member=member[0]):
                archive(self.payload, [*self.members, member])
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    P.extract(self.payload, self.root / f"unsafe-{index}", "go")
        archive(self.payload, [*self.members, self.members[0]])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            P.extract(self.payload, self.root / "duplicate", "go")

    def test_wrong_version_and_missing_archive_tool_refuse(self) -> None:
        for members in [
            self.members[:1],
            [
                ("go/bin/go", b"#!/bin/sh\necho go version go1.25.1 fixture\n", "file"),
                self.members[1],
            ],
        ]:
            with self.subTest(members=members):
                archive(self.payload, members)
                with self.assertRaisesRegex(ValueError, "executable"):
                    self.ensure()

    def test_invalid_selector_and_unsupported_platform_refuse(self) -> None:
        with self.assertRaisesRegex(ValueError, "numeric"):
            P.ensure("go", "stable", self.env, self.temp, self.record)
        with patch.object(P.platform, "system", return_value="unknown"):
            with self.assertRaisesRegex(ValueError, "platform"):
                P.platform_archive("go", "1.24.13")

    def test_actual_download_failure_keeps_process_bytes(self) -> None:
        executable(self.bin / "curl", "echo refused >&2; exit 9")
        target = self.temp / "download"
        with self.assertRaisesRegex(ValueError, "exit 9"):
            P.download("https://go.dev/dl/fixture", target, self.env)
        self.assertEqual((self.temp / "download.download.stderr.txt").read_text(), "refused\n")

    def test_required_provider_failure_blocks_real_dependent_command(self) -> None:
        job = GATE.JobState(str(self.root), "gate")
        job.env.update(self.env)
        step = GATE.Step(
            job="gate",
            position=0,
            name="setup",
            run=None,
            uses="actions/setup-go@v5",
            inputs={"go-version": "stable"},
        )
        block, reason, _ = GATE.resolve_in_job(step, job)
        self.assertIsNone(block)
        self.assertIn("numeric", job.blocked)
        self.assertEqual(job.failed, 1)
        next_step = GATE.Step(
            job="gate",
            position=1,
            name="consumer",
            run=f"touch '{self.root / 'consumer-ran'}'",
            uses="",
            inputs={},
        )
        block, reason, _ = GATE.resolve_in_job(next_step, job)
        self.assertIsNone(block)
        self.assertIn("no dependent shell ran", reason)
        self.assertFalse((self.root / "consumer-ran").exists())

    def test_job_input_and_runtime_symlinks_refuse_before_outside_writes(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        inputs = self.temp / "provider-inputs"
        inputs.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            self.ensure()
        self.assertEqual(list(outside.iterdir()), [])
        inputs.unlink()
        (self.temp / "provider-runtime").symlink_to(outside, target_is_directory=True)
        archive(self.payload, self.members)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            self.ensure()
        self.assertEqual(list(outside.iterdir()), [])

    def setup_consumer(
        self,
        action: str,
        key: str,
        selector: str,
        condition: str = "",
        uv_body: str | None = None,
        continue_on_error: bool = False,
    ) -> tuple[Any, pathlib.Path, pathlib.Path]:
        repo = pathlib.Path(tempfile.mkdtemp(prefix="consumer-source-", dir=self.root))
        (repo / "README.md").write_text("Harmless provider dependency control.\n")
        GATE.git(repo, "init", "--quiet")
        GATE.git(repo, "add", "README.md")
        GATE.git(
            repo,
            "-c",
            "user.name=Provider control",
            "-c",
            "user.email=provider-control@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test: retain provider dependency input",
        )
        with patch.dict(os.environ, {}, clear=True):
            source = GATE.Source(repo)
        job = GATE.JobState(str(self.root), repo.name, repo)
        path = "/usr/bin:/bin"
        if uv_body is not None:
            fixture_bin = job.temp / "fixture-bin"
            executable(fixture_bin / "uv", uv_body)
            path = f"{fixture_bin}:{path}"
        sentinel = job.temp / "consumer.started"
        command = shlex.join(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('started')",
                str(sentinel),
            ]
        )
        steps = [
            GATE.Step(
                job="dependency",
                position=0,
                name="required setup",
                run=None,
                uses=f"{action}@v5",
                inputs={key: selector},
                condition=condition,
                continue_on_error=continue_on_error,
            ),
            GATE.Step(
                job="dependency",
                position=1,
                name="actual child",
                run=command,
                uses="",
                inputs={},
            ),
        ]
        evidence = self.root / f"evidence-{repo.name}"
        with patch.dict(os.environ, {"PATH": path}):
            GATE.execute_job(steps, job, source, evidence, {"PATH": path})
        source.verify()
        return job, sentinel, evidence

    def test_unresolved_setup_inputs_refuse_and_never_start_actual_child(self) -> None:
        for action, key in (
            ("actions/setup-go", "go-version"),
            ("actions/setup-node", "node-version"),
            ("actions/setup-python", "python-version"),
        ):
            for selector in ("${{ format('unsupported') }}", "${{ unknown.version }}"):
                with self.subTest(action=action, selector=selector):
                    job, sentinel, evidence = self.setup_consumer(action, key, selector)
                    self.assertEqual(job.failed, 1)
                    self.assertEqual(job.ran, 0)
                    self.assertTrue(job.blocked)
                    self.assertFalse(sentinel.exists())
                    setup = json.loads((evidence / "steps/0/result.json").read_text())
                    child = json.loads((evidence / "steps/1/result.json").read_text())
                    self.assertEqual(setup["status"], "NOT_RUN")
                    self.assertTrue(setup["fault"])
                    self.assertEqual(child["status"], "NOT_RUN")
                    self.assertFalse(child["fault"])
                    self.assertEqual(child["reason"], job.blocked)
                    self.assertFalse((evidence / "steps/1/command.sh").exists())

    def test_proven_excluded_setup_does_not_resolve_inputs_or_block_child(self) -> None:
        for action, key in (
            ("actions/setup-go", "go-version"),
            ("actions/setup-node", "node-version"),
            ("actions/setup-python", "python-version"),
        ):
            with self.subTest(action=action):
                job, sentinel, evidence = self.setup_consumer(
                    action,
                    key,
                    "${{ format('unsupported') }}",
                    "github.event_name == 'schedule'",
                )
                self.assertEqual(job.failed, 0)
                self.assertEqual(job.ran, 1)
                self.assertEqual(job.blocked, "")
                self.assertEqual(sentinel.read_text(), "started")
                setup = json.loads((evidence / "steps/0/result.json").read_text())
                child = json.loads((evidence / "steps/1/result.json").read_text())
                self.assertEqual(setup["status"], "NOT_RUN")
                self.assertFalse(setup["fault"])
                self.assertIn("false for a push", setup["reason"])
                self.assertEqual(child["status"], "EXECUTED")
                self.assertEqual(child["returncode"], 0)

    def test_unavailable_exact_python_fails_and_never_starts_actual_child(self) -> None:
        for selector in ("9.9.9", ""):
            with self.subTest(selector=selector):
                job, sentinel, evidence = self.setup_consumer(
                    "actions/setup-python",
                    "python-version",
                    selector,
                    uv_body="echo no-exact-version; exit 0",
                )
                self.assertEqual(job.failed, 1)
                self.assertEqual(job.ran, 0)
                self.assertIn("interpreter was not provisioned", job.blocked)
                self.assertFalse(sentinel.exists())
                setup = json.loads((evidence / "steps/0/result.json").read_text())
                child = json.loads((evidence / "steps/1/result.json").read_text())
                self.assertTrue(setup["fault"])
                self.assertEqual(child["status"], "NOT_RUN")
                self.assertEqual(child["reason"], job.blocked)

    def test_failed_python_provisioning_never_starts_actual_child(self) -> None:
        for continued in (False, True):
            with self.subTest(continue_on_error=continued):
                job, sentinel, evidence = self.setup_consumer(
                    "actions/setup-python",
                    "python-version",
                    "9.9.9",
                    uv_body='if [ "$1" = python ]; then '
                    "echo cpython-9.9.9-linux-x86_64-none; exit 0; fi\n"
                    "echo provisioning-refused >&2; exit 7",
                    continue_on_error=continued,
                )
                self.assertEqual(job.failed, 1)
                self.assertEqual(job.ran, 1)
                self.assertIn("actions/setup-python exited 7", job.blocked)
                self.assertFalse(sentinel.exists())
                setup = json.loads((evidence / "steps/0/result.json").read_text())
                child = json.loads((evidence / "steps/1/result.json").read_text())
                self.assertEqual(setup["status"], "EXECUTED")
                self.assertEqual(setup["returncode"], 7)
                self.assertEqual(setup["continue_on_error"], continued)
                self.assertEqual(
                    (evidence / "steps/0/stderr").read_text(), "provisioning-refused\n"
                )
                self.assertEqual(child["status"], "NOT_RUN")
                self.assertEqual(child["reason"], job.blocked)
                self.assertFalse((evidence / "steps/1/command.sh").exists())

    def test_original_archive_retention_and_symlink_refusal(self) -> None:
        archive(self.payload, self.members)
        self.ensure()
        job = GATE.JobState(str(self.root), "retain")
        job.temp = self.temp
        job.provider_probes = [self.record]
        retained = self.root / "retained"
        GATE.retain_provider_archives(job, retained)
        target = retained / "reports/runner-temp" / self.record["inputDirectory"] / "archive.tar.gz"
        self.assertEqual(target.read_bytes(), self.payload.read_bytes())
        source = self.temp / self.record["inputDirectory"] / "archive.tar.gz"
        source.unlink()
        source.symlink_to(self.payload)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            GATE.retain_provider_archives(job, self.root / "refused")


if __name__ == "__main__":
    unittest.main()
