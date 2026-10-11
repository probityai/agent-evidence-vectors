#!/usr/bin/env python3
"""Exercise real Git, subprocess, archive, and hook refusal boundaries."""

from __future__ import annotations

import base64
import contextlib
import gzip
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from _branch_authority import require_closure

HERE = Path(__file__).resolve().parent


def load(name: str, filename: str) -> Any:
    """Load the committed mechanism by its source path."""
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    """Read a declared regular test member and reject a missing stream."""
    stream = archive.extractfile(name)
    assert stream is not None
    return stream.read()


BRIDGE = load("pre_push_pool", "pre-push-pool.py")
GATE = load("workflow_steps_gate", "workflow-steps-gate.py")


def required_tool(name: str) -> str:
    """Resolve a required executable before any native control can run."""
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"pre-push-pool tests require {name} on PATH")
    return executable


REAL_GIT = required_tool("git")
REAL_UV = required_tool("uv")
FIXTURE_GATE = """import json, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parent.parent
assert os.path.abspath(sys.prefix) == os.path.abspath(root/'.venv')
assert sys.prefix != sys.base_prefix and (root/'.venv/pyvenv.cfg').is_file()
def git(*args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
for key in ['SSH_AUTH_SOCK', 'GH_TOKEN', 'GITHUB_TOKEN', 'PRIVATE_TOKEN']:
    assert key not in os.environ
if len(sys.argv) == 1:
    out = root / '.build/fixture'; out.mkdir(parents=True)
else:
    assert sys.argv[1] == '--evidence-dir' and len(sys.argv) == 5
    out = pathlib.Path(sys.argv[2]); out.mkdir()
result = {'ran': 1, 'failed': 0, 'not_run': ['hosting is not exercised by this transport fixture']}
tags = git('for-each-ref','--format=%(refname) %(objectname)','refs/tags')
source = {'head':git('rev-parse','HEAD'), 'tree':git('rev-parse','HEAD^{tree}'),
          'tags':dict(line.split(' ',1) for line in tags.splitlines())}
if len(sys.argv) > 1:
    assert sys.argv[3] == '--branch-authority'
    source['branch_authority'] = json.loads(pathlib.Path(sys.argv[4]).read_bytes())
(out/'source-input.json').write_text(json.dumps(source))
(out/'result.json').write_text(json.dumps(result))
(out/'actual-bytes.sig').write_bytes(bytes(range(64)))
print('fixture gate reached')
"""


class Controls(unittest.TestCase):
    """Transport controls use an isolated real Git repository and actual children."""

    def test_missing_required_tools_refuses_before_controls(self):
        for missing, present in (("git", REAL_UV), ("uv", REAL_GIT)):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                binary = Path(directory)
                (binary / ("uv" if missing == "git" else "git")).symlink_to(present)
                result = subprocess.run(
                    [sys.executable, "-B", str(HERE / "pre-push-pool-test.py")],
                    env={**os.environ, "PATH": str(binary)},
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"tests require {missing} on PATH", result.stderr)
                self.assertNotIn("Ran ", result.stderr)
                self.assertEqual(result.stdout, "")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aev-pool-control-")
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.old_root = BRIDGE.ROOT
        BRIDGE.ROOT = self.root
        self.call("init", "-q")
        self.call("config", "user.name", "Transport fixture")
        self.call("config", "user.email", "fixture@example.com")
        self.call("config", "core.hooksPath", ".githooks")
        # Pin signing off so the fixture does not inherit the caller's global git config.
        self.call("config", "tag.gpgSign", "false")
        self.call("config", "commit.gpgSign", "false")
        self.call("config", "core.editor", "true")
        self.call("remote", "add", "origin", "https://github.com/example/transport.git")
        (self.root / "scripts").mkdir()
        (self.root / ".githooks").mkdir()
        self.gate = self.root / "scripts/workflow-steps-gate.py"
        self.gate.write_text(FIXTURE_GATE)
        shutil.copyfile(HERE / "pre-push-pool.py", self.root / "scripts/pre-push-pool.py")
        shutil.copyfile(HERE.parent / ".githooks/pre-push", self.root / ".githooks/pre-push")
        for name in ("commit-msg.permitted-paths", "commit-msg.forbidden-words"):
            shutil.copyfile(HERE.parent / ".githooks" / name, self.root / ".githooks" / name)
        # The real history scanner remains active in the actual hook tests.
        for name in (
            "pre-push-identity-scan.py",
            "push-hygiene.py",
            "_decoding.py",
            "_gate_json.py",
            "_branch_authority.py",
            "pre-push-pool-native.sh",
            "_go_selector.py",
            "_lockfile.py",
            "_native_provider.py",
        ):
            shutil.copyfile(HERE / name, self.root / "scripts" / name)
        (self.root / ".gitignore").write_text(".build/\n.venv/\n")
        self.commit()
        self.call("tag", "v0.1.0")
        self.call("update-ref", "refs/remotes/origin/trunk", "HEAD")
        self.call("update-ref", "refs/remotes/origin/stale-topic", "HEAD")
        self.call("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/stale-topic")
        self.remote_repo = Path(self.temp.name) / "remote.git"
        self.call("clone", "--quiet", "--bare", str(self.root), str(self.remote_repo))
        subprocess.run(
            [
                "git",
                "-C",
                str(self.remote_repo),
                "update-ref",
                "refs/heads/trunk",
                self.call("rev-parse", "HEAD"),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.remote_repo), "symbolic-ref", "HEAD", "refs/heads/trunk"],
            check=True,
            capture_output=True,
        )
        assert REAL_UV is not None and REAL_GIT is not None
        subprocess.run(
            [REAL_UV, "venv", "--python", sys.executable, str(self.root / ".venv")],
            check=True,
            capture_output=True,
        )
        fixture_python = self.root / ".venv/bin/python"
        self.executable(
            "gh",
            f"#!{fixture_python} -B\nimport json\n"
            "print(json.dumps({'full_name':'example/transport','default_branch':'trunk'}))\n",
        )
        self.executable(
            "git",
            f"#!{fixture_python} -B\nimport os,sys\n"
            f"args=sys.argv[1:];real={REAL_GIT!r}\n"
            "if args[:1] == ['ls-remote']:\n"
            f"    args[2]={str(self.remote_repo)!r}\n"
            "os.execv(real,[real,*args])\n",
        )
        self.executable(
            "uv",
            f"#!{fixture_python} -B\nimport os,pathlib,subprocess,sys\n"
            "assert sys.argv[1] in ('sync','venv')\n"
            "target=pathlib.Path.cwd()/'.venv'\n"
            "if sys.argv[1] == 'sync':\n"
            "    assert os.environ['UV_PROJECT_ENVIRONMENT'] == str(target)\n"
            "if not (target/'bin/python').exists():\n"
            f"    command=[{REAL_UV!r},'venv','--python',sys.executable,str(target)]\n"
            "    subprocess.run(command,check=True)\n",
        )
        self.env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "SSH_AUTH_SOCK": "/not-a-credential",
            "GH_TOKEN": "fixture-value",
            "GITHUB_TOKEN": "fixture-value",
            "PRIVATE_TOKEN": "fixture-value",
        }

    def tearDown(self):
        BRIDGE.ROOT = self.old_root
        self.temp.cleanup()

    def call(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def commit(self):
        self.call("add", ".")
        self.call("commit", "-qm", "test: add transport fixture")

    def executable(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def request(self):
        directory = Path(tempfile.mkdtemp(prefix="primary-", dir=self.temp.name)) / "metadata"
        with patch.dict(os.environ, self.env, clear=True):
            authority = BRIDGE.capture_authority(self.root, directory)
        return {
            "nonce": "0123456789abcdef0123456789abcdef",
            "bindings": BRIDGE.bindings(),
            "branchAuthority": authority,
        }

    def fixture_source(self, request: dict[str, Any]) -> Any:
        """Bind a temporary repository to its own context, preserving the caller's."""
        selected = self.call("rev-parse", "HEAD")
        context = {"GITHUB_SHA": selected, "GITHUB_HEAD_SHA": selected, "GITHUB_EVENT_NAME": "push"}
        with patch.dict(os.environ, context):
            return GATE.Source(self.root, request["branchAuthority"])

    def test_fixture_source_context_preserves_foreign_ci_refusal(self):
        request = self.request()
        foreign = {
            "GITHUB_SHA": "1" * 40,
            "GITHUB_HEAD_SHA": "2" * 40,
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with patch.dict(os.environ, foreign):
            source = self.fixture_source(request)
            self.assertEqual(source.head, self.call("rev-parse", "HEAD"))
            self.assertEqual({key: os.environ[key] for key in foreign}, foreign)
            with self.assertRaisesRegex(ValueError, "GITHUB_SHA does not identify"):
                GATE.Source(self.root, request["branchAuthority"])

    def native(self, request):
        output = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(output):
            code = BRIDGE.remote(request)
        receipt = BRIDGE.completion(output.getvalue(), request, code)
        BRIDGE.check_archive(Path(receipt["archive"]), receipt, request)
        return code, receipt

    def test_real_child_receipt_and_original_bytes(self):
        request = self.request()
        code, receipt = self.native(request)
        self.assertEqual(code, 0)
        with tarfile.open(receipt["archive"]) as archive:
            self.assertEqual(
                member_bytes(archive, "capture/native/actual-bytes.sig"), bytes(range(64))
            )

    def test_wrong_source_coordinates_never_start_gate(self):
        for field in (
            "head",
            "tree",
            "gateSha256",
            "hookSha256",
            "bridgeSha256",
            "tags",
            "origin",
            "hooksPath",
            "authoritySha256",
            "jsonSha256",
            "bootstrapSha256",
            "goSelectorSha256",
            "lockSha256",
            "providerSha256",
        ):
            with self.subTest(field=field):
                request = self.request()
                request["nonce"] = BRIDGE.digest(field.encode())[:32]
                request["bindings"][field] = {} if field == "tags" else "wrong"
                code, receipt = self.native(request)
                self.assertEqual(code, 1)
                self.assertIsNone(receipt["gateExit"])
                with tarfile.open(receipt["archive"]) as archive:
                    self.assertIn("capture/refusal.json", archive.getnames())
                    self.assertNotIn("capture/gate.stdout", archive.getnames())

    def test_actual_child_failure_is_retained(self):
        self.gate.write_text(
            FIXTURE_GATE.replace("'failed': 0", "'failed': 1") + "\nsys.exit(17)\n"
        )
        self.commit()
        code, receipt = self.native(self.request())
        self.assertEqual(code, 17)
        self.assertEqual(receipt["gateExit"], 17)
        self.assertEqual(receipt["nativeResult"]["failed"], 1)

    def test_required_helper_bytes_cannot_be_untracked_or_hidden_from_status(self):
        helper = self.root / "scripts/_branch_authority.py"
        original = helper.read_bytes()
        self.install_transport_fixture()
        self.call("update-index", "--assume-unchanged", "scripts/_branch_authority.py")
        helper.write_bytes(original + b"# uncommitted required mechanism bytes\n")
        try:
            self.assertEqual(self.call("status", "--porcelain", "--untracked-files=no"), "")
            with (
                patch.dict(os.environ, self.env, clear=True),
                self.assertRaisesRegex(ValueError, "differs from selected commit"),
            ):
                BRIDGE.pool()
            self.assertFalse((self.root / ".build/driver-native.log").exists())
        finally:
            helper.write_bytes(original)
            self.call("update-index", "--no-assume-unchanged", "scripts/_branch_authority.py")
        self.call("rm", "--cached", "scripts/_branch_authority.py")
        self.call("commit", "-qm", "test: omit required tracked helper")
        self.assertTrue(helper.is_file())
        with (
            patch.dict(os.environ, self.env, clear=True),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            BRIDGE.pool()
        self.assertFalse((self.root / ".build/driver-native.log").exists())

    def test_non_main_primary_metadata_beats_stale_cached_head(self):
        request = self.request()
        source = self.fixture_source(request)
        self.assertEqual(source.default_branch, "trunk")
        self.assertEqual(source.authority["live_remote_tip"], self.call("rev-parse", "HEAD"))
        cached = self.call("symbolic-ref", "refs/remotes/origin/HEAD")
        destination = Path(self.temp.name) / "source-clone"
        source.checkout(destination)
        self.assertEqual(self.call("symbolic-ref", "refs/remotes/origin/HEAD"), cached)
        self.assertEqual(
            BRIDGE.require_packet(destination, request["branchAuthority"]), source.authority
        )

    def test_transport_restores_only_the_captured_arbitrary_default_ref(self):
        request = self.request()
        tip = request["branchAuthority"]["authority"]["frozen_published_tip"]
        cached = self.call("symbolic-ref", "refs/remotes/origin/HEAD")
        self.call("update-ref", "-d", "refs/remotes/origin/trunk")
        with self.assertRaises(ValueError):
            self.fixture_source(request)
        code, receipt = self.native(request)
        self.assertEqual(code, 0)
        self.assertEqual(self.call("rev-parse", "refs/remotes/origin/trunk"), tip)
        self.assertEqual(self.call("symbolic-ref", "refs/remotes/origin/HEAD"), cached)
        self.assertEqual(
            receipt["branchAuthoritySha256"],
            BRIDGE.digest(BRIDGE.encode(request["branchAuthority"])),
        )
        with tarfile.open(receipt["archive"]) as archive:
            proof = json.loads(member_bytes(archive, "capture/branch-transport.json"))
            self.assertFalse(proof["cachedOriginHeadUsed"])
            self.assertEqual(proof["closure"]["tip"], tip)

    def test_malformed_primary_metadata_refuses_without_starting_native_gate(self):
        for number, raw in enumerate(
            [
                b'{"full_name":"example/transport","default_branch":"trunk","default_branch":"other"}',
                b'{"full_name":"example/transport","default_branch":"trunk","n":NaN}',
                b"null",
                b"[]",
            ]
        ):
            request = self.request()
            request["nonce"] = f"{number:032x}"
            row = request["branchAuthority"]["primary"]["repository"]["stdout"]
            row.update(
                base64=base64.b64encode(raw).decode(), bytes=len(raw), sha256=BRIDGE.digest(raw)
            )
            with self.subTest(raw=raw):
                code, receipt = self.native(request)
                self.assertEqual(code, 1)
                self.assertIsNone(receipt["gateExit"])
                with tarfile.open(receipt["archive"]) as archive:
                    self.assertNotIn("capture/gate.stdout", archive.getnames())
                    self.assertIn("capture/refusal.json", archive.getnames())

    def test_false_missing_and_ambiguous_authority_refuse_before_native_gate(self):
        original = self.request()
        tip = self.call("rev-parse", "HEAD")
        refs = original["branchAuthority"]["frozen_refs"]
        primary = original["branchAuthority"]["primary"]
        remote = (f"ref: refs/heads/trunk\tHEAD\n{tip}\tHEAD\n{tip}\trefs/heads/trunk\n").encode()

        def row(raw):
            return {
                "base64": base64.b64encode(raw).decode(),
                "bytes": len(raw),
                "sha256": BRIDGE.digest(raw),
            }

        api_cases = (
            ("false-api-branch", {"full_name": "example/transport", "default_branch": False}),
            ("missing-api-branch", {"full_name": "example/transport"}),
            ("wrong-api-repository", {"full_name": "other/repository", "default_branch": "trunk"}),
        )
        remote_cases = (
            (
                "wrong-symbolic-head",
                remote.replace(b"ref: refs/heads/trunk", b"ref: refs/heads/other"),
            ),
            ("duplicate-remote-head", remote + f"{tip}\tHEAD\n".encode()),
            ("missing-remote-branch", b"\n".join(remote.splitlines()[:2]) + b"\n"),
            ("extra-remote-ref", remote + f"{tip}\trefs/heads/extra\n".encode()),
        )
        cases = (
            [
                (name, ("primary", "repository", "stdout"), row(json.dumps(document).encode()))
                for name, document in api_cases
            ]
            + [(name, ("primary", "remote_head", "stdout"), row(raw)) for name, raw in remote_cases]
            + [
                ("missing-frozen-ref", ("frozen_refs",), []),
                ("duplicate-frozen-ref", ("frozen_refs",), refs * 2),
                ("symbolic-frozen-ref", ("frozen_refs", 0, "symref"), "refs/heads/trunk"),
                ("forged-derived-branch", ("authority", "default_branch"), "other"),
                ("missing-primary-record", ("primary",), {"remote_head": primary["remote_head"]}),
                ("array-primary-record", ("primary", "repository"), []),
            ]
        )
        for number, (case, path, value) in enumerate(cases, 100):
            request = BRIDGE.decode_json(BRIDGE.encode(original))
            request["nonce"] = f"{number:032x}"
            packet = request["branchAuthority"]
            target = packet
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(case=case):
                code, receipt = self.native(request)
                self.assertEqual(code, 1)
                self.assertIsNone(receipt["gateExit"])
                with tarfile.open(receipt["archive"]) as archive:
                    self.assertNotIn("capture/gate.stdout", archive.getnames())
                    self.assertIn("capture/refusal.json", archive.getnames())
                    self.assertEqual(
                        member_bytes(archive, "capture/branch-authority.json"),
                        BRIDGE.encode(packet),
                    )

    def test_disconnected_history_refuses_before_allocator_and_retains_originals(self):
        self.install_transport_fixture()
        orphan = self.call("commit-tree", "HEAD^{tree}", "-m", "test: disconnected history")
        self.call("update-ref", "refs/remotes/origin/trunk", orphan)
        subprocess.run(
            [
                REAL_GIT,
                "-C",
                str(self.remote_repo),
                "fetch",
                "--quiet",
                str(self.root),
                f"+{orphan}:refs/heads/trunk",
            ],
            check=True,
            capture_output=True,
        )
        with (
            patch.dict(os.environ, self.env, clear=True),
            self.assertRaisesRegex(ValueError, "outside the selected snapshot closure"),
        ):
            BRIDGE.pool()
        storage = self.root / ".git/aev-pre-push-pool"
        retained = list(storage.glob("capture-*/branch-authority/refusal.json"))
        self.assertEqual(len(retained), 1)
        self.assertTrue((retained[0].parent / "repository.stdout.original").is_file())
        self.assertTrue((retained[0].parent / "remote-head.stdout.original").is_file())
        self.assertEqual(list(storage.glob("capture-*/runner.stdout")), [])
        self.assertFalse((self.root / ".build/driver-native.log").exists())

    def test_shallow_and_partial_history_refuse_before_allocation(self):
        self.install_transport_fixture()
        shallow = self.root / ".git/shallow"
        for kind in ("shallow", "partial"):
            if kind == "shallow":
                shallow.write_text(self.call("rev-parse", "HEAD") + "\n")
            else:
                shallow.unlink()
                self.call("config", "remote.origin.promisor", "true")
            with self.subTest(kind=kind), patch.dict(os.environ, self.env, clear=True):
                with self.assertRaisesRegex(ValueError, kind + " history"):
                    BRIDGE.pool()
            self.assertFalse((self.root / ".build/driver-native.log").exists())

    def test_current_remote_tip_cannot_be_replaced_by_a_stale_local_tip(self):
        self.install_transport_fixture()
        old_tip = self.call("rev-parse", "refs/remotes/origin/trunk")
        (self.root / "current-change").write_text("current remote source\n")
        self.commit()
        current = self.call("rev-parse", "HEAD")
        subprocess.run(
            [
                REAL_GIT,
                "-C",
                str(self.remote_repo),
                "fetch",
                "--quiet",
                str(self.root),
                "HEAD:refs/heads/trunk",
            ],
            check=True,
            capture_output=True,
        )
        with (
            patch.dict(os.environ, self.env, clear=True),
            self.assertRaisesRegex(
                ValueError, "local published tip differs from captured current remote"
            ),
        ):
            BRIDGE.pool()
        self.assertEqual(self.call("rev-parse", "refs/remotes/origin/trunk"), old_tip)
        self.assertFalse((self.root / ".build/driver-native.log").exists())
        self.call("update-ref", "refs/remotes/origin/trunk", current)
        request = self.request()
        source = self.fixture_source(request)
        self.assertEqual(source.authority["live_remote_tip"], current)
        self.assertEqual(source.authority["frozen_published_tip"], current)

    def test_incomplete_selected_history_refuses_before_allocator(self):
        self.install_transport_fixture()
        unique = self.root / "unique-source.txt"
        unique.write_text("a unique required source blob for this history control\n")
        self.commit()
        oid = self.call("rev-parse", "HEAD:unique-source.txt")
        blob = self.root / ".git/objects" / oid[:2] / oid[2:]
        original = blob.read_bytes()
        blob.unlink()
        try:
            with (
                patch.dict(os.environ, self.env, clear=True),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                BRIDGE.pool()
            storage = self.root / ".git/aev-pre-push-pool"
            retained = list(storage.glob("capture-*/branch-authority/refusal.json"))
            self.assertEqual(len(retained), 1)
            self.assertIn("rev-list", retained[0].read_text())
            self.assertEqual(list(storage.glob("capture-*/runner.stdout")), [])
            self.assertFalse((self.root / ".build/driver-native.log").exists())
        finally:
            blob.write_bytes(original)

    def test_receipt_authority_hash_cannot_differ_from_producer(self):
        request = self.request()
        code, receipt = self.native(request)
        receipt["branchAuthoritySha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "not bound"):
            BRIDGE.completion(BRIDGE.PREFIX + BRIDGE.encode(receipt).decode(), request, code)

    def test_object_replacements_cannot_forge_history_or_helper_membership(self):
        published = self.call("rev-parse", "HEAD")
        orphan = self.call("commit-tree", "HEAD^{tree}", "-m", "test: disconnected source")
        replacement = self.call(
            "commit-tree", "HEAD^{tree}", "-p", published, "-m", "test: replacement parent"
        )
        self.call("replace", orphan, replacement)
        native_env = {**os.environ}
        native_env.pop("GIT_NO_REPLACE_OBJECTS", None)
        native = subprocess.run(
            [REAL_GIT, "-C", str(self.root), "merge-base", "--is-ancestor", published, orphan],
            env=native_env,
            capture_output=True,
        )
        self.assertEqual(native.returncode, 0, native.stderr)
        with self.assertRaisesRegex(ValueError, "outside the selected snapshot closure"):
            require_closure(self.root, orphan, published)
        self.call("replace", "-d", orphan)
        helper = self.root / "scripts/_branch_authority.py"
        original = helper.read_bytes()
        identity = self.call("rev-parse", "HEAD:scripts/_branch_authority.py")
        altered = original + b"# uncommitted replaced blob bytes\n"
        replacement_blob = (
            subprocess.check_output(
                [REAL_GIT, "-C", str(self.root), "hash-object", "-w", "--stdin"], input=altered
            )
            .decode()
            .strip()
        )
        self.call("replace", identity, replacement_blob)
        self.call("update-index", "--assume-unchanged", "scripts/_branch_authority.py")
        helper.write_bytes(altered)
        try:
            with self.assertRaisesRegex(ValueError, "differs from selected commit"):
                BRIDGE.bindings()
        finally:
            helper.write_bytes(original)
            self.call("update-index", "--no-assume-unchanged", "scripts/_branch_authority.py")
            self.call("replace", "-d", identity)
        self.assertEqual(require_closure(self.root, published, published)["head"], published)

    def test_actual_and_configured_grafts_cannot_forge_complete_history(self):
        published = self.call("rev-parse", "HEAD")
        orphan = self.call("commit-tree", "HEAD^{tree}", "-m", "test: disconnected source")
        paths = (self.root / ".git/info/grafts", self.root / "configured-grafts")
        for number, path in enumerate(paths):
            path.write_text(orphan + " " + published + "\n")
            env = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}
            if number:
                env["GIT_GRAFT_FILE"] = str(path)
            try:
                with self.subTest(path=path.name), patch.dict(os.environ, env, clear=True):
                    native = subprocess.run(
                        [
                            REAL_GIT,
                            "-C",
                            str(self.root),
                            "merge-base",
                            "--is-ancestor",
                            published,
                            orphan,
                        ],
                        env=env,
                        capture_output=True,
                    )
                    self.assertEqual(native.returncode, 0, native.stderr)
                    with self.assertRaisesRegex(ValueError, "graft input"):
                        require_closure(self.root, orphan, published)
                    with self.assertRaisesRegex(ValueError, "graft input"):
                        BRIDGE.bindings()
            finally:
                path.unlink()
        self.assertEqual(require_closure(self.root, published, published)["head"], published)

    def install_transport_fixture(self):
        self.executable(
            "box_run.sh",
            f"#!{self.root / '.venv/bin/python'} -B\n"
            """import os,pathlib,subprocess,sys
assert sys.argv[2:5] == ['--keep','--no-sync','--']
root = pathlib.Path.cwd()
path = root/'.build/driver-native.log'; path.parent.mkdir(exist_ok=True)
with path.open('wb') as log:
    process = subprocess.run(sys.argv[5:],stdout=log,stderr=log)
print('POLL ssh -o BatchMode=yes root@127.0.0.1 sh /tmp/poll job')
print('BOX_LOG fixture  LOCAL_LOG '+str(path)+'  SSH_STATUS '+str(process.returncode))
sys.exit(process.returncode)
""",
        )
        self.executable(
            "ssh",
            f"#!{self.root / '.venv/bin/python'} -B\n"
            """import pathlib,shlex,sys
assert 'ForwardAgent=no' in sys.argv
command = shlex.split(sys.argv[-1]); assert command[0] == 'cat' and len(command) == 2
sys.stdout.buffer.write(pathlib.Path(command[1]).read_bytes())
""",
        )

    def test_pool_coordinator_receives_original_native_archive(self):
        self.install_transport_fixture()
        output = io.StringIO()
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch("tempfile.tempdir", self.temp.name),
            contextlib.redirect_stdout(output),
        ):
            code = BRIDGE.pool()
        self.assertEqual(code, 0)
        self.assertIn("full capture checked", output.getvalue())
        retained = list((self.root / ".git/aev-pre-push-pool").glob("capture-*"))
        self.assertEqual(len(retained), 1)
        self.assertTrue((retained[0] / "completion.json").is_file())
        self.assertTrue((retained[0] / "native.tar.gz").is_file())

    def test_pool_coordinator_refuses_lost_archive(self):
        self.install_transport_fixture()
        self.executable("ssh", "#!/bin/sh\nexit 7\n")
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch("tempfile.tempdir", self.temp.name),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(ValueError, "could not be received"),
        ):
            BRIDGE.pool()

    def test_pool_capture_survives_push_temporary_directory_cleanup(self):
        self.install_transport_fixture()
        wrapper_tmp = Path(self.temp.name) / "push-tmp"
        wrapper_tmp.mkdir()
        selected = wrapper_tmp / "selected-checkout"
        self.call("worktree", "add", "--detach", str(selected), "HEAD")
        output = io.StringIO()
        with patch.object(BRIDGE, "ROOT", selected):
            with (
                patch.dict(os.environ, self.env, clear=True),
                patch("tempfile.tempdir", str(wrapper_tmp)),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(BRIDGE.pool(), 0)
        prefix = "pre-push: pool evidence retained at "
        paths = [
            line[len(prefix) :]
            for line in output.getvalue().splitlines()
            if line.startswith(prefix)
        ]
        self.assertEqual(len(paths), 1)
        retained = Path(paths[0])
        receipt = (retained / "completion.json").read_bytes()
        archive = BRIDGE.file_metadata(retained / "native.tar.gz")
        self.call("worktree", "remove", "--force", str(selected))
        shutil.rmtree(wrapper_tmp)
        self.assertTrue(retained.is_dir(), "push cleanup removed the native evidence")
        self.assertEqual((retained / "completion.json").read_bytes(), receipt)
        self.assertEqual(BRIDGE.file_metadata(retained / "native.tar.gz"), archive)

    def test_pool_coordinator_refuses_linked_evidence_storage(self):
        self.install_transport_fixture()
        storage = self.root / ".git/aev-pre-push-pool"
        storage.symlink_to(self.bin, target_is_directory=True)
        with (
            patch.dict(os.environ, self.env, clear=True),
            self.assertRaisesRegex(ValueError, "evidence storage is a symbolic link"),
        ):
            BRIDGE.pool()
        self.assertEqual(list(self.bin.glob("capture-*")), [])

    def test_cancelled_native_child_stops_and_keeps_its_actual_exit(self):
        self.gate.write_text("""import os, pathlib, time
root = pathlib.Path(__file__).resolve().parent.parent
path = root/'.build/native-pid'; path.parent.mkdir(exist_ok=True)
path.write_text(str(os.getpid()))
time.sleep(30)
""")
        self.commit()
        request = self.request()
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(
                [
                    str(self.root / ".venv/bin/python"),
                    "-B",
                    str(self.root / "scripts/pre-push-pool.py"),
                    "remote",
                    base64.b64encode(BRIDGE.encode(request)).decode(),
                ],
                env=self.env,
                stdout=out,
                stderr=err,
            )
            try:
                # Wait for the native child to start, not for a fixed time: on a
                # loaded host the bridge, its venv and the child took longer
                # than five seconds, and the test failed with no defect. It
                # still fails at once if the bridge exits before the child runs.
                deadline = time.monotonic() + 120
                pid_path = self.root / ".build/native-pid"
                while (
                    not pid_path.exists() and process.poll() is None and time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                err.seek(0)
                self.assertTrue(pid_path.exists(), err.read().decode(errors="replace"))
                native_pid = int(pid_path.read_text())
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=10)
                out.seek(0)
                receipt = BRIDGE.completion(out.read().decode(), request, code)
                self.assertEqual(receipt["gateExit"], -signal.SIGTERM)
                self.assertNotEqual(code, 0)
                self.assertTrue(Path(f"/proc/{os.getpid()}").exists())
                self.assertFalse(Path(f"/proc/{native_pid}").exists())
                BRIDGE.check_archive(Path(receipt["archive"]), receipt, request)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)

    def test_missing_native_result_keeps_failed_process_capture(self):
        self.gate.write_text("import sys\nprint('actual missing-result child', file=sys.stderr)\n")
        self.commit()
        code, receipt = self.native(self.request())
        self.assertEqual((code, receipt["gateExit"]), (1, 0))
        with tarfile.open(receipt["archive"]) as archive:
            self.assertIn(
                b"actual missing-result child", member_bytes(archive, "capture/gate.stderr")
            )
            self.assertIn("capture/refusal.json", archive.getnames())

    def test_missing_runner_refuses_before_native_execution(self):
        with patch("shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "installed box_run"):
                BRIDGE.pool()

    def test_nonce_format_refuses_before_capture_or_source_mutation(self):
        before = self.call("rev-parse", "HEAD")
        for nonce in ("", "x" * 32, "A" * 32, "0" * 31, "0" * 33, "../capture"):
            request = self.request()
            request["nonce"] = nonce
            with self.subTest(nonce=nonce), self.assertRaisesRegex(ValueError, "nonce"):
                BRIDGE.remote(request)
        self.assertEqual(self.call("rev-parse", "HEAD"), before)
        self.assertFalse((self.root / ".build").exists())

    def test_capture_statistics_measure_only_original_regular_files(self):
        request = self.request()
        _, receipt = self.native(request)
        archive = Path(receipt["archive"])
        actual = BRIDGE.check_archive(archive, receipt, request)
        with tarfile.open(archive) as captured:
            original = [
                member
                for member in captured
                if member.isfile() and member.name != "capture/POOL-MANIFEST.json"
            ]
        self.assertEqual(
            actual,
            {
                "archiveBytes": archive.stat().st_size,
                "originalFileCount": len(original),
                "originalFileBytes": sum(member.size for member in original),
                "largestOriginalFileBytes": max(member.size for member in original),
            },
        )

    def test_archive_storage_refusal_keeps_original_native_capture(self):
        scratch = Path(self.temp.name) / "native-custody"
        scratch.mkdir()
        (self.root / ".build").symlink_to(self.bin, target_is_directory=True)
        output = io.StringIO()
        with (
            patch.dict(os.environ, self.env, clear=True),
            patch("tempfile.mkdtemp", return_value=str(scratch)),
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(ValueError, "storage is a symbolic link"),
        ):
            BRIDGE.remote(self.request())
        self.assertIn(str(scratch), output.getvalue())
        self.assertEqual(
            (scratch / "capture/native/actual-bytes.sig").read_bytes(), bytes(range(64))
        )
        self.assertEqual(
            json.loads((scratch / "capture/gate-process.json").read_bytes())["returncode"], 0
        )

    def test_missing_duplicate_wrong_request_and_exit_receipts_refuse(self):
        request = self.request()
        _, receipt = self.native(request)
        line = BRIDGE.PREFIX + BRIDGE.encode(receipt).decode()
        for log, code in [("", 0), (line + "\n" + line, 0), (line, 9)]:
            with self.subTest(log=log[:15], code=code), self.assertRaises(ValueError):
                BRIDGE.completion(log, request, code)
        wrong = {**request, "nonce": "0" * 32}
        with self.assertRaises(ValueError):
            BRIDGE.completion(line, wrong, 0)

    def test_hostile_receipt_counts_exits_and_json_refuse(self):
        request = self.request()
        _, receipt = self.native(request)
        for field in ("bridgeExit", "gateExit", "ran", "failed"):
            for value in (True, False, 0.0):
                hostile = BRIDGE.decode_json(BRIDGE.encode(receipt))
                target = hostile if field.endswith("Exit") else hostile["nativeResult"]
                target[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    BRIDGE.completion(BRIDGE.PREFIX + BRIDGE.encode(hostile).decode(), request, 0)
        original = BRIDGE.encode(receipt).decode()
        for raw in (
            original[:-1] + ',"bridgeExit":0}',
            original[:-1] + ',"extra":NaN}',
            original[:-1] + ',"extra":1e999}',
        ):
            with self.subTest(raw=raw[-30:]), self.assertRaises(ValueError):
                BRIDGE.completion(BRIDGE.PREFIX + raw, request, 0)

    def test_actual_native_hostile_result_is_refused_and_original_bytes_stay(self):
        for index, raw in enumerate(
            [
                '{"ran":true,"failed":0}',
                '{"ran":1,"failed":false}',
                '{"ran":1,"ran":1,"failed":0}',
                '{"ran":1,"failed":0,"extra":Infinity}',
            ]
        ):
            with self.subTest(raw=raw):
                self.gate.write_text(FIXTURE_GATE + f"\n(out/'result.json').write_text({raw!r})\n")
                self.commit()
                request = self.request()
                request["nonce"] = BRIDGE.digest(str(index).encode())[:32]
                output = io.StringIO()
                with (
                    patch.dict(os.environ, self.env, clear=True),
                    contextlib.redirect_stdout(output),
                ):
                    code = BRIDGE.remote(request)
                self.assertEqual(code, 1)
                receipt = BRIDGE.decode_json(output.getvalue().split(BRIDGE.PREFIX)[1])
                with tarfile.open(receipt["archive"]) as archive:
                    self.assertEqual(
                        member_bytes(archive, "capture/native/result.json"), raw.encode()
                    )
                    self.assertIn("capture/refusal.json", archive.getnames())

    def test_remote_request_rejects_duplicate_and_nonfinite_json_before_native(self):
        for raw in ('{"nonce":"x","nonce":"x"}', '{"nonce":NaN}', '{"nonce":1e999}'):
            proc = subprocess.run(
                [
                    sys.executable,
                    str(self.root / "scripts/pre-push-pool.py"),
                    "remote",
                    base64.b64encode(raw.encode()).decode(),
                ],
                env=self.env,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn(b"REFUSED", proc.stderr)
            self.assertFalse((self.root / ".build").exists())

    def test_archive_truncation_and_member_tampering_refuse(self):
        request = self.request()
        _, receipt = self.native(request)
        archive = Path(receipt["archive"])
        original = archive.read_bytes()
        archive.write_bytes(original[:-1])
        with self.assertRaises(ValueError):
            BRIDGE.check_archive(archive, receipt, request)
        archive.write_bytes(original)
        with tarfile.open(archive) as old:
            files = {m.name: member_bytes(old, m.name) for m in old if m.isfile()}
        files["capture/native/actual-bytes.sig"] = b"tampered"
        with tarfile.open(archive, "w:gz") as new:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                new.addfile(info, io.BytesIO(data))
        revised = {
            **receipt,
            "bytes": archive.stat().st_size,
            "sha256": BRIDGE.digest(archive.read_bytes()),
        }
        with self.assertRaisesRegex(ValueError, "member manifest"):
            BRIDGE.check_archive(archive, revised, request)

    def test_large_member_validation_streams_without_retaining_payload(self):
        self.gate.write_text(
            FIXTURE_GATE
            + """
with (out/'large-native.bin').open('wb') as stream:
    for _ in range(32):
        stream.write(b'a' * (1 << 20))
"""
        )
        self.commit()
        request = self.request()
        _, receipt = self.native(request)
        archive = Path(receipt["archive"])
        tracemalloc.start()
        try:
            BRIDGE.check_archive(archive, receipt, request)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        metadata, contracts = BRIDGE.archive_members(archive)
        size = metadata["native/large-native.bin"]["bytes"]
        self.assertEqual(size, 32 << 20)
        self.assertNotIn("native/large-native.bin", contracts)
        self.assertLess(peak, size // 2)
        print(
            "STREAM_MEASUREMENT",
            json.dumps(
                {
                    "archiveBytes": archive.stat().st_size,
                    "memberBytes": size,
                    "peakAllocatedBytes": peak,
                }
            ),
        )

    def test_archive_paths_links_and_duplicate_members_refuse(self):
        archive = Path(self.temp.name) / "hostile.tar.gz"
        for names, kind in [
            (["../escape"], tarfile.REGTYPE),
            (["capture/../escape"], tarfile.REGTYPE),
            (["/capture/root"], tarfile.REGTYPE),
            (["capture//double"], tarfile.REGTYPE),
            (["capture/repeated", "capture/repeated"], tarfile.REGTYPE),
            (["capture/request.json", "capture/request.json/"], tarfile.REGTYPE),
            (["capture/directory", "capture/directory/"], tarfile.DIRTYPE),
            (["capture/directory", "capture/directory//"], tarfile.DIRTYPE),
            (["capture/link"], tarfile.SYMTYPE),
            (["capture/link"], tarfile.LNKTYPE),
            (["capture/pipe"], tarfile.FIFOTYPE),
        ]:
            with tarfile.open(archive, "w:gz") as output:
                for name in names:
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    info.linkname = "outside"
                    info.size = 1 if kind == tarfile.REGTYPE else 0
                    output.addfile(info, io.BytesIO(b"x") if info.size else None)
            with self.subTest(names=names, kind=kind), self.assertRaises(ValueError):
                BRIDGE.archive_members(archive)

    def test_directory_and_file_cannot_share_one_archive_identity(self):
        archive = Path(self.temp.name) / "directory-file-collision.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            directory = tarfile.TarInfo("capture/conflict/")
            directory.type = tarfile.DIRTYPE
            output.addfile(directory)
            regular = tarfile.TarInfo("capture/conflict")
            regular.size = 1
            output.addfile(regular, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "unsafe or repeated member"):
            BRIDGE.archive_members(archive)

    def test_pax_path_cannot_hide_a_noncanonical_regular_file_name(self):
        archive = Path(self.temp.name) / "pax-file-alias.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            regular = tarfile.TarInfo("capture/request.json")
            regular.pax_headers = {"path": "capture/request.json/"}
            regular.size = 1
            output.addfile(regular, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "unsafe or repeated member"):
            BRIDGE.archive_members(archive)

    def test_truncated_compression_footer_refuses_even_with_rebound_archive_hash(self):
        request = self.request()
        _, receipt = self.native(request)
        archive = Path(receipt["archive"])
        archive.write_bytes(archive.read_bytes()[:-4])
        rebound = {**receipt, **BRIDGE.file_metadata(archive)}
        with self.assertRaisesRegex(ValueError, "compression or tar stream"):
            BRIDGE.check_archive(archive, rebound, request)

    def test_hidden_archive_after_tar_end_marker_refuses(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as output:
            info = tarfile.TarInfo("capture/first")
            info.size = 1
            output.addfile(info, io.BytesIO(b"x"))
        archive = Path(self.temp.name) / "concatenated.tar.gz"
        archive.write_bytes(gzip.compress(buffer.getvalue() * 2))
        with self.assertRaisesRegex(ValueError, "after its tar end marker"):
            BRIDGE.archive_members(archive)

    def test_safe_transport_route_disables_agent_forwarding(self):
        route = BRIDGE.ssh_route(
            "POLL ssh -o BatchMode=yes -i key root@192.0.2.1 sh /tmp/poll job\n"
        )
        self.assertIn("ForwardAgent=no", route)
        for line in [
            "POLL ",
            "POLL ssh",
            "POLL ssh -o",
            "POLL ssh root@192.0.2.1",
            "POLL ssh -A root@192.0.2.1 sh /tmp/poll job",
            "POLL sh root@192.0.2.1 sh /tmp/poll job",
        ]:
            with self.assertRaises(ValueError):
                BRIDGE.ssh_route(line)

    def test_archive_manifest_duplicate_and_nonfinite_values_refuse(self):
        request = self.request()
        _, receipt = self.native(request)
        archive = Path(receipt["archive"])
        with tarfile.open(archive) as old:
            files = {
                member.name: member_bytes(old, member.name) for member in old if member.isfile()
            }
        manifest = files["capture/POOL-MANIFEST.json"].decode()
        first = next(iter(BRIDGE.decode_json(manifest)))
        repeated = json.dumps(first) + ":" + json.dumps(BRIDGE.decode_json(manifest)[first])
        for tail in ("," + repeated + "}", ',"extra":NaN}', ',"extra":1e999}'):
            files["capture/POOL-MANIFEST.json"] = (manifest[:-1] + tail).encode()
            with tarfile.open(archive, "w:gz") as new:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    new.addfile(info, io.BytesIO(data))
            revised = {
                **receipt,
                "bytes": archive.stat().st_size,
                "sha256": BRIDGE.digest(archive.read_bytes()),
            }
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                BRIDGE.check_archive(archive, revised, request)

    def test_timestamp_manifest_duplicate_and_nonfinite_values_refuse(self):
        candidate, job = self.timestamp()
        manifest = candidate / "manifest.json"
        original = manifest.read_text()
        for tail in (',"members":[]}', ',"extra":NaN}', ',"extra":1e999}'):
            manifest.write_text(original[:-1] + tail)
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                GATE.retain_reports(job, Path(self.temp.name) / "retained")

    def timestamp(self):
        job = GATE.JobState(self.temp.name, "timestamp-custody", self.root)
        candidate = job.temp / "timestamp-candidate"
        members = []
        for name, raw in [
            ("release/CORPUS-DIGESTS.txt.sig", bytes(range(64))),
            ("release/CORPUS-DIGESTS.txt.sig.tsr", b"public timestamp response"),
            ("spec/tsa-roots.pem", b"-----BEGIN CERTIFICATE-----\npublic certificate\n"),
        ]:
            source = self.root / name
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(raw)
            copy = candidate / name
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(raw)
            members.append(
                {"path": name, "state": "present", "bytes": len(raw), "sha256": BRIDGE.digest(raw)}
            )
        self.commit()
        report = {
            "sourceCommit": self.call("rev-parse", "HEAD"),
            "sourceTree": self.call("rev-parse", "HEAD^{tree}"),
            "members": members,
        }
        (candidate / "manifest.json").write_text(json.dumps(report))
        return candidate, job

    def test_selected_public_timestamp_inputs_are_retained_byte_exact(self):
        candidate, job = self.timestamp()
        evidence = Path(self.temp.name) / "retained"
        GATE.retain_reports(job, evidence)
        for name in (
            "release/CORPUS-DIGESTS.txt.sig",
            "release/CORPUS-DIGESTS.txt.sig.tsr",
            "spec/tsa-roots.pem",
        ):
            self.assertEqual(
                (evidence / "reports/runner-temp/timestamp-candidate" / name).read_bytes(),
                (candidate / name).read_bytes(),
            )

    def test_unselected_private_pem_does_not_enter_native_capture(self):
        candidate, job = self.timestamp()
        (candidate / "private.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nfixture marker\n")
        evidence = Path(self.temp.name) / "retained"
        GATE.retain_reports(job, evidence)
        self.assertFalse(list(evidence.rglob("private.pem")))

    def test_private_bytes_at_selected_certificate_refuse_before_copy(self):
        candidate, job = self.timestamp()
        (candidate / "spec/tsa-roots.pem").write_bytes(
            b"-----BEGIN PRIVATE KEY-----\nfixture marker\n"
        )
        evidence = Path(self.temp.name) / "retained"
        with self.assertRaisesRegex(ValueError, "public source"):
            GATE.retain_reports(job, evidence)
        self.assertFalse(
            (evidence / "reports/runner-temp/timestamp-candidate/spec/tsa-roots.pem").exists()
        )

    def test_selected_timestamp_symlink_and_missing_declared_member_refuse(self):
        candidate, job = self.timestamp()
        selected = candidate / "spec/tsa-roots.pem"
        raw = selected.read_bytes()
        selected.unlink()
        selected.symlink_to(self.root / "spec/tsa-roots.pem")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            GATE.retain_reports(job, Path(self.temp.name) / "retained")
        selected.unlink()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            GATE.retain_reports(job, Path(self.temp.name) / "retained")
        selected.write_bytes(raw)

    def test_timestamp_special_file_and_broken_manifest_refuse(self):
        candidate, job = self.timestamp()
        selected = candidate / "spec/tsa-roots.pem"
        selected.unlink()
        os.mkfifo(selected)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            GATE.retain_reports(job, Path(self.temp.name) / "retained")
        manifest = candidate / "manifest.json"
        manifest.unlink()
        manifest.symlink_to(candidate / "missing-manifest")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            GATE.retain_reports(job, Path(self.temp.name) / "retained")

    def test_actual_hook_venue_empty_input_and_delete_contract(self):
        hook = self.root / ".githooks/pre-push"
        zero = "0" * 40
        for venue, stdin, expected in [
            ("", f"refs/heads/x {zero} refs/heads/x {zero}\n", 1),
            ("unknown", f"refs/heads/x {zero} refs/heads/x {zero}\n", 1),
            ("pool", "", 1),
            ("pool", f"refs/heads/x {zero} refs/heads/x {zero}\n", 0),
        ]:
            with self.subTest(venue=venue, stdin=bool(stdin)):
                proc = subprocess.run(
                    ["bash", str(hook)],
                    cwd=self.root,
                    env={**self.env, "AEV_PRE_PUSH_VENUE": venue},
                    input=stdin,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(proc.returncode, expected, proc.stderr)

    def test_actual_hook_default_leak_uses_own_environment_and_hygiene(self):
        # The actual pushed-revision hygiene script runs; a full mirror and an
        # ambient interpreter would each leave a distinct observable failure.
        self.executable("python3", "#!/bin/sh\nexit 98\n")
        self.executable("uv", "#!/bin/sh\nexit 99\n")
        env = {**self.env, "TMPDIR": self.temp.name}
        env.pop("AEV_PRE_PUSH_VENUE", None)
        first = self.call("rev-parse", "HEAD")
        hook = self.root / ".githooks/pre-push"

        def push(local):
            return subprocess.run(
                ["bash", str(hook)],
                cwd=self.root,
                env=env,
                input=f"refs/heads/x {local} refs/heads/x {first}\n",
                text=True,
                capture_output=True,
            )

        clean = push(first)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertIn("push-hygiene: no blob", clean.stdout)
        self.assertIn("Remote CI is the proof", clean.stdout)
        self.assertFalse((self.root / ".build/fixture").exists())
        (self.root / "conflict.txt").write_text("<<<<<<< unresolved\n")
        self.commit()
        conflict = push(self.call("rev-parse", "HEAD"))
        self.assertEqual(conflict.returncode, 1, conflict.stderr)
        self.assertIn("unresolved merge conflict marker", conflict.stdout)
        self.assertIn("pre-push: REFUSED", conflict.stderr)
        self.assertFalse((self.root / ".build/fixture").exists())

    def test_owning_environment_refuses_missing_config_and_foreign_prefix(self):
        self.executable("uv", "#!/bin/sh\nexit 99\n")
        head = self.call("rev-parse", "HEAD")
        env = {**self.env, "AEV_PRE_PUSH_VENUE": "leak"}

        def refused():
            commands = (
                ["bash", str(self.root / ".githooks/pre-push")],
                ["sh", str(self.root / "scripts/pre-push-pool-native.sh"), "unused-request"],
            )
            for command in commands:
                proc = subprocess.run(
                    command,
                    cwd=self.root,
                    env=env,
                    input=f"refs/heads/x {head} refs/heads/x {head}\n",
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn("environment prefix", proc.stderr)
                self.assertFalse((self.root / ".build/fixture").exists())

        config = self.root / ".venv/pyvenv.cfg"
        original = config.read_bytes()
        config.unlink()
        try:
            refused()
        finally:
            config.write_bytes(original)
        foreign = Path(self.temp.name) / "foreign-repo/.venv"
        subprocess.run(
            [REAL_UV, "venv", "--python", sys.executable, str(foreign)],
            check=True,
            capture_output=True,
        )
        python = self.root / ".venv/bin/python"
        saved = python.with_name("python.original")
        python.rename(saved)
        try:
            # This deliberate invalid route executes a genuine foreign venv.
            # Renaming first preserves uv's binary symlink without writing its target.
            python.write_text(f'#!/bin/sh\nexec "{foreign}/bin/python" "$@"\n')
            python.chmod(0o755)
            refused()
        finally:
            python.unlink()
            saved.rename(python)

    def test_full_mirror_preserves_a_failed_owned_dependency_sync(self):
        self.executable(
            "uv",
            f"#!{self.root / '.venv/bin/python'} -B\n"
            "import pathlib,subprocess,sys\n"
            "if sys.argv[1] == 'sync':\n"
            "    print('fixture-owned-sync-failed-37',file=sys.stderr);sys.exit(37)\n"
            "assert sys.argv[1] == 'venv'\n"
            "target=pathlib.Path.cwd()/'.venv'\n"
            f"subprocess.run([{REAL_UV!r},'venv','--python',sys.executable,str(target)],check=True)\n",
        )
        head = self.call("rev-parse", "HEAD")
        env = {
            key: value
            for key, value in self.env.items()
            if key not in {"SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "PRIVATE_TOKEN"}
        }
        proc = subprocess.run(
            ["bash", str(self.root / ".githooks/pre-push")],
            cwd=self.root,
            env={**env, "AEV_PRE_PUSH_VENUE": "local"},
            input=f"refs/heads/x {head} refs/heads/x {head}\n",
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 37, proc.stdout + proc.stderr)
        self.assertIn("fixture-owned-sync-failed-37", proc.stderr)
        self.assertNotIn("fixture gate reached", proc.stdout)
        self.assertEqual(
            len(self.call("worktree", "list", "--porcelain").split("worktree ")) - 1, 1
        )

    def test_actual_hook_multiple_refs_are_all_gated(self):
        self.install_transport_fixture()
        first = self.call("rev-parse", "HEAD")
        self.gate.write_text(FIXTURE_GATE + "\nsys.exit(23)\n")
        self.commit()
        second = self.call("rev-parse", "HEAD")
        zero = "0" * 40
        env = {
            key: value
            for key, value in self.env.items()
            if key not in {"SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "PRIVATE_TOKEN"}
        }
        env["UV_PROJECT_ENVIRONMENT"] = str(Path(self.temp.name) / "foreign-env-must-not-be-used")
        for venue in ("local", "pool"):
            with self.subTest(venue=venue):
                proc = subprocess.run(
                    ["bash", str(self.root / ".githooks/pre-push")],
                    cwd=self.root,
                    env={**env, "AEV_PRE_PUSH_VENUE": venue, "TMPDIR": self.temp.name},
                    input=(
                        f"refs/heads/a {first} refs/heads/a {zero}\n"
                        f"refs/heads/b {second} refs/heads/b {zero}\n"
                    ),
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(first, proc.stdout)
                self.assertIn(second, proc.stdout)
                if venue == "pool":
                    self.assertIn("pool native exit 0", proc.stdout)
                    self.assertIn("pool native exit 23", proc.stdout)
                self.assertEqual(
                    len(self.call("worktree", "list", "--porcelain").split("worktree ")) - 1,
                    1,
                )


if __name__ == "__main__":
    unittest.main()
