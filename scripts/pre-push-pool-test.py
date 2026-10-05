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
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

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
FIXTURE_GATE = """import json, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parent.parent
def git(*args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
for key in ['SSH_AUTH_SOCK', 'GH_TOKEN', 'GITHUB_TOKEN', 'PRIVATE_TOKEN']:
    assert key not in os.environ
if len(sys.argv) == 1:
    out = root / '.build/fixture'; out.mkdir(parents=True)
else:
    assert sys.argv[1] == '--evidence-dir' and len(sys.argv) == 3
    out = pathlib.Path(sys.argv[2]); out.mkdir()
result = {'ran': 1, 'failed': 0, 'not_run': ['hosting is not exercised by this transport fixture']}
tags = git('for-each-ref','--format=%(refname) %(objectname)','refs/tags')
source = {'head':git('rev-parse','HEAD'), 'tree':git('rev-parse','HEAD^{tree}'),
          'tags':dict(line.split(' ',1) for line in tags.splitlines())}
(out/'source-input.json').write_text(json.dumps(source))
(out/'result.json').write_text(json.dumps(result))
(out/'actual-bytes.sig').write_bytes(bytes(range(64)))
print('fixture gate reached')
"""


class Controls(unittest.TestCase):
    """Transport controls use an isolated real Git repository and actual children."""

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
        for name in ("pre-push-identity-scan.py", "_decoding.py", "_gate_json.py"):
            shutil.copyfile(HERE / name, self.root / "scripts" / name)
        (self.root / ".gitignore").write_text(".build/\n")
        self.commit()
        self.call("tag", "v0.1.0")
        self.executable(
            "uv",
            '#!/usr/bin/env python3\nimport os,sys\np=sys.argv.index("python")\n'
            "os.execv(sys.executable,[sys.executable,*sys.argv[p+1:]])\n",
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
        return {"nonce": "0123456789abcdef0123456789abcdef", "bindings": BRIDGE.bindings()}

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

    def install_transport_fixture(self):
        self.executable(
            "box_run.sh",
            """#!/usr/bin/env python3
import os,pathlib,subprocess,sys
assert sys.argv[2:4] == ['--keep','--']
root = pathlib.Path.cwd()
path = root/'.build/driver-native.log'; path.parent.mkdir(exist_ok=True)
with path.open('wb') as log:
    process = subprocess.run(sys.argv[4:],stdout=log,stderr=log)
print('POLL ssh -o BatchMode=yes root@127.0.0.1 sh /tmp/poll job')
print('BOX_LOG fixture  LOCAL_LOG '+str(path)+'  SSH_STATUS '+str(process.returncode))
sys.exit(process.returncode)
""",
        )
        self.executable(
            "ssh",
            """#!/usr/bin/env python3
import pathlib,shlex,sys
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
        retained = list(Path(self.temp.name).glob("aev-pre-push-pool-*"))
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
                    sys.executable,
                    str(self.root / "scripts/pre-push-pool.py"),
                    "remote",
                    base64.b64encode(BRIDGE.encode(request)).decode(),
                ],
                env=self.env,
                stdout=out,
                stderr=err,
            )
            try:
                deadline = time.monotonic() + 5
                pid_path = self.root / ".build/native-pid"
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists())
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
        candidate = Path(self.temp.name) / "job/timestamp-candidate"
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
        return candidate, SimpleNamespace(root=self.root, temp=candidate.parent)

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
