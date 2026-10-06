#!/usr/bin/env python3
"""Run the complete selected workflow gate through the installed box pool."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import IO, Any

from _gate_json import decode_json

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "AEV_POOL_COMPLETION "
KEEP_ENV = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "WORKSTATION_HEAVY_GATE_HOLDER",
    "BOX_RUN_JOB",
    "UV_LINK_MODE",
    "GOMAXPROCS",
    "GOFLAGS",
    "CARGO_BUILD_JOBS",
    "MAKEFLAGS",
}


def digest(data: bytes) -> str:
    """Hash exact bytes, including original process output."""
    return hashlib.sha256(data).hexdigest()


def stream_metadata(stream: IO[bytes], retained: bytearray | None = None) -> dict[str, Any]:
    """Hash bounded chunks and keep bytes only for required JSON contract files."""
    hashed = hashlib.sha256()
    size = 0
    while chunk := stream.read(1 << 20):
        hashed.update(chunk)
        size += len(chunk)
        if retained is not None:
            retained.extend(chunk)
    return {"bytes": size, "sha256": hashed.hexdigest()}


def file_metadata(path: Path) -> dict[str, Any]:
    """Measure exact file bytes without loading the file into memory."""
    with path.open("rb") as stream:
        return stream_metadata(stream)


def encode(value: Any) -> bytes:
    """Encode the one request and receipt representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def git(*args: str) -> str:
    """Read the selected repository, refusing errors."""
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def bindings() -> dict[str, Any]:
    """Bind the native gate, hook, source revision, origin, and every tag."""
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked source differs from the selected commit")
    return {
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "origin": git("config", "--get", "remote.origin.url"),
        "hooksPath": git("config", "--get", "core.hooksPath"),
        "tags": dict(
            line.split(" ", 1)
            for line in git(
                "for-each-ref", "--format=%(refname) %(objectname)", "refs/tags"
            ).splitlines()
        ),
        "gateSha256": digest((ROOT / "scripts/workflow-steps-gate.py").read_bytes()),
        "hookSha256": digest((ROOT / ".githooks/pre-push").read_bytes()),
        "bridgeSha256": digest(Path(__file__).read_bytes()),
    }


def require_bindings(expected: dict[str, Any]) -> None:
    """Refuse any changed source coordinate before starting the native gate."""
    if bindings() != expected:
        raise ValueError("pool checkout does not match the selected source bindings")


def read_json(path: Path) -> Any:
    """Read a native JSON capture without ignoring parse failures."""
    return decode_json(path.read_bytes())


def child(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    """Forward cancellation to this owned process group and wait for its real exit."""
    process = subprocess.Popen(command, start_new_session=True, **kwargs)
    previous = {}

    def forward(signum: int, _frame: Any) -> None:
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, forward)
        return subprocess.CompletedProcess(command, process.wait())
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def retain(capture: Path, archive: Path) -> dict[str, Any]:
    """Keep all original native files, with a manifest, before removing scratch."""
    files = {}
    for path in sorted(capture.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("native capture has a link or special file")
        if path.is_file():
            files[path.relative_to(capture).as_posix()] = file_metadata(path)
    (capture / "POOL-MANIFEST.json").write_bytes(encode(files))
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(capture, arcname="capture", recursive=True)
    return file_metadata(archive)


def remote(request: dict[str, Any]) -> int:
    """Reset only the new pool snapshot and run the complete committed gate."""
    if not re.fullmatch(r"[0-9a-f]{32}", request["nonce"]):
        raise ValueError("pool request nonce is not a fixed hexadecimal identifier")
    expected = request["bindings"]
    env = {key: value for key, value in os.environ.items() if key in KEEP_ENV}
    scratch = Path(tempfile.mkdtemp(prefix="aev-pool-native-"))
    print(f"pre-push: original native capture retained at {scratch}", flush=True)
    capture = Path(scratch) / "capture"
    capture.mkdir()
    (capture / "request.json").write_bytes(encode(request))
    gate_exit, bridge_exit, result = run_native(expected, env, capture)
    storage = ROOT / ".build" / ("pre-push-pool-" + request["nonce"])
    if storage.parent.is_symlink():
        raise ValueError("pool capture storage is a symbolic link")
    storage.mkdir(parents=True, exist_ok=False)
    archive = storage / "native.tar.gz"
    artifact = retain(capture, archive)
    receipt = {
        "requestSha256": digest(encode(request)),
        "bindings": expected,
        "gateExit": gate_exit,
        "bridgeExit": bridge_exit,
        "nativeResult": result,
        "archive": str(archive),
        **artifact,
    }
    (storage / "completion.json").write_bytes(encode(receipt))
    shutil.rmtree(scratch)
    print(PREFIX + encode(receipt).decode(), flush=True)
    return bridge_exit


def run_native(
    expected: dict[str, Any],
    env: dict[str, str],
    capture: Path,
) -> tuple[int | None, int, Any]:
    """Retain both native failures and refusals before the remote scratch closes."""
    gate_exit = None
    result = None
    try:
        git("checkout", "--quiet", "--detach", expected["head"])
        require_bindings(expected)
        command = [
            "uv",
            "run",
            "--quiet",
            "--with",
            "pyyaml",
            "--with",
            "cryptography",
            "python",
            str(ROOT / "scripts/workflow-steps-gate.py"),
            "--evidence-dir",
            str(capture / "native"),
        ]
        with (capture / "gate.stdout").open("wb") as out:
            with (capture / "gate.stderr").open("wb") as err:
                process = child(command, env=env, stdout=out, stderr=err)
        gate_exit = process.returncode
        (capture / "gate-process.json").write_bytes(encode({"returncode": gate_exit}))
        require_bindings(expected)
        result = read_json(capture / "native/result.json")
        source = read_json(capture / "native/source-input.json")
        if any(source[key] != expected[key] for key in ("head", "tree", "tags")):
            raise ValueError("native source capture does not match the request")
        if not isinstance(result, dict) or type(result.get("ran")) is not int or result["ran"] < 1:
            raise ValueError("native gate did not retain a nonempty execution result")
        if type(result.get("failed")) is not int or result["failed"] < 0:
            raise ValueError("native gate retained an invalid failure count")
        if gate_exit == 0 and result.get("failed") != 0:
            raise ValueError("native gate exit contradicts its retained failures")
        return gate_exit, gate_exit, result
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        (capture / "refusal.json").write_bytes(encode({"reason": str(exc)}))
        return gate_exit, 1, result


def completion(log: str, request: dict[str, Any], runner_exit: int) -> dict[str, Any]:
    """Require one complete receipt bound to this run and its actual exit."""
    lines = [line[len(PREFIX) :] for line in log.splitlines() if line.startswith(PREFIX)]
    if len(lines) != 1:
        raise ValueError("pool run did not return exactly one completion receipt")
    receipt = decode_json(lines[0])
    if (
        not isinstance(receipt, dict)
        or type(runner_exit) is not int
        or type(receipt.get("bridgeExit")) is not int
        or (receipt.get("gateExit") is not None and type(receipt.get("gateExit")) is not int)
    ):
        raise ValueError("pool receipt does not contain actual integer process exits")
    if (
        receipt.get("requestSha256") != digest(encode(request))
        or receipt.get("bindings") != request["bindings"]
        or receipt.get("bridgeExit") != runner_exit
    ):
        raise ValueError("pool receipt is not bound to this source and actual exit")
    result = receipt.get("nativeResult", {})
    if result is not None and (
        not isinstance(result, dict)
        or type(result.get("ran")) is not int
        or result["ran"] < 1
        or type(result.get("failed")) is not int
        or result["failed"] < 0
    ):
        raise ValueError("pool receipt has invalid native integer counts")
    if runner_exit == 0:
        if result is None or type(receipt.get("gateExit")) is not int:
            raise ValueError("pool receipt has no native execution result or actual gate exit")
        if receipt.get("gateExit") != 0 or result.get("failed") != 0:
            raise ValueError("pool receipt claims success over retained failures")
    return receipt


def ssh_route(log: str) -> list[str]:
    """Read the installed pool runner's SSH route, without interpreting a shell."""
    lines = [line[5:] for line in log.splitlines() if line.startswith("POLL ")]
    if len(lines) != 1:
        raise ValueError("pool runner did not retain exactly one SSH route")
    parts = shlex.split(lines[0])
    if len(parts) < 5 or parts[0] != "ssh" or parts[-3] != "sh":
        raise ValueError("pool runner returned an unsupported SSH route")
    host = parts[-4]
    user, separator, address = host.partition("@")
    if separator != "@" or user != "root":
        raise ValueError("pool runner returned an unsupported SSH principal")
    ipaddress.ip_address(address)
    options = parts[1:-4]
    if len(options) % 2 or any(options[n] not in {"-o", "-i"} for n in range(0, len(options), 2)):
        raise ValueError("pool runner returned unsupported SSH options")
    # OpenSSH uses the first value, so this also overrides a later runner option.
    return ["ssh", "-o", "ForwardAgent=no", *options, host]


def check_archive(
    archive: Path, receipt: dict[str, Any], request: dict[str, Any]
) -> dict[str, int]:
    """Check every received member and the original request and native result."""
    if (
        type(receipt["bytes"]) is not int
        or receipt["bytes"] < 0
        or file_metadata(archive) != {key: receipt[key] for key in ("bytes", "sha256")}
    ):
        raise ValueError("received native archive does not match its completion receipt")
    try:
        actual, contracts = archive_members(archive)
    except (EOFError, gzip.BadGzipFile, tarfile.TarError) as exc:
        raise ValueError(
            "native archive compression or tar stream is incomplete or invalid"
        ) from exc
    manifest = decode_json(contracts["POOL-MANIFEST.json"])
    if not isinstance(manifest, dict) or any(
        not isinstance(member, dict) or type(member.get("bytes")) is not int or member["bytes"] < 0
        for member in manifest.values()
    ):
        raise ValueError("native archive manifest has an invalid integer member size")
    actual.pop("POOL-MANIFEST.json")
    if manifest != actual:
        raise ValueError("native archive does not match its complete member manifest")
    if decode_json(contracts["request.json"]) != request:
        raise ValueError("native archive contains another request")
    result = (
        decode_json(contracts["native/result.json"]) if "native/result.json" in contracts else None
    )
    if result != receipt["nativeResult"]:
        raise ValueError("native archive result differs from its completion receipt")
    if receipt["bridgeExit"] == 0:
        source = decode_json(contracts["native/source-input.json"])
        if any(source[key] != request["bindings"][key] for key in ("head", "tree", "tags")):
            raise ValueError("native archive source differs from the selected revision")
    return {
        "archiveBytes": receipt["bytes"],
        "originalFileCount": len(actual),
        "originalFileBytes": sum(member["bytes"] for member in actual.values()),
        "largestOriginalFileBytes": max((member["bytes"] for member in actual.values()), default=0),
    }


def archive_members(archive: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Stream every canonical regular member; retain only JSON contracts in memory."""
    with (
        archive.open("rb") as raw,
        gzip.GzipFile(fileobj=raw) as expanded,
        tarfile.open(fileobj=expanded, mode="r|") as tar,
    ):
        names = set()
        files = {}
        contracts = {}
        for member in tar:
            name = PurePosixPath(member.name)
            identity = name.as_posix()
            canonical = (identity, identity + "/") if member.isdir() else (identity,)
            if (
                identity in names
                or member.name not in canonical
                or any(
                    member.pax_headers[field] not in canonical
                    for field in ("path", "GNU.sparse.name")
                    if field in member.pax_headers
                )
                or name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or name.parts[0] != "capture"
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("native archive has an unsafe or repeated member")
            names.add(identity)
            if member.isfile():
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("native archive member could not be read")
                relative = name.relative_to("capture").as_posix()
                retained = (
                    bytearray()
                    if relative
                    in {
                        "POOL-MANIFEST.json",
                        "request.json",
                        "native/result.json",
                        "native/source-input.json",
                    }
                    else None
                )
                files[relative] = stream_metadata(stream, retained)
                if retained is not None:
                    contracts[relative] = bytes(retained)
        # Read through tar's own buffer: another archive or hidden member after
        # its end marker is not padding. This also validates the gzip trailer.
        while padding := tar.fileobj.read(1 << 20):
            if padding.strip(b"\0"):
                raise ValueError("native archive contains data after its tar end marker")
        return files, contracts


def pool() -> int:
    """Run the installed pool driver and receive full evidence before permitting a push."""
    runner = shutil.which("box_run.sh")
    if runner is None:
        raise ValueError("pool venue needs the installed box_run.sh on PATH")
    request = {"nonce": secrets.token_hex(16), "bindings": bindings()}
    storage = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir")) / "aev-pre-push-pool"
    if storage.is_symlink():
        raise ValueError("pool evidence storage is a symbolic link")
    storage.mkdir(exist_ok=True)
    retained = Path(tempfile.mkdtemp(prefix="capture-", dir=storage))
    (retained / "request.json").write_bytes(encode(request))
    print(f"pre-push: pool evidence retained at {retained}", flush=True)
    argument = base64.b64encode(encode(request)).decode()
    command = [
        runner,
        "pre-push-" + request["nonce"],
        "--keep",
        "--",
        "python3",
        "scripts/pre-push-pool.py",
        "remote",
        argument,
    ]
    with (retained / "runner.stdout").open("wb") as out:
        with (retained / "runner.stderr").open("wb") as err:
            process = child(command, cwd=ROOT, stdout=out, stderr=err)
    (retained / "runner-process.json").write_bytes(encode({"returncode": process.returncode}))
    log = (retained / "runner.stdout").read_text()
    # box_run's console includes only a tail. Its LOCAL_LOG holds the full job.
    paths = [
        line.split(" LOCAL_LOG ", 1)[1].split(" SSH_STATUS ", 1)[0].strip()
        for line in log.splitlines()
        if " LOCAL_LOG " in line
    ]
    if len(paths) != 1:
        raise ValueError("pool runner did not return its full original job log")
    full_log = Path(paths[0]).read_bytes()
    (retained / "job.log").write_bytes(full_log)
    receipt = completion(full_log.decode(), request, process.returncode)
    route = ssh_route(log)
    path = PurePosixPath(receipt["archive"])
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.parts[-3:] != (".build", "pre-push-pool-" + request["nonce"], "native.tar.gz")
    ):
        raise ValueError("pool receipt names an unbound archive path")
    archive = retained / "native.tar.gz"
    with archive.open("xb") as out, (retained / "archive-read.stderr").open("wb") as err:
        received = child([*route, "cat " + shlex.quote(str(path))], stdout=out, stderr=err)
    (retained / "archive-read-process.json").write_bytes(
        encode({"returncode": received.returncode})
    )
    if received.returncode:
        raise ValueError("full native archive could not be received")
    measurements = check_archive(archive, receipt, request)
    (retained / "archive-validation.json").write_bytes(encode(measurements))
    require_bindings(request["bindings"])
    (retained / "completion.json").write_bytes(encode(receipt))
    print(f"pre-push: pool native exit {process.returncode}; full capture checked at {retained}")
    if isinstance(receipt["nativeResult"], dict):
        print("pre-push: native NOT RUN steps: " + json.dumps(receipt["nativeResult"]["not_run"]))
    return process.returncode


def main() -> int:
    """Expose the pool coordinator and its source-bound remote entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("pool", "remote"))
    parser.add_argument("request", nargs="?")
    args = parser.parse_args()
    try:
        if args.mode == "pool" and args.request is None:
            return pool()
        if args.mode == "remote" and args.request is not None:
            request = decode_json(base64.b64decode(args.request, validate=True))
            if not isinstance(request, dict):
                raise ValueError("pool request is not a JSON object")
            return remote(request)
        raise ValueError("pool takes no request; remote needs its bound request")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"pre-push: REFUSED -- {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
