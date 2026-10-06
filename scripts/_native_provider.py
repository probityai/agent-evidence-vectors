"""Verify declared Go/Node versions and provision only an owned job runtime."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any

from _gate_json import decode_json

TOOLS = {"go": ("go", "gofmt"), "node": ("node", "npm", "npx")}


def matches(actual: str, wanted: str) -> bool:
    return actual.split(".")[: len(wanted.split("."))] == wanted.split(".")


def command(
    argv: list[str], env: dict[str, str], directory: pathlib.Path, label: str
) -> subprocess.CompletedProcess[bytes]:
    directory.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(argv, env=env, capture_output=True, check=False)  # noqa: S603
    (directory / f"{label}.stdout.txt").write_bytes(proc.stdout)
    (directory / f"{label}.stderr.txt").write_bytes(proc.stderr)
    (directory / f"{label}.result.json").write_text(
        json.dumps({"command": argv, "returncode": proc.returncode}, allow_nan=False) + "\n"
    )
    return proc


def probe(
    kind: str,
    env: dict[str, str],
    directory: pathlib.Path,
    label: str,
    records: list[dict[str, Any]],
) -> str:
    tools = {tool: shutil.which(tool, path=env.get("PATH")) for tool in TOOLS[kind]}
    record: dict[str, Any] = {"kind": kind, "tools": tools, "label": label}
    records.append(record)
    if not all(tools.values()):
        return ""
    argv = [kind, "version" if kind == "go" else "--version"]
    proc = command(argv, env, directory, label)
    record.update(
        command=argv,
        returncode=proc.returncode,
        stdout=proc.stdout.decode("utf-8", "replace"),
        stderr=proc.stderr.decode("utf-8", "replace"),
    )
    pattern = (
        r"go version go([0-9]+(?:\.[0-9]+)+) [^\r\n]+"
        if kind == "go"
        else r"v([0-9]+(?:\.[0-9]+)+)"
    )
    version = re.fullmatch(pattern, record["stdout"].strip())
    return version.group(1) if proc.returncode == 0 and version else ""


def platform_archive(kind: str, version: str) -> tuple[str, str, str]:
    system = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    machine = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not system or not machine:
        raise ValueError("declared provider has no supported official archive for this platform")
    if kind == "go":
        return system, machine, f"go{version}.{system}-{machine}.tar.gz"
    node_machine = "x64" if machine == "amd64" else machine
    return system, machine, f"node-v{version}-{system}-{node_machine}.tar.gz"


def download(url: str, destination: pathlib.Path, env: dict[str, str]) -> None:
    proc = command(
        [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            url,
            "--output",
            str(destination),
        ],
        env,
        destination.parent,
        destination.name + ".download",
    )
    if proc.returncode:
        raise ValueError(f"official provider download failed with exit {proc.returncode}: {url}")
    if not destination.is_file() or destination.is_symlink():
        raise ValueError("official provider download did not create a regular input")


def selected_release(rows: Any, kind: str, wanted: str) -> tuple[dict[str, Any], str]:
    if not isinstance(rows, list):
        raise ValueError("official provider release index is not a list")
    choices = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("version"), str):
            raise ValueError("official provider release version is not a string")
        value = row["version"]
        if value in seen:
            raise ValueError("official provider release index repeats a version")
        seen.add(value)
        version = value.removeprefix("go" if kind == "go" else "v")
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) and matches(version, wanted):
            if kind != "go" or row.get("stable") is True:
                choices.append((tuple(map(int, version.split("."))), row, version))
    if not choices:
        raise ValueError("declared version has no stable official provider release")
    _, selected, version = max(choices, key=lambda item: item[0])
    return selected, version


def release(
    kind: str, wanted: str, directory: pathlib.Path, env: dict[str, str]
) -> tuple[str, str, str]:
    url = (
        "https://go.dev/dl/?mode=json&include=all"
        if kind == "go"
        else "https://nodejs.org/dist/index.json"
    )
    metadata = directory / "index.json"
    download(url, metadata, env)
    selected, version = selected_release(decode_json(metadata.read_bytes()), kind, wanted)
    system, machine, filename = platform_archive(kind, version)
    if kind == "go":
        if not isinstance(selected.get("files"), list) or not all(
            isinstance(entry, dict) for entry in selected["files"]
        ):
            raise ValueError("official Go release files are not archive records")
        files = [
            entry
            for entry in selected["files"]
            if entry.get("filename") == filename
            and entry.get("os") == system
            and entry.get("arch") == machine
            and entry.get("kind") == "archive"
        ]
        if len(files) != 1:
            raise ValueError("official Go release does not bind a unique platform archive")
        checksum = files[0]["sha256"]
        archive_url = "https://go.dev/dl/" + filename
    else:
        archive_url = f"https://nodejs.org/dist/v{version}/{filename}"
        sums = directory / "SHASUMS256.txt"
        download(f"https://nodejs.org/dist/v{version}/SHASUMS256.txt", sums, env)
        entries = [line.split() for line in sums.read_text().splitlines()]
        checksums = [parts[0] for parts in entries if len(parts) == 2 and parts[1] == filename]
        if len(checksums) != 1:
            raise ValueError("official Node checksums do not bind a unique archive")
        checksum = checksums[0]
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("official provider checksum is malformed")
    return version, archive_url, checksum


def digest(path: pathlib.Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def extract(archive: pathlib.Path, runtime: pathlib.Path, root: str) -> None:
    """Validate canonical member identities, then use Python's contained data filter."""
    with tarfile.open(archive, "r:gz") as source:
        seen: set[str] = set()
        for member in source:
            identity = pathlib.PurePosixPath(member.name)
            canonical = str(identity)
            if (
                identity.is_absolute()
                or ".." in identity.parts
                or not identity.parts
                or identity.parts[0] != root
                or member.name
                != canonical + ("/" if member.isdir() and member.name.endswith("/") else "")
                or canonical in seen
                or not (member.isfile() or member.isdir() or member.issym() or member.islnk())
            ):
                raise ValueError("official provider archive has unsafe or duplicate members")
            seen.add(canonical)
        runtime.mkdir()
        source.extractall(runtime, filter="data")


def inventory(
    kind: str,
    wanted: str,
    env: dict[str, str],
    directory: pathlib.Path,
    records: list[dict[str, Any]],
) -> pathlib.Path | None:
    """Read maintained mise inventory without changing installation or configuration."""
    mise = shutil.which("mise", path=env.get("PATH"))
    if not mise:
        return None
    proc = command([mise, "where", f"{kind}@{wanted}"], env, directory, "inventory")
    if proc.returncode:
        return None
    location = pathlib.Path(proc.stdout.decode().strip())
    if not location.is_absolute() or not location.is_dir():
        return None
    candidate = location / "bin"
    if not contained_tools(kind, candidate, location):
        return None
    selected = {**env, "PATH": str(candidate) + os.pathsep + env.get("PATH", "")}
    actual = probe(kind, selected, directory, "inventory-version", records)
    return candidate if actual and matches(actual, wanted) else None


def contained_tools(kind: str, binary: pathlib.Path, root: pathlib.Path) -> bool:
    return all(
        (binary / tool).is_file()
        and os.access(binary / tool, os.X_OK)
        and (binary / tool).resolve().is_relative_to(root.resolve())
        for tool in TOOLS[kind]
    )


def ensure(
    kind: str, wanted: str, env: dict[str, str], temp: pathlib.Path, record: dict[str, Any]
) -> tuple[pathlib.Path | None, pathlib.Path | None]:
    if kind not in TOOLS or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", wanted):
        raise ValueError("provider version must be an explicit numeric Go or Node selector")
    inputs = temp / "provider-inputs"
    if inputs.is_symlink():
        raise ValueError("provider input directory is a symbolic link")
    inputs.mkdir(exist_ok=True)
    directory = pathlib.Path(tempfile.mkdtemp(prefix=f"{kind}-{wanted}-", dir=inputs))
    probes: list[dict[str, Any]] = []
    record.update(
        kind=kind,
        wanted=wanted,
        probes=probes,
        hosted_provisioning=False,
        inputDirectory=directory.relative_to(temp).as_posix(),
    )
    actual = probe(kind, env, directory, "original-version", probes)
    if actual and matches(actual, wanted):
        record["route"] = "existing PATH"
        return None, None
    available = inventory(kind, wanted, env, directory, probes)
    if available:
        record.update(route="maintained installed inventory", selectedBin=str(available))
        return available, available.parent if kind == "go" else None
    version, url, checksum = release(kind, wanted, directory, env)
    archive = directory / "archive.tar.gz"
    download(url, archive, env)
    actual_checksum = digest(archive)
    record.update(
        route="job-owned official archive",
        version=version,
        archiveUrl=url,
        expectedSha256=checksum,
        actualSha256=actual_checksum,
        archiveBytes=archive.stat().st_size,
        archiveVerified=actual_checksum == checksum,
    )
    if actual_checksum != checksum:
        raise ValueError("official provider archive does not match its selected SHA256")
    root = "go" if kind == "go" else url.rsplit("/", 1)[1].removesuffix(".tar.gz")
    runtime = temp / "provider-runtime" / directory.name
    if runtime.parent.is_symlink():
        raise ValueError("provider runtime directory is a symbolic link")
    runtime.parent.mkdir(exist_ok=True)
    extract(archive, runtime, root)
    binary = runtime / root / "bin"
    if not contained_tools(kind, binary, runtime / root):
        raise ValueError("verified provider archive is missing contained executable tools")
    selected = {**env, "PATH": str(binary) + os.pathsep + env.get("PATH", "")}
    if kind == "go":
        selected["GOROOT"] = str(binary.parent)
    actual = probe(kind, selected, directory, "selected-version", probes)
    if not actual or not matches(actual, wanted):
        raise ValueError("verified provider archive did not supply the declared executable version")
    record["selectedBin"] = str(binary)
    return binary, binary.parent if kind == "go" else None
