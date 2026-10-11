#!/usr/bin/env python3
"""Bind the Python source archive to its declared public source and metadata."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import subprocess
import tarfile
import tomllib
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import IO, Any

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


class BoundaryError(ValueError):
    """A generated artifact changes the selected public package contract."""


def source_sha256(stream: IO[bytes]) -> str:
    hashed = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        hashed.update(chunk)
    return hashed.hexdigest()


def excluded(name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(name, pattern.replace("**/", "")):
            return True
        if pattern.startswith("**/") and pattern[3:] in PurePosixPath(name).parts:
            return True
    return False


def selected(name: str, includes: list[str]) -> bool:
    return any(name == item or name.startswith(item.rstrip("/") + "/") for item in includes)


def source_files(root: Path, config: dict[str, Any]) -> dict[str, str]:
    target = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    paths = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    expected = {}
    for raw in paths.split(b"\0"):
        if not raw:
            continue
        name = raw.decode()
        if name == "pyproject.toml" or (
            selected(name, target["only-include"]) and not excluded(name, target.get("exclude", []))
        ):
            if name.startswith("docs/research/"):
                raise BoundaryError("research-source-selected: sdist includes research documents")
            with (root / name).open("rb") as stream:
                expected[name] = source_sha256(stream)
    return expected


def requirement_text(text: str) -> str:
    requirement = Requirement(text)
    requirement.name = canonicalize_name(requirement.name)
    return str(requirement)


def requirements(project: dict[str, Any]) -> set[str]:
    expected = {requirement_text(text) for text in project.get("dependencies", [])}
    for extra, declarations in project.get("optional-dependencies", {}).items():
        for text in declarations:
            requirement = Requirement(text)
            condition = f'extra == "{canonicalize_name(extra)}"'
            if requirement.marker:
                condition = f"({requirement.marker}) and {condition}"
            requirement.marker = Marker(condition)
            expected.add(requirement_text(str(requirement)))
    return expected


def metadata(data: bytes, project: dict[str, Any], root: Path) -> None:
    message = BytesParser(policy=default).parsebytes(data)
    fields = {
        "Name": project["name"],
        "Version": project["version"],
        "Summary": project["description"],
        "Requires-Python": project["requires-python"],
    }
    for field, value in fields.items():
        if message.get_all(field) != [value]:
            raise BoundaryError(f"metadata-field: {field} differs from the selected project")
    urls = {tuple(value.split(", ", 1)) for value in message.get_all("Project-URL", [])}
    if urls != set(project.get("urls", {}).items()):
        raise BoundaryError("metadata-urls: package URLs differ from the selected project")
    actual = {requirement_text(value) for value in message.get_all("Requires-Dist", [])}
    if actual != requirements(project):
        raise BoundaryError("metadata-dependencies: requirements differ from the selected project")
    extras = {canonicalize_name(value) for value in message.get_all("Provides-Extra", [])}
    if extras != {canonicalize_name(value) for value in project.get("optional-dependencies", {})}:
        raise BoundaryError("metadata-extras: extras differ from the selected project")
    description = message.get_payload(decode=True)
    if (
        not isinstance(description, bytes)
        or description.strip() != (root / project["readme"]).read_bytes().strip()
    ):
        raise BoundaryError(
            "metadata-description: long description differs from the selected README"
        )


def member_name(member: tarfile.TarInfo, prefix: str) -> str:
    parts = PurePosixPath(member.name).parts
    if not member.isfile() or len(parts) < 2 or parts[0] != prefix or ".." in parts:
        raise BoundaryError("archive-member: unsupported source archive member")
    return PurePosixPath(*parts[1:]).as_posix()


def source_member(name: str, stream: IO[bytes], expected: dict[str, str]) -> None:
    if name.startswith("docs/research/"):
        raise BoundaryError("research-artifact: source archive contains research documents")
    if name not in expected:
        raise BoundaryError(f"source-unlisted: source archive contains undeclared source {name}")
    if source_sha256(stream) != expected[name]:
        raise BoundaryError("source-bytes: source archive differs from the selected source")


def read_archive(
    path: Path, prefix: str, expected: dict[str, str]
) -> tuple[set[str], bytes | None]:
    seen: set[str] = set()
    package_metadata = None
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            name = member_name(member, prefix)
            if name in seen:
                raise BoundaryError("archive-duplicate: repeated source archive member")
            seen.add(name)
            stream = archive.extractfile(member)
            if stream is None:
                raise BoundaryError("archive-unreadable: source member has no readable bytes")
            with stream:
                if name == "PKG-INFO":
                    package_metadata = stream.read()
                else:
                    source_member(name, stream, expected)
    return seen, package_metadata


def check(root: Path, dist: Path) -> int:
    config = tomllib.loads((root / "pyproject.toml").read_text())
    project = config["project"]
    if project.get("dependencies"):
        raise BoundaryError("runtime-contract: the reference rail declares runtime dependencies")
    filename = canonicalize_name(project["name"]).replace("-", "_") + "-" + project["version"]
    archives = list(dist.glob("*.tar.gz"))
    if len(archives) != 1 or archives[0].name != filename + ".tar.gz":
        raise BoundaryError("archive-selection: expected exactly the selected project's sdist")
    expected = source_files(root, config)
    seen, package_metadata = read_archive(archives[0], filename, expected)
    if seen != set(expected) | {"PKG-INFO"}:
        raise BoundaryError("source-missing: source archive omits declared public source")
    if package_metadata is None:
        raise BoundaryError("metadata-missing: source archive omits PKG-INFO")
    metadata(package_metadata, project, root)
    return len(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        count = check(args.root.resolve(), args.dist.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"OK: sdist contains exactly {count} selected public source files and matching metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
