"""Check that Python distributions contain the exact released registry bytes."""

import argparse
import base64
import csv
import hashlib
import io
import json
import stat
import tomllib
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

import yaml
from distribution_checks import check_source_archive, check_wheel_metadata


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check(wheel: Path, sdist: Path, source_root: Path | None = None) -> None:
    root = source_root.resolve() if source_root is not None else Path(__file__).resolve().parents[1]
    manifest = tomllib.loads((root / "pyproject.toml").read_text())
    project = manifest["project"]
    require(project["license"] == "Apache-2.0 AND CC0-1.0"
            and project["license-files"] == ["LICENSE", "LICENSE-CC0"], "released registry grants")
    data = (root / "vocabulary.yaml").read_bytes()
    require(yaml.safe_load(data)["meta"]["version"] == project["version"], "registry and package version")
    index = json.loads((root / "registry.json").read_text(encoding="utf-8"))
    require(hashlib.sha256(data).hexdigest() == index["source_sha256"], "registry digest")
    source = {"agent_evidence_vocabulary/__init__.py": root / "__init__.py",
              "agent_evidence_vocabulary/vocabulary.yaml": root / "vocabulary.yaml",
              "agent_evidence_vocabulary/registry.json": root / "registry.json",
              "agent_evidence_vocabulary/registry.py": root / "registry.py"}
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate wheel member")
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.filename
                    and path.as_posix() == member.filename, "wheel member path")
            require(not member.is_dir() and stat.S_IFMT(member.external_attr >> 16) in {0, stat.S_IFREG},
                    "wheel regular-file payload")
        infos = [n for n in names if n.endswith(".dist-info/METADATA")]
        require(len(infos) == 1, "wheel metadata population")
        info = infos[0].rsplit("/", 1)[0]
        require(not project.get("dependencies") and not project.get("optional-dependencies")
                and not project.get("scripts") and not project.get("gui-scripts")
                and not project.get("entry-points"), "data-only package declarations")
        metadata = check_wheel_metadata(archive, info, root, project, "agent_evidence_vocabulary",
                                        ["LICENSE", "LICENSE-CC0"])
        require({n for n in names if not n.startswith(info + "/")} == set(source), "wheel payload population")
        for name, path in source.items():
            require(archive.read(name) == path.read_bytes(), "wheel source bytes: " + name)
        record = info + "/RECORD"
        rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
        require(all(len(row) == 3 for row in rows), "RECORD columns")
        require(len(rows) == len(names) and {r[0] for r in rows} == set(names), "RECORD population")
        for name, digest, size in rows:
            if name == record:
                require(digest == size == "", "RECORD self-reference")
            else:
                raw = archive.read(name)
                value = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
                require(digest == "sha256=" + value and size == str(len(raw)), "RECORD bytes: " + name)
    expected = {"__init__.py", "vocabulary.yaml", "pyproject.toml", "README.md", "LICENSE", "LICENSE-CC0",
                "MANIFEST.in", "requirements.txt", "registry.json", "registry.py"}
    records = {"./__init__.py", "./vocabulary.yaml", "./registry.json", "./registry.py"} if manifest["tool"]["setuptools"]["package-dir"][
        "agent_evidence_vocabulary"] == "." else set()
    check_source_archive(sdist, root, project, metadata, expected,
                         "agent_evidence_vocabulary.egg-info", "agent_evidence_vocabulary", records)
    print("checked released registry bytes, both licenses, package metadata and every wheel RECORD hash")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--source-root", type=Path, help="compare a retained artifact with its matching source snapshot")
    args = parser.parse_args()
    check(args.wheel, args.sdist, args.source_root)
