"""Static checks for the data-only wheel and its setuptools source archive."""

import tarfile
from collections import Counter
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.utils import canonicalize_name
from packaging.version import Version


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_wheel_metadata(archive, info: str, root: Path, project: dict, package: str,
                         licenses: list[str]) -> bytes:
    require(not any(project.get(key) for key in ["dependencies", "optional-dependencies", "scripts",
                                                "gui-scripts", "entry-points"]), "data-only package declarations")
    expected_info = f"{canonicalize_name(project['name']).replace('-', '_')}-{Version(project['version'])}.dist-info"
    require(info == expected_info, "wheel metadata location")
    expected = {"METADATA", "WHEEL", "RECORD", "top_level.txt", *("licenses/" + name for name in licenses)}
    require({name[len(info) + 1:] for name in archive.namelist() if name.startswith(info + "/")} == expected,
            "wheel dist-info population")
    raw = archive.read(info + "/METADATA")
    metadata = BytesParser().parsebytes(raw)
    require(not metadata.defects, "wheel metadata syntax")
    singles = {"Metadata-Version": "2.4", "Name": project["name"], "Version": project["version"],
               "Summary": project["description"], "Requires-Python": project["requires-python"],
               "License-Expression": project["license"], "Description-Content-Type": "text/markdown",
               "Dynamic": "license-file"}
    if project.get("keywords"):
        singles["Keywords"] = ",".join(project["keywords"])
    authors = project.get("authors", [])
    require(all(set(author) == {"name"} for author in authors), "supported source author fields")
    if authors:
        singles["Author"] = ", ".join(author["name"] for author in authors)
    repeated = {"Project-URL", "License-File"}
    if project.get("classifiers"):
        repeated.add("Classifier")
    require(set(metadata.keys()) == set(singles) | repeated, "declared metadata field population")
    for key, value in singles.items():
        require(metadata.get_all(key) == [value], "wheel metadata: " + key)
    require(metadata.get_payload(decode=True) == (root / project["readme"]).read_bytes(), "wheel README bytes")
    require(Counter(metadata.get_all("Project-URL", [])) == Counter(
        f"{key}, {value}" for key, value in project["urls"].items()), "wheel project URLs")
    require(metadata.get_all("Classifier", []) == list(project.get("classifiers", [])), "wheel classifiers")
    require(Counter(metadata.get_all("License-File", [])) == Counter(licenses), "wheel license fields")
    for name in licenses:
        require(archive.read(info + "/licenses/" + name) == (root / name).read_bytes(), "wheel license bytes")
    require(archive.read(info + "/top_level.txt") == (package + "\n").encode(), "wheel top-level packages")
    wheel = BytesParser().parsebytes(archive.read(info + "/WHEEL"))
    require(not wheel.defects, "WHEEL metadata syntax")
    expected_wheel = {"Wheel-Version": "1.0", "Generator": "setuptools (84.2.1)",
                      "Root-Is-Purelib": "true", "Tag": "py3-none-any"}
    require(set(wheel.keys()) == set(expected_wheel), "WHEEL field population")
    for key, value in expected_wheel.items():
        require(wheel.get_all(key) == [value], "WHEEL metadata: " + key)
    return raw


def check_source_archive(sdist: Path, root: Path, project: dict, metadata: bytes,
                         authored: set[str], egg_info: str, package: str,
                         extra_source_records: set[str] = frozenset()) -> None:
    generated = {"PKG-INFO", "setup.cfg", *(egg_info + "/" + name for name in
                 ["PKG-INFO", "SOURCES.txt", "dependency_links.txt", "top_level.txt"])}
    require(not authored & generated and bool(authored), "source ownership population")
    expected_files = authored | generated
    prefix = canonicalize_name(project["name"]).replace("-", "_") + "-" + str(Version(project["version"]))
    expected_dirs = {prefix}
    for name in expected_files:
        expected_dirs.update(parent.as_posix() for parent in (PurePosixPath(prefix) / name).parents
                             if parent.as_posix() != ".")
    with tarfile.open(sdist) as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "duplicate source member")
        files = {}
        directories = set()
        for member in members:
            name = member.name
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name
                    and path.as_posix() == name and path.parts[0] == prefix, "source member path and root")
            require(not member.mode & 0o7000 and (member.isfile() or member.isdir()), "source member type")
            if member.isdir():
                directories.add(name)
            else:
                files[path.relative_to(prefix).as_posix()] = member
        require(set(files) == expected_files, "source file population")
        require(directories == expected_dirs, "source directory population")
        def read(name):
            return archive.extractfile(files[name]).read()
        for name in authored:
            path = root / name
            require(path.is_file() and not path.is_symlink() and read(name) == path.read_bytes(),
                    "source authored bytes: " + name)
        require(read("setup.cfg") == b"[egg_info]\ntag_build = \ntag_date = 0\n\n", "generated source setup.cfg")
        require(read("PKG-INFO") == metadata and read(egg_info + "/PKG-INFO") == metadata, "source package metadata")
        require(read(egg_info + "/dependency_links.txt") == b"\n", "source dependency links")
        require(read(egg_info + "/top_level.txt") == (package + "\n").encode(), "source top-level packages")
        sources = read(egg_info + "/SOURCES.txt").decode("utf-8").splitlines()
        expected_sources = authored | {name for name in generated if name.startswith(egg_info + "/")}
        require(len(sources) == len(set(sources)) and set(sources) == expected_sources | extra_source_records,
                "generated source inventory")
