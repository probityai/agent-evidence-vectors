#!/usr/bin/env python3
"""Verify the built Python files before PyPI publication, then lay them out in one upload directory.

    check-jcs-admit-python-release.py DIST --tag jcs-admit-py-v0.1.0 --out UPLOAD

DIST holds every file .github/workflows/jcs-admit-python-build.yml built. The check refuses unless the tag names
the version in python/pyproject.toml, the file set is exactly the expected population
(seven jcs-admit abi3 wheels and its sdist, nothing else), and every wheel and sdist
carries the project's name and version in its own metadata. It copies the files to OUT.
"""
import argparse
import re
import shutil
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "jcs-admit"
TAG_PREFIX = "jcs-admit-py-v"
PYPROJECT = Path("crates/jcs-admit/python/pyproject.toml")
PLATFORMS = (
    "manylinux_2_28_x86_64",
    "manylinux_2_28_aarch64",
    "musllinux_1_2_x86_64",
    "musllinux_1_2_aarch64",
    "macosx_",  # two files, told apart below
    "win_amd64",
)


def need(condition, message):
    if not condition:
        raise SystemExit("check-python-release: " + message)


def project(path):
    return tomllib.loads((ROOT / path).read_text())["project"]


def metadata(path):
    """Return the core metadata text of a wheel or an sdist."""
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as wheel:
            names = [n for n in wheel.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)]
            need(len(names) == 1, f"{path.name}: expected one METADATA, found {names}")
            return wheel.read(names[0]).decode()
    with tarfile.open(path) as sdist:
        names = [n for n in sdist.getnames() if n.count("/") == 1 and n.endswith("/PKG-INFO")]
        need(len(names) == 1, f"{path.name}: expected one PKG-INFO, found {names}")
        member = sdist.extractfile(names[0])
        need(member is not None, f"{path.name}: {names[0]} is not a regular file")
        assert member is not None
        return member.read().decode()


def field(text, name):
    return [m.group(1).strip() for m in re.finditer(rf"^{name}: (.*)$", text, re.MULTILINE)]


def plan(dist, binding):
    """Map each expected file name to its project name."""
    files = {p.name: p for p in dist.iterdir()}
    stem = f"{NAME.replace('-', '_')}-{binding['version']}"
    expected = {f"{stem}.tar.gz": NAME}
    wheels = [n for n in files if n.startswith(f"{stem}-cp310-abi3-") and n.endswith(".whl")]
    for family in PLATFORMS:
        hits = [n for n in wheels if family in n]
        need(len(hits) == (2 if family == "macosx_" else 1), f"wheels for {family}: {hits}")
        expected.update({n: NAME for n in hits})
    need(files.keys() == expected.keys(), f"file set differs: extra {sorted(files.keys() - expected.keys())}, missing {sorted(expected.keys() - files.keys())}")
    return files, expected


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dist", type=Path)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--pyproject", type=Path, default=PYPROJECT,
                    help="the binding's pyproject.toml, relative to the repository root")
    args = ap.parse_args(argv)

    binding = project(args.pyproject)
    need(binding["name"] == NAME, f"project name {binding['name']} is not {NAME}")
    need(args.tag == TAG_PREFIX + binding["version"],
         f"tag {args.tag} is not {TAG_PREFIX}{binding['version']}")
    files, expected = plan(args.dist, binding)

    for name in expected:
        text = metadata(files[name])
        need(field(text, "Name") == [NAME], f"{name}: Name {field(text, 'Name')}")
        need(field(text, "Version") == [binding["version"]], f"{name}: Version {field(text, 'Version')}")

    args.out.mkdir(parents=True, exist_ok=True)
    need(not any(args.out.iterdir()), f"{args.out} is not empty")
    chosen = sorted(expected)
    for name in chosen:
        shutil.copy2(files[name], args.out / name)
    print(f"{NAME} {binding['version']}: {len(chosen)} files verified and staged in {args.out}")
    for name in chosen:
        print("  " + name)


if __name__ == "__main__":
    main(sys.argv[1:])
