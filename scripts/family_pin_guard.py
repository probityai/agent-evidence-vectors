#!/usr/bin/env python3
"""Refuse a PyPI release that the newest release of a sibling distribution cannot install beside.

    family_pin_guard.py check --name NAME --version VERSION [--pins-out FILE]
                              [--metadata-dir DIR] [--family FILE]

The family is the distributions listed in scripts/family-packages.toml. For each one other than
NAME the guard reads the newest PyPI release's requirements and looks for a requirement on NAME.
When that requirement's specifier excludes VERSION, installing the candidate beside that sibling
fails (or silently falls back to an older sibling), so the guard names the sibling and its pin and
exits 1. `--pins-out` writes `name==version` for every sibling, one per line, for the install
check that follows in the release workflow.

A candidate that is not newer than its own newest published release passes: it cannot become the
version a resolver picks. Exit 0 is a pass, 1 a refusal, 2 a check that could not run (an
unreadable or missing sibling, or a NAME outside the family), which also blocks the publish.

`--metadata-dir` reads `<name>.json` files shaped like PyPI's JSON API instead of the network;
the tests use it. The dependency is `packaging`, declared in the root pyproject's dev group.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
FAMILY_FILE = ROOT / "scripts" / "family-packages.toml"
PYPI_URL = "https://pypi.org/pypi/{name}/json"
ATTEMPTS = 4


class MetadataError(Exception):
    """A release's metadata could not be read, so no verdict can be given."""


class NotPublished(MetadataError):
    """The distribution has no release on the index."""


@dataclass(frozen=True)
class Release:
    """The newest published release of one distribution."""

    name: str
    version: Version
    requires: tuple[str, ...]


@dataclass(frozen=True)
class Violation:
    """A sibling whose published requirement excludes the candidate."""

    sibling: str
    sibling_version: Version
    requirement: str
    candidate: str
    candidate_version: Version


def family(path: Path = FAMILY_FILE) -> list[str]:
    """Return the canonical names of the family's distributions."""
    names = tomllib.loads(path.read_text())["packages"]
    return [canonicalize_name(n) for n in names]


def _parse(name: str, document: dict) -> Release:
    info = document["info"]
    return Release(name, Version(info["version"]), tuple(info.get("requires_dist") or ()))


def _read(url: str) -> dict:
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NotPublished(url) from error
            last = error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last = error
        time.sleep(2**attempt)
    raise MetadataError(f"{url}: {last}")


def fetch(name: str, metadata_dir: Path | None = None) -> Release:
    """Return the newest published release of ``name``."""
    if metadata_dir is not None:
        path = metadata_dir / f"{name}.json"
        if not path.is_file():
            raise NotPublished(str(path))
        try:
            return _parse(name, json.loads(path.read_text()))
        except (ValueError, KeyError) as error:
            raise MetadataError(f"{path}: {error}") from error
    try:
        return _parse(name, _read(PYPI_URL.format(name=name)))
    except (ValueError, KeyError) as error:
        raise MetadataError(f"{name}: unreadable PyPI document: {error}") from error


def _binding(requirement: Requirement) -> bool:
    """Whether the requirement can apply to an install.

    A requirement behind an extra is kept: `pip install sibling[extra]` breaks the same way.
    """
    marker = requirement.marker
    if marker is None or "extra" in str(marker):
        return True
    return marker.evaluate()


def violations(candidate: str, version: Version, siblings: list[Release]) -> list[Violation]:
    """Return every sibling requirement on ``candidate`` that excludes ``version``."""
    found = []
    for release in siblings:
        for text in release.requires:
            requirement = Requirement(text)
            if canonicalize_name(requirement.name) != candidate or not _binding(requirement):
                continue
            if not requirement.specifier.contains(version, prereleases=True):
                found.append(Violation(release.name, release.version, text, candidate, version))
    return found


def check(name: str, version: str, names: list[str], metadata_dir: Path | None = None
          ) -> tuple[list[Violation], list[Release], str]:
    """Return (violations, sibling releases, note) for a candidate release."""
    candidate = canonicalize_name(name)
    if candidate not in names:
        raise MetadataError(f"{name} is not listed in {FAMILY_FILE.name}; add it before releasing it")
    wanted = Version(version)
    siblings = [fetch(n, metadata_dir) for n in names if n != candidate]
    try:
        own = fetch(candidate, metadata_dir)
    except NotPublished:
        own = None
    if own is not None and wanted <= own.version:
        return [], siblings, f"{candidate} {wanted} is not newer than the published {own.version}"
    return violations(candidate, wanted, siblings), siblings, ""


def _report(found: list[Violation]) -> str:
    first = found[0]
    lines = [f"family-pin-guard: REFUSE {first.candidate} {first.candidate_version}"]
    for v in found:
        lines.append(f"  {v.sibling} {v.sibling_version} requires {v.requirement}, which excludes {v.candidate_version}")
    siblings = " and ".join(sorted({v.sibling for v in found}))
    lines.append(f"  fix: release {siblings} with a widened pin first, then publish this release again")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("check")
    one.add_argument("--name", required=True)
    one.add_argument("--version", required=True)
    one.add_argument("--pins-out", type=Path)
    one.add_argument("--metadata-dir", type=Path)
    one.add_argument("--family", type=Path, default=FAMILY_FILE)
    args = parser.parse_args(argv)
    try:
        found, siblings, note = check(args.name, args.version, family(args.family), args.metadata_dir)
    except MetadataError as error:
        print(f"family-pin-guard: CHECK DID NOT RUN: {error}", file=sys.stderr)
        return 2
    if args.pins_out:
        args.pins_out.write_text("".join(f"{r.name}=={r.version}\n" for r in siblings))
    if found:
        print(_report(found), file=sys.stderr)
        return 1
    suffix = f" ({note})" if note else ""
    print(f"family-pin-guard: PASS {canonicalize_name(args.name)} {args.version}: "
          f"{len(siblings)} siblings read{suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
