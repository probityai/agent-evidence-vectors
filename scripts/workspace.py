"""Map changed paths to areas of the repository, and release tags to units.

    python3 scripts/workspace.py areas                    # JSON list of every area
    python3 scripts/workspace.py changes <base> <head>    # JSON {area: true|false}
    python3 scripts/workspace.py all                      # JSON {area: true} (pushes to main)
    python3 scripts/workspace.py release-target <tag>     # JSON for the unit the tag releases

An area is a directory with its own checks: crates/<name>, packages/<name>,
actions, vectors, site and pages, each once it exists. An area is changed when a file under it
changed, or when a shared file changed (anything outside every area, except
documentation). CI and the tests read the same answer from here. Standard
library only, because CI runs it before anything is installed.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
_DOCS = re.compile(r"(docs/.*|.*\.md|LICENSE)\Z")
_TAG = re.compile(r"(?P<prefix>[a-z0-9][a-z0-9-]*?)-v(?P<version>\d+\.\d+\.\d+)\Z")
# The corpus release: a bare v<major>.<minor>.<patch> tag. release.yml publishes it from its
# own tag-push path, so a GitHub release published for it resolves to no registry.
_BARE_TAG = re.compile(r"v(?P<version>\d+\.\d+\.\d+)\Z")
_TOP_AREAS = ("actions", "vectors", "pages")
# A workflow file is checked by what it runs, not by every area. The reusable workflows that
# parts.yml calls belong to one area each. parts.yml, release.yml and the workflows only release.yml
# calls stay shared, because no pull request job exercises them. Every other workflow has its own
# pull_request trigger and path filter, so editing it selects no area here.
_WORKFLOW_AREAS = (
    (re.compile(r"\.github/workflows/crate-dsse(-npm)?\.yml\Z"), "crates/dsse"),
    (re.compile(r"\.github/workflows/(crate-jcs-admit(-npm)?|jcs-admit-python-build)\.yml\Z"), "crates/jcs-admit"),
    (re.compile(r"\.github/workflows/package-admission\.yml\Z"), "packages/admission"),
    (re.compile(r"\.github/workflows/actions-admission\.yml\Z"), "actions"),
    (re.compile(r"\.github/workflows/package-vocabulary\.yml\Z"), "packages/vocabulary"),
)
_WORKFLOW_SHARED = re.compile(
    r"\.github/workflows/(parts|release|family-pin-guard|python-build)\.yml\Z")
_WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.yml\Z")


def _workflow_areas(path: str) -> list[str] | None:
    """Return the areas a workflow file selects, or None when it is not a workflow file."""
    if not _WORKFLOW.match(path):
        return None
    if _WORKFLOW_SHARED.match(path):
        return None
    return [area for pattern, area in _WORKFLOW_AREAS if pattern.match(path)]


def areas(root: Path = ROOT) -> list[str]:
    """Return every area directory, relative to the root, sorted."""
    found = [d for d in _TOP_AREAS if (root / d).is_dir()]
    for parent in ("crates", "packages"):
        if (root / parent).is_dir():
            found += [f"{parent}/{d.name}" for d in (root / parent).iterdir() if d.is_dir()]
    return sorted(found)


def changed(paths: list[str], root: Path = ROOT) -> dict[str, bool]:
    """Return, for each area, whether these changed paths require its checks."""
    table = areas(root)
    owner = {p: [a for a in table if PurePosixPath(p).is_relative_to(a)] for p in paths}
    for p in paths:
        flows = _workflow_areas(p)
        if flows is not None:
            owner[p] = [a for a in flows if a in table]
    independent = {p for p in paths if _workflow_areas(p) is not None}
    shared = any(not owner[p] and not _DOCS.match(p) and p not in independent for p in paths)
    return {a: shared or any(a in owner[p] for p in paths) for a in table}


def _version(unit: dict[str, str], root: Path) -> str:
    directory = root / unit["directory"]
    if unit["registry"] == "crates.io":
        return tomllib.loads((directory / "Cargo.toml").read_text())["package"]["version"]
    if unit["registry"] == "pypi":
        return tomllib.loads((directory / "pyproject.toml").read_text())["project"]["version"]
    if unit["registry"] == "npm":
        return json.loads((directory / "package.json").read_text())["version"]
    if unit["registry"] == "github-actions":
        # An Action has no manifest version; its release line is a one-line VERSION file.
        return (directory / "VERSION").read_text().strip()
    raise SystemExit(f"unit {unit['prefix']!r} names an unknown registry {unit['registry']!r}")


_MANIFEST = {"crates.io": "Cargo.toml", "pypi": "pyproject.toml", "npm": "package.json"}


def _release_links() -> ModuleType:
    """Load scripts/release_links.py from beside this file; the tests load this file by path."""
    spec = importlib.util.spec_from_file_location("release_links", Path(__file__).with_name("release_links.py"))
    if spec is None or spec.loader is None:
        raise SystemExit("scripts/release_links.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _refuse_unusable_links(unit: dict[str, str], root: Path) -> None:
    """Stop the release when the unit's manifest links to an archive, a redirect, a private repository or nothing."""
    name = _MANIFEST.get(unit["registry"])
    if name is None:
        return
    problems = _release_links().check_manifest(root / unit["directory"] / name)
    if problems:
        raise SystemExit("the registry page would link to nowhere useful:\n" + "\n".join(problems))


def release_target(tag: str, root: Path = ROOT, check_links: bool = False) -> dict[str, str]:
    """Resolve a release tag ``<prefix>-v<version>`` to the unit it publishes.

    A bare ``v<version>`` tag is the corpus release; it names no unit of release.toml and
    resolves to registry ``none``, which every release job treats as "publish nothing".
    """
    bare = _BARE_TAG.match(tag)
    if bare:
        return {"prefix": "", "name": "agent-evidence-vectors", "registry": "none",
                "directory": "", "version": bare["version"]}
    match = _TAG.match(tag)
    if not match:
        raise SystemExit(f"release tag {tag!r} is not <prefix>-v<major>.<minor>.<patch>")
    units = tomllib.loads((root / "release.toml").read_text()).get("unit", [])
    found = [u for u in units if u["prefix"] == match["prefix"]]
    if len(found) != 1:
        known = ", ".join(sorted(u["prefix"] for u in units))
        raise SystemExit(f"release tag {tag!r} names no single unit (units: {known})")
    unit = found[0]
    if not (root / unit["directory"]).is_dir():
        raise SystemExit(f"unit {unit['prefix']!r} directory {unit['directory']} does not exist")
    version = _version(unit, root)
    if version != match["version"]:
        raise SystemExit(
            f"release tag {tag!r} does not match {unit['directory']} version {version}"
        )
    if check_links:
        _refuse_unusable_links(unit, root)
    return {**unit, "version": version}


def main(argv: list[str]) -> int:
    if argv == ["areas"]:
        print(json.dumps(areas()))
        return 0
    if argv == ["all"]:
        print(json.dumps({a: True for a in areas()}, sort_keys=True))
        return 0
    if len(argv) == 3 and argv[0] == "changes":
        diff = subprocess.run(["git", "diff", "--name-only", f"{argv[1]}...{argv[2]}"], cwd=ROOT,
                              check=True, capture_output=True, text=True).stdout.split()
        print(json.dumps(changed(diff), sort_keys=True))
        return 0
    if len(argv) == 2 and argv[0] == "release-target":
        print(json.dumps(release_target(argv[1], check_links=True), sort_keys=True))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
