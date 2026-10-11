#!/usr/bin/env python3
"""The action builds on an exact interpreter with a hash-locked build backend.

Why this file exists
--------------------
The action set up Python as "3.13", which resolves to whatever 3.13 release the
runner image carries that day, and built the package with pip's default build
isolation, which fetched hatchling and its dependencies from PyPI by version
range with no hashes. Two runs of one action pin could therefore build and
replay with different code. The action now names a patch release and installs
the backend from action-build-requirements.txt, by version and hash, as wheels
only, and builds with no index.

The cases read action.yml as YAML rather than grepping it, so a value moved to
a comment does not pass. The last two cases put the floating values back into
a copy of the action and require this file to go red against the copy.

Usage: python3 scripts/action-build-pin-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from packaging.requirements import Requirement

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION = Path(os.environ.get("AEV_ACTION_UNDER_TEST", REPO_ROOT / "action.yml"))
LOCK = REPO_ROOT / "action-build-requirements.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"
SETUP_PYTHON = "actions/setup-python@"
INSTALL_STEP = "Install the suite"
PINNED_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)\s*\\$")
HASH_LINE = re.compile(r"^\s+--hash=sha256:[0-9a-f]{64}(\s*\\)?$")


def steps() -> list[dict[str, Any]]:
    loaded: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    found: list[dict[str, Any]] = loaded["runs"]["steps"]
    return found


def install_script() -> str:
    matches = [s for s in steps() if s.get("name") == INSTALL_STEP]
    assert len(matches) == 1, f"expected one {INSTALL_STEP!r} step, found {len(matches)}"
    return str(matches[0]["run"])


def locked() -> dict[str, tuple[str, int]]:
    """Each locked distribution, with its version and how many hashes it carries."""
    out: dict[str, tuple[str, int]] = {}
    current = ""
    for line in LOCK.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        pinned = PINNED_LINE.match(line)
        if pinned:
            current = pinned.group(1).lower()
            out[current] = (pinned.group(2), 0)
            continue
        assert HASH_LINE.match(line) and current, f"unexpected line in the lock: {line!r}"
        version, hashes = out[current]
        out[current] = (version, hashes + 1)
    return out


def python_version() -> str:
    setups = [s for s in steps() if str(s.get("uses", "")).startswith(SETUP_PYTHON)]
    assert len(setups) == 1, f"expected one setup-python step, found {len(setups)}"
    return str(setups[0].get("with", {}).get("python-version", ""))


def case_python_is_an_exact_patch_release(work: Path) -> None:
    del work
    version = python_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
        f"setup-python python-version is {version!r}, not an exact patch release"
    )


def case_backend_installed_from_the_lock(work: Path) -> None:
    del work
    script = install_script()
    for flag in ("--require-hashes", "--only-binary :all:", "action-build-requirements.txt"):
        assert flag in script, f"the install step does not install the backend with {flag}"
    for flag in ("--no-build-isolation", "--no-index"):
        assert script.count(flag) >= 1, f"the install step does not build with {flag}"


def case_every_lock_entry_is_pinned_and_hashed(work: Path) -> None:
    del work
    entries = locked()
    assert "hatchling" in entries, "the lock does not carry hatchling"
    for name, (_, hashes) in entries.items():
        assert hashes > 0, f"{name} is locked without a hash"


def case_locked_backend_satisfies_pyproject(work: Path) -> None:
    del work
    build = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["build-system"]
    entries = locked()
    for spec in build["requires"]:
        requirement = Requirement(spec)
        name = requirement.name.lower()
        assert name in entries, f"pyproject requires {name}, which the lock does not carry"
        version = entries[name][0]
        assert requirement.specifier.contains(version), (
            f"the lock has {name} {version}, outside pyproject's {requirement.specifier}"
        )


def _mutation_goes_red(work: Path, anchor: str, replacement: str, reason: str) -> None:
    if os.environ.get("AEV_ACTION_UNDER_TEST"):
        return
    text = ACTION.read_text(encoding="utf-8")
    assert text.count(anchor) == 1, f"mutation anchor {anchor!r} moved; update this test"
    copy = work / "action.yml"
    copy.write_text(text.replace(anchor, replacement), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, "AEV_ACTION_UNDER_TEST": str(copy)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, f"this test stayed green with {replacement!r}"
    assert reason in proc.stdout, "mutation failed for a different reason"


def case_floating_python_goes_red(work: Path) -> None:
    """With the minor-only version restored, this file must fail."""
    version = python_version()
    minor = ".".join(version.split(".")[:2])
    _mutation_goes_red(
        work,
        f'python-version: "{version}"',
        f'python-version: "{minor}"',
        "not an exact patch release",
    )


def case_unhashed_backend_goes_red(work: Path) -> None:
    """With hash checking dropped from the backend install, this file must fail."""
    _mutation_goes_red(work, "--require-hashes ", "", "--require-hashes")


CASES: list[Callable[[Path], None]] = [
    case_python_is_an_exact_patch_release,
    case_backend_installed_from_the_lock,
    case_every_lock_entry_is_pinned_and_hashed,
    case_locked_backend_satisfies_pyproject,
    case_floating_python_goes_red,
    case_unhashed_backend_goes_red,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
                print(f"ok   {case.__name__}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
