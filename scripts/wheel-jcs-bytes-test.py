#!/usr/bin/env python3
"""The wheel carries the JCS byte vectors, at the path the package names.

An SDK's CI that wants the RFC 8785 byte cases should be able to pin
``agent-evidence-vectors==X`` and read the file from the installed package,
instead of fetching it from a tag at run time. That only holds if three things
are true of the wheel, and this test builds one and checks each:

1. ``cases.json`` and its README are inside it, byte for byte the files in
   ``corpora/jcs-byte-vectors/`` (compared by SHA-256), and ``check.mjs`` is
   not, because nothing in the package runs it.
2. The installed module's ``jcs_byte_vectors_path()`` names that file, so a
   consumer never hard-codes a site-packages layout.
3. ``agent-evidence-vectors --jcs-byte-vectors`` prints the same path, for a
   consumer whose CI step is a shell line rather than Python.

The installed checks run from a scratch directory outside the checkout, so a
path that only resolves inside the repository fails here and not in a
consumer's CI.

Usage: python3 scripts/wheel-jcs-bytes-test.py
Exit 0 when every check holds; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "corpora" / "jcs-byte-vectors"
INSTALLED = "agent_evidence_vectors/corpora/corpora/jcs-byte-vectors/"
SHIPPED = ("cases.json", "README.md")
NOT_SHIPPED = ("check.mjs",)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_wheel(out: Path) -> Path:
    uv = shutil.which("uv")
    if uv is None:
        sys.exit("FAIL: uv is not on PATH, so no wheel could be built and nothing was checked")
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(out), str(ROOT)],
        check=True,
        capture_output=True,
    )
    wheels = sorted(out.glob("agent_evidence_vectors-*.whl"))
    if len(wheels) != 1:
        sys.exit(f"FAIL: expected one wheel in {out}, found {[w.name for w in wheels]}")
    return wheels[0]


def check_members(wheel: Path) -> list[str]:
    failures: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for name in SHIPPED:
            member = INSTALLED + name
            if member not in names:
                failures.append(f"{member} is not in the wheel")
                continue
            got = sha256(archive.read(member))
            want = sha256((SOURCE / name).read_bytes())
            if got != want:
                failures.append(f"{member} has sha256 {got}; the repository copy has {want}")
        for name in NOT_SHIPPED:
            if INSTALLED + name in names:
                failures.append(f"{INSTALLED + name} ships, and nothing in the package runs it")
    return failures


def installed_run(wheel: Path, scratch: Path, *args: str) -> str:
    uv = shutil.which("uv")
    assert uv is not None
    proc = subprocess.run(
        [uv, "run", "--no-project", "--with", str(wheel), *args],
        cwd=str(scratch),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return f"ERROR exit {proc.returncode}: {proc.stdout}{proc.stderr}"
    return proc.stdout.strip()


def check_locator(wheel: Path, scratch: Path) -> list[str]:
    failures: list[str] = []
    want = sha256((SOURCE / "cases.json").read_bytes())
    from_function = installed_run(
        wheel,
        scratch,
        "python",
        "-c",
        "from agent_evidence_vectors.run_vectors import jcs_byte_vectors_path; "
        "print(jcs_byte_vectors_path())",
    )
    from_cli = installed_run(wheel, scratch, "agent-evidence-vectors", "--jcs-byte-vectors")
    answers = (("jcs_byte_vectors_path()", from_function), ("--jcs-byte-vectors", from_cli))
    for label, printed in answers:
        path = Path(printed)
        if printed.startswith("ERROR") or not path.is_file():
            failures.append(f"{label} did not name an installed file: {printed}")
            continue
        if ROOT in path.parents:
            failures.append(f"{label} named the checkout ({path}), not the installed package")
        elif sha256(path.read_bytes()) != want:
            failures.append(f"{label} names {path}, whose bytes differ from the repository copy")
    if from_function != from_cli:
        failures.append(f"the function says {from_function} and the flag says {from_cli}")
    return failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wheel-jcs-bytes-") as tmp:
        wheel = build_wheel(Path(tmp) / "dist")
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        failures = check_members(wheel) + check_locator(wheel, scratch)
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        return 1
    print(f"OK: the wheel ships {', '.join(SHIPPED)} at {INSTALLED} and the package names them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
