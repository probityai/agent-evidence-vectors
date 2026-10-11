#!/usr/bin/env python3
"""Tests for scripts/release-gate.py.

Each case starts with a signed, committed fixture. Transient Ed25519 keys
exist only in temporary test directories. A candidate source tree is allowed
to be unsigned; these controls do not qualify its release or replace its keys.

The two acceptance cases establish a satisfiable gate. Refusal cases then alter
one artifact and require the gate to identify it. A separate control verifies
that inherited Git selectors cannot bind --root to a foreign repository.

`openssl` is used to mint the substitute keys. If it is absent the run FAILS
rather than skipping those cases: a test that quietly drops the case for the
wrong key algorithm reports a coverage it does not have.

Usage: uv run --extra dev python scripts/release-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from _workflow_test_fixture import fixture_git

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "release-gate.py"

DIGESTS = "release/CORPUS-DIGESTS.txt"
SIGNATURE = "release/CORPUS-DIGESTS.txt.sig"
PUBLIC_KEY = "release/cosign.pub"
ROOTS = "spec/tsa-roots.pem"

TAG = "v0.0.0-gate-test"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...], tuple[str, ...]]


# A staged copy holds every tracked file as a loose object, so the first commit
# starts a background `git gc --auto` that can still be writing under `.git`
# when TemporaryDirectory removes the copy; CI failed on 2026-10-05 with
# "Directory not empty: release-order/.git" in the citation test. The same three settings, and the
# measurement behind them, are in spec-anchor-gate-test.py.
QUIESCENT = {
    "maintenance.auto": "false",
    "gc.auto": "0",
    "gc.autoDetach": "false",
}


def stage(destination: Path) -> None:
    """Copy the source into a signed fixture, without using a release key."""
    for rel in fixture_git(REPO_ROOT, "ls-files", "-z").split("\0"):
        if not rel:
            continue
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        shutil.copymode(source, target)
    fixture_git(destination, "init", "-q")
    for key, value in QUIESCENT.items():
        fixture_git(destination, "config", key, value)
    sign_fixture(destination)
    fixture_git(destination, "add", "-A")
    fixture_git(
        destination,
        "-c",
        "user.email=gate-test@example.invalid",
        "-c",
        "user.name=release gate test",
        "commit",
        "-qm",
        "staged signed fixture",
    )


def openssl(arguments: list[str], stdin: bytes | None = None) -> bytes:
    done = subprocess.run(["openssl", *arguments], input=stdin, capture_output=True, check=False)
    if done.returncode != 0:
        raise SystemExit(
            "release-gate-test: openssl "
            + " ".join(arguments)
            + f" failed ({done.returncode}). The substitute-key cases cannot run, and "
            "a skipped case is not a passing case.\n" + done.stderr.decode(errors="replace")
        )
    return done.stdout


def sign_fixture(root: Path) -> None:
    """Sign fixture bytes with a transient key kept outside the Git tree."""
    with tempfile.TemporaryDirectory(prefix="release-control-key-") as raw:
        key = Path(raw) / "private.pem"
        key.touch(mode=0o600)
        openssl(["genpkey", "-algorithm", "ed25519", "-out", str(key)])
        (root / PUBLIC_KEY).write_bytes(openssl(["pkey", "-pubout", "-in", str(key)]))
        signature = openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(root / DIGESTS),
            ]
        )
        (root / SIGNATURE).write_bytes(base64.b64encode(signature) + b"\n")


def regenerated_digest_list(root: Path) -> None:
    """Regeneration cannot authenticate changed release metadata."""
    path = root / "vectors/MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["suite"] += "-signature-control"
    path.write_text(json.dumps(manifest) + "\n")
    subprocess.run(
        [sys.executable, str(root / "scripts/release-digests.py"), "--root", str(root)],
        check=True,
        capture_output=True,
    )


def public_key_pem(algorithm: str) -> bytes:
    if algorithm == "ed25519":
        private = openssl(["genpkey", "-algorithm", "ed25519"])
    else:
        private = openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
    return openssl(["pkey", "-pubout"], stdin=private)


def edited_digest_list(root: Path) -> None:
    """Add one to whatever vector count the first corpus line carries.

    Derived rather than typed. Naming the current total here would restate a
    measured number in a second place where nothing re-measures it, which is the
    defect scripts/count-gate.py exists to refuse, and it would go stale the next
    time the corpus grows.
    """
    path = root / DIGESTS
    text = path.read_text(encoding="utf-8")
    found = re.search(r"vectors=(\d+)", text)
    if found is None:
        raise SystemExit(
            "release-gate-test: no vectors= field in the digest list, so this case "
            "would assert nothing. Fix the case, never the gate."
        )
    start, end = found.span(1)
    path.write_text(text[:start] + str(int(found.group(1)) + 1) + text[end:], encoding="utf-8")


def flipped_signature(root: Path) -> None:
    """One bit of the signature, re-encoded, so the file still parses as base64."""
    path = root / SIGNATURE
    raw = bytearray(base64.b64decode(path.read_text(encoding="utf-8")))
    raw[0] ^= 0x01
    path.write_text(base64.b64encode(bytes(raw)).decode("ascii"), encoding="utf-8")


def substituted_key(root: Path) -> None:
    (root / PUBLIC_KEY).write_bytes(public_key_pem("ed25519"))


def wrong_algorithm_key(root: Path) -> None:
    (root / PUBLIC_KEY).write_bytes(public_key_pem("ecdsa"))


def missing_signature(root: Path) -> None:
    (root / SIGNATURE).unlink()


def missing_key(root: Path) -> None:
    (root / PUBLIC_KEY).unlink()


def dirty_release_surface(root: Path) -> None:
    """A tracked file in the release surface is edited after the tag is cut."""
    path = root / ROOTS
    path.write_text(path.read_text(encoding="utf-8") + "# edited after the tag\n", encoding="utf-8")


def nothing(root: Path) -> None:
    del root


#: name, mutation, extra arguments, phrases the refusal must carry
REFUSALS: tuple[Case, ...] = (
    (
        "an edited digest list",
        edited_digest_list,
        (),
        ("digest list does not match", "release/CORPUS-DIGESTS.txt"),
    ),
    (
        "a regenerated digest list with a stale signature",
        regenerated_digest_list,
        (),
        ("does not verify",),
    ),
    ("a flipped signature", flipped_signature, (), ("does not verify",)),
    ("a substituted public key", substituted_key, (), ("does not verify", PUBLIC_KEY)),
    ("a key of the wrong algorithm", wrong_algorithm_key, (), ("not an Ed25519 public key",)),
    ("no signature at all", missing_signature, (), (SIGNATURE, "absent")),
    ("no published key at all", missing_key, (), (PUBLIC_KEY, "absent")),
    (
        "a tag that does not resolve",
        nothing,
        ("--tag", "v99.99.99-absent"),
        ("does not resolve",),
    ),
    (
        "a dirty release surface",
        dirty_release_surface,
        ("--tag", TAG),
        ("uncommitted changes", ROOTS),
    ),
)

ACCEPTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("a signed fixture", ()),
    ("a fixture tag at HEAD with a clean surface", ("--tag", TAG)),
)


def prepare(tmp: Path, name: str, mutate: Mutation) -> Path:
    root = tmp / name.replace(" ", "-")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    stage(root)
    fixture_git(root, "tag", TAG)
    mutate(root)
    return root


def run_gate(root: Path, extra: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def foreign_repository_control(tmp: Path) -> str | None:
    """A real verifier must select the supplied root and leave foreign refs intact."""
    root = prepare(tmp, "owned-root", nothing)
    foreign = prepare(tmp, "foreign-root", nothing)
    fixture_git(foreign, "tag", "-d", TAG)
    refs = fixture_git(foreign, "show-ref")
    index = (foreign / ".git/index").read_bytes()
    env = {
        **os.environ,
        "GIT_DIR": str(foreign / ".git"),
        "GIT_WORK_TREE": str(foreign),
        "GIT_INDEX_FILE": str(foreign / ".git/index"),
    }
    done = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), "--tag", TAG],
        capture_output=True,
        text=True,
        env=env,
    )
    if done.returncode:
        return (
            "foreign selectors redirected the real release verifier:\n" + done.stdout + done.stderr
        )
    if fixture_git(foreign, "show-ref") != refs or (foreign / ".git/index").read_bytes() != index:
        return "the real release verifier changed the foreign repository"
    return None


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for name, mutate, extra, wanted in REFUSALS:
            done = run_gate(prepare(tmp, name, mutate), extra)
            output = done.stdout + done.stderr
            if done.returncode == 0:
                failures.append(f"{name}: the gate passed the release anyway.\n{output}")
                continue
            missing = [want for want in wanted if want not in output]
            if missing:
                failures.append(
                    f"{name}: the right exit status, and the refusal does not name "
                    f"{missing!r}.\n{output}"
                )
        for name, extra in ACCEPTS:
            done = run_gate(prepare(tmp, name, nothing), extra)
            if done.returncode != 0:
                failures.append(
                    f"{name}: the gate refused a release that is correct.\n"
                    f"{done.stdout}{done.stderr}"
                )
        if failure := foreign_repository_control(tmp):
            failures.append(failure)
    total = len(REFUSALS) + len(ACCEPTS) + 1
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"OK: {total} case(s), of which {len(REFUSALS)} assert a refusal the gate "
        "makes and name the artifact it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
