#!/usr/bin/env python3
"""Build and check an offline install bundle for the pinned verifier and its corpora.

    airgap-bundle.py lock --version X.Y.Z --out requirements.lock
    airgap-bundle.py build --lock requirements.lock --out DIR [--release-dir release]
        [--find-links DIR --no-index] [--tar]
    airgap-bundle.py verify DIR

``lock`` writes a hash-pinned requirements file from the digests PyPI publishes for one
release and refuses a release that has runtime dependencies (use ``uv pip compile
--generate-hashes`` for those). ``build`` downloads every pinned wheel with
``--require-hashes``, unpacks the shipped corpora beside them, copies the signed digest list from ``--release-dir``, writes ``SHA256SUMS`` over
every file, and adds the install script. ``verify`` re-checks ``SHA256SUMS``. Carry the
directory (or its tarball) into the enclave and run ``install.sh`` there: it verifies the sums,
then installs with ``--no-index --find-links --require-hashes`` and replays one corpus.

Exit status: 0 done, 1 a check failed, 2 unusable input.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

DISTRIBUTION = "agent-evidence-vectors"
WHEEL_PREFIX = "agent_evidence_vectors-"
CORPORA_IN_WHEEL = "agent_evidence_vectors/corpora/"
SUMS_NAME = "SHA256SUMS"
RELEASE_REQUIRED = ("CORPUS-DIGESTS.txt", "CORPUS-DIGESTS.txt.sig", "cosign.pub")
RELEASE_OPTIONAL = ("CORPUS-DIGESTS.txt.sig.tsr", "CORPUS-DIGESTS.txt.sig.ots")
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")
PIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.!+_-]+\b")

INSTALL_SH = """#!/bin/sh
# Offline install of the pinned verifier. Needs Python 3.11 or newer with venv and pip;
# set PYTHON to pick the interpreter.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
target=${1:-"$here/venv"}
cd "$here"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS --quiet
else
    shasum -a 256 -c SHA256SUMS --quiet
fi
"${PYTHON:-python3}" -m venv "$target"
PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 "$target/bin/python" -m pip install \\
    --no-index --find-links "$here/wheels" --require-hashes -r "$here/requirements.lock"
if ! "$target/bin/agent-evidence-vectors" --corpus "${AEV_SELFCHECK_CORPUS:-vectors}" \\
    --report "$target/selfcheck-report.json" > "$target/selfcheck.log" 2>&1; then
    tail -n 20 "$target/selfcheck.log" >&2
    echo "self-check failed" >&2
    exit 1
fi
tail -n 1 "$target/selfcheck.log"
echo "installed: run $target/bin/agent-evidence-vectors --list-corpora"
"""


class BundleError(ValueError):
    """The lock, a wheel, or the bundle is not what a bundle must be."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def read_lock(path: Path) -> list[str]:
    """Return the pinned requirement names, refusing any line without an exact pin and hash."""
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    names = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not PIN_RE.match(line) or not HASH_RE.search(line):
            raise BundleError(f"lock line is not an exact pin with a sha256 hash: {line[:80]!r}")
        names.append(line.split("==", 1)[0].lower())
    if not names:
        raise BundleError("lock names no requirement")
    return names


def write_lock(version: str, out: Path) -> None:
    """Write the lock for one published release from the digests PyPI states."""
    url = PYPI_JSON.format(name=DISTRIBUTION, version=version)
    with urllib.request.urlopen(url, timeout=30) as reply:  # noqa: S310 - fixed https host
        meta = json.load(reply)
    runtime = [r for r in meta["info"].get("requires_dist") or [] if "extra ==" not in r]
    if runtime:
        raise BundleError("this release has runtime dependencies; compile a full lock instead")
    hashes = sorted(f["digests"]["sha256"] for f in meta["urls"] if f["filename"].endswith(".whl"))
    if not hashes:
        raise BundleError(f"{DISTRIBUTION}=={version} publishes no wheel")
    body = " \\\n".join([f"{DISTRIBUTION}=={version}", *(f"    --hash=sha256:{h}" for h in hashes)])
    out.write_text(body + "\n", encoding="utf-8")


def download_wheels(lock: Path, wheels: Path, find_links: str | None, no_index: bool) -> None:
    if importlib.util.find_spec("pip") is None:
        raise BundleError("this interpreter has no pip; run the builder with one that does")
    command = [
        sys.executable, "-m", "pip", "download", "--require-hashes", "--no-deps",
        "--only-binary=:all:", "-r", str(lock), "-d", str(wheels),
    ]  # fmt: skip
    if no_index:
        command.append("--no-index")
    if find_links:
        command += ["--find-links", find_links]
    done = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    if done.returncode:
        raise BundleError(f"pip download failed: {(done.stderr or done.stdout).strip()[-600:]}")


def unpack_corpora(wheels: Path, corpora: Path) -> int:
    """Extract the corpora the verifier wheel carries; return how many corpus directories."""
    found = sorted(wheels.glob(f"{WHEEL_PREFIX}*.whl"))
    if len(found) != 1:
        raise BundleError(f"expected one {DISTRIBUTION} wheel, found {[w.name for w in found]}")
    with zipfile.ZipFile(found[0]) as archive:
        for info in archive.infolist():
            if not info.filename.startswith(CORPORA_IN_WHEEL) or info.is_dir():
                continue
            relative = PurePosixPath(info.filename[len(CORPORA_IN_WHEEL) :])
            if relative.is_absolute() or ".." in relative.parts:
                raise BundleError(f"wheel member escapes the corpora directory: {info.filename}")
            target = corpora.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    return len([p for p in corpora.iterdir() if p.is_dir()])


def copy_release(release_dir: Path, target: Path) -> None:
    """Carry the maintainer's signed digest list and its proofs, so the enclave can check them."""
    missing = [n for n in RELEASE_REQUIRED if not (release_dir / n).is_file()]
    if missing:
        raise BundleError(f"{release_dir} lacks {', '.join(missing)}")
    target.mkdir()
    for name in (*RELEASE_REQUIRED, *RELEASE_OPTIONAL):
        if (release_dir / name).is_file():
            shutil.copyfile(release_dir / name, target / name)


def write_sums(root: Path) -> int:
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != SUMS_NAME)
    lines = [f"{sha256_file(p)}  {p.relative_to(root).as_posix()}" for p in files]
    (root / SUMS_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def verify(root: Path) -> list[str]:
    """Return every problem found re-checking SHA256SUMS: a changed, missing or extra file."""
    sums = root / SUMS_NAME
    if not sums.is_file():
        return [f"{SUMS_NAME} is missing"]
    listed: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest
    problems = []
    for name, digest in sorted(listed.items()):
        path = root / name
        if not path.is_file():
            problems.append(f"missing: {name}")
        elif sha256_file(path) != digest:
            problems.append(f"changed: {name}")
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    problems += [f"extra: {name}" for name in sorted(on_disk - set(listed) - {SUMS_NAME})]
    return problems


def build(args: argparse.Namespace) -> dict[str, int]:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise BundleError(f"{out} exists and is not empty")
    lock = Path(args.lock)
    read_lock(lock)
    (out / "wheels").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(lock, out / "requirements.lock")
    download_wheels(out / "requirements.lock", out / "wheels", args.find_links, args.no_index)
    (out / "corpora").mkdir()
    corpus_count = unpack_corpora(out / "wheels", out / "corpora")
    if args.release_dir:
        copy_release(Path(args.release_dir), out / "release")
    install = out / "install.sh"
    install.write_text(INSTALL_SH, encoding="utf-8")
    install.chmod(0o755)
    files = write_sums(out)
    return {"files": files, "corpora": corpus_count}


def pack(root: Path) -> Path:
    """Tar the bundle reproducibly enough to carry, and write the tarball's own digest."""
    tarball = root.parent / f"{root.name}.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(root, arcname=root.name)
    tarball.with_name(tarball.name + ".sha256").write_text(
        f"{sha256_file(tarball)}  {tarball.name}\n", encoding="utf-8"
    )
    return tarball


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    lock_p = sub.add_parser("lock")
    lock_p.add_argument("--version", required=True)
    lock_p.add_argument("--out", required=True)
    build_p = sub.add_parser("build")
    build_p.add_argument("--lock", required=True)
    build_p.add_argument("--out", required=True)
    build_p.add_argument("--find-links", default=None)
    build_p.add_argument("--no-index", action="store_true")
    build_p.add_argument(
        "--release-dir", default=None, help="the release/ directory of the matching tag"
    )
    build_p.add_argument("--tar", action="store_true", help="also write OUT.tar.gz and its digest")
    verify_p = sub.add_parser("verify")
    verify_p.add_argument("bundle")
    args = parser.parse_args(argv)
    try:
        if args.command == "lock":
            write_lock(args.version, Path(args.out))
            print(f"lock written to {args.out}")
        elif args.command == "build":
            counts = build(args)
            if args.tar:
                print(f"tarball: {pack(Path(args.out))}")
            print(f"bundle {args.out}: {counts['files']} files, {counts['corpora']} corpora")
        else:
            problems = verify(Path(args.bundle))
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1 if problems else 0
    except (BundleError, OSError, KeyError, ValueError) as error:
        print(f"airgap-bundle: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
