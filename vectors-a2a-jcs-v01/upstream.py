#!/usr/bin/env python3
"""Keep this directory byte-identical to the a2a-tck corpus it was vendored from.

The vectors and MANIFEST.json here are a2aproject/a2a-tck
``conformance-vectors/a2a-jcs-v01`` at the commit ``source-lock.json`` names,
copied without a byte changed. Nothing in this repository regenerates them:
their expected bytes come from two independent RFC 8785 oracles that run in
the upstream repository, so the only honest local operations are to copy them
and to check that the copy has not drifted.

    python3 vectors-a2a-jcs-v01/upstream.py check
        Every locked file is on disk with its locked SHA-256, nothing else sits
        in the vector directories, the MANIFEST's corpusDigest recomputes to the
        locked digest, and the lock's commit and digest are the ones RUNS.md
        records. Exit 0 clean, 1 on any drift.

    python3 vectors-a2a-jcs-v01/upstream.py check --upstream <a2a-tck clone>
        Also reads every locked file from the clone at the locked commit with
        ``git show`` and requires the same bytes.

    python3 vectors-a2a-jcs-v01/upstream.py vendor --upstream <a2a-tck clone> --commit <sha>
        Copy the corpus at that commit and rewrite source-lock.json. The vector
        README and the upstream generators and runners are not copied: the
        generators need both oracles installed and the runners are replaced here
        by the packaged reader and its external-verifier contract.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent
LOCK = HERE / "source-lock.json"
UPSTREAM_PATH = "conformance-vectors/a2a-jcs-v01"
REPOSITORY = "a2aproject/a2a-tck"
SCHEMA = "agent-evidence-vectors.a2a-jcs-v01.source-lock.v1"
# Ours, beside the vendored bytes; everything else in this directory is theirs.
OWN = {"README.md", "source-lock.json", "upstream.py", "digest.py", "tests"}


def _reader() -> ModuleType:
    """The packaged reader, which owns the corpus-digest preimage."""
    path = HERE.parent / "packaging" / "agent_evidence_vectors" / "a2ajcs.py"
    spec = importlib.util.spec_from_file_location("a2ajcs", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vendored_files(root: Path) -> list[str]:
    """Every file in this directory that is not ours, as a sorted relative path."""
    return sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.relative_to(root).parts[0] not in OWN and "__pycache__" not in p.parts
    )


def runs_md_pins(root: Path) -> tuple[str, str] | None:
    """The commit and corpus digest RUNS.md records for this corpus, if it records them."""
    runs = root.parent / "RUNS.md"
    if not runs.is_file():
        return None
    for line in runs.read_text(encoding="utf-8").splitlines():
        if "a2a-jcs-v01" in line and "corpus digest" in line:
            words = line.replace("`", " ").split()
            commits = [w for w in words if len(w) == 40 and all(c in "0123456789abcdef" for c in w)]
            digests = [w for w in words if len(w) == 64 and all(c in "0123456789abcdef" for c in w)]
            if commits and digests:
                return commits[0], digests[0]
    return None


def _local_findings(root: Path, locked: dict[str, dict[str, object]]) -> list[str]:
    """Unlocked files, missing files and changed bytes in the vendored tree."""
    findings = [
        f"{extra} is in the vendored tree and not in the lock"
        for extra in sorted(set(vendored_files(root)) - set(locked))
    ]
    for path, entry in sorted(locked.items()):
        target = root / path
        if not target.is_file():
            findings.append(f"{path} is locked and missing")
            continue
        body = target.read_bytes()
        if sha256(body) != entry["sha256"] or len(body) != entry["bytes"]:
            findings.append(f"{path} differs from the locked bytes")
    return findings


def _pin_findings(root: Path, lock: dict[str, object]) -> list[str]:
    """The MANIFEST's digest against the lock, and the lock against RUNS.md."""
    findings = []
    try:
        digest = _reader().corpus_digest((root / "MANIFEST.json").read_bytes())
    except ValueError as exc:
        findings.append(str(exc))
        digest = None
    if digest != lock["corpusDigest"]:
        findings.append(
            f"the MANIFEST recomputes to {digest}, the lock pins {lock['corpusDigest']}"
        )
    pins = runs_md_pins(root)
    if pins is None:
        findings.append("RUNS.md records no commit and corpus digest for a2a-jcs-v01")
    elif pins != (lock["commit"], lock["corpusDigest"]):
        findings.append(
            f"RUNS.md pins {pins}, the lock pins {(lock['commit'], lock['corpusDigest'])}"
        )
    return findings


def _upstream_findings(
    upstream: Path, commit: str, locked: dict[str, dict[str, object]]
) -> list[str]:
    """Every locked file against ``git show`` of the locked commit in a clone."""
    findings = []
    for path, entry in sorted(locked.items()):
        shown = subprocess.run(
            ["git", "-C", str(upstream), "show", f"{commit}:{UPSTREAM_PATH}/{path}"],
            capture_output=True,
            check=False,
        )
        if shown.returncode != 0:
            findings.append(f"{path} could not be read from the upstream clone at {commit}")
        elif sha256(shown.stdout) != entry["sha256"]:
            findings.append(f"{path} differs from upstream at {commit}")
    return findings


def check(root: Path, upstream: Path | None) -> list[str]:
    lock = json.loads((root / "source-lock.json").read_text(encoding="utf-8"))
    locked = {entry["path"]: entry for entry in lock["files"]}
    findings = _local_findings(root, locked) + _pin_findings(root, lock)
    if upstream is not None:
        findings += _upstream_findings(upstream, lock["commit"], locked)
    return findings


def vendor(root: Path, upstream: Path, commit: str) -> None:
    listed = subprocess.run(
        ["git", "-C", str(upstream), "ls-tree", "-r", "--name-only", commit, UPSTREAM_PATH + "/"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    files = []
    for full in sorted(listed):
        rel = full[len(UPSTREAM_PATH) + 1 :]
        if not rel.endswith(".json") or rel.startswith("oracle-go/"):
            continue
        body = subprocess.run(
            ["git", "-C", str(upstream), "show", f"{commit}:{full}"],
            capture_output=True,
            check=True,
        ).stdout
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(body)
        files.append({"path": rel, "bytes": len(body), "sha256": sha256(body)})
    lock = {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "path": UPSTREAM_PATH,
        "commit": commit,
        "corpusDigest": _reader().corpus_digest((root / "MANIFEST.json").read_bytes()),
        "files": files,
    }
    (root / "source-lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Keep this directory byte-identical to its a2a-tck source."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check_cmd = sub.add_parser("check")
    check_cmd.add_argument("--upstream", type=Path, default=None)
    vendor_cmd = sub.add_parser("vendor")
    vendor_cmd.add_argument("--upstream", type=Path, required=True)
    vendor_cmd.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    if args.command == "vendor":
        vendor(HERE, args.upstream, args.commit)
        print(f"vendored {UPSTREAM_PATH} at {args.commit}")
        return 0
    findings = check(HERE, args.upstream)
    for finding in findings:
        print(f"FAIL {finding}")
    if findings:
        return 1
    count = len(vendored_files(HERE))
    print(f"OK: {count} files match {REPOSITORY} {UPSTREAM_PATH} at the locked commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
