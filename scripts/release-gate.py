#!/usr/bin/env python3
"""Refuse a release whose signed artifacts do not verify, or do not cover it.

What a signature is worth depends entirely on what was checked at the moment it
was made. A repository can carry a `.sig` beside a digest list, publish a public
key, write a verify recipe into its README, and have all three describe a corpus
that moved two commits ago -- and every file involved still looks right. So this
gate makes the four statements a release makes about itself, and refuses when
any of them is false:

1. The digest list is what the corpora on disk produce, recomputed rather than
   read (delegated to scripts/release-digests.py --check, so there is one
   implementation of "what the list should say" rather than two).
2. The signature verifies against the PUBLISHED public half, not against
   anything derived from the private one. `release/cosign.pub` is the only key a
   stranger has, so it is the only key worth checking with.
3. That public half is the key shape this release claims: an Ed25519 SPKI. A
   swap for a different algorithm is a thing a reader would not notice by eye.
4. Under `--tag`, the tag being cut is the commit being checked, and no tracked
   file in the release surface has uncommitted changes. A tag is a promise that
   the bytes are fetchable by name; an artifact signed from a dirty tree is
   signed over bytes no clone will ever hold.

The RFC 3161 and OpenTimestamps proofs are checked only under
`--with-timestamps`, and that flag defaults OFF. Both proofs are built, tested
and shipped, and both are real; the flag is off because verifying them reaches
the network -- the OpenTimestamps calendars, and, for a full path validation,
nothing less than the pinned root -- and a gate that runs on every push must not
depend on a third party being reachable. The default path is entirely offline.
Turn the flag on at tag time and in the release workflow, where a network call
is expected and its failure is legible.

Usage:
  uv run python scripts/release-gate.py
  uv run python scripts/release-gate.py --with-timestamps
  uv run python scripts/release-gate.py --tag v0.10.0
  uv run python scripts/release-gate.py --root <tree>

Exit 0 when every statement holds; 1 on the first summary of what does not.
"""

from __future__ import annotations

import argparse
import base64
import subprocess
import sys
from pathlib import Path

from _branch_authority import git_environment

REPO_ROOT = Path(__file__).resolve().parent.parent

DIGESTS_REL = "release/CORPUS-DIGESTS.txt"
SIGNATURE_REL = "release/CORPUS-DIGESTS.txt.sig"
PUBLIC_KEY_REL = "release/cosign.pub"
TSR_REL = "release/CORPUS-DIGESTS.txt.sig.tsr"
OTS_REL = "release/CORPUS-DIGESTS.txt.sig.ots"
ROOTS_REL = "spec/tsa-roots.pem"

#: The DER prefix of an Ed25519 SubjectPublicKeyInfo: SEQUENCE, AlgorithmIdentifier
#: with OID 1.3.101.112, then the 32-byte key. RFC 8410 section 4.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570")

#: The release surface. A change to any of these between signing and tagging
#: invalidates the signature, and each one is here because it is covered by the
#: signature or is the thing that verifies it.
RELEASE_SURFACE = ("release", "vectors", "vectors-ai-agent-action", ROOTS_REL)


def run(command: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=root,
        env=git_environment(root if command[0] == "git" else None),
        capture_output=True,
        text=True,
        check=False,
    )


def check_digests_current(root: Path) -> list[str]:
    """One implementation of what the list should say, invoked rather than copied."""
    script = root / "scripts" / "release-digests.py"
    if not script.is_file():
        return [
            "scripts/release-digests.py is absent, so nothing can say what the digest "
            "list should hold"
        ]
    done = run([sys.executable, str(script), "--check", "--root", str(root)], root)
    if done.returncode != 0:
        return [
            "the digest list does not match the corpora on disk:\n"
            + "\n".join(f"      {line}" for line in done.stderr.strip().splitlines())
        ]
    return []


def check_key_shape(root: Path) -> list[str]:
    """The published key is the algorithm this release says it is."""
    path = root / PUBLIC_KEY_REL
    if not path.is_file():
        return [f"{PUBLIC_KEY_REL} is absent, so a verifier has no key to verify with"]
    body = "".join(
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("-----")
    )
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError:
        return [f"{PUBLIC_KEY_REL} is not decodable as a PEM public key"]
    if not der.startswith(ED25519_SPKI_PREFIX):
        return [
            f"{PUBLIC_KEY_REL} is not an Ed25519 public key. The README tells a "
            "stranger which algorithm to expect, and a key of another shape "
            "verifying successfully is a different claim from the one published."
        ]
    return []


def check_signature(root: Path) -> list[str]:
    """cosign, against the published public half. An absent cosign is a failure."""
    for rel in (DIGESTS_REL, SIGNATURE_REL, PUBLIC_KEY_REL):
        if not (root / rel).is_file():
            return [f"{rel} is absent, so the signature cannot be checked at all"]
    probe = run(["cosign", "version"], root)
    if probe.returncode != 0:
        return [
            "cosign is not runnable here, so the signature was NOT checked. This is "
            "a failure rather than a skip: a gate that passes when its checker is "
            "missing reports a clean result for a check that did not run."
        ]
    done = run(
        [
            "cosign",
            "verify-blob",
            "--key",
            PUBLIC_KEY_REL,
            "--signature",
            SIGNATURE_REL,
            "--insecure-ignore-tlog=true",
            DIGESTS_REL,
        ],
        root,
    )
    if done.returncode != 0:
        return [
            f"the signature over {DIGESTS_REL} does not verify against "
            f"{PUBLIC_KEY_REL}:\n"
            + "\n".join(f"      {line}" for line in done.stderr.strip().splitlines()[-4:])
        ]
    return []


def check_timestamps(root: Path) -> list[str]:
    """The two time proofs, when asked for. Pending is a state, not a defect."""
    for rel in (TSR_REL, OTS_REL, ROOTS_REL):
        if not (root / rel).is_file():
            return [f"{rel} is absent, so the release carries no time evidence"]
    script = root / "scripts" / "release-timestamps.sh"
    done = run([str(script), "verify"], root)
    if done.returncode != 0:
        return [
            "the time evidence does not verify:\n"
            + "\n".join(
                f"      {line}" for line in (done.stdout + done.stderr).strip().splitlines()[-6:]
            )
        ]
    return []


def check_tag(root: Path, tag: str) -> list[str]:
    """The tag being cut is this commit, and the release surface is committed."""
    errors: list[str] = []
    resolved = run(["git", "rev-parse", f"{tag}^{{commit}}"], root)
    if resolved.returncode != 0:
        return [
            f"tag {tag!r} does not resolve in this repository, so there is nothing "
            "to release. Create the tag on the commit whose artifacts were signed."
        ]
    head = run(["git", "rev-parse", "HEAD"], root)
    if head.returncode != 0:
        return [f"HEAD does not resolve in {root}"]
    if resolved.stdout.strip() != head.stdout.strip():
        errors.append(
            f"tag {tag!r} is at {resolved.stdout.strip()[:12]} and HEAD is at "
            f"{head.stdout.strip()[:12]}. The artifacts checked here belong to the "
            "checkout, not to the tag."
        )
    dirty = run(["git", "status", "--porcelain", "--", *RELEASE_SURFACE], root)
    if dirty.returncode != 0:
        errors.append(f"git status failed in {root}: {dirty.stderr.strip()[:120]}")
    elif dirty.stdout.strip():
        errors.append(
            "the release surface has uncommitted changes, so the signed bytes are "
            "not the bytes the tag publishes:\n"
            + "\n".join(f"      {line}" for line in dirty.stdout.strip().splitlines())
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="the tree to check")
    parser.add_argument("--tag", help="the tag being cut; adds the tag and cleanliness checks")
    parser.add_argument(
        "--with-timestamps",
        action="store_true",
        help="also verify the RFC 3161 token and the OpenTimestamps proof (reaches the network)",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    errors: list[str] = []
    errors += check_digests_current(root)
    errors += check_key_shape(root)
    errors += check_signature(root)
    if args.with_timestamps:
        errors += check_timestamps(root)
    if args.tag:
        errors += check_tag(root, args.tag)

    if errors:
        print(
            f"FAIL: this release does not verify ({len(errors)} problem(s)):",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    checked = ["the digest list", "the key shape", "the signature"]
    if args.with_timestamps:
        checked.append("the RFC 3161 token and the OpenTimestamps proof")
    if args.tag:
        checked.append(f"the tag {args.tag}")
    print(
        "OK: " + ", ".join(checked) + ". Every digest was recomputed from the vector "
        "files on disk, and the signature was checked against the public half a "
        "stranger would use."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
