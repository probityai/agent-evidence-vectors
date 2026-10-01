#!/usr/bin/env python3
"""Refuse a release tag that the published tag-signing key did not sign.

Why this file exists
--------------------
The digest list a release publishes is signed, and the tag that names the
release was not checked by anything. A tag can be moved or recreated by anyone
who can push to the repository, and a stranger who fetches by tag name trusts
whatever the tag points at. Release tags from v0.13.0 on were already signed
with the key in `release/tag-signing-key.asc`, but only because of the
maintainer's local git configuration, and nothing checked it. This script is
what the release workflow now runs to refuse a tag that is not signed by it.

The key is imported into a throwaway GnuPG home, so the check reads only the
published key and nothing the runner's keyring happens to hold. A good
signature is not enough: the signing key's fingerprint must be the pinned one,
because any key at all produces a good signature over its own tag.

Usage:
  python3 scripts/verify-release-tag.py vX.Y.Z
  python3 scripts/verify-release-tag.py vX.Y.Z --key-file K --fingerprint F

Exit 0 when the tag is annotated, signed, and signed by the pinned key; 1
otherwise, with the reason on stderr.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = REPO_ROOT / "release" / "tag-signing-key.asc"
# The primary key fingerprint of release/tag-signing-key.asc.
FINGERPRINT = "494767A5F0B0494C3A8878F320D2E0E72DF45D39"


def signer_fingerprints(status: str) -> set[str]:
    """Primary-key fingerprints named by VALIDSIG lines of a GnuPG status stream.

    VALIDSIG carries the signing subkey's fingerprint first and the primary
    key's last, so both are returned and either may match the pin.
    """
    found: set[str] = set()
    for line in status.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            found.add(fields[2].upper())
            found.add(fields[-1].upper())
    return found


def verify(tag: str, key_file: Path, fingerprint: str, repo: Path) -> str | None:
    """None when the tag is signed by the pinned key, else the reason it is not."""
    kind = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", f"refs/tags/{tag}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if kind.returncode != 0:
        return f"tag {tag} does not resolve: {kind.stderr.strip()}"
    if kind.stdout.strip() != "tag":
        return f"tag {tag} is a lightweight tag, so it carries no signature"
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        env = {**os.environ, "GNUPGHOME": home}
        imported = subprocess.run(
            ["gpg", "--batch", "--import", str(key_file)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if imported.returncode != 0:
            return f"the key file {key_file} did not import: {imported.stderr.strip()}"
        checked = subprocess.run(
            ["git", "-C", str(repo), "verify-tag", "--raw", tag],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    if checked.returncode != 0:
        return f"tag {tag} has no good signature from the published key: {checked.stderr.strip()}"
    signers = signer_fingerprints(checked.stderr)
    if fingerprint.upper() not in signers:
        return f"tag {tag} is signed by {sorted(signers)}, not the pinned key {fingerprint}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("tag")
    parser.add_argument("--key-file", type=Path, default=KEY_FILE)
    parser.add_argument("--fingerprint", default=FINGERPRINT)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    args = parser.parse_args()
    reason = verify(args.tag, args.key_file, args.fingerprint, args.repo)
    if reason is not None:
        print(f"verify-release-tag: REFUSED: {reason}", file=sys.stderr)
        return 1
    print(f"verify-release-tag: {args.tag} is signed by {args.fingerprint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
