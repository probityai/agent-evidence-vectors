#!/usr/bin/env python3
"""The release-tag check accepts the pinned key's tag and refuses everything else.

Each case builds a throwaway repository and throwaway keys in a temporary GnuPG
home, so nothing here reads or writes the maintainer's keyring. The cases are
the ways a tag can be wrong: lightweight, annotated but unsigned, and signed by
a key that is not the pinned one. The last is the case a plain `git verify-tag`
passes, so the last case of all deletes the fingerprint comparison in a copy of
the script and requires this file to go red against the copy.

Usage: python3 scripts/verify-release-tag-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(
    os.environ.get("AEV_TAG_CHECK_UNDER_TEST", REPO_ROOT / "scripts" / "verify-release-tag.py")
)
MUTATION_ANCHOR = "    if fingerprint.upper() not in signers:\n"


class Fixture:
    """A repository with one commit, and a GnuPG home holding two keys."""

    def __init__(self, work: Path) -> None:
        self.home = work / "gnupg"
        self.home.mkdir(mode=0o700)
        self.repo = work / "repo"
        self.env = {**os.environ, "GNUPGHOME": str(self.home)}
        self.pinned = self._key("Pinned Release <pinned@example.invalid>")
        self.other = self._key("Other Signer <other@example.invalid>")
        self.key_file = work / "pinned.asc"
        exported = self._gpg("--armor", "--export", self.pinned)
        self.key_file.write_text(exported, encoding="utf-8")
        self._git("init", "-q", str(self.repo), cwd=work)
        self._git(
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "base",
        )

    def _gpg(self, *args: str) -> str:
        proc = subprocess.run(
            ["gpg", "--batch", *args], capture_output=True, text=True, env=self.env, check=True
        )
        return proc.stdout

    def _key(self, uid: str) -> str:
        self._gpg("--passphrase", "", "--quick-generate-key", uid, "ed25519", "sign", "never")
        listing = self._gpg("--with-colons", "--list-keys", uid)
        return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr"))

    def _git(self, *args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args], cwd=cwd or self.repo, env=self.env, check=True, capture_output=True
        )

    def tag(self, name: str, *flags: str) -> None:
        self._git(
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "tag.gpgSign=false",
            "tag",
            *flags,
            name,
        )

    def check(self, name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                name,
                "--key-file",
                str(self.key_file),
                "--fingerprint",
                self.pinned,
                "--repo",
                str(self.repo),
            ],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )


def case_pinned_signature_passes(work: Path) -> None:
    fx = Fixture(work)
    fx.tag("v1.0.0", "-s", "-u", fx.pinned, "-m", "v1.0.0")
    got = fx.check("v1.0.0")
    assert got.returncode == 0, f"a tag signed by the pinned key was refused: {got.stderr}"


def case_lightweight_tag_refused(work: Path) -> None:
    fx = Fixture(work)
    fx.tag("v1.0.0")
    got = fx.check("v1.0.0")
    assert got.returncode == 1 and "lightweight" in got.stderr, got.stderr


def case_unsigned_annotated_tag_refused(work: Path) -> None:
    fx = Fixture(work)
    fx.tag("v1.0.0", "-a", "-m", "v1.0.0")
    got = fx.check("v1.0.0")
    assert got.returncode == 1 and "no good signature" in got.stderr, got.stderr


def case_other_key_refused(work: Path) -> None:
    fx = Fixture(work)
    # The other key's public half is in the published file too, so git verifies
    # the signature as good and only the fingerprint pin can refuse it.
    both = fx._gpg("--armor", "--export", fx.pinned, fx.other)
    fx.key_file.write_text(both, encoding="utf-8")
    fx.tag("v1.0.0", "-s", "-u", fx.other, "-m", "v1.0.0")
    got = fx.check("v1.0.0")
    assert got.returncode == 1 and "not the pinned key" in got.stderr, got.stderr


def case_missing_tag_refused(work: Path) -> None:
    fx = Fixture(work)
    got = fx.check("v9.9.9")
    assert got.returncode == 1 and "does not resolve" in got.stderr, got.stderr


def case_mutation_goes_red(work: Path) -> None:
    """Without the fingerprint pin, this file must fail."""
    if os.environ.get("AEV_TAG_CHECK_UNDER_TEST"):
        return
    text = SCRIPT.read_text(encoding="utf-8")
    assert MUTATION_ANCHOR in text, "mutation anchor moved; update this test"
    copy = work / "verify-release-tag.py"
    copy.write_text(text.replace(MUTATION_ANCHOR, "    if False:\n"), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, "AEV_TAG_CHECK_UNDER_TEST": str(copy)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, "this test stayed green against a check with no fingerprint pin"


CASES: list[Callable[[Path], None]] = [
    case_pinned_signature_passes,
    case_lightweight_tag_refused,
    case_unsigned_annotated_tag_refused,
    case_other_key_refused,
    case_missing_tag_refused,
    case_mutation_goes_red,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
                print(f"ok   {case.__name__}")
            except (AssertionError, subprocess.CalledProcessError) as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
