"""The published release, read from git tags: the one source for every pin.

A release is published when its tag exists, so the newest `vX.Y.Z` tag is the
published version. The preferred citation in CITATION.cff and the install pins
on the inbound pages follow it. They cannot move in the release commit itself:
the citation names the tagged commit and the annotated tag object, neither of
which exists until the tag is cut, and RELEASING.md forbids advancing published
install instructions before publication. So the follow-up commit that names the
new tag is the one that moves them, and `lagging()` is how a descendant of the
tag is refused while they still name an older release.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _git(root: Path, *args: str) -> str | None:
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    return done.stdout.strip() if done.returncode == 0 else None


def newest_tag(root: Path) -> str | None:
    """The newest release tag as `X.Y.Z`, or None when the checkout has no tags."""
    listed = _git(root, "tag", "--list", "v*") or ""
    found = [(tuple(int(p) for p in m.groups()), t) for t in listed.split() if (m := TAG.match(t))]
    return max(found)[1][1:] if found else None


def tag_facts(root: Path, version: str) -> dict[str, str] | None:
    """Commit, annotated tag object and commit date of `v<version>`, or None."""
    ref = f"refs/tags/v{version}"
    commit = _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    tag_object = _git(root, "rev-parse", "--verify", ref)
    date = _git(root, "log", "-1", "--format=%cs", f"{ref}^{{commit}}")
    if not (commit and tag_object and date):
        return None
    return {"commit": commit, "object": tag_object, "date": date}


def head_is_tag_commit(root: Path, version: str) -> bool:
    """True on the tagged commit itself, where the citation cannot yet name it."""
    facts = tag_facts(root, version)
    return facts is not None and facts["commit"] == _git(root, "rev-parse", "HEAD")


def lagging(root: Path, cited: str) -> str | None:
    """A refusal when `cited` is not the newest tag, off the tagged commit itself."""
    newest = newest_tag(root)
    if newest is None or newest == cited or head_is_tag_commit(root, newest):
        return None
    return (
        f"the newest release tag is v{newest} and the published pins name {cited}; "
        "run python3 scripts/sync-install-pins.py and commit the result"
    )
