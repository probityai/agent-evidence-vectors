#!/usr/bin/env python3
"""Move the published pins and the preferred citation to the newest release tag.

The published release is the newest `vX.Y.Z` tag (scripts/_release_source.py),
not the source version in pyproject.toml: a source version may not be tagged or
on PyPI yet. This rewrites the install pins on the README, DISTRIBUTION.md and
the runner guide, and the `preferred-citation` block of CITATION.cff (version,
url, commit, date and annotated tag object), all read from the tag. It runs in
the commit that follows a release, because the citation names a commit and a tag
object that do not exist until the tag is cut. On the tagged commit itself
`--check` passes, since nothing there can name the tag yet.

    python3 scripts/sync-install-pins.py           rewrite in place
    python3 scripts/sync-install-pins.py --check   exit 1 when anything lags the tag
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _release_source  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
V = r"\d+\.\d+\.\d+"
PROSE = (rf"`v({V})`", rf"\[v({V}) release\]")
# Per page, patterns with one group around the version. Only pins of this
# project are listed: a pin of another package, or an Action example that
# deliberately names another tag, never matches.
RULES: dict[str, tuple[str, ...]] = {
    "README.md": (
        *PROSE,
        rf"agent-evidence-vectors==({V})",
        rf"aee-verify@v({V})",
        rf"releases/tag/v({V})",
        rf"pypi\.org/project/agent-evidence-vectors/({V})/",
        rf"agent-evidence-vectors/blob/v({V})/",
        rf"At v({V}) the default corpus",
    ),
    "DISTRIBUTION.md": (
        *PROSE,
        rf"aee-verify@v({V})",
        rf"releases/tag/v({V})",
        rf"pypi\.org/project/agent-evidence-vectors/({V})/",
        rf"git checkout v({V})",
        rf"agent-evidence-vectors==({V})",
    ),
    "docs/reference/release-verification.md": (rf"git checkout v({V})", *PROSE),
    "docs/reference/citing.md": (
        rf"version\s*=\s*\{{({V})\}}",
        rf"releases/tag/v({V})",
    ),
    "docs/guides/runner.md": (
        rf"agent-evidence-vectors@v({V})",
        rf"aee-verify@v({V})",
        rf"agent-evidence-vectors==({V})",
    ),
}


def published_version(root: Path) -> str:
    """The newest release tag; a checkout without tags cannot say, so it fails."""
    version = _release_source.newest_tag(root)
    if version is None:
        raise SystemExit("no vX.Y.Z tag in this checkout; fetch the tags")
    return version


CITATION = "CITATION.cff"
BLOCK = re.compile(r"(?m)^(preferred-citation:\n(?:[ \t]+[^\n]*\n|\n)*)")


def rewrite_citation(text: str, version: str, facts: dict[str, str]) -> str:
    """Point the preferred-citation block at `version`'s tag."""
    repo = "https://github.com/probityai/agent-evidence-vectors"
    fields = {
        "url": f"{repo}/releases/tag/v{version}",
        "version": version,
        "commit": facts["commit"],
        "date-released": f'"{facts["date"]}"',
    }

    def block(match: re.Match[str]) -> str:
        body = match.group(1)
        for key, value in fields.items():
            body = re.sub(
                rf"(?m)^(  {re.escape(key)}:).*$", lambda m, v=value: f"{m.group(1)} {v}", body
            )
        return re.sub(
            r"(?m)^(      value: https://api\.github\.com/repos/probityai/agent-evidence-vectors/git/tags/)\S+$",
            lambda m: m.group(1) + facts["object"],
            body,
        )

    text = BLOCK.sub(block, text, count=1)
    # A top-level version equal to the published one is a dated historical
    # release, so the gate wants the same date there; a newer candidate has none.
    top = re.search(r"(?m)^version:\s*(\S+)\s*$", text)
    if top and top.group(1) == version:
        dated = f'date-released: "{facts["date"]}"'
        if re.search(r"(?m)^date-released:", text):
            text = re.sub(r"(?m)^date-released:.*$", dated, text, count=1)
        else:
            text = text[: top.end()] + "\n" + dated + text[top.end() :]
    return text


def _swap(match: re.Match[str], version: str) -> str:
    whole = match.group(0)
    lo, hi = match.start(1) - match.start(), match.end(1) - match.start()
    return whole[:lo] + version + whole[hi:]


def rewrite(text: str, rules: tuple[str, ...], version: str) -> str:
    for rule in rules:
        text = re.sub(rule, lambda m: _swap(m, version), text)
    return text


def sync(root: Path, version: str, apply: bool) -> list[str]:
    """Pages whose pins differ from `version`; with apply, rewrite them."""
    stale = []
    for rel, rules in RULES.items():
        path = root / rel
        old = path.read_text()
        new = rewrite(old, rules, version)
        if new != old:
            stale.append(rel)
            if apply:
                path.write_text(new)
    citation = root / CITATION
    facts = _release_source.tag_facts(root, version)
    if facts is None:
        raise SystemExit(f"tag v{version} does not resolve; fetch the tags")
    old = citation.read_text()
    new = rewrite_citation(old, version, facts)
    if new != old:
        stale.append(CITATION)
        if apply:
            citation.write_text(new)
    return stale


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail instead of rewriting")
    args = parser.parse_args()
    version = published_version(ROOT)
    if args.check and _release_source.head_is_tag_commit(ROOT, version):
        print(f"HEAD is the v{version} commit; the citation and pins follow in the next commit")
        return 0
    stale = sync(ROOT, version, apply=not args.check)
    if args.check and stale:
        print(f"install pins differ from newest tag v{version}: {', '.join(stale)}")
        print("fix: python3 scripts/sync-install-pins.py")
        return 1
    if args.check:
        print(f"install pins match newest tag v{version}")
    else:
        print(f"pins set to {version}: {stale or 'unchanged'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
