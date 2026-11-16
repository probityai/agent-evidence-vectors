#!/usr/bin/env python3
"""Refuse a live reference to a repository the probityai organisation archived.

    python3 scripts/archived-repo-gate.py          # every tracked file
    python3 scripts/archived-repo-gate.py --live   # the list against GitHub

Every repository named in scripts/archived-repos.toml was merged into a larger one and
archived by transfer to probityai-archive, and its old probityai/<name> URL resolves
only through GitHub's 301. A reader who follows a link, an install line, an Action ref
or a clone command to one lands on a frozen copy, so every live reference points at the
repository's `home` instead. The gate reads every tracked text file and fails on a
reference to an archived name (the name not followed by a hyphen, so agent-evidence-vectors
and the other agent-evidence-* names never match) unless one of these holds:

- the text is an identifier and not a link. A predicate type URI under
  github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/ is inside
  signed statements and never changes (the identifier-hosts workflow watches that its
  redirect keeps working); an npm scope such as @probityai/dsse and an MCP registry
  namespace such as io.github.probityai/agent-evidence-admission name a package, not a
  repository. A predicate URI written as the target of a Markdown link is still a link
  and is refused: a reader who clicks it lands on the archive.
- the text names something that exists only in the archived repository: a CI run, a pull
  request, a commit, a file at a full commit id, or an issue that was not transferred
  (see untransferred_issues in the list). Those are records of what happened there, and
  repointing them would name something the new home does not hold;
- the file is listed in scripts/archived-repo-allowlist.txt with its reason: history
  sentences, records whose bytes are pinned by a digest, and checks that watch an
  archived repository on purpose.

Exit 0 when every reference is accounted for; 1 naming each one that is not; 2 when the
gate did not run. With --live it also asks GitHub whether the list is whole and true:
every repository in probityai-archive has a row, every row still redirects to the
archive, and every home exists. A network failure there exits 2, never 0.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "scripts" / "archived-repo-allowlist.txt"
REPOS = ROOT / "scripts" / "archived-repos.toml"
ARCHIVE_ORG = "probityai-archive"
API = "https://api.github.com"

# A predicate type URI names a predicate inside signed statements; it is never rewritten.
PREDICATE_URI = (
    r"https://github\.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/[a-z0-9-]+\.md"
)
_PREDICATE_AS_LINK = re.compile(r"\]\(\s*" + PREDICATE_URI)
_PREDICATE_BARE = re.compile(PREDICATE_URI)


class Archived(NamedTuple):
    """One archived repository, its new home and the issues that stayed behind."""

    name: str
    home: str
    untransferred_issues: tuple[int, ...]


def load_repos(text: str) -> list[Archived]:
    """Parse the list; every row needs a name and a home."""
    rows = []
    for row in tomllib.loads(text).get("repo", []):
        if not row.get("name") or not row.get("home"):
            raise ValueError(f"list row needs a name and a home: {row!r}")
        rows.append(Archived(row["name"], row["home"], tuple(row.get("untransferred_issues", ()))))
    if not rows:
        raise ValueError("the list of archived repositories is empty")
    return rows


def _names(repos: list[Archived]) -> str:
    return "|".join(re.escape(r.name) for r in sorted(repos, key=lambda r: -len(r.name)))


def reference_pattern(repos: list[Archived]) -> re.Pattern[str]:
    """A reference to an archived name as a repository: not an npm scope, not a dotted namespace."""
    return re.compile(rf"(?<![@\w.-])(?:probityai|astrogilda)/(?:{_names(repos)})(?![A-Za-z0-9_-])")


def records_pattern(repos: list[Archived]) -> re.Pattern[str]:
    """Text that names something existing only in an archived repository."""
    names = _names(repos)
    parts = [
        rf"github\.com/(?:probityai|astrogilda)/(?:{names})/(?:actions/runs/[0-9]+|pull/[0-9]+|commit/[0-9a-f]{{7,40}}"
        rf"|(?:blob|tree|raw)/[0-9a-f]{{40}}(?![0-9a-f]))",
        rf"raw\.githubusercontent\.com/(?:probityai|astrogilda)/(?:{names})/[0-9a-f]{{40}}(?![0-9a-f])",
    ]
    for repo in repos:
        if repo.untransferred_issues:
            issues = "|".join(str(n) for n in repo.untransferred_issues)
            name = re.escape(repo.name)
            parts.append(rf"github\.com/(?:probityai|astrogilda)/{name}/issues/(?:{issues})(?![0-9])")
            parts.append(rf"(?:probityai|astrogilda)/{name}#(?:{issues})(?![0-9])")
    return re.compile("|".join(parts))


def allowed_paths(text: str) -> set[str]:
    """Return the path patterns of the allowlist; each line is `<glob>  # <reason>`."""
    paths = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, sep, reason = line.partition("#")
        if not sep or not reason.strip():
            raise ValueError(f"allowlist line has no reason: {raw!r}")
        paths.add(path.strip())
    return paths


def is_allowed(path: str, patterns: set[str]) -> bool:
    """True when `path` matches an allowlist pattern (an exact path or a `dir/**` prefix)."""
    return any(path == p or (p.endswith("/**") and path.startswith(p[:-2])) for p in patterns)


def live_references(text: str, repos: list[Archived]) -> bool:
    """True when `text` still names an archived repository as something a reader can follow."""
    if _PREDICATE_AS_LINK.search(text):
        return True
    left = _PREDICATE_BARE.sub("", text)
    left = records_pattern(repos).sub("", left)
    return reference_pattern(repos).search(left) is not None


def findings(root: Path, patterns: set[str], repos: list[Archived]) -> list[str]:
    """Every unaccounted reference under `root`, as `path:line: text`."""
    prefilter = rf"(probityai|astrogilda)/({_names(repos)})"
    out = subprocess.run(
        ["git", "-C", str(root), "grep", "-n", "-I", "-E", prefilter],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed: {out.stderr.strip()}")
    hits = []
    for line in out.stdout.splitlines():
        path, _, rest = line.partition(":")
        number, _, text = rest.partition(":")
        if is_allowed(path, patterns):
            continue
        if live_references(text, repos):
            hits.append(f"{path}:{number}: {text.strip()[:160]}")
    return hits


Fetch = Callable[[str], object]


def github_fetch(url: str) -> object:
    """GET a GitHub API url and return its JSON; a token in GH_TOKEN or GITHUB_TOKEN is used."""
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https host
        return json.load(response)


def archive_org_names(fetch: Fetch) -> set[str]:
    """Every repository name in the archive organisation, following pages."""
    names: set[str] = set()
    page = 1
    while True:
        batch = fetch(f"{API}/orgs/{ARCHIVE_ORG}/repos?per_page=100&type=all&page={page}")
        if not isinstance(batch, list):
            raise RuntimeError(f"unexpected reply listing {ARCHIVE_ORG}: {batch!r}")
        names.update(str(r["name"]) for r in batch)
        if len(batch) < 100:
            return names
        page += 1


def live_problems(repos: list[Archived], fetch: Fetch) -> list[str]:
    """Where the list and GitHub disagree; an empty list means the list is whole and true."""
    problems = []
    listed = {r.name for r in repos}
    for name in sorted(archive_org_names(fetch) - listed):
        problems.append(f"{ARCHIVE_ORG}/{name} is archived but has no row in scripts/archived-repos.toml")
    for repo in repos:
        record = fetch(f"{API}/repos/probityai/{repo.name}")
        if not isinstance(record, dict):
            problems.append(f"probityai/{repo.name}: GitHub answered {record!r}, not a repository")
            continue
        full = record.get("full_name")
        if full != f"{ARCHIVE_ORG}/{repo.name}":
            problems.append(
                f"probityai/{repo.name} resolves to {full!r}, not {ARCHIVE_ORG}/{repo.name}: "
                "a repository at that path ends the redirect that keeps old links working"
            )
        elif not record.get("archived"):
            problems.append(f"{ARCHIVE_ORG}/{repo.name} is not archived")
        owner, repository, *path = repo.home.split("/", 2)
        suffix = f"/contents/{path[0]}" if path else ""
        try:
            fetch(f"{API}/repos/{owner}/{repository}{suffix}")
        except urllib.error.HTTPError as error:
            problems.append(f"home of {repo.name} ({repo.home}) answers HTTP {error.code}")
    return problems


def main(argv: list[str]) -> int:
    live = "--live" in argv
    try:
        repos = load_repos(REPOS.read_text(encoding="utf-8"))
        if live:
            problems = live_problems(repos, github_fetch)
            for problem in problems:
                print(problem, file=sys.stderr)
            if problems:
                return 1
            print(f"archived-repo-gate --live: {len(repos)} archived repositories match GitHub")
            return 0
        patterns = allowed_paths(ALLOWLIST.read_text(encoding="utf-8"))
        hits = findings(ROOT, patterns, repos)
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        print(f"archived-repo-gate did not run: {exc}", file=sys.stderr)
        return 2
    for hit in hits:
        print(hit, file=sys.stderr)
    if hits:
        print(
            f"{len(hits)} reference(s) to an archived probityai repository; point each at its home "
            "in scripts/archived-repos.toml, or list the file in scripts/archived-repo-allowlist.txt "
            "with its reason",
            file=sys.stderr,
        )
        return 1
    print(f"no live reference to the {len(repos)} archived probityai repositories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
