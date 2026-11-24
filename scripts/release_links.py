"""Refuse a release whose package metadata links to a repository readers cannot use.

A registry page (crates.io, PyPI, npm) shows the links its manifest carried at publish time,
and it never changes until the next release. A link that lands on an archive organisation, a
private repository, a renamed repository that redirects, or a path that does not exist sends
every reader of that page to the wrong place for the life of the release. This module reads
the GitHub links of a unit's manifest and answers, for each one, whether it resolves to a
public, non-archived repository of the probityai organisation under its current name, and
whether a tree or blob path in it exists on its branch.

    python3 scripts/release_links.py <manifest> [<manifest> ...]

`scripts/workspace.py release-target` runs the same check for the unit a release tag names, so
release.yml's `resolve` job stops before any build or upload. A manifest with no GitHub
repository link at all is refused too: a page with no way back to the source is the same
failure with fewer words. Standard library only, because CI runs it before anything is installed.
Reads GITHUB_TOKEN or GH_TOKEN when set, which lifts the anonymous API limit.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path

OWNER = "probityai"
_GITHUB = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[^/\s#?]+)/(?P<repo>[^/\s#?]+)(?P<rest>/[^\s#?]*)?"
)
# Every other spelling a registry renders as a link to a GitHub repository: the git+, git://,
# ssh:// and scp-like forms npm, pip and cargo accept, npm's github: shorthand, and the host in
# any case. Each is rewritten to the https form _GITHUB reads, so a link to an archived or
# renamed repository cannot pass by being spelled another way.
_GITHUB_PREFIX = re.compile(
    r"\A(?:git\+)?(?:(?:https?|git|ssh)://(?:[^@/\s]+@)?(?:www\.)?github\.com/"
    r"|git@github\.com:|github:)",
    re.IGNORECASE,
)
# npm's bare owner/repo shorthand for a GitHub repository, valid only in package.json's
# repository field.
_NPM_SHORTHAND = re.compile(r"\A[\w.-]+/[\w.-]+\Z")


def github_match(url: str) -> re.Match[str] | None:
    """The owner, repository and path of a GitHub link in any spelling, or None for another host."""
    url = url.strip()
    prefix = _GITHUB_PREFIX.match(url)
    if prefix is None:
        return None
    return _GITHUB.match("https://github.com/" + url[prefix.end() :])


def npm_repository_url(value: object) -> str:
    """The URL an npm manifest's repository field names, with the owner/repo shorthand expanded."""
    url = value.get("url", "") if isinstance(value, dict) else value
    if not isinstance(url, str):
        return ""
    return "github:" + url if _NPM_SHORTHAND.match(url) else url


# A tree or blob link names a ref and then, optionally, a path. A ref may itself hold a slash
# (release/1.0), so the split is not known from the URL; GitHub takes whichever split names a
# ref that exists, and so does ref_candidates.
_TREE = re.compile(r"/(?:tree|blob)/(?P<spec>[^\s]+?)/?\Z")


def ref_candidates(spec: str) -> list[tuple[str, str]]:
    """Every (ref, path) split of a tree or blob link's ref-and-path text, shortest ref first."""
    segments = [urllib.parse.unquote(s) for s in spec.split("/")]
    return [("/".join(segments[:k]), "/".join(segments[k:])) for k in range(1, len(segments) + 1)]


# The first path segment of every repository page github.com serves. Any other segment under
# owner/repo is a 404 (`/crates/jcs-admit` without `/tree/<ref>` is the measured case), so a link
# whose first segment is not here is refused rather than passed unread. A release tag page is
# read like a ref, because `/releases/tag/<tag>` for a tag never pushed is a 404 as well.
_REPO_ROUTES = frozenset(
    {
        "actions", "activity", "blob", "branches", "commit", "commits", "compare", "contributors",
        "deployments", "discussions", "forks", "graphs", "issues", "labels", "milestones",
        "network", "packages", "projects", "pull", "pulls", "pulse", "raw", "releases", "security",
        "stargazers", "tags", "tree", "watchers", "wiki",
    }
)
_RELEASE_TAG = re.compile(r"/releases/tag/(?P<tag>[^/\s]+)/?\Z")

RepoLookup = Callable[[str, str], "dict | None"]
PathLookup = Callable[[str, str, str], bool]


def _json_get(url: str) -> tuple[int, dict | list | None]:
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "release-links-check"}
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        raise SystemExit(
            f"GitHub answered {error.code} for {url}; an unread repository is not a pass"
        ) from error
    except OSError as error:
        raise SystemExit(
            f"could not read {url}: {error}; an unread repository is not a pass"
        ) from error


def github_repo(owner: str, repo: str) -> dict | None:
    """The repository record GitHub holds for owner/repo, or None when it answers 404."""
    status, body = _json_get(f"https://api.github.com/repos/{owner}/{repo}")
    return body if status == 200 and isinstance(body, dict) else None


def github_path_exists(full_name: str, ref: str, path: str) -> bool:
    """Whether `path` exists on `ref` of the repository, read through the contents API.

    An empty `path` asks whether the ref exists at all: the contents API answers 404 for a ref
    the repository does not have.
    """
    quoted = "/" + urllib.parse.quote(path) if path else ""
    status, _ = _json_get(
        f"https://api.github.com/repos/{full_name}/contents{quoted}"
        f"?ref={urllib.parse.quote(ref, safe='')}"
    )
    return status == 200


def manifest_urls(manifest: Path) -> list[tuple[str, str]]:
    """Every (field, url) a manifest of a crate, a Python distribution or an npm package carries."""
    name = manifest.name
    if name == "Cargo.toml":
        package = tomllib.loads(manifest.read_text())["package"]
        return [
            (k, package[k])
            for k in ("repository", "homepage", "documentation")
            if isinstance(package.get(k), str)
        ]
    if name == "pyproject.toml":
        project = tomllib.loads(manifest.read_text())["project"]
        urls = project.get("urls") or {}
        return [(f"urls.{key}", value) for key, value in urls.items() if isinstance(value, str)]
    if name == "package.json":
        data = json.loads(manifest.read_text())
        found = [("repository", npm_repository_url(data.get("repository")))]
        found.append(("homepage", data.get("homepage") or ""))
        bugs = data.get("bugs")
        found.append(("bugs", bugs.get("url", "") if isinstance(bugs, dict) else bugs or ""))
        return [(k, re.sub(r"^git\+|\.git$", "", v)) for k, v in found if v]
    raise SystemExit(f"{manifest}: not a Cargo.toml, pyproject.toml or package.json")


def _github_links(urls: list[tuple[str, str]]) -> Iterator[tuple[str, str, re.Match[str]]]:
    for field, url in urls:
        match = github_match(url)
        if match:
            yield field, url, match


def check_url(
    field: str, url: str, match: re.Match[str], repo_lookup: RepoLookup, path_lookup: PathLookup
) -> list[str]:
    """The reasons one GitHub link is unusable; empty when it reaches a live public repository."""
    owner, repo = match["owner"], re.sub(r"\.git$", "", match["repo"])
    if owner.lower() != OWNER:
        return [f"{field}: {url} names the owner {owner!r}, not {OWNER!r}"]
    record = repo_lookup(owner, repo)
    if record is None:
        return [f"{field}: {url} resolves to no repository readers can open"]
    problems = []
    if record.get("private"):
        problems.append(f"{field}: {url} is a private repository")
    if record.get("archived"):
        problems.append(f"{field}: {url} is an archived repository")
    current = str(record.get("full_name", ""))
    if current.lower() != f"{owner}/{repo}".lower():
        problems.append(f"{field}: {url} redirects to {current}, so the link names a retired name")
    if problems:
        return problems
    rest = match["rest"] or ""
    first = rest.strip("/").split("/", 1)[0]
    if first and first not in _REPO_ROUTES:
        return [f"{field}: {url} names {rest}, a path github.com serves no repository page for"]
    tree = _TREE.match(rest)
    if tree and not any(path_lookup(current, ref, p) for ref, p in ref_candidates(tree["spec"])):
        return [
            f"{field}: {url} names {tree['spec']}, and {current} has no branch or tag with that"
            " path under it"
        ]
    release = _RELEASE_TAG.match(rest)
    if release and not path_lookup(current, urllib.parse.unquote(release["tag"]), ""):
        return [f"{field}: {url} names the release tag {release['tag']}, which {current} lacks"]
    return []


def check_manifest(
    manifest: Path,
    repo_lookup: RepoLookup = github_repo,
    path_lookup: PathLookup = github_path_exists,
) -> list[str]:
    """Every reason `manifest` must not be released, as `manifest: reason` lines."""
    urls = manifest_urls(manifest)
    links = list(_github_links(urls))
    if not links:
        return [f"{manifest}: carries no GitHub repository link"]
    problems = []
    for field, url, match in links:
        problems += [
            f"{manifest}: {reason}"
            for reason in check_url(field, url, match, repo_lookup, path_lookup)
        ]
    return problems


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    problems = [p for arg in argv for p in check_manifest(Path(arg))]
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
