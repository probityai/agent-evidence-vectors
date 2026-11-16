"""Check the repository links every published package page shows today.

`scripts/release_links.py` refuses a release whose manifest links somewhere readers cannot
use. It cannot see a page that was published before that check existed, or a repository that
was archived, renamed or made private after the release: a registry page keeps the links its
manifest carried at publish time until the next release. This reads the live page of every
crates.io, PyPI and npm unit in release.toml, plus the corpus distribution on PyPI, and applies
the same rule to each GitHub link it shows.

    python3 scripts/registry_links.py

Exit 0 when every published page links to a live public probityai repository under its current
name; 1 when a page does not, naming each page and link; 2 when a registry or GitHub could not
be read, because an unread page is not a pass. A unit with no page yet is listed and is not a
failure. Standard library only. Reads GITHUB_TOKEN or GH_TOKEN when set.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRIES = ("crates.io", "pypi", "npm")
# The corpus release is a bare v<version> tag, so release.toml has no unit for it.
CORPUS = ("pypi", "agent-evidence-vectors")

Fetch = Callable[[str], "dict | None"]


class Unread(Exception):
    """A registry answered with something other than a page or a 404."""


def _release_links():
    spec = importlib.util.spec_from_file_location(
        "release_links", Path(__file__).with_name("release_links.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch_json(url: str) -> dict | None:
    """The JSON a registry serves at `url`, or None for a 404. Anything else raises Unread."""
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "registry-links-check"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise Unread(f"{url} answered {error.code}") from error
    except (OSError, ValueError) as error:
        raise Unread(f"could not read {url}: {error}") from error
    if not isinstance(body, dict):
        raise Unread(f"{url} did not answer with a JSON object")
    return body


def page_url(registry: str, name: str) -> str:
    if registry == "crates.io":
        return f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}"
    if registry == "pypi":
        return f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    if registry == "npm":
        return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"
    raise ValueError(f"unknown registry {registry!r}")


def page_links(registry: str, body: dict) -> tuple[str, list[tuple[str, str]]]:
    """The version a page shows and every (field, url) on it, as the registry reports them."""
    if registry == "crates.io":
        crate = body["crate"]
        version = crate.get("max_stable_version") or crate["max_version"]
        fields = ("repository", "homepage", "documentation")
        return version, [(k, crate[k]) for k in fields if isinstance(crate.get(k), str)]
    if registry == "pypi":
        info = body["info"]
        links = [(f"project_urls.{k}", v) for k, v in (info.get("project_urls") or {}).items()]
        if isinstance(info.get("home_page"), str) and info["home_page"]:
            links.append(("home_page", info["home_page"]))
        return info["version"], [(k, v) for k, v in links if isinstance(v, str)]
    if registry == "npm":
        version = body["dist-tags"]["latest"]
        meta = body["versions"][version]
        found = []
        for key in ("repository", "homepage", "bugs"):
            value = meta.get(key)
            if key == "repository":
                url = _release_links().npm_repository_url(value)
            else:
                url = value.get("url", "") if isinstance(value, dict) else value or ""
            if url:
                found.append((key, re.sub(r"\.git$", "", url)))
        return version, found
    raise ValueError(f"unknown registry {registry!r}")


def published_units(root: Path = ROOT) -> list[tuple[str, str]]:
    """Every (registry, name) with a registry page, deduplicated, corpus distribution included."""
    units = tomllib.loads((root / "release.toml").read_text()).get("unit", [])
    found = {(u["registry"], u["name"]) for u in units if u["registry"] in REGISTRIES}
    found.add(CORPUS)
    return sorted(found)


def check(
    units: list[tuple[str, str]],
    fetch: Fetch = fetch_json,
    repo_lookup=None,
    path_lookup=None,
) -> tuple[list[str], list[str], list[str]]:
    """(problems, unpublished, checked) over `units`; Unread propagates to the caller."""
    links_module = _release_links()
    repo_lookup = repo_lookup or links_module.github_repo
    path_lookup = path_lookup or links_module.github_path_exists
    problems: list[str] = []
    unpublished: list[str] = []
    checked: list[str] = []
    for registry, name in units:
        body = fetch(page_url(registry, name))
        if body is None:
            unpublished.append(f"{registry} {name}")
            continue
        try:
            version, urls = page_links(registry, body)
        except (KeyError, TypeError, AttributeError) as error:
            # A page without the fields this registry's pages carry is not a page with no
            # links: it was not read, and an unread page is not a finding either.
            raise Unread(
                f"{page_url(registry, name)} did not have the shape of a {registry} page: "
                f"{type(error).__name__} {error}"
            ) from error
        label = f"{registry} {name} {version}"
        checked.append(label)
        github = [
            (field, url, match)
            for field, url in urls
            if (match := links_module.github_match(url)) is not None
        ]
        if not github:
            problems.append(f"{label}: the page carries no GitHub repository link")
            continue
        for field, url, match in github:
            problems += [
                f"{label}: {reason}"
                for reason in links_module.check_url(field, url, match, repo_lookup, path_lookup)
            ]
    return problems, unpublished, checked


def main(argv: list[str]) -> int:
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        problems, unpublished, checked = check(published_units())
    except (Unread, SystemExit) as error:
        print(f"inconclusive: {error}", file=sys.stderr)
        return 2
    for label in checked:
        print(f"read {label}")
    for label in unpublished:
        print(f"no page yet: {label}")
    for problem in problems:
        print(problem, file=sys.stderr)
    print(
        f"{len(checked)} pages read, {len(problems)} unusable links, {len(unpublished)} unpublished"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
