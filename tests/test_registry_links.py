"""Tests for scripts/registry_links.py: the live check of every published package page."""

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


registry_links = _load("registry_links")

REPOS = {
    "probityai/agent-evidence-vectors": {
        "full_name": "probityai/agent-evidence-vectors",
        "private": False,
        "archived": False,
    },
    "probityai/agent-evidence": {
        "full_name": "probityai-archive/agent-evidence",
        "private": False,
        "archived": True,
    },
}


def repo_lookup(owner, repo):
    return REPOS.get(f"{owner}/{repo}")


def path_lookup(full_name, ref, path):
    return full_name == "probityai/agent-evidence-vectors" and ref == "main"


ARCHIVE = "https://github.com/probityai/agent-evidence"
LIVE = "https://github.com/probityai/agent-evidence-vectors"


def crate(version, repository, homepage):
    return {
        "crate": {
            "max_version": version,
            "max_stable_version": version,
            "repository": repository,
            "homepage": homepage,
            "documentation": f"https://docs.rs/x/{version}",
        }
    }


# The pages as crates.io served them on 15 Nov 2026, before the releases that move the links.
BEFORE = {
    "https://crates.io/api/v1/crates/jcs-admit": crate(
        "0.1.3", ARCHIVE, f"{ARCHIVE}/tree/main/crates/jcs-admit#readme"
    ),
    "https://crates.io/api/v1/crates/dsse": crate(
        "0.1.6", ARCHIVE, f"{ARCHIVE}/tree/main/crates/dsse#readme"
    ),
}
AFTER = {
    "https://crates.io/api/v1/crates/jcs-admit": crate(
        "0.1.4", LIVE, f"{LIVE}/tree/main/crates/jcs-admit#readme"
    ),
    "https://crates.io/api/v1/crates/dsse": crate(
        "0.1.7", LIVE, f"{LIVE}/tree/main/crates/dsse#readme"
    ),
}
UNITS = [("crates.io", "dsse"), ("crates.io", "jcs-admit")]


def run(pages, units=UNITS):
    return registry_links.check(units, pages.get, repo_lookup, path_lookup)


def test_the_pages_before_the_release_are_refused():
    problems, unpublished, checked = run(BEFORE)
    assert checked == ["crates.io dsse 0.1.6", "crates.io jcs-admit 0.1.3"]
    assert unpublished == []
    for name in ("dsse 0.1.6", "jcs-admit 0.1.3"):
        mine = [p for p in problems if p.startswith(f"crates.io {name}:")]
        assert any("archived repository" in p for p in mine), mine
        assert any("redirects to probityai-archive/agent-evidence" in p for p in mine), mine


def test_the_pages_after_the_release_pass():
    problems, unpublished, checked = run(AFTER)
    assert problems == [] and unpublished == []
    assert checked == ["crates.io dsse 0.1.7", "crates.io jcs-admit 0.1.4"]


def test_a_page_with_no_github_link_is_refused():
    pages = {"https://crates.io/api/v1/crates/dsse": crate("0.1.7", "https://example.org", "")}
    problems, _, _ = run(pages, [("crates.io", "dsse")])
    assert problems == ["crates.io dsse 0.1.7: the page carries no GitHub repository link"]


def test_a_unit_with_no_page_is_listed_not_failed():
    problems, unpublished, checked = run({}, [("npm", "jcs-admit")])
    assert (problems, unpublished, checked) == ([], ["npm jcs-admit"], [])


def test_pypi_and_npm_pages_are_read_by_their_own_shape():
    pages = {
        "https://pypi.org/pypi/jcs-admit/json": {
            "info": {
                "version": "0.1.1",
                "home_page": None,
                "project_urls": {
                    "Source": f"{LIVE}/tree/main/crates/jcs-admit/python",
                    "Issues": f"{ARCHIVE}/issues",
                },
            }
        },
        "https://registry.npmjs.org/@probityai%2Fdsse": {
            "dist-tags": {"latest": "0.1.0"},
            "versions": {
                "0.1.0": {
                    "repository": {"type": "git", "url": f"git+{LIVE}.git"},
                    "homepage": f"{LIVE}/blob/main/crates/dsse/npm/README.md",
                }
            },
        },
    }
    problems, unpublished, checked = run(pages, [("pypi", "jcs-admit"), ("npm", "@probityai/dsse")])
    assert checked == ["pypi jcs-admit 0.1.1", "npm @probityai/dsse 0.1.0"]
    assert unpublished == []
    assert problems
    assert all(p.startswith("pypi jcs-admit 0.1.1: project_urls.Issues") for p in problems)


def test_an_unreadable_registry_is_not_a_pass():
    def broken(url):
        raise registry_links.Unread(f"{url} answered 503")

    with pytest.raises(registry_links.Unread):
        registry_links.check(UNITS, broken, repo_lookup, path_lookup)


def test_every_published_unit_and_the_corpus_are_covered():
    units = registry_links.published_units()
    assert ("pypi", "agent-evidence-vectors") in units
    for unit in [
        ("crates.io", "jcs-admit"),
        ("crates.io", "dsse"),
        ("pypi", "jcs-admit"),
        ("npm", "jcs-admit"),
        ("npm", "@probityai/dsse"),
    ]:
        assert unit in units
    assert all(registry in registry_links.REGISTRIES for registry, _ in units)
    assert len(units) == len(set(units))


def test_the_scoped_npm_name_is_one_path_segment():
    assert registry_links.page_url("npm", "@probityai/dsse") == (
        "https://registry.npmjs.org/@probityai%2Fdsse"
    )
