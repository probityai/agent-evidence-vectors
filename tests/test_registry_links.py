"""Tests for scripts/registry_links.py: the live check of every published package page."""

import importlib.util
import subprocess
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


# Every spelling below is one npm, pip or cargo accepts and the registry renders as a link to
# probityai/agent-evidence, which is archived. Each passed before github_match: the check read
# only https://github.com/ links, found the live homepage, and never saw the repository field.
ARCHIVE_SPELLINGS = [
    {"type": "git", "url": "git+ssh://git@github.com/probityai/agent-evidence.git"},
    {"type": "git", "url": "git://github.com/probityai/agent-evidence.git"},
    {"type": "git", "url": "git@github.com:probityai/agent-evidence.git"},
    {"type": "git", "url": "https://GitHub.com/probityai/agent-evidence"},
    "github:probityai/agent-evidence",
    "probityai/agent-evidence",
]


@pytest.mark.parametrize("repository", ARCHIVE_SPELLINGS, ids=repr)
def test_an_archived_repository_is_refused_in_every_spelling(repository):
    pages = {
        "https://registry.npmjs.org/jcs-admit": {
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"repository": repository, "homepage": f"{LIVE}#readme"}},
        }
    }
    problems, _, checked = run(pages, [("npm", "jcs-admit")])
    assert checked == ["npm jcs-admit 1.0.0"]
    assert any(
        p.startswith("npm jcs-admit 1.0.0: repository:") and "archived repository" in p
        for p in problems
    ), problems


def test_a_pypi_link_to_another_host_spelled_like_github_is_not_read_as_github():
    pages = {
        "https://pypi.org/pypi/jcs-admit/json": {
            "info": {
                "version": "0.1.1",
                "home_page": None,
                "project_urls": {
                    "Source": "https://github.com.example.org/probityai/agent-evidence",
                    "Gist": "https://gist.github.com/probityai/agent-evidence",
                },
            }
        }
    }
    problems, _, _ = run(pages, [("pypi", "jcs-admit")])
    assert problems == ["pypi jcs-admit 0.1.1: the page carries no GitHub repository link"]


@pytest.mark.parametrize(
    "body",
    [
        {"name": "jcs-admit", "time": {"unpublished": {"versions": ["0.1.0"]}}},
        {"dist-tags": {"latest": "0.1.1"}, "versions": {"0.1.0": {}}},
        {"dist-tags": [], "versions": {}},
    ],
    ids=["unpublished", "latest-not-in-versions", "dist-tags-not-a-map"],
)
def test_a_page_without_the_registry_shape_is_inconclusive_not_a_finding(body):
    # main() exits 2 for Unread and 1 for a finding; an uncaught KeyError exited 1.
    with pytest.raises(registry_links.Unread, match="did not have the shape of a npm page"):
        run({"https://registry.npmjs.org/jcs-admit": body}, [("npm", "jcs-admit")])


@pytest.mark.parametrize(
    ("event", "script_exit", "step_exit"),
    [
        ("pull_request", 0, 0),
        ("pull_request", 1, 0),
        ("pull_request", 2, 2),
        ("schedule", 1, 1),
        ("schedule", 2, 2),
        ("workflow_dispatch", 1, 1),
    ],
)
def test_a_pull_request_reports_a_published_page_finding_without_gating_on_it(
    tmp_path: Path, event: str, script_exit: int, step_exit: int
) -> None:
    """A pull request cannot change a page already published, and the release that
    clears a finding waits behind the merge train that touched the script; gating there
    held every such train red. An unread page (2) still fails on every event."""
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "identifier-hosts.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["registry-links"]["steps"]
    step = next(s for s in steps if "registry_links.py" in s.get("run", ""))
    assert step["env"]["EVENT"] == "${{ github.event_name }}"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "registry_links.py").write_text(
        f"raise SystemExit({script_exit})\n", encoding="utf-8"
    )
    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "EVENT": event},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == step_exit, result.stdout + result.stderr
