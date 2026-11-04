"""The sitemap dates pages by their sources' history, and IndexNow gets only what moved."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from xml.etree.ElementTree import fromstring

import pytest

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


site = load("vectors_site_build_dates", "docs/site/build.py")
changed = load("vectors_sitemap_changed", "scripts/sitemap_changed.py")
NS = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def git(repo: Path, *args: str, when: str | None = None) -> None:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.org")
    if when:
        env.update(GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when)
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "a.md").write_text("a1\n")
    (repo / "b.md").write_text("b1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "one", when="2026-10-01T23:30:00-05:00")
    (repo / "b.md").write_text("b2\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "two", when="2026-10-09T12:00:00+00:00")
    monkeypatch.setattr(site, "REPO_ROOT", repo)
    return repo


def test_each_page_is_dated_by_its_own_sources(history: Path) -> None:
    dates = site.git_dates({Path("a.html"): (history / "a.md",), Path("b.html"): (history / "b.md",)})
    # 23:30 at UTC-5 on 1 Oct is 04:30 UTC on 2 Oct: the date is the UTC one.
    assert dates == {Path("a.html"): "2026-10-02", Path("b.html"): "2026-10-09"}


def test_a_page_with_several_sources_takes_the_newest(history: Path) -> None:
    dates = site.git_dates({Path("both.html"): (history / "a.md", history / "b.md")})
    assert dates == {Path("both.html"): "2026-10-09"}


def test_a_shallow_clone_yields_no_dates(history: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{history}", str(shallow)], check=True,
                   capture_output=True)
    monkeypatch.setattr(site, "REPO_ROOT", shallow)
    assert site.git_dates({Path("a.html"): (shallow / "a.md",)}) == {}


def test_a_directory_that_is_not_a_work_tree_yields_no_dates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(site, "REPO_ROOT", tmp_path)
    assert site.git_dates({Path("a.html"): (tmp_path / "a.md",)}) == {}


def test_sitemap_carries_lastmod_only_where_a_date_exists() -> None:
    paths = [Path("start.html"), Path("codes.html"), Path("predicate/v1/x.html"), Path("predicate/v1/x/index.html")]
    dates = {Path("start.html"): "2026-10-02", Path("predicate/v1/x.html"): "2026-10-09",
             Path("predicate/v1/x/index.html"): "2026-10-08"}
    root = fromstring(site.sitemap(paths, dates))
    got = {u.find("s:loc", NS).text.rsplit("/", 1)[-1]: getattr(u.find("s:lastmod", NS), "text", None)
           for u in root.findall("s:url", NS)}
    assert got == {"start.html": "2026-10-02", "codes.html": None, "x": "2026-10-09"}


def test_the_page_sources_cover_every_published_route() -> None:
    routes = site.published_routes()
    sources = site.page_sources(routes)
    pages = {Path("index.html"), Path("codes.html"), *routes.values()}
    assert pages <= set(sources)
    assert all(files and all(f.is_file() for f in files) for files in sources.values())


def test_changed_lists_new_urls_and_moved_dates_only() -> None:
    live = changed.entries(
        "<urlset><url><loc>https://h/a</loc><lastmod>2026-10-01</lastmod></url>"
        "<url><loc>https://h/b</loc></url></urlset>"
    )
    built = {"https://h/a": "2026-10-01", "https://h/b": "2026-10-02", "https://h/c": "2026-10-03"}
    assert changed.changed(built, live) == ["https://h/b", "https://h/c"]


def test_changed_fails_on_a_url_without_lastmod(tmp_path: Path) -> None:
    built = tmp_path / "sitemap.xml"
    built.write_text("<urlset><url><loc>https://h/a</loc></url></urlset>")
    code = changed.main(["--built", str(built), "--live", "file:///nonexistent", "--out", str(tmp_path / "o.txt")])
    assert code == 1
