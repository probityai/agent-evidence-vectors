"""Tests for scripts/check_predicate_pages.py: the published predicate pages and their pins."""

import importlib.util
import shutil
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("check_predicate_pages",
                                               _ROOT / "scripts" / "check_predicate_pages.py")
pages_check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pages_check)


@pytest.fixture
def pages(tmp_path: Path) -> Path:
    shutil.copytree(_ROOT / "pages", tmp_path / "pages")
    return tmp_path / "pages"


def _page(pages: Path, name: str) -> Path:
    return pages / "predicate" / "v1" / name / "index.html"


def test_the_published_pages_pass() -> None:
    assert pages_check.check(_ROOT / "pages") == []


def test_the_done_pages_are_published() -> None:
    names = {d.name for d in (_ROOT / "pages" / "predicate" / "v1").iterdir() if d.is_dir()}
    assert {"done-contract", "done-receipt"} <= names


def test_a_changed_byte_is_refused(pages: Path) -> None:
    page = _page(pages, "done-contract")
    page.write_bytes(page.read_bytes().replace(b"</main>", b" </main>"))
    failures = pages_check.check(pages)
    assert len(failures) == 1
    assert failures[0].startswith("done-contract: page changed without its pin")


def test_an_unpinned_page_is_refused(pages: Path) -> None:
    extra = _page(pages, "extra")
    extra.parent.mkdir()
    shutil.copy(_page(pages, "done-contract"), extra)
    assert any("extra: not pinned" in f for f in pages_check.check(pages))


def test_a_missing_pinned_page_is_refused(pages: Path) -> None:
    shutil.rmtree(_page(pages, "done-receipt").parent)
    assert pages_check.check(pages) == ["done-receipt: pinned but missing"]


def test_a_wrong_canonical_link_is_refused(pages: Path) -> None:
    page = _page(pages, "done-contract")
    text = page.read_text(encoding="utf-8").replace(
        'rel="canonical" href="https://w3id.org/agent-evidence/predicate/v1/done-contract"',
        'rel="canonical" href="https://example.org/done-contract"')
    page.write_text(text, encoding="utf-8")
    assert any("canonical link is not its type URI" in f for f in pages_check.check(pages))


def test_a_link_to_an_unlisted_host_is_refused(pages: Path) -> None:
    page = _page(pages, "done-receipt")
    page.write_text(page.read_text(encoding="utf-8").replace(
        "</main>", '<a href="https://example.org/">x</a></main>'), encoding="utf-8")
    assert any("unlisted host example.org" in f for f in pages_check.check(pages))
