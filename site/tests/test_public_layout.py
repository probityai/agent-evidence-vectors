"""Exercise the actual generated pages with keyboard input and small viewports.

Install requirements/public-layout.txt and Playwright's Chromium before running.
ATLAS_LAYOUT_ROOT can select an immutable baseline for before/after controls.
Screenshots go to ATLAS_LAYOUT_EVIDENCE when the caller retains a native run.
These checks cover browser layout and controls, not full WCAG conformance.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

ROOT = Path(os.environ.get("ATLAS_LAYOUT_ROOT", Path(__file__).resolve().parents[1]))
PAGES = sorted((ROOT / "docs").glob("*.html"))
assert PAGES, "The check needs actual generated pages"


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as runtime:
        instance = runtime.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    instance = browser.new_page(viewport={"width": 320, "height": 800})
    yield instance
    instance.close()


@pytest.mark.parametrize("document", PAGES, ids=lambda path: path.stem)
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_pages_reflow_without_losing_table_semantics(
    page: Page, document: Path, theme: str
) -> None:
    page.emulate_media(color_scheme=theme, reduced_motion="reduce")
    page.goto(document.as_uri())
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), "The page scrolls horizontally; only its wide tables or code should do that"
    for table in page.locator("table").all():
        region = table.locator("..").first
        assert region.get_attribute("role") == "region"
        assert region.get_attribute("aria-label")
        assert region.get_attribute("tabindex") == "0"
        assert table.evaluate("element => getComputedStyle(element).display") == "table"


def test_skip_link_moves_keyboard_focus_into_content(page: Page) -> None:
    page.goto((ROOT / "docs/index.html").as_uri())
    page.keyboard.press("Tab")
    assert page.locator(".skip").evaluate("element => element === document.activeElement")
    assert page.locator(".skip").bounding_box()["x"] >= 0
    page.keyboard.press("Enter")
    assert page.locator("main").evaluate("element => element === document.activeElement")
    page.keyboard.press("Tab")
    assert page.locator("main").evaluate("element => element.contains(document.activeElement)")


def test_wide_table_can_scroll_and_release_focus(page: Page) -> None:
    page.goto((ROOT / "docs/claims.html").as_uri())
    regions = page.locator(".table-scroll").all()
    wide = next(
        region for region in regions
        if region.evaluate("element => element.scrollWidth > element.clientWidth")
    )
    wide.focus()
    assert wide.evaluate("element => getComputedStyle(element).outlineStyle") == "solid"
    page.keyboard.press("ArrowRight")
    page.wait_for_function("element => element.scrollLeft > 0", arg=wide.element_handle())
    page.keyboard.press("Tab")
    assert not wide.evaluate("element => element === document.activeElement")


def test_every_source_claim_renders_as_one_dated_table_row(page: Page) -> None:
    """A blank line must not turn a ledger claim into unstructured prose."""
    expected = re.findall(
        r"(?m)^\|\s*([A-Z]+-[A-Za-z0-9]+)\s*\|", (ROOT / "CLAIMS.md").read_text()
    )
    assert expected, "The control needs the actual source claim ledger"
    assert all(count == 1 for count in Counter(expected).values())
    page.goto((ROOT / "docs/claims.html").as_uri())
    rows = page.locator("main table tbody tr").evaluate_all(
        "elements => elements.map(row => ({"
        "id: Array.from(row.firstElementChild.childNodes)"
        ".filter(node => node.nodeType === Node.TEXT_NODE)"
        ".map(node => node.textContent).join('').trim(), "
        "read: row.getAttribute('data-read')}))"
    )
    claims = [row for row in rows if re.fullmatch(r"[A-Z]+-[A-Za-z0-9]+", row["id"])]
    assert Counter(row["id"] for row in claims) == Counter(expected)
    assert all(row["read"] for row in claims), "Each rendered claim needs its read date"


def test_long_code_can_scroll_and_release_focus(page: Page) -> None:
    page.goto((ROOT / "docs/repository.html").as_uri())
    regions = page.locator(".code-scroll").all()
    wide = next(
        region for region in regions
        if region.evaluate("element => element.scrollWidth > element.clientWidth")
    )
    assert wide.get_attribute("role") == "region"
    assert wide.get_attribute("aria-label") == "Code example"
    assert wide.get_attribute("tabindex") == "0"
    wide.focus()
    page.keyboard.press("ArrowRight")
    page.wait_for_function("element => element.scrollLeft > 0", arg=wide.element_handle())
    page.keyboard.press("Tab")
    assert not wide.evaluate("element => element === document.activeElement")


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_navigation_has_usable_hit_areas(page: Page, theme: str) -> None:
    page.emulate_media(color_scheme=theme)
    page.goto((ROOT / "docs/start.html").as_uri())
    for link in page.locator("header.site .links a").all():
        assert link.bounding_box()["height"] >= 44
    evidence = os.environ.get("ATLAS_LAYOUT_EVIDENCE")
    if evidence:
        path = Path(evidence)
        path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path / f"start-mobile-{theme}.png"), full_page=True)
        page.set_viewport_size({"width": 1280, "height": 900})
        page.screenshot(path=str(path / f"start-desktop-{theme}.png"), full_page=True)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_explicit_theme_status_colors_match_system_theme(page: Page, theme: str) -> None:
    page.goto((ROOT / "docs/versions.html").as_uri())
    page.emulate_media(color_scheme=theme)
    colors = page.locator(".label").evaluate_all(
        "elements => elements.map(element => getComputedStyle(element).color)"
    )
    assert colors, "The control must exercise actual status labels"
    page.emulate_media(color_scheme="dark" if theme == "light" else "light")
    page.locator("html").evaluate("(element, theme) => element.dataset.theme = theme", theme)
    assert colors == page.locator(".label").evaluate_all(
        "elements => elements.map(element => getComputedStyle(element).color)"
    )
