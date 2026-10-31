"""Check the worked article's actual evidence routes and keyboard access."""
import hashlib
import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = 'w3c-report-replay-2026-10-06'


@pytest.fixture(scope='module')
def browser():
    with sync_playwright() as runtime:
        instance = runtime.chromium.launch()
        yield instance
        instance.close()


@pytest.mark.parametrize('width,height', [(1280, 900), (320, 800)])
@pytest.mark.parametrize('javascript', [True, False])
def test_article_evidence_and_keyboard_routes(browser, width, height, javascript):
    context = browser.new_context(viewport={'width': width, 'height': height},
                                  java_script_enabled=javascript, reduced_motion='reduce')
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    try:
        document = ROOT / 'docs/evidence-test-meaning.html'
        page.goto(document.as_uri())
        expect(page.get_by_role('heading', level=1, name='A green test suite can contain negative conclusions')).to_be_visible()
        assert page.locator('main table').first.locator('tbody tr').count() == 6
        expect(page.locator('main')).to_contain_text('synthetic artifacts')
        expect(page.locator('main')).to_contain_text('no live refund, customer deployment or independent custody')
        assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        page.keyboard.press('Tab')
        assert page.locator('.skip').evaluate('element => element === document.activeElement')
        page.keyboard.press('Enter')
        assert page.locator('main').evaluate('element => element === document.activeElement')
        page.keyboard.press('Tab')
        assert page.locator('main').evaluate('element => element.contains(document.activeElement)')
        report = page.get_by_role('link', name='original report', exact=True)
        assert report.get_attribute('href') == f'experiments/{IDENTITY}/original-report.json'
        published = ROOT / 'docs' / report.get_attribute('href')
        assert hashlib.sha256(published.read_bytes()).hexdigest() == '37288d8dfc01f56cb5ef553232258dc596928bc962e2309e0c7dc09ae588baf2'
        output = os.environ.get('ATLAS_LAYOUT_EVIDENCE')
        if output:
            destination = Path(output)
            destination.mkdir(parents=True, exist_ok=True)
            name = f'evidence-meaning-{width}-{"javascript" if javascript else "no-javascript"}'
            page.screenshot(path=str(destination / (name + '.png')), full_page=True)
            receipt = {'page': str(document.relative_to(ROOT)), 'pageSHA256': hashlib.sha256(document.read_bytes()).hexdigest(),
                       'viewport': {'width': width, 'height': height}, 'javascript': javascript,
                       'browserVersion': browser.version, 'keyboardAccess': True,
                       'originalReportSHA256': hashlib.sha256(published.read_bytes()).hexdigest(),
                       'screenshot': name + '.png'}
            (destination / (name + '.json')).write_text(json.dumps(receipt, indent=2) + '\n')
        page.get_by_role('link', name='retained Lab record', exact=True).click()
        heading = page.locator('#record-' + IDENTITY)
        expect(heading).to_be_visible()
        expect(page.get_by_role("heading", level=2, name=IDENTITY, exact=True)).to_be_visible()
        assert page.url.endswith('runs.html#record-' + IDENTITY)
        assert errors == []
    finally:
        context.close()
