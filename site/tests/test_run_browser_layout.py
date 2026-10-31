"""Actual-browser controls for filters, keyboard disclosure and static fallback."""
import json
import os
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / 'data/lab-register.json').read_bytes())['records']
PAGE = ROOT / 'docs/runs.html'


@pytest.fixture(scope='module')
def browser():
    with sync_playwright() as runtime:
        instance = runtime.chromium.launch()
        yield instance
        instance.close()


def screenshot(page, name):
    path = os.environ.get('ATLAS_LAYOUT_EVIDENCE')
    if path:
        output = Path(path); output.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(output / name))


def test_filters_preserve_exact_tokens_and_mixed_claim_results(browser):
    page = browser.new_page(viewport={'width': 1280, 'height': 900}, reduced_motion='reduce')
    errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
    try:
        page.goto(PAGE.as_uri())
        expect(page.locator('#run-filters')).to_be_visible()
        assert page.locator('.run-record').count() == len(DATA)
        page.get_by_label('Contains a per-claim result').select_option('fail')
        expected = {record['id'] for record in DATA if any(claim['result'] == 'fail' for claim in record['claimResults'])}
        actual = set(page.locator('.run-disclosure:visible summary h2').all_text_contents())
        assert actual == expected and expected
        page.get_by_label('Search records, claims, roles or limits').fill('no-such-retained-record')
        expect(page.locator('#run-empty')).to_be_visible()
        assert page.locator('.run-disclosure:visible').count() == 0
        page.get_by_role('button', name='Clear filters').click()
        assert page.locator('.run-disclosure:visible').count() == len(DATA)
        assert page.locator('.run-record').count() == len(DATA)
        screenshot(page, 'runs-desktop-light.png')
        assert errors == []
    finally: page.close()


@pytest.mark.parametrize('theme', ['light', 'dark'])
def test_mobile_search_keyboard_disclosure_and_original_links(browser, theme):
    page = browser.new_page(viewport={'width': 320, 'height': 800}, color_scheme=theme, reduced_motion='reduce')
    try:
        page.goto(PAGE.as_uri())
        search = page.get_by_label('Search records, claims, roles or limits')
        search.focus(); page.keyboard.type('aeoess-receipt-signature-2026-10-05')
        assert page.locator('.run-disclosure:visible').count() == 1
        page.keyboard.press('Tab')
        assert page.locator('#run-result').evaluate('element => element === document.activeElement')
        summary = page.locator('.run-disclosure:visible summary')
        summary.focus(); page.keyboard.press('Enter')
        expect(page.locator('.run-disclosure:visible')).to_have_attribute('open', '')
        page.keyboard.press('Tab')
        assert page.get_by_role('link', name='Report', exact=True).evaluate('element => element === document.activeElement')
        assert page.get_by_role('link', name='Report', exact=True).get_attribute('href') == 'experiments/aeoess-receipt-signature-2026-10-05/report.json'
        assert page.locator('.run-disclosure:visible').get_by_text('not-established', exact=True).count() > 0
        assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        for control in page.locator('#run-filters input, #run-filters select, #run-filters button').all():
            assert control.bounding_box()['height'] >= 44
        screenshot(page, f'runs-mobile-{theme}.png')
    finally: page.close()


def test_hash_link_opens_its_exact_record_and_handles_malformed_hash(browser):
    page = browser.new_page(viewport={'width': 1280, 'height': 900})
    errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
    try:
        page.goto(PAGE.as_uri() + '#record-aeoess-receipt-signature-2026-10-05')
        disclosure = page.locator('.run-disclosure:has(#record-aeoess-receipt-signature-2026-10-05)')
        expect(disclosure).to_have_attribute('open', '')
        page.get_by_label('Search records, claims, roles or limits').fill('no-such-retained-record')
        expect(disclosure).to_be_hidden()
        page.evaluate('location.hash = "record-E6-observer-admission"')
        selected = page.locator('.run-disclosure:has(#record-E6-observer-admission)')
        expect(selected).to_be_visible()
        expect(selected).to_have_attribute('open', '')
        expect(page.get_by_label('Search records, claims, roles or limits')).to_have_value('')
        page.evaluate('location.hash = "%"')
        assert errors == []
    finally: page.close()


def test_without_javascript_all_records_results_and_links_remain(browser):
    context = browser.new_context(java_script_enabled=False, viewport={'width': 320, 'height': 800})
    page = context.new_page()
    try:
        page.goto(PAGE.as_uri())
        expect(page.locator('#run-filters')).to_be_hidden()
        assert page.locator('.run-record').count() == len(DATA)
        assert page.locator('.run-disclosure').count() == 0
        for record in DATA:
            expect(page.locator(f'#record-{record["id"]} h2')).to_have_text(record['id'])
        assert page.get_by_role('link', name='Report', exact=True).count() == len(DATA)
        assert page.get_by_role('link', name='Provenance', exact=True).count() == len(DATA)
        assert page.get_by_text('not-exercised', exact=True).count() > 0
        assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        screenshot(page, 'runs-no-javascript-mobile.png')
    finally: context.close()


def test_static_render_keeps_recorded_identifiers_and_declarations_literal(browser):
    context = browser.new_context(java_script_enabled=False)
    page = context.new_page()
    try:
        page.goto(PAGE.as_uri())
        for record in DATA:
            section = page.locator(f'#record-{record["id"]}')
            tables = section.locator('table')
            claims = tables.nth(0).locator('tbody tr').evaluate_all(
                'rows => rows.map(row => Array.from(row.cells, cell => cell.textContent.trim()))')
            assert claims == [[claim['claim'], claim['result']] for claim in record['claimResults']]
            roles = tables.nth(1).locator('tbody tr').evaluate_all(
                'rows => rows.map(row => Array.from(row.cells, cell => cell.textContent.trim()))')
            assert roles == [list(pair) for pair in record['roles'].items()]
            limits = section.locator('ul li').all_text_contents()
            assert limits == record['limits']
        assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
    finally: context.close()
