"""Meaningful projection and refusal controls for retained-record navigation."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("run_browser", ROOT / "tools/run_browser.py")
browser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


def fixture():
    return {"records": [{"id": "outside-receipt", "evidenceClaim": "public-fixture-check", "reviewState": "retained", "roles": {"runner": "outside-reported", "independentOperation": "not-established"}, "limits": ["No external effect claim"], "claimResults": [{"claim": "bytes", "result": "pass"}, {"claim": "custody", "result": "not-exercised"}, {"claim": "policy", "result": "fail"}], "report": "../experiments/example/report.json", "provenance": "../experiments/example/provenance.json", "contract": "https://github.com/example/tool/blob/0123456789abcdef/README.md"}]}


def test_literal_projection_retains_mixed_results_roles_and_originals():
    data = fixture(); original = copy.deepcopy(data)
    result = browser.markdown(data)
    assert '| bytes | pass |' in result
    assert '| policy | fail |' in result
    assert '| custody | not-exercised |' in result
    assert '| independentOperation | not-established |' in result
    assert '[Report](experiments/example/report.json)' in result
    assert data == original
    assert 'data-results="fail not-exercised pass"' in result


def test_present_register_ids_and_each_source_claim_survive_projection():
    data = json.loads((ROOT / "data/lab-register.json").read_bytes())
    result = browser.markdown(data)
    assert result.count('::: {.run-record ') == len(data['records'])
    for record in data['records']:
        assert f'{{#record-{record["id"]}}}' in result
        for claim in record['claimResults']:
            assert f'| {browser.text(claim["claim"])} | {claim["result"]} |' in result
        for limit in record['limits']:
            assert browser.text(limit) in result


def test_new_record_and_new_result_token_need_no_hardcoded_count_or_grade():
    data = fixture(); extra = copy.deepcopy(data['records'][0]); extra['id'] = 'future-record'
    extra['claimResults'] = [{'claim': 'new-control', 'result': 'unresolved'}]
    data['records'].append(extra)
    result = browser.markdown(data)
    assert result.count('::: {.run-record ') == 2
    assert '<option value="unresolved">unresolved</option>' in result
    assert '| new-control | unresolved |' in result


@pytest.mark.parametrize('destination', ['javascript:alert(1)', '//evil.example/file', '../..//escape', '../x/../../escape', '../x\\escape', '../x"onclick="bad', '../x)bad', '/outside', '../x/%2e%2e/%2e%2e/escape', '../x%2fescape', '../javascript:alert', '../data:text/html', '../https:outside.example', '../mailto:operator@example.org'])
def test_unsafe_or_ambiguous_record_links_refuse(destination):
    with pytest.raises(ValueError): browser.destination(destination)


def test_untrusted_text_cannot_become_markup_link_or_extra_table_cell():
    data = fixture(); data['records'][0]['roles']['runner'] = '<script>alert(1)</script> | [fake](javascript:alert(1))'
    result = browser.markdown(data)
    assert '<script>' not in result
    assert '&#124;' in result
    assert '\\[fake\\]\\(javascript:alert\\(1\\)\\)' in result


@pytest.mark.parametrize('change', [lambda d: d['records'].append(copy.deepcopy(d['records'][0])), lambda d: d['records'][0].update(id='x" onload="bad'), lambda d: d['records'][0]['claimResults'][0].update(result=True), lambda d: d['records'][0]['claimResults'][0].update(result='pass" onclick="bad'), lambda d: d['records'][0]['roles'].update(runner=False)])
def test_bad_id_result_or_role_shape_refuses(change):
    data = fixture(); change(data)
    with pytest.raises(ValueError): browser.markdown(data)
