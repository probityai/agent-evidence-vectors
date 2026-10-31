"""Pin the claim status page's verdict mapping, operation-class rule and freshness check."""
import copy
import hashlib
import importlib.util
import json
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gen_status", ROOT / "tools/gen_status.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def record(rid, results, roles):
    return {"id": rid, "evidenceClaim": "public-fixture-check", "reviewState": "retained", "roles": roles,
            "limits": [], "claimResults": [{"claim": f"c{i}", "result": r} for i, r in enumerate(results)],
            "report": f"../experiments/{rid}/report.json", "provenance": f"../experiments/{rid}/provenance.json",
            "contract": "https://github.com/example/tool/blob/0123456789abcdef/README.md"}


def open_cells():
    return {"cell": [{"mechanism": "mech:a", "mechanism_title": "A", "property": "prop:x", "property_title": "X",
                      "property_question": "is x so", "words": "a cannot show x", "url": "https://example.org/a",
                      "basis": "states the limit", "excerpt": "cannot show x"},
                     {"mechanism": "mech:b", "mechanism_title": "B", "property": "prop:x", "property_title": "X",
                      "property_question": "is x so", "words": "b cannot show x", "url": "https://example.org/b",
                      "basis": "states the scope", "excerpt": "b does y"}],
            "start": [{"rank": 1, "mechanism": "mech:b", "property": "prop:x", "passing_case": "a passing case shows x"}]}


@pytest.mark.parametrize("result, verdict", [
    ("pass", "ESTABLISHED"), ("fail", "CONTRADICTED"),
    ("unknown", "UNKNOWN"),
    ("not-exercised", "NOT_ESTABLISHED"), ("out-of-scope", "NOT_ESTABLISHED")])
def test_verdict_mapping(result, verdict):
    assert gen.verdict(result) == verdict


def test_unsupported_result_is_refused():
    with pytest.raises(ValueError):
        gen.verdict("passed")


@pytest.mark.parametrize("roles, expected", [
    ({"runner": "Probity-owned GitHub Actions", "independentOperation": "not-established"}, "Probity-operated"),
    ({"fixtureOperator": "Probity"}, "Probity-operated"),
    ({"atlasOperator": "Probity", "independentOperation": "Probity operated the reader separately; not independent of Probity"}, "Probity-operated"),
    ({"fixtureOperator": "same-operator-fixture", "atlasReplay": "author-produced", "independentOperation": "not-established"}, "author-operated"),
    ({"runner": "a producer's agent under its author's mandate"}, "author-operated"),
    ({"runner": "Probity-owned GitHub Actions", "independentOperation": "established"}, "independently operated"),
    ({"historicalRunner": "outside lab", "independentOperator": "established"}, "independently operated"),
])
def test_operation_class_rule(roles, expected):
    assert gen.operation_class(roles) == expected


def test_record_without_operator_role_is_refused():
    with pytest.raises(ValueError):
        gen.operation_class({"readerAuthor": "Probity", "independentEffectCustody": "not-established"})


def test_totals_count_each_result_under_its_record_class():
    register = {"records": [
        record("p-run", ["pass", "fail", "not-exercised", "out-of-scope"], {"runner": "Probity CI"}),
        record("a-run", ["pass", "pass"], {"fixtureOperator": "same-operator-fixture"})]}
    page = gen.render(register, open_cells())
    assert "| ESTABLISHED (`pass`) | 1 | 2 | 0 | **3** |" in page
    assert "| CONTRADICTED (`fail`) | 1 | 0 | 0 | **1** |" in page
    assert "| NOT_ESTABLISHED, out of scope (`out-of-scope`) | 1 | 0 | 0 | **1** |" in page
    assert "| records | 1 | 1 | 0 | **2** |" in page
    assert "| 1 | 1 | 2 (1 out of scope) | 0 | Probity-operated |" in page
    assert "no record here was independently operated" in page


def test_unknown_observation_counts_separately_from_unexercised_checks():
    register = {"records": [
        record("unresolved", ["unknown", "not-exercised", "out-of-scope"],
               {"runner": "a producer's own CI"})]}
    page = gen.render(register, open_cells())
    assert "| unknown, observation unresolved (`unknown`) | 0 | 1 | 0 | **1** |" in page
    assert "| NOT_ESTABLISHED, not exercised (`not-exercised`) | 0 | 1 | 0 | **1** |" in page
    assert "| 0 | 0 | 2 (1 out of scope) | 1 | author-operated |" in page
    assert "| claim results | 0 | 3 | 0 | **3** |" in page


def test_real_outside_packet_can_support_a_local_unknown_intake_candidate():
    """Exercise a derived review candidate, not a new outside submission or run."""
    from tools.check_lab import artifact_path, validate_register
    from tools.run_browser import markdown

    register_path = ROOT / "data/lab-register.json"
    original = register_path.read_bytes()
    retained = next(row for row in json.loads(original)["records"]
                    if row["id"] == "aeoess-receipt-signature-2026-10-05")
    artifacts = {row["path"]: hashlib.sha256(artifact_path(ROOT, row["path"]).read_bytes()).hexdigest()
                 for row in retained["artifacts"]}
    candidate = copy.deepcopy(retained)
    candidate["id"] += "-unknown-intake-control"
    candidate["claimResults"].append({"claim": "separate-operational-control-review", "result": "unknown"})
    candidate["limits"].append("Local contract-test review candidate; no new outside submission, execution or custody claim")
    register = {"protocolVersion": "0.1", "records": [candidate]}
    validate_register(register, ROOT)
    browser_page = markdown(register)
    assert '| separate-operational-control-review | unknown |' in browser_page
    assert '<option value="unknown">unknown</option>' in browser_page
    page = gen.render(register, open_cells())
    assert "| unknown, observation unresolved (`unknown`) | 0 | 1 | 0 | **1** |" in page
    assert "| records | 0 | 1 | 0 | **1** |" in page
    assert register_path.read_bytes() == original
    assert all(hashlib.sha256(artifact_path(ROOT, path).read_bytes()).hexdigest() == digest
               for path, digest in artifacts.items())


def test_start_cells_lead_and_are_not_repeated():
    page = gen.render({"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}, open_cells())
    start, rest = page.split("## Every open cell", 1)
    assert "**B x X**" in start and "a passing case shows x" in start
    assert "b cannot show x" not in rest and "a cannot show x" in rest


def test_start_entry_must_name_an_open_cell():
    cells = open_cells()
    cells["start"][0]["mechanism"] = "mech:missing"
    with pytest.raises(ValueError):
        gen.render({"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}, cells)


def test_committed_page_matches_its_data():
    register = json.loads((ROOT / "data/lab-register.json").read_text(encoding="utf-8"))
    cells = tomllib.loads((ROOT / "data/open-cells.toml").read_text(encoding="utf-8"))
    filed = tomllib.loads((ROOT / "data/filed-runs.toml").read_text(encoding="utf-8"))
    assert (ROOT / "src/status.md").read_text(encoding="utf-8") == gen.render(register, cells, filed)


def filed_run(**changes):
    run = {key: f"{key} text" for key in gen.RUN_KEYS}
    run.update(changes)
    return run


def test_filed_runs_are_listed_and_not_counted():
    register = {"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}
    page = gen.render(register, open_cells(), {"run": [filed_run(id="x-run", link="https://example.org/1")]})
    assert "## Runs filed against cells and cases" in page
    assert "[`x-run`](https://example.org/1)" in page
    assert page.count("| records | 1 |") == 1


def test_no_filed_runs_leaves_no_section():
    page = gen.render({"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}, open_cells())
    assert "Runs filed against" not in page


@pytest.mark.parametrize("bad", [{"open": ""}, {"extra": "x"}])
def test_filed_run_with_a_missing_empty_or_extra_field_is_refused(bad):
    run = filed_run(**bad)
    with pytest.raises(ValueError):
        gen.render({"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}, open_cells(), {"run": [run]})


def test_repeated_filed_run_id_is_refused():
    with pytest.raises(ValueError):
        gen.render({"records": [record("p-run", ["pass"], {"runner": "Probity CI"})]}, open_cells(),
                   {"run": [filed_run(id="a"), filed_run(id="a")]})
