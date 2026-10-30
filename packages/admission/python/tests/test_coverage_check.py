"""Tests for the coverage check: the vector manifest, the CLI, and the corners the vectors leave."""

import json
from pathlib import Path

import pytest
from agent_evidence_admission import coverage_check as cc
from agent_evidence_admission.cli import main

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "coverage"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())
CASES = MANIFEST["cases"]


def statuses(report: cc.Report) -> dict[str, str]:
    return {r.name: r.status for r in report.results}


def run_case(case: dict) -> tuple[int, dict]:
    argv = ["coverage-check", str(VECTORS / case["document"]), "--require", ",".join(case["required"]), "--json"]
    return main(argv + case.get("flags", [])), {}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_vector(case, capsys):
    code = main(
        ["coverage-check", str(VECTORS / case["document"]), "--require", ",".join(case["required"]), "--json", *case.get("flags", [])]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == case["exit"]
    got = {c["class"]: c["status"] for c in report["classes"]}
    for name, status in case["statuses"].items():
        assert got[name] == status
    assert list(got) == case["required"]
    assert report["ok"] is (case["exit"] == 0)


def test_the_manifest_holds_both_polarities_and_every_failing_status():
    assert {c["polarity"] for c in CASES} == {"positive", "negative"}
    seen = {s for c in CASES for s in c["statuses"].values()}
    assert {"ASSESSED", "NOT-ASSESSED", "COVERED-ELSEWHERE", "INCOMPLETE", *cc.FAILING} <= seen


def test_every_document_in_the_directory_is_used_by_a_case():
    used = {c["document"] for c in CASES}
    documents = {p.name for p in VECTORS.glob("*.json") if not p.name.startswith("required-")}
    assert documents - {"manifest.json"} == used


def test_the_required_list_the_action_self_test_uses_names_six_cyclonedx_classes():
    assert len(cc.parse_required((VECTORS / "required-cyclonedx.json").read_text(), "cyclonedx")) == 6


def test_text_report_names_each_class_and_the_verdict(capsys):
    code = main(["coverage-check", str(VECTORS / "cdx-1.6-baseline.json"), "--require", "library,machine-learning-model"])
    out = capsys.readouterr().out
    assert code == 1
    assert "MISSING" in out and "machine-learning-model" in out
    assert out.strip().endswith("FAIL cyclonedx: 1 of 2 required classes accounted for")


def test_required_file_json_object_picks_the_list_for_the_format(tmp_path, capsys):
    path = tmp_path / "tender.json"
    path.write_text(json.dumps({"required": ["library"], "cyclonedx": ["service"], "spdx": ["model"]}))
    assert main(["coverage-check", str(VECTORS / "cdx-1.6-baseline.json"), "--required", str(path)]) == 0
    assert "service" in capsys.readouterr().out
    assert main(["coverage-check", str(VECTORS / "spdx-3.0.1-baseline.json"), "--required", str(path)]) == 1


def test_required_text_file_allows_comments_and_lines(tmp_path):
    path = tmp_path / "tender.txt"
    path.write_text("library  # the code\nservice, application\n")
    assert cc.parse_required(path.read_text()) == ["library", "service", "application"]


@pytest.mark.parametrize("text", ["", "# only a comment", "[]", "[1]", "{bad", '{"required": "library"}'])
def test_unreadable_required_lists_are_input_errors(text):
    with pytest.raises(cc.CoverageInputError):
        cc.parse_required(text)


def test_unreadable_inputs_exit_two(tmp_path, capsys):
    document = VECTORS / "cdx-1.6-baseline.json"
    assert main(["coverage-check", str(tmp_path / "nope.json"), "--require", "library"]) == 2
    assert main(["coverage-check", str(document), "--required", str(tmp_path / "nope.txt")]) == 2
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}')
    assert main(["coverage-check", str(other), "--require", "library"]) == 2
    assert main(["coverage-check", str(document), "--require", "# nothing"]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert main(["coverage-check", str(bad), "--require", "library"]) == 2
    assert "could not read" in capsys.readouterr().err


def test_either_required_option_is_needed():
    with pytest.raises(SystemExit):
        main(["coverage-check", str(VECTORS / "cdx-1.6-baseline.json")])


def test_unknown_aggregate_is_an_input_error():
    bom = {"bomFormat": "CycloneDX", "compositions": [{"aggregate": "maybe", "assemblies": []}]}
    with pytest.raises(cc.CoverageInputError):
        cc.check(bom, ["library"])


def test_non_object_composition_is_an_input_error():
    with pytest.raises(cc.CoverageInputError):
        cc.check({"bomFormat": "CycloneDX", "compositions": ["x"]}, ["library"])


def test_invalid_spdx_completeness_is_an_input_error():
    graph = [{"type": "Relationship", "spdxId": "r", "completeness": "mostly", "from": "a", "to": []}]
    with pytest.raises(cc.CoverageInputError):
        cc.check({"@graph": graph}, ["library"])


def test_nested_components_and_services_are_counted():
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            "junk",
            {"type": "library", "bom-ref": "outer", "components": [{"type": "library", "bom-ref": "inner"}]},
            {"type": "library"},
        ],
        "services": ["junk", {"bom-ref": "s", "services": [{"bom-ref": "t"}]}],
        "compositions": [{"aggregate": "complete", "assemblies": ["outer", "inner"], "dependencies": ["s", "t"]}],
    }
    report = cc.check(bom, ["library", "service"])
    assert statuses(report) == {"library": cc.MISSING, "service": cc.ASSESSED}
    assert "1 member(s) of the class are in no entry" in report.results[0].detail


def test_a_class_with_members_but_no_entry_says_how_many():
    bom = {"bomFormat": "CycloneDX", "components": [{"type": "library", "bom-ref": "a"}]}
    assert cc.check(bom, ["library"]).results[0].detail.startswith("1 member(s) present")


def test_a_link_only_composition_covers_no_class_and_says_so():
    bom = {"bomFormat": "CycloneDX", "compositions": [{"aggregate": "unknown", "assemblies": ["urn:cdx:abc/1"]}]}
    report = cc.check(bom, ["library"])
    assert report.results[0].status == cc.MISSING
    assert any("selects no class" in n for n in report.notes)


def test_a_not_assessed_entry_outside_the_required_list_is_a_note_not_a_failure():
    bom = {
        "bomFormat": "CycloneDX",
        "compositions": [
            {"aggregate": "complete", "filter": {"componentTypes": ["library"]}},
            {"aggregate": "not-assessed", "filter": {"componentTypes": ["device"]}},
        ],
    }
    report = cc.check(bom, ["library"])
    assert report.ok
    assert any(n.startswith("outside the required list") for n in report.notes)


def test_complete_entry_that_is_only_a_link_is_covered_elsewhere():
    bom = {"bomFormat": "CycloneDX", "compositions": [{"aggregate": "complete", "filter": {"componentTypes": ["library"]}, "assemblies": ["urn:cdx:abc/1#x"]}]}
    assert cc.check(bom, ["library"]).results[0].status == cc.COVERED_ELSEWHERE


def test_spdx_iri_purposes_and_reasons_are_reduced_to_their_names():
    base = "https://spdx.org/rdf/3.0.1/terms/Software/"
    graph = [
        {"type": "SpdxDocument", "spdxId": "d", "rootElement": ["root"], "import": [{"externalSpdxId": "ext"}, "junk"]},
        {"type": "software_Package", "spdxId": "root"},
        {
            "type": "software_CoverageRelationship",
            "spdxId": "r",
            "from": "root",
            "completeness": "noAssertion",
            "software_coveredPurpose": base + "SoftwarePurpose/model",
            "software_notAssessedReason": base + "NotAssessedReason/withheld",
            "to": ["https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement"],
        },
        {"type": "Relationship", "spdxId": "skip", "from": "elsewhere", "completeness": "complete", "to": []},
        {"type": "Relationship", "spdxId": "no-completeness", "from": "root", "to": []},
        "junk",
    ]
    result = cc.check({"@graph": graph}, ["model"]).results[0]
    assert (result.status, result.reason) == (cc.NOT_ASSESSED, "withheld")


def test_spdx_without_a_document_element_reads_every_relationship():
    graph = [
        {"type": "software_Package", "spdxId": "p", "software_primaryPurpose": "library", "software_additionalPurpose": ["data"]},
        {"type": "Relationship", "spdxId": "r", "from": "x", "completeness": "incomplete", "to": ["p", "gone"]},
    ]
    report = cc.check({"@graph": graph}, ["library", "data"])
    assert statuses(report) == {"library": cc.INCOMPLETE, "data": cc.INCOMPLETE}


def test_spdx_coverage_relationship_without_completeness_is_not_assessed():
    graph = [{"type": "software_CoverageRelationship", "spdxId": "r", "software_coveredPurpose": ["model"], "to": []}]
    assert cc.check({"@graph": graph}, ["model"]).results[0].status == cc.NO_REASON


def test_reasoned_not_assessed_is_accounted_for_but_unreasoned_is_not():
    entry = {"aggregate": "not-assessed", "filter": {"componentTypes": ["device"]}}
    assert cc.check({"bomFormat": "CycloneDX", "compositions": [entry]}, ["device"]).results[0].status == cc.NO_REASON
    entry["notAssessedReason"] = "withheld"
    assert cc.check({"bomFormat": "CycloneDX", "compositions": [entry]}, ["device"]).ok


def test_detect_format_refuses_other_documents():
    with pytest.raises(cc.CoverageInputError):
        cc.detect_format([])


def test_two_listed_entries_for_one_class_that_disagree_are_a_double():
    bom = {
        "bomFormat": "CycloneDX",
        "components": [{"type": "library", "bom-ref": "a"}, {"type": "library", "bom-ref": "b"}],
        "compositions": [
            {"aggregate": "complete", "assemblies": ["a"]},
            {"aggregate": "incomplete", "assemblies": ["b"]},
        ],
    }
    result = cc.check(bom, ["library"]).results[0]
    assert result.status == cc.DOUBLE
    assert "compositions[0] is ASSESSED but compositions[1] is INCOMPLETE" in result.detail
