"""Adverse supplied records must not become a matching committed execution."""

import base64
import copy
import json
from pathlib import Path

import pytest

from sql_illustration.check import InvalidInput, assess, main, read

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "fixtures/manifest.json").read_text())


def document():
    return json.loads((ROOT / "fixtures/matching-commit.json").read_text())


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=lambda c: c["path"])
def test_finite_cases(case, capsys):
    path = ROOT / case["path"]
    result = assess(read(path))
    assert result["result"] == case["expected_result"]
    assert result["later_state"] == case["expected_later_state"]
    assert result["origin"] == "author-created-fixture"
    assert result["later_change_attribution"] == "not_assessed"
    assert main([str(path)]) == case["expected_exit"]
    assert json.loads(capsys.readouterr().out) == result


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("database", "another", "database"),
        ("schema", "another", "schema"),
        ("instance", "another", "database_instance"),
    ],
)
def test_identical_sql_in_another_target_is_a_difference(field, value, expected):
    obj = document()
    obj["audit"]["records"][0]["call"]["target"][field] = value
    result = assess(obj)
    assert result["result"] == "execution_differs_from_approval"
    assert result["approval_audit_differences"] == [expected]


def test_parameter_type_is_part_of_what_was_approved():
    obj = document()
    obj["audit"]["records"][0]["call"]["parameters"][0]["database_type"] = "text"
    assert assess(obj)["approval_audit_differences"] == ["typed_parameters"]


def test_sql_null_and_empty_bytes_are_distinct():
    obj = document()
    obj["approval"]["call"]["parameters"][0]["value_b64"] = None
    obj["audit"]["records"][0]["call"]["parameters"][0]["value_b64"] = ""
    assert assess(obj)["approval_audit_differences"] == ["typed_parameters"]


def test_same_looking_unicode_sql_is_not_normalised():
    obj = document()
    obj["approval"]["call"]["sql_utf8_b64"] = base64.b64encode("SELECT '\u00e9'".encode()).decode()
    obj["audit"]["records"][0]["call"]["sql_utf8_b64"] = base64.b64encode(
        "SELECT 'e\u0301'".encode()
    ).decode()
    assert assess(obj)["approval_audit_differences"] == ["sql_bytes"]


def test_wrong_scope_cannot_prove_an_absence():
    obj = document()
    obj["audit"]["records"] = []
    obj["audit"]["scope"]["target"]["instance"] = "other"
    result = assess(obj)
    assert result["result"] == "insufficient_audit_evidence"
    assert result["declared_audit_scope"]["complete"] is True
    assert result["declared_audit_scope"]["matches_approval"] is False
    assert result["declared_audit_scope"]["target"]["instance"] == "other"


def test_unrelated_request_does_not_match_by_sql_alone():
    obj = document()
    obj["audit"]["records"][0]["call"]["request_id"] = "unrelated"
    assert assess(obj)["audit_matches"] == 0


def test_missing_database_record_preserves_application_claim():
    obj = document()
    obj["audit"]["records"] = []
    obj["audit"]["complete"] = False
    result = assess(obj)
    assert result["result"] == "insufficient_audit_evidence"
    assert result["application_present"] is True
    assert result["application_outcome"] == {"statement": "succeeded", "transaction": "committed"}


def test_outcome_disagreement_keeps_both_reported_values():
    obj = json.loads((ROOT / "fixtures/outcome-disagreement.json").read_text())
    result = assess(obj)
    assert result["result"] == "application_audit_disagreement"
    assert result["application_outcome"] == {"statement": "succeeded", "transaction": "committed"}
    assert result["audit_outcome"] == {"statement": "failed", "transaction": "rolled_back"}


def test_application_request_cannot_be_swapped():
    obj = document()
    obj["application"]["call"]["request_id"] = "unrelated"
    assert assess(obj)["application_audit_differences"] == ["request_id"]


def test_later_state_from_another_target_is_not_comparable():
    obj = json.loads((ROOT / "fixtures/matching-commit-later-change.json").read_text())
    obj["later_state"]["target"]["instance"] = "other"
    result = assess(obj)
    assert result["result"] == "recorded_commit_matches"
    assert result["later_state"] == "target_not_comparable"


def test_unchanged_supplied_state():
    obj = json.loads((ROOT / "fixtures/matching-commit-later-change.json").read_text())
    obj["later_state"]["later_b64"] = obj["later_state"]["at_commit_b64"]
    assert assess(obj)["later_state"] == "supplied_state_unchanged"


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_event",
        "position_boolean",
        "position_gap",
        "constant_nan",
        "noncanonical_base64",
        "invalid_base64",
        "sql_invalid_utf8",
        "sql_empty",
        "parameters_missing",
        "records_not_list",
        "unexpected_field",
        "wrong_profile",
        "native_origin",
        "granted_integer",
        "principal_empty",
        "principal_surrogate",
        "bad_statement",
        "bad_transaction",
        "bad_target",
        "not_an_object",
        "parameter_not_bytes",
    ],
)
def test_malformed_records_refuse(mutation):
    obj = document()
    call = obj["approval"]["call"]
    if mutation == "duplicate_event":
        obj["audit"]["records"].append(copy.deepcopy(obj["audit"]["records"][0]))
    elif mutation == "position_boolean":
        call["parameters"][0]["position"] = True
    elif mutation == "position_gap":
        call["parameters"][0]["position"] = 2
    elif mutation == "constant_nan":
        call["parameters"][0]["position"] = float("nan")
    elif mutation == "noncanonical_base64":
        call["parameters"][0]["value_b64"] = "Yh=="
    elif mutation == "invalid_base64":
        call["parameters"][0]["value_b64"] = "not base64"
    elif mutation == "sql_invalid_utf8":
        call["sql_utf8_b64"] = "/w=="
    elif mutation == "sql_empty":
        call["sql_utf8_b64"] = ""
    elif mutation == "parameters_missing":
        call["parameters"] = None
    elif mutation == "records_not_list":
        obj["audit"]["records"] = None
    elif mutation == "unexpected_field":
        call["sql"] = "alias"
    elif mutation == "wrong_profile":
        obj["profile"] = "other"
    elif mutation == "native_origin":
        obj["origin"] = "database-native"
    elif mutation == "granted_integer":
        obj["approval"]["granted"] = 1
    elif mutation == "principal_empty":
        call["executing_principal"] = ""
    elif mutation == "principal_surrogate":
        call["executing_principal"] = "\ud800"
    elif mutation == "bad_statement":
        obj["application"]["outcome"]["statement"] = "SUCCESS"
    elif mutation == "bad_transaction":
        obj["application"]["outcome"]["transaction"] = "done"
    elif mutation == "bad_target":
        call["target"] = None
    elif mutation == "not_an_object":
        obj = []
    elif mutation == "parameter_not_bytes":
        call["parameters"][0]["value_b64"] = 7
    with pytest.raises(InvalidInput):
        assess(obj)


@pytest.mark.parametrize("payload", [b'{"x": 1, "x": 2}', b'{"x": NaN}', b"{", b"\xff"])
def test_strict_json_reader(payload, tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(InvalidInput):
        read(path)


def test_deep_document_has_no_illustration_shape(tmp_path):
    path = tmp_path / "deep.json"
    path.write_bytes(b"[" * 2000 + b"0" + b"]" * 2000)
    with pytest.raises(InvalidInput):
        assess(read(path))


def test_invalid_cli_has_no_success_output(tmp_path, capsys):
    assert main([str(tmp_path / "missing.json")]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["result"] == "invalid_input"
