"""Protect literal source custody during subsequent registry appends."""

import json

import pytest

from tools.append_lab_record import append_record


PRIOR = (
    b'{\n  "maintainer": "Probity",\n  "protocolVersion": "0.1",\n  "records": [\n'
    b'    {\n      "id": "retained-source",\n      "limits": ["upgrade \\u2192 later"],\n'
    b'      "artifacts": [{"path": "source.json", "sha256": "original"}]\n    }\n  ]\n}\n'
)


def test_append_keeps_literal_escape_content_id_and_artifact_source():
    candidate = append_record(PRIOR, {"id": "new-reader", "result": "adverse"})
    assert candidate.startswith(PRIOR[:-len(b"\n  ]\n}\n")] + b",\n")
    assert b"\\u2192" in candidate and "→".encode() not in candidate
    assert json.loads(candidate)["records"] == [
        {"id": "retained-source", "limits": ["upgrade → later"],
         "artifacts": [{"path": "source.json", "sha256": "original"}]},
        {"id": "new-reader", "result": "adverse"},
    ]


def test_subsequent_append_preserves_both_retained_records():
    first = append_record(PRIOR, {"id": "first-reader", "result": "indeterminate"})
    second = append_record(first, {"id": "second-reader", "result": "adverse"})
    assert second.startswith(first[:-len(b"\n  ]\n}\n")] + b",\n")
    assert [row["id"] for row in json.loads(second)["records"]] == [
        "retained-source", "first-reader", "second-reader"
    ]


def test_empty_population_can_receive_its_first_record():
    empty = b'{\n  "maintainer": "Probity",\n  "records": [\n  ]\n}\n'
    assert json.loads(append_record(empty, {"id": "first"}))["records"] == [{"id": "first"}]


@pytest.mark.parametrize("record", [
    {"id": "retained-source"}, {"id": ""}, {"id": True}, {}, [],
    {"id": "new", "number": float("nan")}, {"id": "new", "number": float("inf")},
])
def test_duplicate_or_invalid_new_record_refused(record):
    with pytest.raises(ValueError):
        append_record(PRIOR, record)


@pytest.mark.parametrize("original", [
    PRIOR.replace(b'"retained-source"', b'"retained-source", "id": "replacement"'),
    PRIOR.replace(b'"records": [', b'"records": [], "records": ['),
    PRIOR.replace(b'"original"', b'NaN'),
    PRIOR.replace(b'"retained-source"', b'null'),
    PRIOR.replace(b'"records": [', b'"records": {'),
    PRIOR.rstrip(b"\n"),
])
def test_ambiguous_malformed_or_changed_closing_input_refused(original):
    with pytest.raises(ValueError):
        append_record(original, {"id": "new-reader"})
