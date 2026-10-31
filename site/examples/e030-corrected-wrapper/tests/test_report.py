"""Refuse plausible bad process/report pairs without rewriting native meaning."""

import json
import os

import pytest

from e030_case.faults import emit, report_fixture
from e030_case.report import (
    MAX_REPORT_BYTES,
    assess,
    compare_report,
    operator_identity,
    read_report,
)

START = "2026-10-09T12:00:00.000Z"
END = "2026-10-09T12:00:01.000Z"


def raw_report():
    return json.dumps(report_fixture(START)).encode()


def test_native_projection_and_declared_operator_have_distinct_roles():
    assert compare_report(raw_report(), START, END) is None
    identity = operator_identity("Pico / Agent Errata")
    assert identity == {
        "identity": "Pico / Agent Errata",
        "source": "caller-declared",
        "authenticated": False,
    }
    assert "operator" not in json.loads(raw_report())


@pytest.mark.parametrize(
    "identity",
    [
        None,
        "",
        " space",
        "space ",
        "--operator",
        "a\nb",
        "a\u200db",
        "a\u2028b",
        "a\u2029b",
        "a\ud800b",
        "x" * 513,
    ],
)
def test_operator_is_never_guessed_or_normalized(identity):
    with pytest.raises(ValueError, match="operator identity"):
        operator_identity(identity)


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"profile":"x","profile":"y"}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"[]",
        b"[" * 2000 + b"0" + b"]" * 2000,
    ],
)
def test_invalid_documents_do_not_become_valid_reports(raw):
    assert compare_report(raw, START, END) in {"REPORT_MALFORMED", "REPORT_PROFILE_MISMATCH"}


@pytest.mark.parametrize(
    "fault,expected",
    [
        ("absent", "REPORT_ABSENT"),
        ("malformed", "REPORT_MALFORMED"),
        ("wrong-profile", "REPORT_PROFILE_MISMATCH"),
        ("wrong-input", "REPORT_INPUT_MISMATCH"),
        ("wrong-claim", "REPORT_CLAIMS_MISMATCH"),
        ("wrong-summary", "REPORT_SUMMARY_MISMATCH"),
        ("stale-generation", "REPORT_TIME_OUTSIDE_INTERVAL"),
        ("future-generation", "REPORT_TIME_OUTSIDE_INTERVAL"),
        ("symlink", "REPORT_UNREADABLE"),
    ],
)
def test_fault_report_is_refused_even_with_zero_process_and_recorded_exits(
    tmp_path, fault, expected
):
    destination = tmp_path / "report.json"
    emit(fault, destination)
    outcome = assess(
        process_exit=0,
        capture_complete=True,
        recorded_exit=0,
        report_before=False,
        report_path=destination,
        started=START,
        ended=END,
    )
    assert outcome["reason"] == expected
    assert not outcome["accepted_projection"]
    assert outcome["run_correlation"] == "not supplied by the native contract"


@pytest.mark.parametrize(
    "change,expected",
    [
        (lambda r: r.pop("pins"), "REPORT_INPUT_MISMATCH"),
        (lambda r: r["pins"].__setitem__("aps_owner_fixture_binding", {}), "REPORT_INPUT_MISMATCH"),
        (
            lambda r: r["pins"]["aps_owner_fixture_binding"].__setitem__("byte_identical", 1),
            "REPORT_INPUT_MISMATCH",
        ),
        (lambda r: r.__setitem__("claims", [None]), "REPORT_CLAIMS_MISMATCH"),
        (lambda r: r.__setitem__("claims", {}), "REPORT_CLAIMS_MISMATCH"),
        (lambda r: r["claims"].append(r["claims"][0]), "REPORT_CLAIMS_MISMATCH"),
        (lambda r: r.__setitem__("summary", None), "REPORT_SUMMARY_MISMATCH"),
        (lambda r: r.pop("generated_at"), "REPORT_TIME_INVALID"),
        (
            lambda r: r.__setitem__("generated_at", "2026-10-09T12:00:00+00:00"),
            "REPORT_TIME_INVALID",
        ),
        (
            lambda r: r.__setitem__("generated_at", "0000-01-01T12:00:00.000Z"),
            "REPORT_TIME_INVALID",
        ),
    ],
)
def test_native_field_types_and_claim_sets_do_not_have_compatibility_aliases(change, expected):
    report = report_fixture(START)
    change(report)
    assert compare_report(json.dumps(report).encode(), START, END) == expected


def test_inverted_observed_clock_interval_is_not_accepted():
    assert compare_report(raw_report(), END, START) == "OBSERVED_INTERVAL_INVALID"


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"process_exit": 17}, "PROCESS_NONZERO"),
        ({"process_exit": None}, "PROCESS_NOT_COMPLETE"),
        ({"process_exit": False}, "PROCESS_NOT_COMPLETE"),
        ({"capture_complete": False}, "PROCESS_NOT_COMPLETE"),
        ({"capture_complete": 1}, "PROCESS_NOT_COMPLETE"),
        ({"recorded_exit": None}, "RECORDED_EXIT_MISMATCH"),
        ({"recorded_exit": False}, "RECORDED_EXIT_MISMATCH"),
        ({"recorded_exit": 17}, "RECORDED_EXIT_MISMATCH"),
        ({"report_before": True}, "REPORT_PREEXISTED"),
        ({"report_before": None}, "REPORT_PRESENCE_NOT_OBSERVED"),
        ({"report_before": 0}, "REPORT_PRESENCE_NOT_OBSERVED"),
        ({"report_before": ""}, "REPORT_PRESENCE_NOT_OBSERVED"),
    ],
)
def test_process_failure_and_status_forgery_cannot_promote_a_good_report(
    tmp_path, overrides, reason
):
    report = tmp_path / "report.json"
    report.write_bytes(raw_report())
    arguments = dict(
        process_exit=0,
        capture_complete=True,
        recorded_exit=0,
        report_before=False,
        report_path=report,
        started=START,
        ended=END,
    )
    arguments.update(overrides)
    assert assess(**arguments)["reason"] == reason


def test_good_projection_retains_the_run_correlation_limit(tmp_path):
    report = tmp_path / "report.json"
    report.write_bytes(raw_report())
    outcome = assess(
        process_exit=0,
        capture_complete=True,
        recorded_exit=0,
        report_before=False,
        report_path=report,
        started=START,
        ended=END,
    )
    assert outcome["accepted_projection"]
    assert outcome["run_correlation"] == "not supplied by the native contract"


def test_file_boundary_has_presence_and_adverse_controls(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(raw_report())
    assert read_report(path) == (raw_report(), None)
    path.write_bytes(b"x" * (MAX_REPORT_BYTES + 1))
    assert read_report(path)[1] == "REPORT_TOO_LARGE"
    assert read_report(tmp_path / "missing")[1] == "REPORT_ABSENT"
    assert read_report(tmp_path)[1] == "REPORT_NOT_REGULAR"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert read_report(fifo)[1] == "REPORT_NOT_REGULAR"
