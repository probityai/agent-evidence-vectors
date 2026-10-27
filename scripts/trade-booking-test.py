"""Challenge the trade-booking reader: every expected answer, refusal and rule kill."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.occurrence_binding import reader as signing  # noqa: E402
from agent_evidence_vectors.trade_booking import reader  # noqa: E402
from agent_evidence_vectors.trade_booking.reader import (  # noqa: E402
    AXES,
    KINDS,
    MalformedInput,
    evaluate,
    summary,
)
from agent_evidence_vectors.trade_booking.run import main as run_main  # noqa: E402
from agent_evidence_vectors.trade_booking.run import run_corpus  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/trade_booking/corpus"
OCCURRENCE = json.loads((CORPUS / "occurrence.json").read_text())
TRUST = json.loads((CORPUS / "trust.json").read_text())
CASES = json.loads((CORPUS / "cases.json").read_text())["cases"]
BY_ID = {case["id"]: case for case in CASES}
E, C, N = "ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"


def _load_builder() -> Any:
    path = Path(__file__).with_name("trade-booking-build.py")
    spec = importlib.util.spec_from_file_location("trade_booking_build", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = _load_builder()


def _judge(statements: list[dict[str, Any]]) -> dict[str, str]:
    return summary(evaluate(OCCURRENCE, TRUST, {"statements": statements}))


def _by_id(case_id: str) -> dict[str, str]:
    return summary(evaluate(OCCURRENCE, TRUST, BY_ID[case_id]))


def _outsider(statement: dict[str, Any]) -> dict[str, Any]:
    """Signed by a valid key that the trust inputs do not list at all."""
    seed = B.seed("outsider")
    keyid = "sha256:" + B.hashlib.sha256(B.ed25519_public_key(seed)).hexdigest()
    signature = B.ed25519_sign(seed, B.canonical(statement)).hex()
    return {"statement": statement, "keyid": keyid, "signature_hex": signature}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert summary(evaluate(OCCURRENCE, TRUST, case)) == case["expected"]


def test_case_ids_are_unique_and_every_variant_is_present() -> None:
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids)) == 21
    assert {case["variant"] for case in CASES} == {
        B.CONTROL,
        B.V1,
        B.V2,
        B.V3,
        B.BREAK,
        B.TRUST_CONTROL,
    }


def test_each_axis_has_every_answer_in_the_corpus() -> None:
    for axis in AXES:
        assert {E, C, N} <= {case["expected"][axis] for case in CASES}, axis


def _closing_absence() -> dict[str, Any]:
    return B.record("absent", "reconciliation_close", minute=9)


def test_reader_never_reads_the_expected_answer() -> None:
    case = copy.deepcopy(BY_ID["control_normal_success"])
    del case["expected"]
    assert summary(evaluate(OCCURRENCE, TRUST, case)) == BY_ID["control_normal_success"]["expected"]


def test_every_statement_names_the_frozen_booking_and_the_limit_is_fixed() -> None:
    allowed = {B.GONE, B.LIVE, B.TWO_LIVE, B.DROPPED_TWICE}
    for case in CASES:
        for envelope in case["statements"]:
            body = envelope["statement"]
            if "binding" in body and case["id"] != "booking_record_names_other_reference":
                assert body["binding"] == B.BIND, case["id"]
            if body["schema"] == reader.USAGE:
                assert body["limit"] == B.LIMIT and body["used"] in allowed, case["id"]
                assert body["client"] == OCCURRENCE["booking"]["client"], case["id"]


def test_binding_covers_reference_system_client_and_quote_but_not_pair_or_notional() -> None:
    base = reader.booking_binding(OCCURRENCE)
    for name in ("booking_ref", "booking_system", "client", "quote_id"):
        moved = copy.deepcopy(OCCURRENCE)
        moved["booking"][name] = "other"
        assert reader.booking_binding(moved) != base, name
    for name, value in (("pair", "GBP/USD"), ("notional", 5)):
        moved = copy.deepcopy(OCCURRENCE)
        moved["booking"][name] = value
        assert reader.booking_binding(moved) == base, name


def test_a_ledger_alone_never_establishes_the_booking() -> None:
    ledger = B.ledger(timed_out=False, released=True, copy_used=B.LIVE)
    got = _judge([B.ag(ledger)])
    assert got["booking_committed"] == N and got["one_live_booking_per_quote"] == N
    assert got["release_backed"] == C and got["resolved"] == N


class TestClosingAbsence:
    """A reconciliation_close absent record settles a lost reply; a search miss does not."""

    def test_a_search_by_reference_miss_settles_nothing(self) -> None:
        released = B.ledger(timed_out=True, released=True, copy_used=B.GONE)
        got = _judge([B.bs(B.record("absent")), B.ag(released)])
        assert got["release_backed"] == C and got["resolved"] == N

    @pytest.mark.parametrize(
        "statements",
        [
            [B.bs(B.ack())],
            [B.bs(B.record("booked", minute=1))],
            [B.ag(B.ledger(timed_out=False, released=False, copy_used=B.LIVE))],
        ],
        ids=["ack", "booked-record", "ledger-without-timeout"],
    )
    def test_contradicts_anything_that_says_booked(self, statements: list[dict[str, Any]]) -> None:
        got = _judge([B.bs(_closing_absence()), *statements])
        assert got["resolved"] == C
        if statements[0]["statement"]["schema"] != reader.LEDGER:
            assert got["booking_committed"] == C


def test_lost_reply_stays_unresolved_after_a_booked_record_with_no_compensation() -> None:
    got = _by_id("v1_resend_same_reference_rejected")
    assert got["resolved"] == N and got["booking_committed"] == E


@pytest.mark.parametrize("schema", sorted(KINDS))
def test_a_broken_signature_contradicts_the_axis_the_kind_feeds(schema: str) -> None:
    samples = {
        B.ACK: B.ack(),
        B.RECORD: B.record("booked"),
        B.REPLY: B.reply("confirmed", "EV-1"),
        B.DUPLICATE: B.duplicate(),
        B.USAGE: B.usage(B.LIVE),
        B.OTHERS: B.others(("R2", "cancelled")),
        B.LP_RESULT: B.lp("filled"),
        B.LEDGER: B.ledger(timed_out=True, released=False, copy_used=B.LIVE),
    }
    role = KINDS[schema].role
    broken = B._broken(B._sign(samples[schema], role))
    assert _judge([broken])[KINDS[schema].axis] == C


def test_an_unknown_key_does_not_count() -> None:
    got = _judge([_outsider(B.record("booked"))])
    assert got["booking_committed"] == N and got["one_live_booking_per_quote"] == N


def test_a_trusted_key_for_another_role_does_not_count() -> None:
    ledger = B.ledger(timed_out=True, released=False, copy_used=B.LIVE)
    statements = [B.bs(B.usage(B.LIVE)), B.bs(ledger)]
    assert _judge(statements)["limit_copy_matches"] == N
    assert _judge([B.bs(B.usage(B.LIVE)), B.ag(ledger)])["limit_copy_matches"] == E


def test_a_broken_signature_on_a_statement_for_another_booking_is_set_aside() -> None:
    other = B._broken(B.bs(B.record("booked", binding=B.OTHER_BIND)))
    assert _judge([other])["booking_committed"] == N


def test_standings_name_why_each_statement_counted_or_not() -> None:
    case = BY_ID["cancel_reply_signature_broken"]
    standings = {
        s["schema"]: s["standing"] for s in evaluate(OCCURRENCE, TRUST, case)["statements"]
    }
    assert standings[reader.REPLY] == reader.BROKEN
    other = evaluate(OCCURRENCE, TRUST, BY_ID["booking_record_names_other_reference"])
    assert other["statements"][0]["standing"] == reader.OTHER_BOOKING
    agent = evaluate(OCCURRENCE, TRUST, BY_ID["booking_record_signed_by_agent"])
    assert agent["statements"][0]["standing"] == reader.NOT_COUNTED
    assert agent["statements"][0]["reason"]


def test_events_are_counted_once_whoever_reports_them() -> None:
    got = evaluate(OCCURRENCE, TRUST, BY_ID["v3_agent_cancel_rejected_already_cancelled"])
    assert got["single_compensation"]["event_ids"] == ["EV-1"]
    two = evaluate(
        OCCURRENCE, TRUST, BY_ID["v3_ops_reversed_then_agent_cancel_accepted_two_events"]
    )
    assert two["single_compensation"]["event_ids"] == ["EV-1", "EV-2"]


def test_a_cancel_error_carries_no_event() -> None:
    got = evaluate(OCCURRENCE, TRUST, BY_ID["v2_lp_reject_cancel_error_held_for_operations"])
    assert got["single_compensation"]["result"] == N
    assert got["cancel_confirmed"]["result"] == N


def test_the_latest_record_decides_whether_a_cancel_claim_is_backed() -> None:
    booked_after = [
        B.bs(B.record("cancelled", events=(("EV-1", "agent_system"),), minute=2)),
        B.bs(B.record("booked", minute=4)),
        B.ag(B.ledger(timed_out=True, released=True, copy_used=B.GONE, claims=True)),
    ]
    assert _judge(booked_after)["cancel_confirmed"] == C


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda s: s.update(schema="other"), "unknown statement schema"),
        (lambda s: s.pop("binding"), r"missing \[.binding.\]"),
        (lambda s: s.update(extra=1), r"unexpected \[.extra.\]"),
        (lambda s: s.update(status="open"), "field status is not valid"),
        (lambda s: s.update(observed_at="yesterday"), "field observed_at is not valid"),
        (
            lambda s: s.update(cancel_events=[{"event_id": "EV-1"}]),
            "field cancel_events is not valid",
        ),
    ],
    ids=["schema", "missing", "extra", "status", "time", "event"],
)
def test_a_malformed_statement_is_refused(mutate: Any, message: str) -> None:
    statement = B.record("booked")
    mutate(statement)
    with pytest.raises(MalformedInput, match=message):
        _judge([B.bs(statement)])


def test_envelope_and_case_shape_are_refused() -> None:
    with pytest.raises(MalformedInput):
        _judge([{"keyid": "x"}])
    with pytest.raises(MalformedInput):
        evaluate(OCCURRENCE, TRUST, {"statements": "none"})


def test_two_counted_ledgers_are_refused() -> None:
    ledger = B.ledger(timed_out=True, released=False, copy_used=B.LIVE)
    with pytest.raises(MalformedInput):
        _judge([B.ag(ledger), B.ag(dict(ledger, limit_copy_used=1))])


def test_wrong_trust_and_occurrence_schemas_are_refused() -> None:
    with pytest.raises(MalformedInput):
        evaluate(OCCURRENCE, dict(TRUST, schema="other"), BY_ID["control_normal_success"])
    with pytest.raises(MalformedInput):
        reader.booking_binding(dict(OCCURRENCE, schema="other"))
    with pytest.raises(MalformedInput):
        reader.booking_binding(dict(OCCURRENCE, booking={"client": "CLIENT-A"}))


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("trade-booking-build.py")
    assert subprocess.run([sys.executable, str(script), "--check"], check=False).returncode == 0


class TestKills:
    """Disable one rule at a time; a named case must turn."""

    def test_signature_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(signing, "ed25519_verify", lambda pub, msg, sig: True)
        assert _by_id("cancel_reply_signature_broken")["cancel_confirmed"] == E

    def test_role_check(self) -> None:
        trust = copy.deepcopy(TRUST)
        trust["roles"] = {role: list(trust["keys"]) for role in trust["roles"]}
        got = summary(evaluate(OCCURRENCE, trust, BY_ID["booking_record_signed_by_agent"]))
        assert got["booking_committed"] == E

    def test_binding_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "_names_booking", lambda schema, body, binding, client: True)
        assert _by_id("booking_record_names_other_reference")["booking_committed"] == E

    def test_cancel_claim_needs_the_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader.Facts, "claim_unbacked", property(lambda self: False))
        got = _by_id("v1_cancel_claimed_by_agent_only")
        assert got["cancel_confirmed"] == N and got["resolved"] == N

    def test_resolved_needs_the_provider_to_have_filled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def ignores_provider(self: reader.Facts) -> bool:
            current = self.current
            return bool(
                self.ledger is not None
                and current is not None
                and not self.ledger["timed_out"]
                and current["status"] == "booked"
            )

        monkeypatch.setattr(reader.Facts, "intended_end_state", property(ignores_provider))
        got = _by_id("v2_lp_reject_cancel_error_held_for_operations")
        assert got["resolved"] == E

    def test_events_are_deduplicated_across_record_and_reply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def per_source(self: reader.Facts) -> frozenset[str]:
            ids = {"record:" + e["event_id"] for r in self.records for e in r["cancel_events"]}
            ids |= {"reply:" + r["event_id"] for r in self.replies if "event_id" in r}
            return frozenset(ids)

        monkeypatch.setattr(reader.Facts, "event_ids", property(per_source))
        got = _by_id("v3_agent_cancel_rejected_already_cancelled")
        assert got["single_compensation"] == C

    def test_release_needs_a_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.judge_release

        def always_backed(facts: Any, committed: Any, cancel: Any, single: Any) -> Any:
            got = real(facts, committed, cancel, single)
            return reader._result(E, "lax") if got["result"] == C else got

        monkeypatch.setattr(reader, "judge_release", always_backed)
        assert _by_id("v1_lost_ack_released_on_timeout_no_evidence")["release_backed"] == E

    def test_second_live_booking_is_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            reader, "judge_one_live", lambda facts, quote_id, ref: reader._result(E, "lax")
        )
        got = _by_id("v1_resend_new_reference_duplicate_booking")
        assert got["one_live_booking_per_quote"] == E

    def test_limit_copy_is_compared(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "judge_limit", lambda facts: reader._result(E, "lax", used=0))
        assert _by_id("v1_unresolved_deal_dropped_from_limit_copy")["limit_copy_matches"] == E

    def test_closing_absence_settles_a_never_booked_deal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(reader.Facts, "recon_absent", property(lambda self: False))
        got = _by_id("v1_search_absent_reconciliation_closes_never_booked")
        assert got["release_backed"] == C and got["resolved"] == N

    def test_a_ledger_without_a_timeout_says_the_deal_is_booked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(reader.Facts, "says_booked", property(lambda self: self.committed))
        got = _by_id("break_agent_booked_booking_system_absent")
        assert got["booking_committed"] == N and got["resolved"] == E

    def test_an_absent_record_is_not_a_booking(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def counts_absent(self: reader.Facts) -> bool:
            return bool(self.acks or self.records)

        monkeypatch.setattr(reader.Facts, "committed", property(counts_absent))
        got = _by_id("v1_search_absent_reconciliation_closes_never_booked")
        assert got["booking_committed"] == C


def test_tampered_corpus_is_refused(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    path = copy_root / "cases.json"
    path.write_text(path.read_text().replace("ESTABLISHED", "CONTRADICTED", 1))
    with pytest.raises(MalformedInput):
        run_corpus(copy_root)


def test_cases_built_for_another_booking_are_refused(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    occurrence = json.loads((copy_root / "occurrence.json").read_text())
    occurrence["booking"]["booking_ref"] = "R2"
    text = json.dumps(occurrence, indent=2, ensure_ascii=False) + "\n"
    (copy_root / "occurrence.json").write_text(text)
    manifest = json.loads((copy_root / "manifest.json").read_text())
    manifest["members"]["occurrence.json"] = reader.sha256_tag(text.encode())
    (copy_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(MalformedInput, match="not built for this booking"):
        run_corpus(copy_root)


def test_cli_writes_a_report_and_refuses_reuse(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert run_main(["--output", str(out), "--implementation-revision", "a" * 40]) == 0
    report = json.loads((out / "report.json").read_text())
    assert report["failures"] == [] and len(report["results"]) == len(CASES)
    assert report["axes"] == list(AXES)
    with pytest.raises(FileExistsError):
        run_main(["--output", str(out), "--implementation-revision", "a" * 40])
    with pytest.raises(SystemExit):
        run_main(["--output", str(tmp_path / "bad"), "--implementation-revision", "HEAD"])


def test_cli_reports_a_wrong_expectation(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    cases = json.loads((copy_root / "cases.json").read_text())
    cases["cases"][0]["expected"]["resolved"] = "CONTRADICTED"
    text = json.dumps(cases, indent=2, ensure_ascii=False) + "\n"
    (copy_root / "cases.json").write_text(text)
    manifest = json.loads((copy_root / "manifest.json").read_text())
    manifest["members"]["cases.json"] = reader.sha256_tag(text.encode())
    (copy_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    out = tmp_path / "run"
    code = run_main(
        ["--corpus", str(copy_root), "--output", str(out), "--implementation-revision", "b" * 40]
    )
    assert code == 1
    assert json.loads((out / "report.json").read_text())["failures"] == [CASES[0]["id"]]
