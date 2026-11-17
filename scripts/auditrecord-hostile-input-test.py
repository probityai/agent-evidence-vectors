#!/usr/bin/env python3
"""Hostile inputs the audit record reader must judge, never crash on.

Run: python3 scripts/auditrecord-hostile-input-test.py
Every case here was a crash or a wrong verdict in the reader before it was fixed:

- a time value that is not an RFC 3339 date-time (a week date, the basic format, a comma
  fraction, an offset without its colon) was read as valid, and the RFC 3339 lowercase
  t and z were refused (draft-gilda-audit-agent-audit-record, "Every time value in a
  record MUST be an RFC3339 date-time");
- a lone surrogate escape in a string or a member name raised UnicodeEncodeError out of
  verify(), with no key needed, because no UTF-8 text can carry it;
- nesting deep enough to exhaust the interpreter's stack but not the parser's raised
  RecursionError instead of nesting-too-deep (vector T4's code);
- an integer written with more than 4300 digits was not-parseable, not unsafe-integer;
- in a retained record, an anchorWithin no timedelta can hold, an issuedAt in year 1 and
  an envelope nested past the stack raised OverflowError or RecursionError out of the
  dating check, which runs whatever the envelope's own verdict.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpora" / "vectors-agent-audit-record"
sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402,F401  (the reader resolves the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord  # noqa: E402

UTC = datetime.UTC
MANIFEST: dict[str, Any] = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
MEMBERS = {entry["draftId"]: entry for entry in MANIFEST["vectors"]}
POLICY = auditrecord.policy_for(MANIFEST)
HEADS = auditrecord.tree_heads(MANIFEST)


def member(draft_id: str) -> bytes:
    return (CORPUS / str(MEMBERS[draft_id]["file"])).read_bytes()


def code(call: Any, *args: Any) -> str:
    """The refusal ``call`` raises, or the empty string when it returns."""
    try:
        call(*args)
    except auditrecord.Malformed as exc:
        return exc.code
    return ""


def envelope_of(payload: bytes) -> dict[str, Any]:
    """An envelope whose signature is not the observer's: dating runs regardless."""
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": auditrecord.PAYLOAD_TYPE,
        "signatures": [{"keyid": "unknown", "sig": base64.b64encode(bytes(64)).decode()}],
    }


class TimestampTests(unittest.TestCase):
    def test_rfc3339_forms_read(self) -> None:
        cases = {
            "2026-09-19T11:04:11Z": datetime.datetime(2026, 9, 19, 11, 4, 11, tzinfo=UTC),
            "2026-09-19t11:04:11z": datetime.datetime(2026, 9, 19, 11, 4, 11, tzinfo=UTC),
            "2026-09-19T13:04:11+02:00": datetime.datetime(2026, 9, 19, 11, 4, 11, tzinfo=UTC),
            "2026-09-19T11:04:11-00:00": datetime.datetime(2026, 9, 19, 11, 4, 11, tzinfo=UTC),
            "2026-09-19T11:04:11.5Z": datetime.datetime(2026, 9, 19, 11, 4, 11, 500000, UTC),
            "2026-09-19T11:04:11.123456789Z": datetime.datetime(
                2026, 9, 19, 11, 4, 11, 123456, UTC
            ),
            "2016-12-31T23:59:60Z": datetime.datetime(2017, 1, 1, tzinfo=UTC),
            "2016-12-31T18:59:60-05:00": datetime.datetime(2017, 1, 1, tzinfo=UTC),
            "0001-01-01T00:00:00Z": datetime.datetime(1, 1, 1, tzinfo=UTC),
        }
        for text, want in cases.items():
            self.assertEqual(auditrecord._instant(text), want, text)

    def test_other_iso8601_forms_are_malformed(self) -> None:
        for text in (
            "2026-09-19 11:04:11Z",
            "2026-W38-6T11:04:11Z",
            "2026-262T11:04:11Z",
            "20260919T110411Z",
            "2026-09-19T110411Z",
            "2026-09-19T11:04Z",
            "2026-09-19T11Z",
            "2026-09-19T11:04:11,5Z",
            "2026-09-19T11:04:11+0000",
            "2026-09-19T11:04:11.5+00",
            "2026-09-19T11:04:11+00:00:30",
            "2026-09-19T11:04:11+24:00",
            "2026-09-19T11:04:11+05:60",
            "2026-09-19T11:04:11.Z",
            "2026-09-19T11:04:11",
            "+002026-09-19T11:04:11Z",
            "2026-09-19T11:04:1١Z",
            "2026-02-30T11:04:11Z",
            "2026-09-19T24:00:00Z",
            "2026-09-19T23:59:60Z",
            "2016-12-31T23:58:60Z",
            " 2026-09-19T11:04:11Z",
            "2026-09-19T11:04:11Z\n",
        ):
            self.assertEqual(code(auditrecord._instant, text), "timestamp-malformed", repr(text))

    def test_a_week_date_issued_at_is_malformed_in_a_record(self) -> None:
        pred = {
            "issuedAt": "2026-W38-6T11:04:11Z",
            "effect": {"interval": {"sealedAt": "2026-09-19T11:04:06Z"}},
        }
        state = auditrecord._State({}, pred, POLICY)
        self.assertEqual(code(auditrecord._rule_issued_after_sealed, state), "timestamp-malformed")


class ProfileTests(unittest.TestCase):
    def test_a_lone_surrogate_is_not_parseable_before_any_signature(self) -> None:
        for text in ('{"a":"\\ud800"}', '{"\\udc00":1}', '["x\\udbff"]', '{"a":["\\udfff z"]}'):
            self.assertEqual(code(auditrecord.parse_statement, text.encode()), "not-parseable")
            report = auditrecord.verify(json.dumps(envelope_of(text.encode())).encode(), POLICY)
            self.assertEqual((report.verdict, report.codes), ("malformed", ["not-parseable"]))

    def test_a_surrogate_pair_is_one_scalar_and_reads(self) -> None:
        self.assertEqual(
            auditrecord.parse_statement(b'{"a":"\\ud83d\\ude00"}'), {"a": "\U0001f600"}
        )

    def test_canonical_bytes_refuses_what_rfc8785_cannot_write(self) -> None:
        for node in ({"a": "\ud800"}, {"\udc00": 1}, ["\udbff"]):
            self.assertEqual(code(auditrecord.canonical_bytes, node), "value-not-representable")

    def test_every_depth_past_the_bound_is_nesting_too_deep(self) -> None:
        for depth in (129, 1000, 5000, 50000, 500000):
            text = '{"a":' * depth + "1" + "}" * depth
            self.assertEqual(
                code(auditrecord.parse_statement, text.encode()), "nesting-too-deep", depth
            )
        self.assertEqual(code(auditrecord.parse_statement, b"[" * 128 + b"]" * 128), "")

    def test_an_integer_past_int_reading_is_unsafe(self) -> None:
        for digits in ("9" * 17, "1" + "0" * 4300, "-" + "9" * 5000):
            payload = ('{"n":' + digits + "}").encode()
            self.assertEqual(
                code(auditrecord.parse_statement, payload), "unsafe-integer", digits[:8]
            )
        self.assertEqual(auditrecord.parse_statement(b'{"n":9007199254740991}'), {"n": 2**53 - 1})
        self.assertEqual(
            code(auditrecord.parse_statement, b'{"n":9007199254740992}'), "unsafe-integer"
        )


class RetainedTests(unittest.TestCase):
    def dated(self, bundle: dict[str, Any]) -> tuple[str, list[str], str, list[str]]:
        report, dating = auditrecord.verify_retained(json.dumps(bundle).encode(), POLICY, HEADS)
        return report.verdict, report.codes, dating.entry, dating.codes

    def test_any_anchor_within_in_range_is_read_exactly(self) -> None:
        bundle = json.loads(member("R1"))
        for within in (3 * 10**11, 10**14, 2**53 - 1):
            bundle["retention"]["anchorWithin"] = within
            self.assertEqual(self.dated(bundle), ("valid", [], "well-formed", []), within)
        for within in (2**53, 2**64):
            bundle["retention"]["anchorWithin"] = within
            self.assertEqual(self.dated(bundle)[2:], ("malformed", ["entry-shape-malformed"]))

    def test_the_late_bound_is_exact_to_the_microsecond(self) -> None:
        start = datetime.datetime(2026, 9, 19, 11, 4, 11, tzinfo=UTC)
        retained = auditrecord._Retained({"anchorWithin": 300}, start, "", HEADS)
        bound = datetime.timedelta(seconds=300) + auditrecord.SKEW_TOLERANCE
        retained.retention_time = start + bound
        self.assertEqual(code(auditrecord._dating_anchor_late, retained), "")
        retained.retention_time = start + bound + datetime.timedelta(microseconds=1)
        self.assertEqual(code(auditrecord._dating_anchor_late, retained), "entry-anchor-late")

    def test_instants_at_either_end_of_the_calendar_date_without_overflow(self) -> None:
        received = json.loads(member("R2"))
        statement = json.loads(base64.b64decode(received["envelope"]["payload"]))
        for issued in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
            statement["predicate"]["issuedAt"] = issued
            envelope = envelope_of(auditrecord.canonical_bytes(statement))
            digest = hashlib.sha256(auditrecord.canonical_bytes(envelope)).hexdigest()
            for at in ("0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"):
                retention = dict(received["retention"], envelopeDigest=digest, receivedAt=at)
                verdict, codes, entry, _ = self.dated(
                    {"envelope": envelope, "retention": retention}
                )
                self.assertEqual((verdict, codes), ("malformed", ["signature-invalid"]))
                self.assertIn(entry, ("well-formed", "malformed"))

    def test_a_deep_or_unwritable_envelope_is_judged(self) -> None:
        bundle = json.loads(member("R1"))
        bundle["envelope"]["deep"] = json.loads('{"a":' * 900 + "1" + "}" * 900)
        unreadable = ("malformed", ["retained-unreadable"], "malformed", ["retained-unreadable"])
        self.assertEqual(self.dated(bundle), unreadable)
        bundle = json.loads(member("R1"))
        bundle["envelope"]["note"] = "\ud800"
        self.assertEqual(self.dated(bundle)[2:], ("malformed", ["value-not-representable"]))


if __name__ == "__main__":
    unittest.main()
