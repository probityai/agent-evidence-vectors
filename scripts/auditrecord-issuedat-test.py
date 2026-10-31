#!/usr/bin/env python3
"""Pin the issuedAt rule: a record's issuedAt parses and is not before sealedAt.

Run: python3 scripts/auditrecord-issuedat-test.py
Rows IS1 and IS2 of draft-gilda-audit-agent-audit-record-03 cover a record
issued one second and one day before its interval sealed. This test adds the
unparsable and mistyped forms, which the draft rules out in the same sentence
but gives no row of their own, and the boundary where the two times are equal.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packaging"))

from agent_evidence_vectors import auditrecord  # noqa: E402

SEALED = "2026-09-19T11:04:06Z"


def refusal(issued: Any, sealed: Any = SEALED) -> str:
    pred = {"issuedAt": issued, "effect": {"interval": {"sealedAt": sealed}}}
    state = auditrecord._State({}, pred, None)  # type: ignore[arg-type]
    try:
        auditrecord._rule_issued_after_sealed(state)
    except auditrecord.Malformed as exc:
        return exc.code
    return ""


class IssuedAtTests(unittest.TestCase):
    def test_issued_at_or_after_sealed_passes(self) -> None:
        for issued in (SEALED, "2026-09-19T11:04:11Z", "2026-09-19T13:04:06+02:00"):
            self.assertEqual(refusal(issued), "", issued)

    def test_issued_before_sealed_refuses_however_far(self) -> None:
        for issued in (
            "2026-09-19T11:04:05Z",
            "2026-09-18T11:04:06Z",
            "2026-09-19T12:04:05+02:00",
        ):
            self.assertEqual(refusal(issued), "issued-before-sealed", issued)

    def test_unparsable_issued_at_refuses(self) -> None:
        for issued in ("yesterday", "2026-09-19", "2026-09-19T11:04:11", "", 20260919, None):
            self.assertEqual(refusal(issued), "timestamp-malformed", repr(issued))

    def test_unparsable_sealed_at_leaves_the_times_uncomparable(self) -> None:
        self.assertEqual(refusal("2026-09-19T11:04:11Z", "later"), "timestamp-malformed")


if __name__ == "__main__":
    unittest.main()
