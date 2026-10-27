#!/usr/bin/env python3
"""Exercise producer aggregation without constructing a calendar expiry.

Run: python3 scripts/auditrecord-aggregation-test.py
These are helper regressions, not new corpus vectors or a full -01 assessment.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "packaging"))

from agent_evidence_vectors import auditrecord  # noqa: E402


def value(last_result: str, max_age: int) -> dict[str, Any]:
    return {"lastResult": last_result, "maxAge": max_age}


class AggregationTests(unittest.TestCase):
    def assert_pair(self, values: list[dict[str, Any]], expected: dict[str, Any]) -> None:
        before = [dict(item) for item in values]
        for item in values:
            entry = {"input": "standing-source", **item}
            auditrecord._entry_shape(entry)
            auditrecord.canonical_bytes(entry)
            if item["lastResult"] != auditrecord.NEVER_HELD:
                auditrecord._instant(item["lastResult"])
        self.assertEqual(auditrecord.aggregate_values(values), expected)
        self.assertEqual(values, before, "aggregation must not rewrite the source values")

    def test_individually_fresh_values_keep_the_earliest_pair(self) -> None:
        first = value("2026-10-20T11:59:30Z", 60)
        second = value("2026-10-20T11:00:00Z", 7200)
        self.assert_pair([second, first], first)

    def test_safe_integer_limit_does_not_overflow(self) -> None:
        first = value("2026-10-20T11:59:30Z", 60)
        second = value("2026-10-20T11:00:00Z", (1 << 53) - 1)
        self.assert_pair([first, second], first)

    def test_adjacent_large_bounds_remain_distinct(self) -> None:
        later = value("2026-10-20T11:00:00Z", (1 << 53) - 1)
        earlier = value("2026-10-20T11:00:00Z", (1 << 53) - 2)
        self.assert_pair([later, earlier], earlier)

    def test_expiry_past_the_calendar_limit(self) -> None:
        later = value("9999-12-31T23:59:59Z", 1)
        earlier = value("9999-12-31T23:59:58Z", 1)
        self.assert_pair([later, earlier], earlier)

    def test_offset_before_the_minimum_utc_date(self) -> None:
        earlier = value("0001-01-01T00:00:00+01:00", 3600)
        later = value("0001-01-01T00:00:00Z", 1)
        self.assert_pair([later, earlier], earlier)

    def test_offset_after_the_maximum_utc_date(self) -> None:
        later = value("9999-12-31T23:59:59-01:00", 0)
        earlier = value("9999-12-31T23:59:59Z", 1)
        self.assert_pair([later, earlier], earlier)

    def test_fractional_seconds_do_not_use_float_epoch_arithmetic(self) -> None:
        later = value("9000-01-01T00:00:00.000002Z", 60)
        earlier = value("9000-01-01T00:00:00.000001Z", 60)
        self.assert_pair([later, earlier], earlier)

    def test_fraction_before_the_epoch(self) -> None:
        earlier = value("1969-12-31T23:59:59.999999Z", 0)
        later = value("1970-01-01T00:00:00Z", 0)
        self.assert_pair([later, earlier], earlier)

    def test_equal_expiry_uses_the_earlier_source_instant(self) -> None:
        later = value("2026-10-20T12:00:00Z", 60)
        earlier = value("2026-10-20T11:59:30Z", 90)
        self.assert_pair([later, earlier], earlier)

    def test_equal_expiry_compares_instants_across_offsets(self) -> None:
        later = value("2026-10-20T13:00:00+01:00", 30)
        earlier = value("2026-10-20T11:59:30Z", 60)
        self.assert_pair([later, earlier], earlier)

    def test_never_held_uses_only_never_held_bounds(self) -> None:
        held = value("2026-10-20T11:00:00Z", 0)
        never_later = value("none", 7200)
        never_earlier = value("none", 60)
        self.assert_pair([held, never_later, never_earlier], never_earlier)

    def test_empty_values_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            auditrecord.aggregate_values([])


if __name__ == "__main__":
    unittest.main(verbosity=2)
