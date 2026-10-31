"""Reserve a host-selected maximum cost before one protected tool dispatch."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

MAX_INTEGER = (1 << 53) - 1
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CALL_FIELDS = {"call_id", "attempt", "provider", "model", "target", "args_sha256",
               "input_limit", "output_limit", "price_sha256"}
PRICE_FIELDS = {"provider", "model", "target", "unit", "valid_from", "expires_at",
                "input_rate", "output_rate", "fixed_cost"}
POLICY_FIELDS = {"schema_version", "budget_id", "unit", "limit", "valid_from",
                 "expires_at", "prices_sha256"}


class Refused(ValueError):
    """A call or state transition did not meet the receiving host's policy."""


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(value: object) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def integer(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise Refused("invalid-" + label)
    return value


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or not value.isascii():
        raise Refused("invalid-" + label)
    return value


def digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise Refused("invalid-" + label)
    return value


def fields(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise Refused("invalid-" + label)
    return value


def read_json(path: Path) -> object:
    """Keep duplicate members and non-finite numbers out of the policy input."""
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused("duplicate-json-member")
            result[key] = value
        return result
    def invalid(_value: str) -> None:
        raise Refused("nonfinite-json")
    return json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=invalid)


def selected(policy: dict, prices: list[dict]) -> None:
    fields(policy, POLICY_FIELDS, "policy")
    if policy["schema_version"] != "probity-spend-policy/v1":
        raise Refused("unsupported-policy")
    for name in ("budget_id", "unit"):
        text(policy[name], name)
    for name in ("limit", "valid_from", "expires_at"):
        integer(policy[name], name)
    if policy["expires_at"] <= policy["valid_from"]:
        raise Refused("invalid-policy-window")
    if not isinstance(prices, list) or not prices or len(prices) > 256:
        raise Refused("invalid-price-population")
    if digest(policy["prices_sha256"], "prices-sha256") != sha(prices):
        raise Refused("unselected-prices")
    routes = set()
    for price in prices:
        fields(price, PRICE_FIELDS, "price")
        for name in ("provider", "model", "target", "unit"):
            text(price[name], name)
        for name in ("valid_from", "expires_at", "input_rate", "output_rate", "fixed_cost"):
            integer(price[name], name)
        route = tuple(price[name] for name in ("provider", "model", "target"))
        if route in routes or price["unit"] != policy["unit"]:
            raise Refused("ambiguous-price-or-unit")
        if price["expires_at"] <= price["valid_from"]:
            raise Refused("invalid-price-window")
        routes.add(route)


class Budget:
    """One SQLite budget shared by host processes on the same machine.

    The host protects the database and supplies its clock, prices, tool bounds
    and settlement receipts. A dispatched call stays charged at its reserved
    maximum until a receipt arrives. Agent-provided bounds are insufficient.
    """

    def __init__(self, path: Path, policy: dict, prices: list[dict],
                 clock: Callable[[], int]) -> None:
        selected(policy, prices)
        self.policy = json.loads(encode(policy))
        self.prices = json.loads(encode(prices))
        self.clock = clock
        self.path = path
        self.connection = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1),
                policy TEXT NOT NULL, prices TEXT NOT NULL, clock INTEGER NOT NULL,
                frozen INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY,
                call TEXT NOT NULL, maximum INTEGER NOT NULL, state TEXT NOT NULL,
                actual INTEGER, UNIQUE(call));
            CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY,
                body TEXT NOT NULL);
        """)
        with self.transaction():
            row = self.connection.execute("SELECT policy,prices FROM metadata WHERE id=1").fetchone()
            expected = (encode(self.policy).decode(), encode(self.prices).decode())
            if row is None:
                self.connection.execute("INSERT INTO metadata(id,policy,prices,clock) VALUES(1,?,?,?)",
                                        (*expected, self.policy["valid_from"]))
            elif row != expected:
                raise Refused("budget-selection-changed")

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def now(self) -> int:
        now = integer(self.clock(), "host-clock")
        previous = self.connection.execute("SELECT clock FROM metadata WHERE id=1").fetchone()[0]
        if now < previous:
            raise Refused("host-clock-rollback")
        self.connection.execute("UPDATE metadata SET clock=? WHERE id=1", (now,))
        return now

    def remaining(self) -> int:
        charged = self.connection.execute("""SELECT COALESCE(SUM(CASE
            WHEN state='settled' THEN actual WHEN state='refunded' THEN 0
            ELSE maximum END),0) FROM reservations""").fetchone()[0]
        return self.policy["limit"] - charged

    def record(self, kind: str, at: int, **values: object) -> dict:
        number = self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] + 1
        event = {"sequence": number, "kind": kind, "at": at, **values}
        self.connection.execute("INSERT INTO events(sequence,body) VALUES(?,?)",
                                (number, encode(event).decode()))
        return event

    def priced(self, call: dict, at: int) -> tuple[dict, int]:
        fields(call, CALL_FIELDS, "call")
        for name in ("call_id", "provider", "model", "target"):
            text(call[name], name)
        for name in ("attempt", "input_limit", "output_limit"):
            integer(call[name], name)
        digest(call["args_sha256"], "args-sha256")
        digest(call["price_sha256"], "price-sha256")
        price = next((p for p in self.prices if all(p[k] == call[k]
                     for k in ("provider", "model", "target"))), None)
        if price is None:
            raise Refused("unknown-price")
        if sha(price) != call["price_sha256"]:
            raise Refused("price-version-mismatch")
        if not self.policy["valid_from"] <= at < self.policy["expires_at"]:
            raise Refused("budget-window-closed")
        if not price["valid_from"] <= at < price["expires_at"]:
            raise Refused("stale-price")
        maximum = (call["input_limit"] * price["input_rate"] +
                   call["output_limit"] * price["output_rate"] + price["fixed_cost"])
        integer(maximum, "maximum")
        return price, maximum

    def reserve(self, call: dict) -> str:
        failure = None
        reservation = None
        with self.transaction():
            at = self.now()
            try:
                _price, maximum = self.priced(call, at)
                if self.connection.execute("SELECT frozen FROM metadata WHERE id=1").fetchone()[0]:
                    raise Refused("budget-frozen")
                reservation = sha({"budget_id": self.policy["budget_id"],
                                   "call_id": call["call_id"], "attempt": call["attempt"]})
                existing = self.connection.execute("SELECT call FROM reservations WHERE id=?",
                                                   (reservation,)).fetchone()
                if existing is not None:
                    if existing[0] != encode(call).decode():
                        raise Refused("call-attempt-rebound")
                    return reservation
                before = self.remaining()
                if maximum > before:
                    raise Refused("insufficient-budget")
                self.connection.execute("INSERT INTO reservations(id,call,maximum,state) VALUES(?,?,?,'reserved')",
                                        (reservation, encode(call).decode(), maximum))
                self.record("reserve", at, reservation=reservation, call=call,
                            maximum=maximum, remaining_before=before,
                            remaining_after=self.remaining())
            except Refused as exc:
                failure = str(exc)
                # Valid JSON supplied by the host is retained, including refused routes.
                self.record("deny", at, call=call, reason=failure,
                            remaining_after=self.remaining())
        if failure:
            raise Refused(failure)
        return reservation

    def dispatch(self, reservation: str, call: dict) -> None:
        """Claim the exact reservation once, before invoking the bounded tool."""
        with self.transaction():
            at = self.now()
            _price, maximum = self.priced(call, at)
            row = self.connection.execute("SELECT call,maximum,state FROM reservations WHERE id=?",
                                           (reservation,)).fetchone()
            if row != (encode(call).decode(), maximum, "reserved"):
                raise Refused("dispatch-reservation-mismatch-or-used")
            if self.connection.execute("SELECT frozen FROM metadata WHERE id=1").fetchone()[0]:
                raise Refused("budget-frozen")
            self.connection.execute("UPDATE reservations SET state='dispatched' WHERE id=?", (reservation,))
            self.record("dispatch", at, reservation=reservation, call=call,
                        maximum=maximum, remaining_after=self.remaining())

    def settle(self, reservation: str, actual: int) -> None:
        """Apply a host receipt; a bound violation records the liability and freezes admission."""
        integer(actual, "actual")
        exceeded = False
        with self.transaction():
            at = self.now()
            row = self.connection.execute("SELECT maximum,state FROM reservations WHERE id=?",
                                           (reservation,)).fetchone()
            if row is None or row[1] != "dispatched":
                raise Refused("settlement-without-dispatch")
            exceeded = actual > row[0]
            self.connection.execute("UPDATE reservations SET state='settled',actual=? WHERE id=?",
                                    (actual, reservation))
            if exceeded:
                self.connection.execute("UPDATE metadata SET frozen=1 WHERE id=1")
            self.record("settle", at, reservation=reservation, actual=actual,
                        bound_exceeded=exceeded, remaining_after=self.remaining())
            if not exceeded:
                self.record("refund", at, reservation=reservation, amount=row[0] - actual,
                            reason="unused-reservation", remaining_after=self.remaining())
        if exceeded:
            raise Refused("tool-cost-bound-exceeded")

    def cancel(self, reservation: str) -> None:
        """Release only a reservation that has never been dispatched."""
        with self.transaction():
            at = self.now()
            row = self.connection.execute("SELECT maximum,state FROM reservations WHERE id=?",
                                           (reservation,)).fetchone()
            if row is None or row[1] != "reserved":
                raise Refused("refund-after-dispatch-or-used")
            self.connection.execute("UPDATE reservations SET state='refunded' WHERE id=?", (reservation,))
            self.record("refund", at, reservation=reservation, amount=row[0],
                        reason="cancel-before-dispatch", remaining_after=self.remaining())

    def trace(self) -> dict:
        with self.transaction():
            events = [json.loads(row[0]) for row in self.connection.execute(
                "SELECT body FROM events ORDER BY sequence")]
            return {"schema_version": "probity-spend-trace/v1",
                    "budget_id": self.policy["budget_id"], "policy_sha256": sha(self.policy),
                    "events": events}


def main() -> None:
    """Operate one host-owned ledger with a host-owned policy and clock."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("reserve", "dispatch", "settle", "cancel", "trace"))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--prices", type=Path, required=True)
    parser.add_argument("--call", type=Path)
    parser.add_argument("--reservation")
    parser.add_argument("--actual", type=int)
    args = parser.parse_args()
    budget = Budget(args.database, read_json(args.policy), read_json(args.prices),
                    lambda: int(time.time()))
    try:
        if args.operation in ("reserve", "dispatch") and args.call is None:
            parser.error("this operation requires --call")
        if args.operation in ("dispatch", "settle", "cancel") and args.reservation is None:
            parser.error("this operation requires --reservation")
        if args.operation == "reserve":
            print(encode({"reservation": budget.reserve(read_json(args.call))}).decode())
        elif args.operation == "dispatch":
            budget.dispatch(args.reservation, read_json(args.call))
        elif args.operation == "settle":
            if args.actual is None:
                parser.error("settle requires --actual")
            budget.settle(args.reservation, args.actual)
        elif args.operation == "cancel":
            budget.cancel(args.reservation)
        else:
            print(encode(budget.trace()).decode())
    finally:
        budget.close()
