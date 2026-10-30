"""Exercise protected local calls and concurrent host processes."""

from __future__ import annotations

import copy
import importlib.util
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("spend_reservation", HERE / "probity_spend_reservation.py")
reservation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reservation)
Budget, Refused, encode, sha = reservation.Budget, reservation.Refused, reservation.encode, reservation.sha


def fixture(limit=100):
    prices = [{"provider": "local-fixture", "model": "bounded-tool", "target": "local/result",
               "unit": "fixture-cost-unit", "valid_from": 100, "expires_at": 200,
               "input_rate": 1, "output_rate": 2, "fixed_cost": 0}]
    policy = {"schema_version": "probity-spend-policy/v1", "budget_id": "fixture-budget",
              "unit": "fixture-cost-unit", "limit": limit, "valid_from": 100,
              "expires_at": 300, "prices_sha256": sha(prices)}
    return policy, prices


def call(prices, number="call-1", **values):
    return {"call_id": number, "attempt": 0, "provider": "local-fixture",
            "model": "bounded-tool", "target": "local/result", "args_sha256": sha({"text": "hello"}),
            "input_limit": 10, "output_limit": 20, "price_sha256": sha(prices[0]), **values}


def contender(database, policy, prices, index, start, queue):
    budget = Budget(Path(database), policy, prices, lambda: 110)
    try:
        start.wait(10)
        budget.reserve(call(prices, str(index), input_limit=60, output_limit=0))
        queue.put("reserved")
    except Refused as exc:
        queue.put(str(exc))
    finally:
        budget.close()


class ReservationControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        self.policy, self.prices = fixture()
        self.time = 110
        self.budget = Budget(self.path / "budget.sqlite", self.policy, self.prices, lambda: self.time)
        self.effects = []

    def tearDown(self):
        output = os.environ.get("SPEND_RESULTS")
        if output:
            target = Path(output) / self._testMethodName
            target.mkdir(parents=True, exist_ok=False)
            for name, value in (("policy", self.policy), ("prices", self.prices),
                                ("trace", self.budget.trace()), ("effects", self.effects)):
                (target / (name + ".json")).write_bytes(encode(value))
        self.budget.close()
        self.temporary.cleanup()

    def execute(self, request, actual=30):
        ticket = self.budget.reserve(request)
        self.budget.dispatch(ticket, request)
        # The fixture host performs this local effect only after atomic dispatch.
        self.effects.append({"reservation": ticket, "call": request, "cost": actual})
        self.budget.settle(ticket, actual)
        return ticket

    def test_pre_call_single_call_overshoot(self):
        with self.assertRaisesRegex(Refused, "insufficient-budget"):
            self.execute(call(self.prices, input_limit=101, output_limit=0))
        self.assertEqual(self.effects, [])
        self.assertEqual(self.budget.remaining(), 100)

    def test_unknown_price(self):
        with self.assertRaisesRegex(Refused, "unknown-price"):
            self.execute(call(self.prices, model="unknown"))
        self.assertEqual(self.effects, [])

    def test_stale_price(self):
        self.time = 200
        with self.assertRaisesRegex(Refused, "stale-price"):
            self.execute(call(self.prices))
        self.assertEqual(self.effects, [])

    def test_price_version_drift(self):
        with self.assertRaisesRegex(Refused, "price-version-mismatch"):
            self.execute(call(self.prices, price_sha256="0" * 64))
        self.assertEqual(self.effects, [])

    def test_cumulative_varied_argument_loop(self):
        for number in range(3):
            self.execute(call(self.prices, str(number), output_limit=10,
                              args_sha256=sha({"text": str(number)})), actual=30)
        with self.assertRaisesRegex(Refused, "insufficient-budget"):
            self.execute(call(self.prices, "3", args_sha256=sha({"text": "different-again"})))
        self.assertEqual(len(self.effects), 3)
        self.assertEqual(self.budget.remaining(), 10)

    def test_two_processes_cannot_over_reserve(self):
        context = multiprocessing.get_context("spawn")
        start, queue = context.Event(), context.Queue()
        processes = [context.Process(target=contender, args=(str(self.path / "budget.sqlite"),
                     self.policy, self.prices, index, start, queue)) for index in range(2)]
        for process in processes:
            process.start()
        start.set()
        outcomes = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(20)
            if process.is_alive():
                process.terminate()
                process.join()
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(outcomes), ["insufficient-budget", "reserved"])
        self.assertEqual(self.budget.remaining(), 40)

    def test_reservation_retry_is_idempotent_dispatch_is_single_use(self):
        request = call(self.prices)
        ticket = self.budget.reserve(request)
        self.assertEqual(self.budget.reserve(request), ticket)
        self.budget.dispatch(ticket, request)
        with self.assertRaisesRegex(Refused, "dispatch-reservation-mismatch-or-used"):
            self.budget.dispatch(ticket, request)
        self.assertEqual(len(self.budget.trace()["events"]), 2)

    def test_changed_arguments_cannot_rebind_attempt(self):
        self.budget.reserve(call(self.prices))
        with self.assertRaisesRegex(Refused, "call-attempt-rebound"):
            self.budget.reserve(call(self.prices, args_sha256="0" * 64))

    def test_changed_dispatch_target(self):
        request = call(self.prices)
        ticket = self.budget.reserve(request)
        with self.assertRaisesRegex(Refused, "unknown-price"):
            self.budget.dispatch(ticket, {**request, "target": "other"})
        self.assertEqual(self.effects, [])

    def test_new_attempt_has_its_own_charge(self):
        self.budget.reserve(call(self.prices))
        self.budget.reserve(call(self.prices, attempt=1))
        self.assertEqual(self.budget.remaining(), 0)

    def test_unused_reservation_is_refunded_after_receipt(self):
        self.execute(call(self.prices), actual=30)
        self.assertEqual(self.budget.remaining(), 70)
        self.assertEqual([e["kind"] for e in self.budget.trace()["events"]],
                         ["reserve", "dispatch", "settle", "refund"])
        self.assertEqual(self.budget.trace()["events"][-1]["amount"], 20)

    def test_cancellation_before_dispatch(self):
        ticket = self.budget.reserve(call(self.prices))
        self.budget.cancel(ticket)
        self.assertEqual(self.budget.remaining(), 100)
        with self.assertRaises(Refused):
            self.budget.dispatch(ticket, call(self.prices))

    def test_unknown_dispatched_outcome_retains_full_exposure(self):
        request = call(self.prices)
        ticket = self.budget.reserve(request)
        self.budget.dispatch(ticket, request)
        self.budget.close()
        self.budget = Budget(self.path / "budget.sqlite", self.policy, self.prices, lambda: self.time)
        self.assertEqual(self.budget.remaining(), 50)
        with self.assertRaisesRegex(Refused, "refund-after-dispatch"):
            self.budget.cancel(ticket)

    def test_price_expiry_after_reservation_prevents_dispatch(self):
        request = call(self.prices)
        ticket = self.budget.reserve(request)
        self.time = 200
        with self.assertRaisesRegex(Refused, "stale-price"):
            self.budget.dispatch(ticket, request)
        self.budget.cancel(ticket)
        self.assertEqual(self.budget.remaining(), 100)

    def test_actual_bound_violation_freezes_new_calls(self):
        request = call(self.prices)
        ticket = self.budget.reserve(request)
        self.budget.dispatch(ticket, request)
        with self.assertRaisesRegex(Refused, "tool-cost-bound-exceeded"):
            self.budget.settle(ticket, 60)
        self.assertEqual(self.budget.remaining(), 40)
        with self.assertRaisesRegex(Refused, "budget-frozen"):
            self.budget.reserve(call(self.prices, "next", input_limit=1, output_limit=0))

    def test_clock_rollback_refused(self):
        self.budget.reserve(call(self.prices))
        self.time = 109
        with self.assertRaisesRegex(Refused, "host-clock-rollback"):
            self.budget.reserve(call(self.prices, "next"))

    def test_selected_price_bytes_cannot_change_after_restart(self):
        changed = copy.deepcopy(self.prices)
        changed[0]["input_rate"] = 0
        selected_policy = {**self.policy, "prices_sha256": sha(changed)}
        with self.assertRaisesRegex(Refused, "budget-selection-changed"):
            Budget(self.path / "budget.sqlite", selected_policy, changed, lambda: 110)

    def test_boolean_and_float_cost_bounds_refused(self):
        for value in (True, 1.0, -1):
            with self.assertRaises(Refused):
                self.budget.reserve(call(self.prices, input_limit=value))

    def test_settlement_and_refund_cannot_repeat(self):
        ticket = self.execute(call(self.prices))
        with self.assertRaises(Refused):
            self.budget.settle(ticket, 0)
        with self.assertRaises(Refused):
            self.budget.cancel(ticket)
        self.assertEqual(self.budget.remaining(), 70)

    def test_mixed_units_and_duplicate_routes_refused(self):
        for prices in ([{**self.prices[0], "unit": "other"}], self.prices * 2):
            policy = {**self.policy, "prices_sha256": sha(prices)}
            with self.assertRaises(Refused):
                reservation.selected(policy, prices)


if __name__ == "__main__":
    unittest.main()
