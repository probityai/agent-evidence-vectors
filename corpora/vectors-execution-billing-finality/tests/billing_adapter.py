"""Reference runtime adapter: drive the P04 spend ledger through one scenario.

    python billing_adapter.py <scenario.json> --json [--source exposure_ledger.py]

The scenario is the P04 input format (``id``, ``budget``, ``steps``, ``probes``,
and the optional ``contract`` of its v0.2 inputs), so a P04 fixture such as F01
runs unchanged. The adapter reserves attempt A for two units on a fresh SQLite
account, runs the steps, then starts a new interpreter that reopens the same
file and runs the probes, and prints one execution-billing-finality record on
its last stdout line. It exits 0 for a completed observation and 2 for an
operational failure. It never reads an expected value: a step carrying one is
an operational failure.

The ledger is ``p04/exposure_ledger.py``, an unmodified copy of P04 by Mohammed
Messaoudene (MIT, see ``p04/LICENSE`` and ``p04/SOURCE.json``); ``--source`` runs
another copy, which is how the corpus's mutants are run. The command mapping in
``perform`` follows P04's ``run_review.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

HERE = Path(__file__).resolve().parent
LEDGER = HERE / "p04" / "exposure_ledger.py"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/execution-billing-finality"
)
BOUNDARIES = ["external_effect_established", "invoice_authenticity", "production_durability",
              "upstream_acceptance"]
RETURN_KEYS = {"dispatch_allowed": "dispatchAllowed", "new_event": "newEvent",
               "newly_finalized": "newlyFinalized", "newly_reserved": "newlyReserved",
               "state_changed": "stateChanged"}
ORACLE_FIELDS = {"expected", "expect_return", "raises"}


def load(source: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("p04_ledger_under_test", source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def perform(mod: ModuleType, ledger: Any, step: dict[str, Any], index: int) -> dict[str, Any]:
    """Run one scenario command against the ledger with trusted fixture evidence."""
    cmd, attempt = step["cmd"], step.get("attempt", "A")
    event = step.get("event", f"e-{index}")
    if cmd == "reserve":
        result: dict[str, Any] = ledger.reserve(attempt, step["amount"])
        return result
    roles = {"dispatch": ("dispatch_start", "dispatch_gate"),
             "unknown": (step.get("reason", "response_lost"), "client"),
             "outcome": ("execution_outcome", "executor"),
             "invoice": ("final_invoice", "provider_billing"),
             "cost": ("cost_observation", "usage_meter"),
             "non_dispatch": ("non_dispatch_proof", "dispatch_gate")}
    if cmd not in roles:
        raise ValueError(f"unsupported scenario command {cmd!r}")
    kind, role = roles[cmd]
    evidence = mod.Evidence(kind, step.get("source", role), f"fixture:{event}",
                            step.get("evidence_attempt", attempt))
    bound = mod.Evidence("enforced_cost_ceiling", "provider_contract", "fixture:ceiling", attempt)
    if cmd == "dispatch":
        ceiling = step.get("ceiling", True)
        result = ledger.mark_dispatch_started(attempt, event, evidence,
                                              bounded_by_authorization=ceiling,
                                              bound_evidence=bound if ceiling else None)
    elif cmd == "unknown":
        bounded = step["bounded"]
        result = ledger.mark_unknown(attempt, event, reason=kind, unbounded=not bounded,
                                     evidence=evidence, bound_evidence=bound if bounded else None)
    elif cmd == "outcome":
        result = ledger.observe_outcome(attempt, event, step["value"], evidence)
    elif cmd == "invoice":
        result = ledger.finalize_invoice(attempt, event, step["amount"], evidence)
    elif cmd == "cost":
        result = ledger.observe_cost(attempt, event, step["amount"], evidence)
    else:
        result = ledger.confirm_non_dispatch(attempt, event, evidence)
    return result


def view(ledger: Any) -> dict[str, Any]:
    """Attempt A's two axes, its dispatch state and the account's money, as integers."""
    snap = ledger.snapshot()
    item = next(a for a in snap["attempts"] if a["attempt_id"] == "A")
    return {"availableMicroUsd": snap["available_for_admission_microusd"],
            "billingFinality": item["billing_finality"],
            "dispatchState": item["dispatch_state"],
            "executionOutcome": item["outcome"], "frozen": snap["frozen"],
            "heldMicroUsd": item["still_exposed_reservation_microusd"],
            "knownSpendMicroUsd": item["known_spend_microusd"],
            "unbounded": item["unbounded_exposure"]}


def act(mod: ModuleType, ledger: Any, step: dict[str, Any], index: int) -> dict[str, Any]:
    if set(step) & ORACLE_FIELDS:
        raise ValueError("a scenario step carries an expected value")
    try:
        result = perform(mod, ledger, step, index)
    except (mod.LedgerError, mod.EvidenceValidationError) as exc:
        return {"exception": type(exc).__name__, "return": {}, "state": view(ledger)}
    return {"exception": None,
            "return": {ours: result[theirs] for theirs, ours in RETURN_KEYS.items()
                       if theirs in result},
            "state": view(ledger)}


def scenario_of(path: Path) -> dict[str, Any]:
    body = json.loads(path.read_text(encoding="utf-8"))
    body.pop("contract", None)
    if set(body) != {"budget", "id", "probes", "steps"}:
        raise ValueError("a scenario carries id, budget, steps and probes only")
    return {key: body[key] for key in ("budget", "id", "probes", "steps")}


def reopen(mod: ModuleType, scenario: dict[str, Any], database: Path) -> dict[str, Any]:
    ledger = mod.ExposureLedger(database)
    start = view(ledger)
    probes = [act(mod, ledger, step, index) for index, step in enumerate(scenario["probes"], 100)]
    return {"end": view(ledger), "endReopened": view(mod.ExposureLedger(database)),
            "probes": probes, "reopened": start}


def observe(scenario_path: Path, source: Path) -> dict[str, Any]:
    scenario = scenario_of(scenario_path)
    mod = load(source)
    with tempfile.TemporaryDirectory(prefix="aev-billing-") as work:
        database = Path(work) / "ledger.sqlite"
        ledger = mod.ExposureLedger(database, scenario["budget"])
        ledger.reserve("A", 2)
        initial = view(ledger)
        steps = [act(mod, ledger, step, index) for index, step in enumerate(scenario["steps"])]
        observed = view(ledger)
        child = subprocess.run(
            [sys.executable, "-S", "-B", str(Path(__file__).resolve()), str(scenario_path),
             "--source", str(source), "--reopen", str(database)],
            capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)
        if child.returncode:
            raise RuntimeError("the reopening interpreter failed: " + child.stderr[-300:])
        later = json.loads(child.stdout)
    return {"contractId": CONTRACT_ID, "end": later["end"], "endReopened": later["endReopened"],
            "externalEffect": "NOT_EVALUATED", "initial": initial,
            "mustNotClaim": list(BOUNDARIES), "observed": observed, "probes": later["probes"],
            "reopened": later["reopened"], "scenario": scenario,
            "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(), "steps": steps}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--json", action="store_true", help="print the record as JSON")
    parser.add_argument("--source", type=Path, default=LEDGER, help="ledger source to run")
    parser.add_argument("--reopen", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    source = args.source.resolve()
    if args.reopen:
        print(json.dumps(reopen(load(source), scenario_of(args.scenario), args.reopen),
                         sort_keys=True))
        return 0
    print(json.dumps(observe(args.scenario, source), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"operationalError": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        raise SystemExit(2) from exc
