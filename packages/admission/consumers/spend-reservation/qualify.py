"""Run bounded local tools behind admission and installed Observer checkpoints."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
api_distribution = importlib.metadata.distribution("probity-spend-reservation")
api_path = Path(api_distribution.locate_file("probity_spend_reservation.py"))
if api_path.is_symlink() or api_path.read_bytes() != (HERE / "probity_spend_reservation.py").read_bytes():
    raise ValueError("installed-admission-source-differs")
import probity_spend_reservation as reservation

Budget, Refused, encode, sha = reservation.Budget, reservation.Refused, reservation.encode, reservation.sha
CASES = ("accepted", "single-call-overshoot", "unknown-price", "stale-price",
         "varied-argument-loop", "unresolved-receipt", "synthetic-s005-overshoot")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def save(path: Path, value: object) -> None:
    path.write_bytes(encode(value))


def authenticate_observer(checkout: Path, output: Path) -> dict:
    selected = reservation.read_json(HERE / "observer-selection.json")
    distribution = importlib.metadata.distribution("agent-evidence-observer")
    package = Path(distribution.locate_file("probity_observer"))
    actual = {}
    for path in sorted(package.rglob("*")):
        require(not path.is_symlink() and path.suffix not in (".pyc", ".pyo", ".so", ".pyd"),
                "observer-installation-extra-code")
        if path.is_file() and path.suffix == ".py":
            raw = path.read_bytes()
            actual[str(path.relative_to(package))] = hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(actual == selected["pythonGitBlobs"], "installed-observer-source-differs")
    for name, expected in selected["pythonGitBlobs"].items():
        source = checkout / "src/probity_observer" / name
        raw = source.read_bytes()
        require(not source.is_symlink() and hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected,
            "observer-checkout-source-differs")
        target = output / "observer-source/src/probity_observer" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for name in ("LICENSE", "pyproject.toml", "AGENTS.md"):
        shutil.copyfile(checkout / name, output / "observer-source" / name)
    receipt = {"selected": selected, "installedPythonGitBlobs": actual,
               "admissionAPI": {"version": api_distribution.version,
                                "sha256": hashlib.sha256(api_path.read_bytes()).hexdigest()},
               "pythonVersion": sys.version, "dependencies": {
                   name: importlib.metadata.version(name)
                   for name in ("cryptography", "cffi", "pycparser")},
               "verifiedBeforeObserverImport": True}
    save(output / "observer-installation.json", receipt)
    return receipt


def run_case(output: Path, case: str) -> dict:
    # Installed package imports happen only after the launcher checks every source.
    from probity_observer.broker import Broker
    from probity_observer.crypto import SigningKey
    from probity_observer.history import (
        Witness,
        append_history,
        read_history,
        verify_checkpoint,
    )
    from probity_observer.verify import verify_packet

    directory = output / "cases" / case
    directory.mkdir(parents=True)
    workspace = directory / "workspace"
    workspace.mkdir()
    clock = [110]
    prices = [{"provider": "local-fixture", "model": "bounded-file-tool", "target": "/work/result.txt",
               "unit": "fixture-byte-cost", "valid_from": 100, "expires_at": 200,
               "input_rate": 1, "output_rate": 2, "fixed_cost": 0}]
    policy = {"schema_version": "probity-spend-policy/v1", "budget_id": case,
              "unit": "fixture-byte-cost", "limit": 50, "valid_from": 100,
              "expires_at": 300, "prices_sha256": sha(prices)}
    if case == "varied-argument-loop":
        policy["limit"] = 150
    if case == "synthetic-s005-overshoot":
        # A selected synthetic table reproduces the study's 3.015 > 1 arithmetic.
        # It is not a provider price quote or a real billing receipt.
        prices[0].update(unit="synthetic-USD-micros", input_rate=3, output_rate=15)
        policy.update(unit="synthetic-USD-micros", limit=1_000_000,
                      prices_sha256=sha(prices))
    save(directory / "policy.json", policy)
    save(directory / "prices.json", prices)
    budget = Budget(directory / "budget.sqlite", policy, prices, lambda: clock[0])
    observer_key, effect_witness_key, cost_key = (SigningKey.generate() for _ in range(3))
    keys = {"observer": observer_key.public_hex, "effect_witness": effect_witness_key.public_hex,
            "budget_witness": cost_key.public_hex}
    save(directory / "host-keys-before-run.json", keys)
    broker = Broker(workspace, directory / "effect-history.jsonl",
                    {"intervalId": case, "scope": "/work", "operation": "write-file"},
                    observer_key, Witness(directory / "effect-witness-state.json", effect_witness_key))
    save(directory / "effect-begin-before-run.json", broker.begin())
    cost_history = directory / "budget-history.jsonl"
    cost_witness = Witness(directory / "budget-witness-state.json", cost_key)
    checkpoints, links, refused = [], [], []

    def checkpoint() -> dict:
        trace = budget.trace()
        count = len(read_history(cost_history))
        for event in trace["events"][count:]:
            append_history(cost_history, {"kind": "budget", "record": event})
        proof = cost_witness.checkpoint(cost_history)
        verify_checkpoint(read_history(cost_history), proof, keys["budget_witness"])
        checkpoints.append(proof)
        return proof

    def execute(number: int) -> None:
        arguments = {"text": "request-" + str(number)}
        body = encode(arguments)
        request = {"call_id": "call-" + str(number), "attempt": 0,
                   "provider": "local-fixture", "model": "bounded-file-tool", "target": "/work/result.txt",
                   "args_sha256": sha(arguments), "input_limit": len(body), "output_limit": 10,
                   "price_sha256": sha(prices[0])}
        if case == "single-call-overshoot":
            request["input_limit"] = 51
        elif case == "unknown-price":
            request["model"] = "unpriced"
        elif case == "stale-price":
            clock[0] = 200
        elif case == "synthetic-s005-overshoot":
            request.update(input_limit=1_000_000, output_limit=1000)
        try:
            ticket = budget.reserve(request)
            budget.dispatch(ticket, request)
            proof = checkpoint()
            # This concrete local adapter enforces its own byte bounds and exact
            # argument digest before writing. Remote tool adapters need their own bound.
            content = b"ok\n"
            require(sha(arguments) == request["args_sha256"] and
                    len(body) <= request["input_limit"] and len(content) <= request["output_limit"],
                    "local-tool-cost-bound")
            broker.write(ticket, request["target"], content)
            actual = len(body) * prices[0]["input_rate"] + len(content) * prices[0]["output_rate"]
            links.append({"reservation": ticket, "call": request, "arguments": arguments,
                          "inputBytes": len(body), "outputBytes": len(content),
                          "actual": actual, "dispatchCheckpointBeforeEffect": proof})
            if case != "unresolved-receipt":
                budget.settle(ticket, actual)
            checkpoint()
        except Refused as exc:
            refused.append({"call": request, "reason": str(exc)})
            checkpoint()

    try:
        execute(0)
        if case == "varied-argument-loop":
            for number in range(1, 6):
                execute(number)
        trace = budget.trace()
        save(directory / "trace.json", trace)
        save(directory / "budget-checkpoints.json", checkpoints)
        save(directory / "effect-links.json", links)
        save(directory / "refused.json", refused)
        packet = broker.seal()
        save(directory / "effect-packet.json", packet)
        observed = verify_packet(packet, directory / "effect-history.jsonl",
                                 keys["observer"], keys["effect_witness"], workspace)
        history = read_history(cost_history)
        require([entry["event"]["record"] for entry in history] == trace["events"],
                "observer-budget-history-differs")
        for proof in checkpoints:
            verify_checkpoint(history[:proof["count"]], proof, keys["budget_witness"])
        require(len(observed["writes"]) == len(links), "observer-effect-count")
        by_ticket = {event["reservation"]: event for event in trace["events"] if event["kind"] == "dispatch"}
        for link in links:
            dispatch = by_ticket[link["reservation"]]
            require(dispatch["call"] == link["call"] and dispatch["sequence"] <=
                    link["dispatchCheckpointBeforeEffect"]["count"], "effect-without-prior-budget-checkpoint")
        zero_effect = case in ("single-call-overshoot", "unknown-price", "stale-price", "synthetic-s005-overshoot")
        require(not links if zero_effect else bool(links), "native-effect-expectation")
        require(budget.remaining() >= 0, "native-budget-negative")
        result = {"case": case, "effects": len(links), "refusals": len(refused),
                  "remaining": budget.remaining(), "events": len(trace["events"]),
                  "budgetCheckpointVerified": True, "effectPacketVerified": True,
                  "costOutcome": "unestablished-held-at-maximum" if case == "unresolved-receipt" else "fixture-receipts"}
        save(directory / "result.json", result)
        return result
    finally:
        budget.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observer-checkout", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    plan = {"profile": "probity-spend-admission-local-v1", "cases": list(CASES),
            "operator": "author-operated", "witnessScope": "PEER", "realProviderCalls": 0,
            "priceScope": "selected synthetic fixture units; no real billing",
            "prospectiveEightTaskRun": "not-started", "frozenStudies": "unchanged"}
    save(args.output / "plan-before-run.json", plan)
    authenticate_observer(args.observer_checkout, args.output)
    rows = [run_case(args.output, case) for case in CASES]
    result = {**plan, "rows": rows, "status": "finite-local-reference-qualified"}
    save(args.output / "qualification.json", result)
    print(encode(result).decode())


if __name__ == "__main__":
    main()
