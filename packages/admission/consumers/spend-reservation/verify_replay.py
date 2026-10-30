"""Read executed budget journals with an installed, separately pinned Verify."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def source(checkout: Path, output: Path) -> dict:
    selected = json.loads((HERE / "verify-selection.json").read_bytes())
    distribution = importlib.metadata.distribution("probity-verify")
    package = Path(distribution.locate_file("probity_verify"))
    actual = {}
    for path in sorted(package.rglob("*")):
        require(not path.is_symlink() and path.suffix not in (".pyc", ".pyo", ".so", ".pyd"),
                "verify-installation-extra-code")
        if path.is_file() and path.suffix == ".py":
            raw = path.read_bytes()
            actual[str(path.relative_to(package))] = hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(actual == selected["pythonGitBlobs"], "installed-verify-source-differs")
    for name, expected in selected["pythonGitBlobs"].items():
        original = checkout / "src/probity_verify" / name
        raw = original.read_bytes()
        require(not original.is_symlink() and hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected,
            "verify-checkout-source-differs")
        target = output / "verify-source/src/probity_verify" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for name in ("LICENSE", "pyproject.toml"):
        shutil.copyfile(checkout / name, output / "verify-source" / name)
    receipt = {"selected": selected, "installedPythonGitBlobs": actual,
               "version": distribution.version, "pythonVersion": sys.version,
               "verifiedBeforeVerifierExecution": True}
    save(output / "verify-installation.json", receipt)
    return receipt


def select(directory: Path, budget_id: str) -> None:
    # These pins select already captured fixture bytes for author-operated replay.
    # The original run saves its budget and prices before dispatch.
    case = {"schema_version": "probity-case/v1", "case_id": budget_id, "artifacts": {}}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {},
              "assessments": {budget_id: {"claim_type": "spend_reservation/v1",
                  "budget_id": budget_id, "budget_policy_witness": "budget",
                  "price_table_witness": "prices", "trace_witness": "trace"}}}
    for role, name in (("budget", "policy.json"), ("prices", "prices.json"), ("trace", "trace.json")):
        raw = (directory / name).read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        case["artifacts"][role] = {"path": name, "length": len(raw), "sha256": sha}
        policy["witnesses"][role] = {"artifact": role, "sha256": sha,
                                    "authority": "author-selected local fixture replay"}
    save(directory / "case.json", case)
    save(directory / "consumer-policy.json", policy)


def execute(directory: Path, label: str) -> dict:
    command = [sys.executable, "-I", "-B", "-m", "probity_verify.cli", str(directory / "case.json"),
               "--policy", str(directory / "consumer-policy.json"), "--json"]
    result = subprocess.run(command, capture_output=True, check=False)
    (directory / (label + ".stdout")).write_bytes(result.stdout)
    (directory / (label + ".stderr")).write_bytes(result.stderr)
    save(directory / (label + ".process.json"), {"argv": command, "returncode": result.returncode})
    require(result.returncode == 0, "installed-verify-process-failed")
    return json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-checkout", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source(args.verify_checkout, args.output)
    original = json.loads((args.native / "qualification.json").read_bytes())
    require(original["status"] == "finite-local-reference-qualified", "unqualified-native-input")
    rows = []
    for native in original["rows"]:
        name = native["case"]
        directory = args.output / "cases" / name
        directory.mkdir(parents=True)
        for file in ("policy.json", "prices.json", "trace.json"):
            shutil.copyfile(args.native / "cases" / name / file, directory / file)
        select(directory, name)
        first, second = execute(directory, "first"), execute(directory, "second")
        require(first == second and first["decision"] == "supported", "native-budget-replay-differs")
        accounting = first["scope"]["accounting"]
        require(accounting["conservative_remaining"] == native["remaining"] and
                accounting["execution_outcome"] == "not_established", "native-budget-accounting-differs")
        if name == "unresolved-receipt":
            require(accounting["held_maximum"] == 40 and accounting["pending_dispatch_receipts"] == 1,
                    "unresolved-receipt-was-released")
        rows.append({"case": name, "decision": first["decision"], "reason": first["reason"],
                     "accounting": accounting, "actualObserverEffects": native["effects"],
                     "sameOriginalBytes": True, "installedReplays": 2})
    # Repin each synthetic mutation so the independent replay checks its meaning.
    accepted = args.output / "cases/accepted"
    baseline = json.loads((accepted / "trace.json").read_bytes())
    mutations = []
    for name in ("over-budget", "changed-arguments", "changed-attempt", "changed-price", "reordered-events",
                 "missing-refund", "missing-consumer-pin"):
        directory = args.output / "mutations" / name
        directory.mkdir(parents=True)
        for file in ("policy.json", "prices.json"):
            shutil.copyfile(accepted / file, directory / file)
        trace = copy.deepcopy(baseline)
        if name == "over-budget":
            budget = json.loads((directory / "policy.json").read_bytes())
            budget["limit"] = 1
            trace["events"][0]["remaining_before"] = 1
            save(directory / "policy.json", budget)
            trace["policy_sha256"] = hashlib.sha256(json.dumps(
                budget, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        elif name == "changed-arguments":
            trace["events"][1]["call"]["args_sha256"] = "b" * 64
        elif name == "changed-attempt":
            trace["events"][1]["call"]["attempt"] += 1
        elif name == "changed-price":
            trace["events"][1]["call"]["price_sha256"] = "b" * 64
        elif name == "reordered-events":
            trace["events"][0], trace["events"][1] = trace["events"][1], trace["events"][0]
        elif name == "missing-refund":
            trace["events"].pop()
        save(directory / "trace.json", trace)
        select(directory, "accepted")
        if name == "missing-consumer-pin":
            consumer = json.loads((directory / "consumer-policy.json").read_bytes())
            consumer["witnesses"]["trace"]["sha256"] = "b" * 64
            save(directory / "consumer-policy.json", consumer)
        report = execute(directory, "decision")
        expected = "not_established" if name in ("missing-refund", "missing-consumer-pin") else "contradicted"
        reasons = {"over-budget": "over_budget_reservation", "changed-arguments": "dispatch_call_mismatch",
                   "changed-attempt": "dispatch_call_mismatch", "changed-price": "price_version_mismatch",
                   "reordered-events": "trace_sequence_mismatch", "missing-refund": "settlement_refund_missing",
                   "missing-consumer-pin": "trace_unavailable_or_unbound"}
        require(report["decision"] == expected and report["reason"] == reasons[name],
                "mutation-not-refused:" + name)
        mutations.append({"mutation": name, "decision": report["decision"], "reason": report["reason"]})
    result = {"profile": "probity-spend-installed-verify-v1", "operator": "author-operated",
              "scope": "Pinned budget journal replay; Observer authenticates effects separately.",
              "rows": rows, "syntheticMutations": mutations, "realProviderCalls": 0}
    save(args.output / "qualification.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
