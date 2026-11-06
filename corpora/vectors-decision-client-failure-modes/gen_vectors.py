"""Build the decision-client failure-mode cases byte-identically.

The corpus pairs two things. The runtime scenarios are the failure-mode matrix:
seven conditions of the decision point (unreachable, HTTP 500, HTTP 503, an
unparseable body, a timeout, an unknown verdict, a missing verdict) under each
of two client modes (``default``, the client as shipped, and ``strict``), plus
four controls under ``default`` (a block, a halt, an allow and an HTTP 401):
eighteen scenarios a client is driven through. The cases are decision records
a client could write in those scenarios: one conforming record per scenario,
which must be allowed, and records that read a fault as a decision, allow on a
fault, ignore a verdict, drop a halt or act on a denial, each built so the
check it names is the first that fails.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import decisionclient as reader  # noqa: E402

SUITE = reader.SUITE
DECIDED_AT = "2026-11-06T12:00:00Z"
TIMEOUT = 1000
ACTION = "transfer_funds"
ARGS = {"amount": 1000000, "currency": "USD", "to": "acct-0001"}
# A verdict no decision vocabulary this corpus knows of uses.
UNKNOWN_VERDICT = "suspend"

Case = tuple[str, dict[str, Any], str, str, str, str]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(args: dict[str, Any]) -> str:
    """``sha256:`` over the RFC 8785 bytes of the arguments (ASCII keys and integers here)."""
    return "sha256:" + _sha(json.dumps(args, sort_keys=True, separators=(",", ":")).encode())


# Each condition: what the decision point does, the exchange facts a client sees,
# and the condition those facts give.
CONDITIONS: dict[str, dict[str, Any]] = {
    "unreachable": {
        "point": {"body": "", "delayMillis": 0, "listen": False, "status": 0},
        "exchange": {"bodyIsJsonObject": False, "httpStatus": None, "reached": False,
                     "timedOut": False},
        "condition": "unreachable",
        "summary": "nothing listens at the decision point's address",
    },
    "http-500": {
        "point": {"body": '{"error":"down"}', "delayMillis": 0, "listen": True, "status": 500},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 500, "reached": True,
                     "timedOut": False},
        "condition": "http-error",
        "summary": "the decision point answers HTTP 500",
    },
    "http-503": {
        "point": {"body": "", "delayMillis": 0, "listen": True, "status": 503},
        "exchange": {"bodyIsJsonObject": False, "httpStatus": 503, "reached": True,
                     "timedOut": False},
        "condition": "http-error",
        "summary": "the decision point answers HTTP 503 with an empty body",
    },
    "unparseable-body": {
        "point": {"body": "<html>gateway</html>", "delayMillis": 0, "listen": True,
                  "status": 200},
        "exchange": {"bodyIsJsonObject": False, "httpStatus": 200, "reached": True,
                     "timedOut": False},
        "condition": "unparseable-body",
        "summary": "the decision point answers HTTP 200 with a body that is not JSON",
    },
    "timeout": {
        "point": {"body": '{"verdict":"block"}', "delayMillis": 2500, "listen": True,
                  "status": 200},
        "exchange": {"bodyIsJsonObject": False, "httpStatus": None, "reached": True,
                     "timedOut": True},
        "condition": "timeout",
        "summary": "the decision point's block arrives 2.5 seconds after a 1 second timeout",
    },
    "unknown-verdict": {
        "point": {"body": json.dumps({"reason": "policy says no", "verdict": UNKNOWN_VERDICT}),
                  "delayMillis": 0, "listen": True, "status": 200},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                     "timedOut": False, "verdict": UNKNOWN_VERDICT},
        "condition": "unknown-verdict",
        "summary": f"HTTP 200 whose verdict {UNKNOWN_VERDICT!r} is outside allow, block, halt",
    },
    "missing-verdict": {
        "point": {"body": '{"reason":"no verdict field"}', "delayMillis": 0, "listen": True,
                  "status": 200},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                     "timedOut": False},
        "condition": "missing-verdict",
        "summary": "HTTP 200 with no verdict member",
    },
}

CONTROLS: dict[str, dict[str, Any]] = {
    "control-block": {
        "point": {"body": '{"reason":"blocked","verdict":"block"}', "delayMillis": 0,
                  "listen": True, "status": 200},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                     "timedOut": False, "verdict": "block"},
        "condition": "ok", "outcome": "deny", "basis": "policy", "halted": False,
        "summary": "the decision point blocks the action",
    },
    "control-halt": {
        "point": {"body": '{"verdict":"halt"}', "delayMillis": 0, "listen": True,
                  "status": 200},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                     "timedOut": False, "verdict": "halt"},
        "condition": "ok", "outcome": "deny", "basis": "policy", "halted": True,
        "summary": "the decision point halts the run",
    },
    "control-allow": {
        "point": {"body": '{"reason":"within limits","verdict":"allow"}', "delayMillis": 0,
                  "listen": True, "status": 200},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                     "timedOut": False, "verdict": "allow"},
        "condition": "ok", "outcome": "allow", "basis": "policy", "halted": False,
        "summary": "the decision point allows the action, which runs once",
    },
    "control-401": {
        "point": {"body": '{"detail":"bad key"}', "delayMillis": 0, "listen": True,
                  "status": 401},
        "exchange": {"bodyIsJsonObject": True, "httpStatus": 401, "reached": True,
                     "timedOut": False},
        "condition": "unauthorized", "outcome": "deny", "basis": "fallback", "halted": False,
        "summary": "the decision point refuses the client's credential",
    },
}


def _scenario(sid: str, mode: str, spec: dict[str, Any], accepted: dict[str, Any]) -> dict[str, Any]:
    return {
        "accepted": accepted, "condition": sid.split("--")[0], "decisionPoint": spec["point"],
        "id": sid, "mode": mode,
        "request": {"action": ACTION, "args": ARGS, "consequential": True},
        "summary": spec["summary"], "timeoutMillis": TIMEOUT,
    }


def _scenarios() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    fault = {"basis": "fallback", "effects": 0, "halted": False, "outcome": "deny"}
    for name, spec in CONDITIONS.items():
        for mode in reader.MODES:
            sid = f"{name}--{mode}"
            out[sid] = _scenario(sid, mode, spec, dict(fault))
    for name, spec in CONTROLS.items():
        accepted = {"basis": spec["basis"], "effects": int(spec["outcome"] == "allow"),
                    "halted": spec["halted"], "outcome": spec["outcome"]}
        out[name] = _scenario(name, "default", spec, accepted)
    return out


SCENARIOS = _scenarios()


def _spec(sid: str) -> dict[str, Any]:
    name = sid.split("--")[0]
    return CONDITIONS.get(name) or CONTROLS[name]


def build(sid: str, name: str, **decision: Any) -> dict[str, Any]:
    """The conforming record for scenario ``sid``, with any decision member replaced."""
    scenario, spec = SCENARIOS[sid], _spec(sid)
    accepted = scenario["accepted"]
    record: dict[str, Any] = {
        "client": {"mode": scenario["mode"], "timeoutMillis": TIMEOUT},
        "contractId": reader.CONTRACT_ID,
        "decidedAt": DECIDED_AT,
        "decision": {"basis": accepted["basis"], "condition": spec["condition"],
                     "halted": accepted["halted"], "outcome": accepted["outcome"]},
        "effect": {"performed": accepted["outcome"] == "allow"},
        "exchange": copy.deepcopy(spec["exchange"]),
        "recordId": f"record-{name}",
        "request": {"action": ACTION, "argsDigest": digest(ARGS), "consequential": True},
        "scenario": sid,
    }
    performed = decision.pop("performed", None)
    record["decision"].update(decision)
    if performed is not None:
        record["effect"]["performed"] = performed
    return record


def _accepts() -> list[Case]:
    return [(f"accept-{sid}", build(sid, f"accept-{sid}"), "allow", reader.ALLOWED_REASON, sid,
             f"control: the conforming record for {sid}") for sid in SCENARIOS]


def _rejects() -> list[Case]:
    def case(name: str, sid: str, reason: str, edit: str, record: dict[str, Any]) -> Case:
        return (f"reject-{name}", record, "deny", reason, sid, edit)

    missing = build("control-allow", "reject-contract-id-missing")
    del missing["contractId"]
    unknown_contract = build("control-allow", "reject-contract-id-unknown")
    unknown_contract["contractId"] = (
        "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-decision")
    malformed = build("control-block", "reject-basis-outside-vocabulary", basis="server")
    status_without_reply = build("timeout--strict", "reject-status-without-reply")
    status_without_reply["exchange"]["httpStatus"] = 200
    return [
        case("contract-id-missing", "control-allow", "contract_id_missing",
             "the record carries no contractId", missing),
        case("contract-id-unknown", "control-allow", "contract_id_unknown",
             "contractId names another contract", unknown_contract),
        case("basis-outside-vocabulary", "control-block", "record_malformed",
             "the basis is 'server', outside policy and fallback", malformed),
        case("status-without-reply", "timeout--strict", "record_malformed",
             "a timed-out exchange carries an HTTP status, which only an arrived reply has",
             status_without_reply),
        case("unknown-verdict-read-as-allow", "unknown-verdict--default",
             "condition_misclassified",
             "the unknown verdict is recorded as ok and the action allowed on a policy basis",
             build("unknown-verdict--default", "reject-unknown-verdict-read-as-allow",
                   basis="policy", condition="ok", outcome="allow", performed=True)),
        case("unknown-verdict-read-as-allow-strict", "unknown-verdict--strict",
             "condition_misclassified",
             "the same reading under the strict mode, which does not close it",
             build("unknown-verdict--strict", "reject-unknown-verdict-read-as-allow-strict",
                   basis="policy", condition="ok", outcome="allow", performed=True)),
        case("missing-verdict-read-as-allow", "missing-verdict--strict",
             "condition_misclassified",
             "a reply with no verdict is recorded as ok and allowed under the strict mode",
             build("missing-verdict--strict", "reject-missing-verdict-read-as-allow",
                   basis="policy", condition="ok", outcome="allow", performed=True)),
        case("fault-recorded-as-policy", "http-500--strict", "fault_recorded_as_policy",
             "an HTTP 500 is denied but recorded as a policy decision",
             build("http-500--strict", "reject-fault-recorded-as-policy", basis="policy")),
        case("unreachable-allowed", "unreachable--default", "fault_allowed",
             "an unreachable decision point leads to a marked fallback allow under the default",
             build("unreachable--default", "reject-unreachable-allowed", outcome="allow",
                   performed=True)),
        case("timeout-allowed", "timeout--default", "fault_allowed",
             "a timeout leads to a marked fallback allow under the default",
             build("timeout--default", "reject-timeout-allowed", outcome="allow",
                   performed=True)),
        case("unparseable-allowed", "unparseable-body--default", "fault_allowed",
             "an unparseable body leads to a marked fallback allow under the default",
             build("unparseable-body--default", "reject-unparseable-allowed", outcome="allow",
                   performed=True)),
        case("unauthorized-allowed", "control-401", "fault_allowed",
             "a refused credential leads to a fallback allow",
             build("control-401", "reject-unauthorized-allowed", outcome="allow",
                   performed=True)),
        case("block-not-followed", "control-block", "verdict_not_followed",
             "a block verdict is recorded and the action allowed",
             build("control-block", "reject-block-not-followed", outcome="allow",
                   performed=True)),
        case("allow-recorded-as-fallback", "control-allow", "verdict_not_followed",
             "an allow verdict is followed but recorded on a fallback basis",
             build("control-allow", "reject-allow-recorded-as-fallback", basis="fallback")),
        case("halt-not-honoured", "control-halt", "halt_not_honoured",
             "a halt verdict denies the action but the run is not halted",
             build("control-halt", "reject-halt-not-honoured", halted=False)),
        case("halt-claimed-on-block", "control-block", "halt_not_honoured",
             "a block verdict is recorded as a halt",
             build("control-block", "reject-halt-claimed-on-block", halted=True)),
        case("effect-on-deny", "http-503--strict", "effect_on_deny",
             "an HTTP 503 is denied as a fallback, and the action is performed anyway",
             build("http-503--strict", "reject-effect-on-deny", performed=True)),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, runtime scenario id, and what it shows."""
    return [*_accepts(), *_rejects()]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, scenario_id, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)},
            "id": name, "path": f"cases/{name}", "retained": reader.retained(body),
            "runtime": {"scenario": SCENARIOS[scenario_id]},
        })
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "runtimeContract": ("client scenario.json, AEV_DECISION_POINT, AEV_EFFECT_SINK, "
                            "AEV_DECISION_RECORD; see decisionclient_runtime"),
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
