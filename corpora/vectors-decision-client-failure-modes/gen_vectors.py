"""Build the decision-client failure-mode cases byte-identically.

The corpus pairs two things. The runtime scenarios are the failure-mode matrix:
nine conditions of the decision point (unreachable, HTTP 500, HTTP 503, an
unparseable body, a timeout, an unknown verdict, a missing verdict, a body one
byte over the client's response limit, and an outage long enough to open the
client's circuit breaker) under each of two client modes (``default``, the client
as shipped, and ``strict``), plus five controls under ``default`` (a block, a
halt, an allow, an HTTP 401 and an allow whose body is exactly at the limit).
The cases are decision records a client could write in those scenarios: one
conforming record per scenario, which must be allowed, records that state an
enforcing posture, and records that read a fault as a decision, allow on a
fault, ignore a verdict, drop a halt, act on a denial, or were written under a
monitor, fail-open or defaulted posture, each built so the check it names is the
first that fails.

The records of the first eighteen scenarios carry none of the optional members
(``posture``, ``maxResponseBytes``, ``bodyBytes``, ``circuitOpen``) and are the
records the corpus shipped before them, byte for byte; ``tests/v1-baseline.json``
holds them to that.
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
from agent_evidence_vectors import decisionclient_runtime as runtime  # noqa: E402

SUITE = reader.SUITE
DECIDED_AT = "2026-11-06T12:00:00Z"
TIMEOUT = 1000
# The response limit every scenario sets, and the body sizes either side of it.
LIMIT = 4096
# Consecutive asks in the outage scenario: past any breaker threshold a client sets.
OUTAGE_ATTEMPTS = 5
ENFORCING = dict(reader.ENFORCING_POSTURE)
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
        "exchange": {
            "bodyIsJsonObject": False,
            "httpStatus": None,
            "reached": False,
            "timedOut": False,
        },
        "condition": "unreachable",
        "summary": "nothing listens at the decision point's address",
    },
    "http-500": {
        "point": {"body": '{"error":"down"}', "delayMillis": 0, "listen": True, "status": 500},
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 500,
            "reached": True,
            "timedOut": False,
        },
        "condition": "http-error",
        "summary": "the decision point answers HTTP 500",
    },
    "http-503": {
        "point": {"body": "", "delayMillis": 0, "listen": True, "status": 503},
        "exchange": {
            "bodyIsJsonObject": False,
            "httpStatus": 503,
            "reached": True,
            "timedOut": False,
        },
        "condition": "http-error",
        "summary": "the decision point answers HTTP 503 with an empty body",
    },
    "unparseable-body": {
        "point": {"body": "<html>gateway</html>", "delayMillis": 0, "listen": True, "status": 200},
        "exchange": {
            "bodyIsJsonObject": False,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
        },
        "condition": "unparseable-body",
        "summary": "the decision point answers HTTP 200 with a body that is not JSON",
    },
    "timeout": {
        "point": {
            "body": '{"verdict":"block"}',
            "delayMillis": 2500,
            "listen": True,
            "status": 200,
        },
        "exchange": {
            "bodyIsJsonObject": False,
            "httpStatus": None,
            "reached": True,
            "timedOut": True,
        },
        "condition": "timeout",
        "summary": "the decision point's block arrives 2.5 seconds after a 1 second timeout",
    },
    "unknown-verdict": {
        "point": {
            "body": json.dumps({"reason": "policy says no", "verdict": UNKNOWN_VERDICT}),
            "delayMillis": 0,
            "listen": True,
            "status": 200,
        },
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
            "verdict": UNKNOWN_VERDICT,
        },
        "condition": "unknown-verdict",
        "summary": f"HTTP 200 whose verdict {UNKNOWN_VERDICT!r} is outside allow, block, halt",
    },
    "missing-verdict": {
        "point": {
            "body": '{"reason":"no verdict field"}',
            "delayMillis": 0,
            "listen": True,
            "status": 200,
        },
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
        },
        "condition": "missing-verdict",
        "summary": "HTTP 200 with no verdict member",
    },
}

# The conditions added with the optional members. Their records carry them.
EXTENDED_CONDITIONS: dict[str, dict[str, Any]] = {
    "oversize": {
        "point": {
            "body": '{"verdict":"allow","pad":""}',
            "delayMillis": 0,
            "listen": True,
            "padTo": LIMIT + 1,
            "status": 200,
        },
        "exchange": {
            "bodyBytes": LIMIT + 1,
            "bodyIsJsonObject": False,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
        },
        "condition": "oversize",
        "summary": "HTTP 200 whose allow body is one byte over the client's response limit",
    },
    "outage": {
        "attempts": OUTAGE_ATTEMPTS,
        "point": {"body": "", "delayMillis": 0, "listen": False, "status": 0},
        "exchange": {
            "bodyIsJsonObject": False,
            "circuitOpen": True,
            "httpStatus": None,
            "reached": False,
            "timedOut": False,
        },
        "condition": "circuit-open",
        "summary": (
            f"nothing listens for {OUTAGE_ATTEMPTS} consecutive asks; a client with a "
            "breaker stops asking, and its last decision is the breaker's"
        ),
    },
}
CONDITIONS.update(EXTENDED_CONDITIONS)

CONTROLS: dict[str, dict[str, Any]] = {
    "control-block": {
        "point": {
            "body": '{"reason":"blocked","verdict":"block"}',
            "delayMillis": 0,
            "listen": True,
            "status": 200,
        },
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
            "verdict": "block",
        },
        "condition": "ok",
        "outcome": "deny",
        "basis": "policy",
        "halted": False,
        "summary": "the decision point blocks the action",
    },
    "control-halt": {
        "point": {"body": '{"verdict":"halt"}', "delayMillis": 0, "listen": True, "status": 200},
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
            "verdict": "halt",
        },
        "condition": "ok",
        "outcome": "deny",
        "basis": "policy",
        "halted": True,
        "summary": "the decision point halts the run",
    },
    "control-allow": {
        "point": {
            "body": '{"reason":"within limits","verdict":"allow"}',
            "delayMillis": 0,
            "listen": True,
            "status": 200,
        },
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
            "verdict": "allow",
        },
        "condition": "ok",
        "outcome": "allow",
        "basis": "policy",
        "halted": False,
        "summary": "the decision point allows the action, which runs once",
    },
    "control-401": {
        "point": {"body": '{"detail":"bad key"}', "delayMillis": 0, "listen": True, "status": 401},
        "exchange": {
            "bodyIsJsonObject": True,
            "httpStatus": 401,
            "reached": True,
            "timedOut": False,
        },
        "condition": "unauthorized",
        "outcome": "deny",
        "basis": "fallback",
        "halted": False,
        "summary": "the decision point refuses the client's credential",
    },
    "control-at-limit": {
        "extended": True,
        "point": {
            "body": '{"verdict":"allow","pad":""}',
            "delayMillis": 0,
            "listen": True,
            "padTo": LIMIT,
            "status": 200,
        },
        "exchange": {
            "bodyBytes": LIMIT,
            "bodyIsJsonObject": True,
            "httpStatus": 200,
            "reached": True,
            "timedOut": False,
            "verdict": "allow",
        },
        "condition": "ok",
        "outcome": "allow",
        "basis": "policy",
        "halted": False,
        "summary": "the decision point allows with a body exactly at the client's limit",
    },
}
for _spec_ in EXTENDED_CONDITIONS.values():
    _spec_["extended"] = True


point_body = runtime.point_body


def _scenario(
    sid: str, mode: str, spec: dict[str, Any], accepted: dict[str, Any]
) -> dict[str, Any]:
    return {
        "accepted": accepted,
        "attempts": spec.get("attempts", 1),
        "condition": sid.split("--")[0],
        "decisionPoint": spec["point"],
        "id": sid,
        "maxResponseBytes": LIMIT,
        "mode": mode,
        "request": {"action": ACTION, "args": ARGS, "consequential": True},
        "summary": spec["summary"],
        "timeoutMillis": TIMEOUT,
    }


def _scenarios() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    fault = {"basis": "fallback", "effects": 0, "halted": False, "outcome": "deny"}
    for name, spec in CONDITIONS.items():
        for mode in reader.MODES:
            sid = f"{name}--{mode}"
            out[sid] = _scenario(sid, mode, spec, dict(fault))
    for name, spec in CONTROLS.items():
        accepted = {
            "basis": spec["basis"],
            "effects": int(spec["outcome"] == "allow"),
            "halted": spec["halted"],
            "outcome": spec["outcome"],
        }
        out[name] = _scenario(name, "default", spec, accepted)
    return out


SCENARIOS = _scenarios()


def _spec(sid: str) -> dict[str, Any]:
    name = sid.split("--")[0]
    return CONDITIONS.get(name) or CONTROLS[name]


def build(
    sid: str,
    name: str,
    extended: bool | None = None,
    posture: dict[str, Any] | None = ENFORCING,
    **decision: Any,
) -> dict[str, Any]:
    """The conforming record for scenario ``sid``, with any decision member replaced.

    An ``extended`` record (the default for the scenarios added with the optional
    members) states the client's response limit, the size of every reply that
    arrived, and ``posture`` unless it is None.
    """
    scenario, spec = SCENARIOS[sid], _spec(sid)
    if extended is None:
        extended = bool(spec.get("extended"))
    accepted = scenario["accepted"]
    record: dict[str, Any] = {
        "client": {"mode": scenario["mode"], "timeoutMillis": TIMEOUT},
        "contractId": reader.CONTRACT_ID,
        "decidedAt": DECIDED_AT,
        "decision": {
            "basis": accepted["basis"],
            "condition": spec["condition"],
            "halted": accepted["halted"],
            "outcome": accepted["outcome"],
        },
        "effect": {"performed": accepted["outcome"] == "allow"},
        "exchange": copy.deepcopy(spec["exchange"]),
        "recordId": f"record-{name}",
        "request": {"action": ACTION, "argsDigest": digest(ARGS), "consequential": True},
        "scenario": sid,
    }
    if extended:
        record["client"]["maxResponseBytes"] = LIMIT
        exchange = record["exchange"]
        if exchange["httpStatus"] is not None and "bodyBytes" not in exchange:
            exchange["bodyBytes"] = len(point_body(spec["point"]).encode())
        if posture is not None:
            record["posture"] = dict(posture)
    performed = decision.pop("performed", None)
    record["decision"].update(decision)
    if performed is not None:
        record["effect"]["performed"] = performed
    return record


def _accepts() -> list[Case]:
    return [
        (
            f"accept-{sid}",
            build(sid, f"accept-{sid}"),
            "allow",
            reader.ALLOWED_REASON,
            sid,
            f"control: the conforming record for {sid}",
        )
        for sid in SCENARIOS
    ] + [
        (
            f"accept-posture-stated-{sid}",
            build(sid, f"accept-posture-stated-{sid}", extended=True),
            "allow",
            reader.ALLOWED_REASON,
            sid,
            f"control: {sid} under a stated enforce, fail-closed, explicitly set posture",
        )
        for sid in ("control-allow", "control-block", "control-halt", "http-500--strict")
    ]


def _posture(**members: str) -> dict[str, str]:
    return {**ENFORCING, **members}


def _rejects() -> list[Case]:
    return [*_rejects_v1(), *_rejects_posture(), *_rejects_extended()]


def _rejects_v1() -> list[Case]:
    def case(name: str, sid: str, reason: str, edit: str, record: dict[str, Any]) -> Case:
        return (f"reject-{name}", record, "deny", reason, sid, edit)

    missing = build("control-allow", "reject-contract-id-missing")
    del missing["contractId"]
    unknown_contract = build("control-allow", "reject-contract-id-unknown")
    unknown_contract["contractId"] = "https://example.org/contracts/decision-client/v9"
    malformed = build("control-block", "reject-basis-outside-vocabulary", basis="server")
    status_without_reply = build("timeout--strict", "reject-status-without-reply")
    status_without_reply["exchange"]["httpStatus"] = 200
    return [
        case(
            "contract-id-missing",
            "control-allow",
            "contract_id_missing",
            "the record carries no contractId",
            missing,
        ),
        case(
            "contract-id-unknown",
            "control-allow",
            "contract_id_unknown",
            "contractId names another contract",
            unknown_contract,
        ),
        case(
            "basis-outside-vocabulary",
            "control-block",
            "record_malformed",
            "the basis is 'server', outside policy and fallback",
            malformed,
        ),
        case(
            "status-without-reply",
            "timeout--strict",
            "record_malformed",
            "a timed-out exchange carries an HTTP status, which only an arrived reply has",
            status_without_reply,
        ),
        case(
            "unknown-verdict-read-as-allow",
            "unknown-verdict--default",
            "condition_misclassified",
            "the unknown verdict is recorded as ok and the action allowed on a policy basis",
            build(
                "unknown-verdict--default",
                "reject-unknown-verdict-read-as-allow",
                basis="policy",
                condition="ok",
                outcome="allow",
                performed=True,
            ),
        ),
        case(
            "unknown-verdict-read-as-allow-strict",
            "unknown-verdict--strict",
            "condition_misclassified",
            "the same reading under the strict mode, which does not close it",
            build(
                "unknown-verdict--strict",
                "reject-unknown-verdict-read-as-allow-strict",
                basis="policy",
                condition="ok",
                outcome="allow",
                performed=True,
            ),
        ),
        case(
            "missing-verdict-read-as-allow",
            "missing-verdict--strict",
            "condition_misclassified",
            "a reply with no verdict is recorded as ok and allowed under the strict mode",
            build(
                "missing-verdict--strict",
                "reject-missing-verdict-read-as-allow",
                basis="policy",
                condition="ok",
                outcome="allow",
                performed=True,
            ),
        ),
        case(
            "fault-recorded-as-policy",
            "http-500--strict",
            "fault_recorded_as_policy",
            "an HTTP 500 is denied but recorded as a policy decision",
            build("http-500--strict", "reject-fault-recorded-as-policy", basis="policy"),
        ),
        case(
            "unreachable-allowed",
            "unreachable--default",
            "fault_allowed",
            "an unreachable decision point leads to a marked fallback allow under the default",
            build(
                "unreachable--default",
                "reject-unreachable-allowed",
                outcome="allow",
                performed=True,
            ),
        ),
        case(
            "timeout-allowed",
            "timeout--default",
            "fault_allowed",
            "a timeout leads to a marked fallback allow under the default",
            build("timeout--default", "reject-timeout-allowed", outcome="allow", performed=True),
        ),
        case(
            "unparseable-allowed",
            "unparseable-body--default",
            "fault_allowed",
            "an unparseable body leads to a marked fallback allow under the default",
            build(
                "unparseable-body--default",
                "reject-unparseable-allowed",
                outcome="allow",
                performed=True,
            ),
        ),
        case(
            "unauthorized-allowed",
            "control-401",
            "fault_allowed",
            "a refused credential leads to a fallback allow",
            build("control-401", "reject-unauthorized-allowed", outcome="allow", performed=True),
        ),
        case(
            "block-not-followed",
            "control-block",
            "verdict_not_followed",
            "a block verdict is recorded and the action allowed",
            build("control-block", "reject-block-not-followed", outcome="allow", performed=True),
        ),
        case(
            "allow-recorded-as-fallback",
            "control-allow",
            "verdict_not_followed",
            "an allow verdict is followed but recorded on a fallback basis",
            build("control-allow", "reject-allow-recorded-as-fallback", basis="fallback"),
        ),
        case(
            "halt-not-honoured",
            "control-halt",
            "halt_not_honoured",
            "a halt verdict denies the action but the run is not halted",
            build("control-halt", "reject-halt-not-honoured", halted=False),
        ),
        case(
            "halt-claimed-on-block",
            "control-block",
            "halt_not_honoured",
            "a block verdict is recorded as a halt",
            build("control-block", "reject-halt-claimed-on-block", halted=True),
        ),
        case(
            "effect-on-deny",
            "http-503--strict",
            "effect_on_deny",
            "an HTTP 503 is denied as a fallback, and the action is performed anyway",
            build("http-503--strict", "reject-effect-on-deny", performed=True),
        ),
    ]


def _case(name: str, sid: str, reason: str, edit: str, record: dict[str, Any]) -> Case:
    return (f"reject-{name}", record, "deny", reason, sid, edit)


def _rejects_posture() -> list[Case]:
    monitor = _posture(enforcement="monitor")
    vocabulary = build("control-block", "reject-posture-outside-vocabulary", extended=True)
    vocabulary["posture"]["enforcement"] = "audit"
    unstated = build("control-allow", "reject-posture-flag-unstated", extended=True)
    del unstated["posture"]["failModeSource"]
    return [
        _case(
            "posture-outside-vocabulary",
            "control-block",
            "record_malformed",
            "the posture's enforcement is 'audit', outside enforce and monitor",
            vocabulary,
        ),
        _case(
            "posture-flag-unstated",
            "control-allow",
            "record_malformed",
            "the posture states no failModeSource, so whether the flag was set is unstated",
            unstated,
        ),
        _case(
            "monitor-block-ran",
            "control-block",
            "monitor_mode",
            "under a monitor posture a block verdict is logged as a deny and the action runs",
            build(
                "control-block",
                "reject-monitor-block-ran",
                extended=True,
                posture=monitor,
                performed=True,
            ),
        ),
        _case(
            "monitor-allow",
            "control-allow",
            "monitor_mode",
            "an allow followed correctly under a monitor posture, which gated nothing",
            build("control-allow", "reject-monitor-allow", extended=True, posture=monitor),
        ),
        _case(
            "monitor-fault-allowed",
            "unreachable--default",
            "monitor_mode",
            "under a monitor posture an unreachable point is allowed as a fallback",
            build(
                "unreachable--default",
                "reject-monitor-fault-allowed",
                extended=True,
                posture=monitor,
                outcome="allow",
                performed=True,
            ),
        ),
        _case(
            "fail-open-posture-ok",
            "control-allow",
            "fail_open_posture",
            "an allow followed correctly under a fail-open posture, set explicitly",
            build(
                "control-allow",
                "reject-fail-open-posture-ok",
                extended=True,
                posture=_posture(failMode="open"),
            ),
        ),
        _case(
            "fail-open-posture-fault-denied",
            "http-503--strict",
            "fail_open_posture",
            "an HTTP 503 denied correctly by a client configured to fail open",
            build(
                "http-503--strict",
                "reject-fail-open-posture-fault-denied",
                extended=True,
                posture=_posture(failMode="open"),
            ),
        ),
        _case(
            "fail-mode-defaulted-open",
            "unreachable--default",
            "fail_open_posture",
            "the fail-closed flag is unset and the shipped default fails open",
            build(
                "unreachable--default",
                "reject-fail-mode-defaulted-open",
                extended=True,
                posture=_posture(failMode="open", failModeSource="default"),
                outcome="allow",
                performed=True,
            ),
        ),
        _case(
            "fail-mode-defaulted-closed",
            "unreachable--default",
            "fail_mode_defaulted",
            "an unreachable point denied correctly while the fail-closed flag is unset",
            build(
                "unreachable--default",
                "reject-fail-mode-defaulted-closed",
                extended=True,
                posture=_posture(failModeSource="default"),
            ),
        ),
        _case(
            "strict-mode-defaulted",
            "timeout--strict",
            "fail_mode_defaulted",
            "a timeout denied correctly under strict mode with the fail mode defaulted",
            build(
                "timeout--strict",
                "reject-strict-mode-defaulted",
                extended=True,
                posture=_posture(failModeSource="default"),
            ),
        ),
    ]


def _rejects_extended() -> list[Case]:
    no_size = build("control-at-limit", "reject-limit-without-body-size")
    del no_size["exchange"]["bodyBytes"]
    size_without_reply = build("timeout--strict", "reject-body-size-without-reply", extended=True)
    size_without_reply["exchange"]["bodyBytes"] = len('{"verdict":"block"}')
    claims_reached = build("outage--strict", "reject-circuit-open-claims-reached")
    claims_reached["exchange"].update(reached=True, httpStatus=200, bodyBytes=0)
    prefix = build(
        "oversize--default",
        "reject-oversize-prefix-parsed",
        basis="policy",
        condition="ok",
        outcome="allow",
        performed=True,
    )
    prefix["exchange"].update(bodyIsJsonObject=True, verdict="allow")
    return [
        _case(
            "limit-without-body-size",
            "control-at-limit",
            "record_malformed",
            "the record states a response limit and gives no size for the reply that arrived",
            no_size,
        ),
        _case(
            "body-size-without-reply",
            "timeout--strict",
            "record_malformed",
            "a timed-out exchange carries a body size, which only an arrived reply has",
            size_without_reply,
        ),
        _case(
            "circuit-open-claims-reached",
            "outage--strict",
            "record_malformed",
            "the breaker is recorded open on an exchange that reached the point",
            claims_reached,
        ),
        _case(
            "oversize-prefix-parsed",
            "oversize--default",
            "condition_misclassified",
            "a body one byte over the limit is truncated and its prefix read as an allow",
            prefix,
        ),
        _case(
            "oversize-allowed",
            "oversize--strict",
            "fault_allowed",
            "an oversize reply is recorded as oversize and the action allowed as a fallback",
            build("oversize--strict", "reject-oversize-allowed", outcome="allow", performed=True),
        ),
        _case(
            "circuit-open-recorded-as-unreachable",
            "outage--default",
            "condition_misclassified",
            "the client never asked, its breaker was open, and it records the point unreachable",
            build(
                "outage--default",
                "reject-circuit-open-recorded-as-unreachable",
                condition="unreachable",
            ),
        ),
        _case(
            "circuit-open-as-policy",
            "outage--strict",
            "fault_recorded_as_policy",
            "an open breaker's denial is recorded as a policy decision",
            build("outage--strict", "reject-circuit-open-as-policy", basis="policy"),
        ),
        _case(
            "circuit-open-allowed",
            "outage--default",
            "fault_allowed",
            "an open breaker lets the action through as a fallback after an outage",
            build(
                "outage--default",
                "reject-circuit-open-allowed",
                outcome="allow",
                performed=True,
            ),
        ),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, runtime scenario id, and what it shows."""
    return [*_accepts(), *_rejects()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    entries = []
    for entry in manifest["vectors"]:
        directory = Path(root) / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, scenario_id, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append(
            {
                "edit": edit,
                "expected": {"decision": decision, "reason": reason},
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(body),
                "runtime": {"scenario": SCENARIOS[scenario_id]},
            }
        )
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "suite": SUITE,
        "runtimeContract": (
            "client scenario.json, AEV_DECISION_POINT, AEV_EFFECT_SINK, "
            "AEV_DECISION_RECORD; see decisionclient_runtime"
        ),
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
