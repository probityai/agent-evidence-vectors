"""A reference decision client for the decision-client failure-mode contract.

``--policy closed`` acts only on a readable ``allow``, reads at most the
scenario's ``maxResponseBytes`` of a reply, denies on every fault in both modes,
opens a circuit breaker after three consecutive faults and denies while it is
open, records each fault as a fallback that names it, states an enforce,
fail-closed, explicitly set posture, and writes a decision record: it passes
every scenario. ``--policy open`` is the shape of a client that fails open: in
the ``default`` mode it allows on a transport fault or an open breaker, marked as
a fallback; in every mode it reads a whole reply whatever its size, and reads a
verdict it does not recognise, or a missing one, as an allow; it states the
fail-open posture it runs under. The posture flags override what the adapter
states, and ``--enforcement monitor`` also performs the action whatever was
decided, the way a monitor mode does.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from typing import Any

POINT = os.environ["AEV_DECISION_POINT"]
SINK = os.environ["AEV_EFFECT_SINK"]
RECORD = os.environ.get("AEV_DECISION_RECORD")
CONTRACT = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/decision-client-failure-modes"
)
VERDICTS = ("allow", "block", "halt")


BREAKER_THRESHOLD = 3


def ask(request: dict[str, Any], timeout: float, limit: int | None) -> dict[str, Any]:
    """The exchange facts of one decision request."""
    facts: dict[str, Any] = {
        "bodyIsJsonObject": False,
        "httpStatus": None,
        "reached": True,
        "timedOut": False,
    }
    data = json.dumps(request).encode()
    call = urllib.request.Request(
        POINT + "/decide", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(call, timeout=timeout) as reply:
            status, body = reply.status, reply.read(-1 if limit is None else limit + 1)
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read(-1 if limit is None else limit + 1)
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError | socket.timeout):
            facts["timedOut"] = True
        else:
            facts["reached"] = False
        return facts
    except TimeoutError:
        facts["timedOut"] = True
        return facts
    except (http.client.HTTPException, OSError):
        facts["reached"] = False
        return facts
    facts["httpStatus"] = status
    facts["bodyBytes"] = len(body)
    if limit is not None and len(body) > limit:
        return facts
    try:
        parsed = json.loads(body)
    except ValueError:
        return facts
    if isinstance(parsed, dict):
        facts["bodyIsJsonObject"] = True
        if "verdict" in parsed:
            facts["verdict"] = parsed["verdict"] if isinstance(parsed["verdict"], str) else ""
    return facts


def condition(facts: dict[str, Any], limit: int) -> str:
    if facts.get("circuitOpen"):
        return "circuit-open"
    if not facts["reached"]:
        return "unreachable"
    if facts["timedOut"]:
        return "timeout"
    status = facts["httpStatus"]
    if status in (401, 403):
        return "unauthorized"
    if not 200 <= status <= 299:
        return "http-error"
    if facts["bodyBytes"] > limit:
        return "oversize"
    if not facts["bodyIsJsonObject"]:
        return "unparseable-body"
    if "verdict" not in facts:
        return "missing-verdict"
    return "ok" if facts["verdict"] in VERDICTS else "unknown-verdict"


def decide(policy: str, mode: str, facts: dict[str, Any], limit: int) -> dict[str, Any]:
    found = condition(facts, limit)
    verdict = facts.get("verdict")
    if policy == "open" and found in ("unknown-verdict", "missing-verdict", "oversize"):
        return {"basis": "policy", "condition": "ok", "halted": False, "outcome": "allow"}
    if found == "ok":
        return {
            "basis": "policy",
            "condition": "ok",
            "halted": verdict == "halt",
            "outcome": "allow" if verdict == "allow" else "deny",
        }
    transport = found in (
        "circuit-open", "unreachable", "timeout", "http-error", "unparseable-body"
    )
    opened = policy == "open" and mode == "default" and transport
    return {
        "basis": "fallback",
        "condition": found,
        "halted": False,
        "outcome": "allow" if opened else "deny",
    }


def perform(action: str, args: dict[str, Any]) -> None:
    call = urllib.request.Request(
        SINK + "/effects",
        data=json.dumps({"action": action, "args": args}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(call, timeout=10) as reply:
        reply.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", choices=("closed", "open"), default="closed")
    parser.add_argument("--no-record", action="store_true")
    parser.add_argument("--no-posture", action="store_true", help="state no posture")
    parser.add_argument("--enforcement", choices=("enforce", "monitor"), default="enforce")
    parser.add_argument("--fail-mode", choices=("closed", "open"), default=None,
                        help="the fail mode to state (default: the policy's)")
    parser.add_argument("--fail-mode-source", choices=("explicit", "default"),
                        default="explicit")
    parser.add_argument("scenario")
    args = parser.parse_args()
    with open(args.scenario, encoding="utf-8") as handle:
        scenario = json.load(handle)
    request, limit = scenario["request"], scenario["maxResponseBytes"]
    posture = {
        "enforcement": args.enforcement,
        "failMode": args.fail_mode or args.policy,
        "failModeSource": args.fail_mode_source,
    }
    # The open policy is a client with no response cap: it reads the whole reply.
    cap = None if args.policy == "open" else limit
    faults = 0
    for _ in range(scenario["attempts"]):
        if faults >= BREAKER_THRESHOLD:
            facts: dict[str, Any] = {"bodyIsJsonObject": False, "circuitOpen": True,
                                     "httpStatus": None, "reached": False, "timedOut": False}
        else:
            facts = ask(request, scenario["timeoutMillis"] / 1000, cap)
        decision = decide(args.policy, scenario["mode"], facts, limit)
        faults = faults + 1 if decision["condition"] != "ok" else 0
        if decision["outcome"] == "allow" or args.enforcement == "monitor":
            perform(request["action"], request["args"])
    if RECORD and not args.no_record:
        canonical = json.dumps(request["args"], sort_keys=True, separators=(",", ":"))
        record = {
            "client": {"maxResponseBytes": limit, "mode": scenario["mode"],
                       "timeoutMillis": scenario["timeoutMillis"]},
            "contractId": CONTRACT,
            "decision": decision,
            "effect": {"performed": decision["outcome"] == "allow"
                       or args.enforcement == "monitor"},
            "exchange": facts,
            "request": {
                "action": request["action"],
                "argsDigest": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
                "consequential": request["consequential"],
            },
        }
        if not args.no_posture:
            record["posture"] = posture
        with open(RECORD, "w", encoding="utf-8") as handle:
            json.dump(record, handle, sort_keys=True)
    report: dict[str, Any] = {key: decision[key] for key in ("basis", "halted", "outcome")}
    if not args.no_posture:
        report["posture"] = posture
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
