"""A reference decision client for the decision-client failure-mode contract.

``--policy closed`` acts only on a readable ``allow``, denies on every fault in
both modes, records each fault as a fallback that names it, and writes a decision
record: it passes every scenario. ``--policy open`` is the shape of a client that
fails open: in the ``default`` mode it allows on a transport fault, marked as a
fallback, and in every mode it reads a verdict it does not recognise, or a missing
one, as an allow. It fails the scenarios that show it.
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


def ask(request: dict[str, Any], timeout: float) -> dict[str, Any]:
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
            status, body = reply.status, reply.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
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
    try:
        parsed = json.loads(body)
    except ValueError:
        return facts
    if isinstance(parsed, dict):
        facts["bodyIsJsonObject"] = True
        if "verdict" in parsed:
            facts["verdict"] = parsed["verdict"] if isinstance(parsed["verdict"], str) else ""
    return facts


def condition(facts: dict[str, Any]) -> str:
    if not facts["reached"]:
        return "unreachable"
    if facts["timedOut"]:
        return "timeout"
    status = facts["httpStatus"]
    if status in (401, 403):
        return "unauthorized"
    if not 200 <= status <= 299:
        return "http-error"
    if not facts["bodyIsJsonObject"]:
        return "unparseable-body"
    if "verdict" not in facts:
        return "missing-verdict"
    return "ok" if facts["verdict"] in VERDICTS else "unknown-verdict"


def decide(policy: str, mode: str, facts: dict[str, Any]) -> dict[str, Any]:
    found = condition(facts)
    verdict = facts.get("verdict")
    if policy == "open" and found in ("unknown-verdict", "missing-verdict"):
        return {"basis": "policy", "condition": "ok", "halted": False, "outcome": "allow"}
    if found == "ok":
        return {
            "basis": "policy",
            "condition": "ok",
            "halted": verdict == "halt",
            "outcome": "allow" if verdict == "allow" else "deny",
        }
    transport = found in ("unreachable", "timeout", "http-error", "unparseable-body")
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
    parser.add_argument("scenario")
    args = parser.parse_args()
    with open(args.scenario, encoding="utf-8") as handle:
        scenario = json.load(handle)
    request = scenario["request"]
    facts = ask(request, scenario["timeoutMillis"] / 1000)
    decision = decide(args.policy, scenario["mode"], facts)
    if decision["outcome"] == "allow":
        perform(request["action"], request["args"])
    if RECORD and not args.no_record:
        canonical = json.dumps(request["args"], sort_keys=True, separators=(",", ":"))
        record = {
            "client": {"mode": scenario["mode"], "timeoutMillis": scenario["timeoutMillis"]},
            "contractId": CONTRACT,
            "decision": decision,
            "effect": {"performed": decision["outcome"] == "allow"},
            "exchange": facts,
            "request": {
                "action": request["action"],
                "argsDigest": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
                "consequential": request["consequential"],
            },
        }
        with open(RECORD, "w", encoding="utf-8") as handle:
            json.dump(record, handle, sort_keys=True)
    print(json.dumps({key: decision[key] for key in ("basis", "halted", "outcome")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
