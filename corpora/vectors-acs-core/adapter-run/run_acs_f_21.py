"""Drive the reference Python client's section 6.4 resolution with family acs-f-21.

Run from a checkout of GenAI-Security-Project/agent-control-standard with its
`adapters/src` importable:

    PYTHONPATH=adapters/src python3 -s run_acs_f_21.py <corpora/vectors-acs-core>

Each acs-f-21 member names what came back from the Guardian and who set which
posture. This script builds the client's own outcome for that answer, using the
client's own refusal sets, applies the client's own `FailPosture`, and compares
whether the step proceeds with what the member requires. Members whose verdict
turns on the audit record or on an observed effect are counted and skipped by
name: posture resolution alone cannot answer them, so they are not scored here.

Exit 0 when every scored member agrees, 1 when any disagrees, 2 when the run
could not be made (the client does not import, or the corpus is missing).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

OUTCOME_REQUIREMENTS = {"ACS-R-074", "ACS-R-075", "ACS-R-078", "ACS-R-079", "ACS-R-080"}
RECORD_REQUIREMENTS = {"ACS-R-076", "ACS-R-077", "ACS-R-081"}


def load_client():
    # The reference client is the external ACS package, installed only for this
    # run; it is imported by name so the repository's type pass does not treat
    # its absence as a missing import.
    from importlib import import_module

    FailPosture = import_module("acs.client._config").FailPosture
    HTTP_REFUSAL_STATUSES = import_module("acs.client._exchange").HTTP_REFUSAL_STATUSES
    outcome = import_module("acs.client._outcome")
    Refused, Undecided = outcome.Refused, outcome.Undecided
    is_guardian_refusal = import_module("acs.core._errors").is_guardian_refusal

    return FailPosture, HTTP_REFUSAL_STATUSES, Refused, Undecided, is_guardian_refusal


def client_outcome(answer, client):
    """The client's own outcome for the member's answer, as `_exchange.py` classifies it."""
    _, http_refusals, refused, undecided, is_refusal = client
    kind = answer["kind"]
    if kind == "silent":
        return undecided("decision_timeout")
    if kind == "http_status":
        status = answer["status"]
        if status in http_refusals:
            return refused(f"http_{status}_refusal")
        return undecided(f"http_{status}_error")
    if kind == "jsonrpc_error":
        if not answer["signed"]:
            return refused("error_signature_invalid")
        return refused("guardian_error") if is_refusal(answer["code"]) else undecided("guardian_error")
    raise ValueError(f"unknown answer kind {kind!r}")


def proceeds(payload, client) -> bool:
    fail_posture = client[0]
    agent = payload["agent_config"].get("on_decision_failure")
    # Config.from_env: deny unless ACS_DEFAULT_DENY=0, which is how the
    # Observed Agent's own configuration opts into proceed.
    posture = fail_posture(deny_on_failure=agent != "proceed", timeout_s=5.0)
    posture = posture.negotiated(payload["server_hello"] or None)
    return posture.resolve(client_outcome(payload["guardian_answer"], client)).proceed


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1])
    try:
        manifest = json.loads((root / "MANIFEST.json").read_text())
        client = load_client()
    except (OSError, ValueError, ImportError) as exc:
        print(f"NOT RUN: {exc}", file=sys.stderr)
        return 2
    members = [v for v in manifest["vectors"] if v["family"] == "acs-f-21"]
    scored = agreed = 0
    skipped = []
    for entry in members:
        member = json.loads((root / entry["file"]).read_text())
        payload, reqs = member["payload"], set(member["requirements"])
        if member["kind"] == "reject" and reqs & RECORD_REQUIREMENTS:
            skipped.append(entry["id"])
            continue
        if not reqs & OUTCOME_REQUIREMENTS:
            skipped.append(entry["id"])
            continue
        if "observed_effects" in payload or "retry" in payload:
            skipped.append(entry["id"])
            continue
        recorded = payload["step_outcome"] == "proceeded"
        required = recorded if member["kind"] == "accept" else not recorded
        got = proceeds(payload, client)
        scored += 1
        ok = got == required
        agreed += ok
        answer = payload["guardian_answer"]
        print(
            f"{'PASS' if ok else 'FAIL'} {entry['id']} {member['kind']:6} "
            f"answer={answer.get('code', answer.get('status', answer['kind']))} "
            f"signed={answer.get('signed', '-')} agent={payload['agent_config'].get('on_decision_failure')} "
            f"guardian={payload['server_hello'].get('on_decision_failure')} "
            f"required={'proceed' if required else 'block'} client={'proceed' if got else 'block'}"
        )
    print(f"acs-f-21: {agreed} of {scored} scored members agree; {len(skipped)} of {len(members)} "
          f"not scored here (record or effect members): {' '.join(skipped)}")
    return 0 if agreed == scored and scored else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
