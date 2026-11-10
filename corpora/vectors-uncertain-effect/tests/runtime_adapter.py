"""A reference runtime for the uncertain-effect runtime contract.

``--policy reconcile`` asks the owner before it sends again after a lost reply,
waits for a final answer, and checks its lease before every dispatch: it passes
every scenario. ``--policy blind`` resends at once after any failure, the way a
plain retry wrapper does: it leaves two effects where the first one committed.
``--policy task-keyed`` is a reconciling runtime that derives its idempotency key from the
engine's task identifier, so a redelivery under a new task defeats the owner's deduplication.

The reconciling policy keeps a checkpoint in ``AEV_STATE_DIR``: it claims the step with an
exclusive file before the first send, so two deliveries of one step cannot both send, and a run
that finds an earlier run's trace, or runs as ``AEV_RUN`` above 1, asks the owner by key before
it sends anything and sends only on a final answer that the effect is absent.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

OWNER = os.environ["AEV_EFFECT_OWNER"]


def _get(path: str) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(OWNER + path, timeout=5) as reply:
            answer: dict[str, Any] = json.loads(reply.read())
            return answer
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _post(body: dict[str, Any]) -> str:
    """``confirmed``, ``no_effect`` or ``unknown`` for one call."""
    request = urllib.request.Request(OWNER + "/effects", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:
            return "confirmed" if json.loads(reply.read())["status"] == "confirmed" else "unknown"
    except urllib.error.HTTPError as error:
        return "no_effect" if error.code == 409 else "unknown"
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return "unknown"


def _settle(key: str) -> str | None:
    """Ask until the owner gives a final answer; None while it cannot answer."""
    for _ in range(5):
        answer = _get(f"/effects/{key}")
        if answer is None:
            return None
        if answer["result"] == "present":
            return "present"
        if answer["final"]:
            return "absent"
        time.sleep(0.05)
    return None


def _holds(token: int | None) -> bool:
    if token is None:
        return True
    lease = _get("/lease")
    return lease is not None and lease["token"] == token


def reconcile(body: dict[str, Any], token: int | None) -> str:
    for _ in range(3):
        if not _holds(token):
            return {"present": "committed"}.get(_settle(body["idempotencyKey"]) or "", "unknown")
        reply = _post(body)
        if reply == "confirmed":
            return "committed"
        if reply == "unknown":
            settled = _settle(body["idempotencyKey"])
            if settled != "absent":
                return "committed" if settled == "present" else "unknown"
    return "not_run"


def _claim(key: str) -> bool:
    """Whether this run is the first delivery of the step and claimed it exclusively."""
    directory = os.environ.get("AEV_STATE_DIR")
    first = int(os.environ.get("AEV_RUN", "1")) == 1
    if not directory:
        return first
    try:
        os.close(os.open(os.path.join(directory, f"claim-{key}"),
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except FileExistsError:
        return False
    return first


def _done_path(key: str) -> str | None:
    directory = os.environ.get("AEV_STATE_DIR")
    return os.path.join(directory, f"done-{key}") if directory else None


def _await_done(key: str) -> str | None:
    """The outcome the run that claimed the step recorded, if it finishes within a second."""
    path = _done_path(key)
    for _ in range(20):
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                return handle.read().strip() or None
        time.sleep(0.05)
    return None


def restart_safe(body: dict[str, Any], token: int | None) -> str:
    """Send only when this run owns the step; otherwise settle it with the owner."""
    key = body["idempotencyKey"]
    if _claim(key):
        outcome = reconcile(body, token)
        path = _done_path(key)
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(outcome)
        return outcome
    if _await_done(key) == "committed":
        return "committed"
    settled = _settle(body["idempotencyKey"])
    if settled == "present":
        return "committed"
    return reconcile(body, token) if settled == "absent" else "unknown"


def blind(body: dict[str, Any]) -> str:
    for _ in range(3):
        if _post(body) == "confirmed":
            return "committed"
    return "not_run"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", choices=("reconcile", "blind", "task-keyed"),
                        default="reconcile")
    parser.add_argument("scenario")
    args = parser.parse_args()
    with open(args.scenario, encoding="utf-8") as handle:
        scenario = json.load(handle)
    operation = scenario["operation"]
    lease = scenario["owner"].get("lease")
    token = lease["token"] if lease else None
    body: dict[str, Any] = {"args": operation["args"],
                            "idempotencyKey": operation["idempotencyKey"]}
    if token is not None:
        body["fencingToken"] = token
    if args.policy == "task-keyed":
        body["idempotencyKey"] = f"{body['idempotencyKey']}:{os.environ.get('AEV_TASK_ID', '')}"
    outcome = blind(body) if args.policy == "blind" else restart_safe(body, token)
    print(json.dumps({"outcome": outcome}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
