"""Drive a runtime through the uncertain-effect scenarios against a counting effect owner.

The reader in ``uncertaineffect`` judges a trail a runtime left. This module
judges the runtime itself. For each scenario the corpus pairs with its cases it
starts an effect owner on the loopback interface that commits, loses replies,
answers lookups and moves a lease exactly as the scenario says, runs the
runtime's adapter against it, and counts what the owner holds afterwards.

The runtime contract, for an adapter in any language:

- it is run as ``<runtime> <scenario.json>`` with ``AEV_EFFECT_OWNER`` set to
  the owner's base URL, and must finish within 60 seconds;
- it performs the scenario's ``operation`` once, through the runtime's own
  execution and retry path, by ``POST {owner}/effects`` with a JSON body of
  ``idempotencyKey``, ``args`` and, when the scenario names a lease,
  ``fencingToken``;
- it may ask the owner ``GET {owner}/effects/{idempotencyKey}``, which answers
  ``{"result": "present" | "absent", "final": bool}`` (or 503 while the owner
  cannot answer), and, in a lease
  scenario, ``GET {owner}/lease``, which answers ``{"token": n}``;
- it prints, as the last line of its standard output, one JSON object whose
  ``outcome`` is ``committed``, ``not_run`` or ``unknown``, and exits 0;
- in a scenario with a ``restart`` block it is run more than once, as the engine
  would run a step that crashed, was redelivered, was replayed or was completed
  twice. Each run gets ``AEV_RUN`` (1 for the first delivery), ``AEV_TASK_ID``
  (the engine's identifier for this delivery, which is the same for every run
  only when the scenario says ``"taskId": "same"``) and ``AEV_STATE_DIR``, a
  directory its checkpoint may use, which is emptied between runs when the
  scenario says ``"state": "wiped"``. ``"mode": "crash"`` kills the first run
  once the owner has received its call; ``"rerun"`` lets it finish first;
  ``"concurrent"`` starts two deliveries together, both with ``AEV_RUN=1``.
  The operation's idempotency key is the same in every run: a key derived from
  the task identifier is the fault this tests.

A lost reply is a connection the owner closes without answering, after it has
or has not applied the effect. A scenario passes when the owner holds an
accepted number of effects and the runtime reports the accepted outcome with
it, no call carried the operation's key with other arguments, and no call in a
lease scenario carried a missing or superseded fencing token.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import shutil
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_evidence_vectors import uncertaineffect as reader

ENV_OWNER = "AEV_EFFECT_OWNER"
ENV_RUN, ENV_TASK, ENV_STATE = "AEV_RUN", "AEV_TASK_ID", "AEV_STATE_DIR"
TIMEOUT_SECONDS = 60
# Seconds a held call stays in flight before the owner applies it.
HOLD_SECONDS = 0.4
# commit_hold applies the effect while the caller waits and then drops the reply, so a
# caller killed meanwhile still leaves the effect; commit_slow applies it the same way and
# then replies.
HELD = ("commit_hold", "commit_slow")
CALL_BEHAVIOURS = ("commit", "commit_drop", "commit_hold", "commit_slow", "drop",
                   "late_commit", "no_effect")
RESTART_MODES = ("crash", "rerun", "concurrent")
LOOKUP_BEHAVIOURS = ("final", "non_final", "unavailable")


@dataclass
class OwnerState:
    """What the counting owner saw and holds; every field is a count or a log."""

    scenario: dict[str, Any]
    effects: int = 0
    calls: int = 0
    lookups: int = 0
    stale_calls: int = 0
    key_args_conflicts: int = 0
    applied_keys: set[str] = field(default_factory=set)
    first_args: dict[str, str] = field(default_factory=dict)
    pending_late: list[str] = field(default_factory=list)
    in_flight: list[str] = field(default_factory=list)
    forgotten: set[str] = field(default_factory=set)
    lease_token: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def summary(self) -> dict[str, int]:
        return {"calls": self.calls, "effects": self.effects,
                "keyArgsConflicts": self.key_args_conflicts, "lookups": self.lookups,
                "staleCalls": self.stale_calls}


def _behaviour(sequence: list[str], index: int, default: str) -> str:
    """The scenario's behaviour for one call: past the list, ``default``."""
    return sequence[index] if index < len(sequence) else default


def _lookup_behaviour(sequence: list[str], index: int) -> str:
    """The behaviour for one lookup: past the list, the last one repeats."""
    return sequence[min(index, len(sequence) - 1)] if sequence else "final"


def _apply(state: OwnerState, key: str) -> None:
    owner = state.scenario["owner"]
    if owner["deduplicatesByKey"] and key in state.applied_keys:
        return
    state.applied_keys.add(key)
    state.effects += 1


def _forget_due(state: OwnerState) -> None:
    """Make the owner forget its keys once it has handled the scenario's number of calls."""
    after = state.scenario["owner"].get("forgetsKeysAfterCalls")
    if after is not None and state.calls >= after:
        state.forgotten |= state.applied_keys
        state.applied_keys.clear()


def _record_call(state: OwnerState, body: dict[str, Any]) -> str:
    """Count one effect call and return the behaviour the scenario gives it."""
    key = str(body.get("idempotencyKey") or "")
    args = json.dumps(body.get("args"), sort_keys=True, separators=(",", ":"))
    if state.first_args.setdefault(key, args) != args:
        state.key_args_conflicts += 1
    lease = state.scenario["owner"].get("lease")
    if lease is not None:
        token = body.get("fencingToken")
        if not isinstance(token, int) or token < state.lease_token:
            state.stale_calls += 1
    behaviour = _behaviour(state.scenario["owner"]["calls"], state.calls, "commit")
    state.calls += 1
    if lease is not None and state.calls >= lease["lostAfterCall"]:
        state.lease_token = lease["token"] + 1
    return behaviour


def _call(state: OwnerState, body: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
    """Apply the scenario's behaviour for one call; None means the reply is lost."""
    key = str(body.get("idempotencyKey") or "")
    with state.lock:
        # A late commit has landed by the time any later request reaches the owner.
        _land_late(state)
        behaviour = _record_call(state, body)
        if behaviour in ("commit", "commit_drop"):
            _apply(state, key)
            _forget_due(state)
        elif behaviour == "late_commit":
            state.pending_late.append(key)
        elif behaviour in HELD:
            state.in_flight.append(key)
    if behaviour in HELD:
        # The owner commits while the caller waits, also when the caller is killed meanwhile.
        time.sleep(HOLD_SECONDS)
        with state.lock:
            state.in_flight.remove(key)
            _apply(state, key)
            _forget_due(state)
    if behaviour in ("commit", "commit_slow"):
        return 200, {"status": "confirmed"}
    if behaviour == "no_effect":
        return 409, {"status": "no_effect"}
    return 0, None


def _lookup(state: OwnerState, key: str) -> dict[str, Any] | None:
    """The owner's answer about one key; None while the owner cannot answer."""
    with state.lock:
        behaviour = _lookup_behaviour(state.scenario["owner"]["lookups"], state.lookups)
        state.lookups += 1
        if behaviour == "unavailable":
            return None
        present = key in state.applied_keys
        # A key still in flight, or one the owner forgot, cannot be answered finally.
        unsettled = not present and (key in state.in_flight or key in state.forgotten)
        answer = {"final": (behaviour == "final" or present) and not unsettled,
                  "result": "present" if present else "absent"}
        # A late commit lands after the lookup that missed it, which is why a
        # lookup that is not final settles nothing.
        _land_late(state)
    return answer


def _land_late(state: OwnerState) -> None:
    for late in state.pending_late:
        _apply(state, late)
    state.pending_late.clear()


def _post_reply(state: OwnerState, path: str, raw: bytes) -> tuple[int, dict[str, Any] | None]:
    """The owner's answer to one POST; None means it closes without answering."""
    if path != "/effects":
        return 404, {"error": "not found"}
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        return 400, {"error": "body is not JSON"}
    return _call(state, body if isinstance(body, dict) else {})


def _get_reply(state: OwnerState, path: str) -> tuple[int, dict[str, Any]]:
    """The owner's answer to one GET: the lease, a lookup, or not found."""
    if path == "/lease":
        return 200, {"token": state.lease_token}
    if not path.startswith("/effects/"):
        return 404, {"error": "not found"}
    answer = _lookup(state, path.removeprefix("/effects/"))
    if answer is None:
        return 503, {"error": "the owner cannot answer lookups now"}
    return 200, answer


def _handler(state: OwnerState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            status, reply = _post_reply(state, self.path, self.rfile.read(length))
            if reply is None:
                # The lost reply: the owner has acted, or not, and says nothing.
                self.close_connection = True
                self.request.shutdown(socket.SHUT_RDWR)
                return
            self._send(status, reply)

        def do_GET(self) -> None:  # noqa: N802
            self._send(*_get_reply(state, self.path))

    return Handler


@contextmanager
def effect_owner(scenario: dict[str, Any]) -> Iterator[tuple[str, OwnerState]]:
    """Serve one scenario's counting owner on the loopback interface.

    Yields the base URL and the owner's state, which a Python runtime's own test
    reads after driving its runtime against the URL.
    """
    state = OwnerState(scenario=scenario)
    lease = scenario["owner"].get("lease")
    state.lease_token = lease["token"] if lease is not None else 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def judge(scenario: dict[str, Any], state: OwnerState, outcome: str | None) -> list[str]:
    """Why the runtime failed this scenario; empty when it passed."""
    problems = []
    if state.key_args_conflicts:
        problems.append(f"{state.key_args_conflicts} call(s) reused the key with other arguments")
    if state.stale_calls:
        problems.append(f"{state.stale_calls} call(s) carried a missing or superseded "
                        "fencing token")
    result = {"effects": state.effects, "outcome": outcome}
    if result not in scenario["accepted"]:
        problems.append(f"the owner holds {state.effects} effect(s) and the runtime reported "
                        f"{outcome!r}; accepted: {scenario['accepted']}")
    return problems


def _reported_outcome(stdout: str) -> str | None:
    lines = [line for line in stdout.strip().splitlines() if line.strip()]
    try:
        outcome = json.loads(lines[-1])["outcome"]
    except (IndexError, ValueError, KeyError, TypeError):
        return None
    return outcome if outcome in reader.OUTCOMES else None


def _spawn(command: list[str], path: Path, env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen([*command, str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)


def _finish(process: subprocess.Popen[str]) -> tuple[int, str | None]:
    out, _ = process.communicate(timeout=TIMEOUT_SECONDS)
    return process.returncode, _reported_outcome(out)


def _wipe(state_dir: Path) -> None:
    shutil.rmtree(state_dir)
    state_dir.mkdir()


def combined_outcome(outcomes: list[str]) -> tuple[str, list[str]]:
    """One outcome for several runs of one step, and why the runs contradict each other."""
    problems = []
    if "committed" in outcomes and "not_run" in outcomes:
        problems.append("one run reported not_run while another reported committed")
    pick = ("committed" if "committed" in outcomes else
            "unknown" if "unknown" in outcomes else "not_run")
    return pick, problems


def _restart_runs(command: list[str], path: Path, url: str, state: OwnerState,
                  state_dir: Path, restart: dict[str, str]) -> list[tuple[int, str | None]]:
    """Run the adapter as the engine would across a crash, a rerun or a double delivery."""
    tasks = ["task-1", "task-1" if restart["taskId"] == "same" else "task-2"]

    def env(run: int, task: str) -> dict[str, str]:
        return {**os.environ, ENV_OWNER: url, ENV_RUN: str(run), ENV_TASK: task,
                ENV_STATE: str(state_dir)}

    if restart["mode"] == "concurrent":
        pair = [_spawn(command, path, env(1, task)) for task in tasks]
        return [_finish(process) for process in pair]
    first = _spawn(command, path, env(1, tasks[0]))
    runs: list[tuple[int, str | None]] = []
    if restart["mode"] == "crash":
        deadline = time.monotonic() + 10
        while state.calls < 1 and first.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        first.kill()
        first.communicate()
    else:
        runs.append(_finish(first))
    if restart["state"] == "wiped":
        _wipe(state_dir)
    runs.append(_finish(_spawn(command, path, env(2, tasks[1]))))
    return runs


def _drive_restart(
    command: list[str], path: Path, url: str, state: OwnerState, state_dir: Path,
    scenario: dict[str, Any],
) -> tuple[bool, list[str], dict[str, Any]]:
    try:
        runs = _restart_runs(command, path, url, state, state_dir, scenario["restart"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, [f"runtime did not run: {exc}"], state.summary()
    bad = [code for code, outcome in runs if code != 0 or outcome is None]
    if bad:
        return True, [f"{len(bad)} run(s) exited without reporting an outcome"], state.summary()
    outcome, contradictions = combined_outcome([str(o) for _, o in runs])
    return True, [*contradictions, *judge(scenario, state, outcome)], \
        {**state.summary(), "outcome": outcome, "runs": len(runs)}


def drive(command: list[str], scenario: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    """Run the adapter through one scenario: whether it ran, its failures and the counts."""
    with tempfile.TemporaryDirectory() as work, effect_owner(scenario) as (url, state):
        path = Path(work) / "scenario.json"
        path.write_text(json.dumps(scenario, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        state_dir = Path(work) / "state"
        state_dir.mkdir()
        if scenario.get("restart"):
            return _drive_restart(command, path, url, state, state_dir, scenario)
        try:
            result = subprocess.run([*command, str(path)], capture_output=True, text=True,
                                    timeout=TIMEOUT_SECONDS, check=False,
                                    env={**os.environ, ENV_OWNER: url})
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, [f"runtime did not run: {exc}"], state.summary()
        outcome = _reported_outcome(result.stdout)
        if result.returncode != 0 or outcome is None:
            return True, [f"runtime exited {result.returncode} without reporting an outcome"], \
                state.summary()
        return True, judge(scenario, state, outcome), {**state.summary(), "outcome": outcome}


def check_runtime(runtime: str | list[str], root: Path = reader.ROOT) -> dict[str, Any]:
    """Drive the runtime through every scenario and return the report body."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    command = shlex.split(runtime) if isinstance(runtime, str) else runtime
    if not command:
        raise ValueError("runtime command is empty")
    rows: list[dict[str, Any]] = []
    failures: list[str] = []
    executed = 0
    for scenario in reader.scenarios(manifest["vectors"]):
        ran, problems, counts = drive(command, scenario)
        executed += int(ran)
        failures.extend(f"{scenario['id']}: {problem}" for problem in problems)
        rows.append({"id": scenario["id"], "kind": "runtime", "observed": counts,
                     "reasons": problems, "status": "FAIL" if problems else "PASS"})
    total = len(rows)
    return {
        "suite": reader.SUITE, "rail": "external", "unit": "runtime scenario",
        "verifier": {"command": command, "vectorsExecuted": executed,
                     "note": "runtime contract: <runtime> <scenario.json>, AEV_EFFECT_OWNER"},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len({f.split(':')[0] for f in failures}),
                   "fail": len({f.split(':')[0] for f in failures}), "suiteRefusals": 0},
        "vectors": rows, "failures": failures,
    }


def run_runtime(runtime: str | list[str], report_path: str, root: Path = reader.ROOT) -> int:
    """Write the runtime report; exit 0 only when every scenario ran and passed."""
    report = check_runtime(runtime, root)
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    for failure in report["failures"]:
        print(failure)
    totals = report["totals"]
    executed = report["verifier"]["vectorsExecuted"]
    print(f"{reader.SUITE}: runtime ran {executed} of {totals['vectors']} scenarios, "
          f"{totals['fail']} failed")
    if not executed:
        return 2
    return 1 if totals["fail"] or executed != totals["vectors"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or reader.SUITE).splitlines()[0])
    parser.add_argument("--runtime", required=True,
                        help="adapter command, run as <runtime> <scenario.json>")
    parser.add_argument("--report", default="uncertain-effect-runtime-report.json")
    parser.add_argument("--vectors", default=None, help="corpus directory (default: shipped)")
    args = parser.parse_args(argv)
    root = Path(args.vectors) if args.vectors else reader.ROOT
    return run_runtime(args.runtime, args.report, root)


if __name__ == "__main__":
    raise SystemExit(main())
