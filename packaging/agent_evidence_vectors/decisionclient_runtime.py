"""Drive a decision client through the failure-mode matrix against a stub decision point.

The reader in ``decisionclient`` judges a record a client wrote. This module
judges the client itself. For each scenario the corpus pairs with its cases it
starts, on the loopback interface, a decision point that answers exactly as the
scenario says (or a closed port, for ``unreachable`` and ``outage``) and a
counting effect sink, runs the client's adapter against both, and counts what the
sink received.

The client contract, for an adapter in any language:

- it is run as ``<client> <scenario.json>`` with ``AEV_DECISION_POINT`` set to the
  decision point's base URL, ``AEV_EFFECT_SINK`` set to the sink's base URL and
  ``AEV_DECISION_RECORD`` set to a path it may write its decision record to; it
  must finish within 60 seconds;
- it builds the client in the scenario's ``mode``: ``default`` is the client as it
  ships, with no error-handling option set, and ``strict`` is the client's own
  strictest fail-closed setting; it sets the client's timeout to the scenario's
  ``timeoutMillis`` and the most it reads of a reply to ``maxResponseBytes``;
- it asks the decision point about the scenario's ``request`` ``attempts`` times
  in a row, with one client instance, so any circuit breaker the client has
  carries its state from one ask to the next; each ask is one POST on whatever
  path the client uses, and the point answers every POST, on any path, with the
  scenario's response; a client whose breaker is open does not ask;
- only when the client allows the action, it performs it once by ``POST
  {sink}/effects`` with a JSON body of ``action`` and ``args``;
- it prints, as the last line of its standard output, one JSON object for its
  last decision with ``outcome`` (``allow`` or ``deny``), ``basis`` (``policy``
  when the decision point's verdict decided, ``fallback`` when the client decided
  because it had no usable verdict), ``halted`` (whether the client stopped the
  run) and ``posture``, the configuration it ran under: ``enforcement``
  (``enforce`` or ``monitor``), ``failMode`` (``closed`` or ``open``) and
  ``failModeSource`` (``explicit`` when the configuration the adapter built, or
  the client's code with no option to change it, fixes the fail mode;
  ``default`` when an option left unset decided); it exits 0;
- when it writes a record to ``AEV_DECISION_RECORD``, the record is its last
  decision's, carries the posture it printed, is judged by the reader, and its
  decision must be the one printed.

A scenario passes when the sink received the accepted number of effects, the
printed decision is the accepted one, the printed posture enforces, and any
record written passes the reader and agrees with what was printed.

The posture rule. A pass is evidence only under a posture that enforces: a
client that prints no posture, or one outside the vocabulary, fails the scenario,
because an unstated posture is not evidence; ``monitor`` fails it, because a
monitored client logs a block and runs the action, so its correct decisions gate
nothing; ``open`` fails it, because a pass under a fail-open configuration says
nothing about the next fault. Under ``strict`` a ``default`` fail-mode source
fails too: the strictest setting is one the adapter set, not one it inherited.
Under ``default``, the client as shipped, a ``default`` source is what the mode
measures and is accepted, and the record such a client writes is held to every
check but ``fail_mode_defaulted``, which the reader reports for it by design: the
record of a defaulted client is a correct decision, not evidence of the
configuration. The composite action reads the posture of every row and fails the
job, with an error naming the scenario and the posture, on any that does not
enforce.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_evidence_vectors import decisionclient as reader

ENV_POINT = "AEV_DECISION_POINT"
ENV_SINK = "AEV_EFFECT_SINK"
ENV_RECORD = "AEV_DECISION_RECORD"
TIMEOUT_SECONDS = 60
REPORT_KEYS = ("outcome", "basis", "halted")
POSTURE_KEYS = ("enforcement", "failMode", "failModeSource")


def point_body(point: dict[str, Any]) -> str:
    """The body the decision point sends: ``body``, its pad filled to ``padTo`` bytes."""
    body: str = point["body"]
    if "padTo" in point:
        fill = "x" * (point["padTo"] - len(body.encode()))
        body = body.replace('"pad":""', '"pad":"' + fill + '"', 1)
        if len(body.encode()) != point["padTo"]:
            raise ValueError(f"cannot pad {point['body']!r} to {point['padTo']} bytes")
    return body


def posture_refusal(mode: str, posture: object) -> str | None:
    """Why a run under this posture is not evidence of enforcement, or None."""
    if not isinstance(posture, dict) or any(
        posture.get(key) not in allowed
        for key, allowed in zip(
            POSTURE_KEYS, (reader.ENFORCEMENTS, reader.FAIL_MODES, reader.FAIL_MODE_SOURCES),
            strict=True,
        )
    ):
        return f"the client stated no posture in the vocabulary ({posture!r}); unstated is not evidence"
    if posture["enforcement"] != "enforce":
        return f"the client ran under posture {posture!r}: a monitored client gates nothing"
    if posture["failMode"] != "closed":
        return f"the client ran under posture {posture!r}: a fail-open pass proves nothing"
    if mode == "strict" and posture["failModeSource"] != "explicit":
        return (f"the client ran strict under posture {posture!r}: the fail mode was "
                "defaulted, not set")
    return None


@dataclass
class Counts:
    """What the stub decision point and the effect sink saw; every field is a count."""

    decisions: int = 0
    effects: int = 0
    paths: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def summary(self) -> dict[str, Any]:
        return {"decisionRequests": self.decisions, "effects": self.effects}


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    return server, thread


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _point_handler(scenario: dict[str, Any], counts: Counts) -> type[BaseHTTPRequestHandler]:
    response = scenario["decisionPoint"]
    body = point_body(response).encode("utf-8")

    class Point(_Quiet):
        def do_POST(self) -> None:  # noqa: N802
            self._body()
            with counts.lock:
                counts.decisions += 1
                counts.paths.append(self.path)
            if response["delayMillis"]:
                time.sleep(response["delayMillis"] / 1000)
            try:
                self._send(response["status"], body)
            except OSError:
                return  # the client gave up waiting, as the scenario intends

    return Point


def _sink_handler(counts: Counts) -> type[BaseHTTPRequestHandler]:
    class Sink(_Quiet):
        def do_POST(self) -> None:  # noqa: N802
            self._body()
            if self.path != "/effects":
                self._send(404, b'{"error":"not found"}')
                return
            with counts.lock:
                counts.effects += 1
            self._send(200, b'{"status":"performed"}')

    return Sink


def _closed_port() -> str:
    """A loopback address nothing listens on: bound once, then released."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}"


@contextmanager
def stubs(scenario: dict[str, Any]) -> Iterator[tuple[str, str, Counts]]:
    """Serve one scenario's decision point and effect sink on the loopback interface.

    Yields the point's URL, the sink's URL and the counts, which a Python client's
    own test reads after driving its client against the URLs.
    """
    counts = Counts()
    with ExitStack() as stack:
        sink, sink_thread = _serve(_sink_handler(counts))
        stack.callback(sink_thread.join)
        stack.callback(sink.server_close)
        stack.callback(sink.shutdown)
        if scenario["decisionPoint"]["listen"]:
            point, point_thread = _serve(_point_handler(scenario, counts))
            stack.callback(point_thread.join)
            stack.callback(point.server_close)
            stack.callback(point.shutdown)
            point_url = f"http://127.0.0.1:{point.server_address[1]}"
        else:
            point_url = _closed_port()
        yield point_url, f"http://127.0.0.1:{sink.server_address[1]}", counts


def judge(scenario: dict[str, Any], counts: Counts, reported: dict[str, Any] | None,
          record_path: Path | None) -> list[str]:
    """Why the client failed this scenario; empty when it passed."""
    accepted = scenario["accepted"]
    problems = []
    if counts.effects != accepted["effects"]:
        problems.append(f"the sink received {counts.effects} effect(s); accepted: "
                        f"{accepted['effects']}")
    wanted = {key: accepted[key] for key in REPORT_KEYS}
    decided = None if reported is None else {key: reported[key] for key in REPORT_KEYS}
    if decided != wanted:
        problems.append(f"the client reported {decided}; accepted: {wanted}")
    posture = None if reported is None else reported.get("posture")
    refusal = posture_refusal(scenario["mode"], posture)
    if refusal is not None:
        problems.append(refusal)
    if record_path is not None and record_path.exists():
        problems.extend(_record_problems(scenario["mode"], record_path, reported))
    return problems


def _record_problems(mode: str, record_path: Path,
                     reported: dict[str, Any] | None) -> list[str]:
    """Why the record the client wrote does not hold; empty when it does."""
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        recorded = record["decision"]["outcome"]
        posture = record.get("posture")
        defaulted = (mode == "default" and isinstance(posture, dict)
                     and posture.get("failModeSource") == "default")
        # A shipped default is what the default mode measures: the record is held
        # to every check but the one that says a defaulted posture is not evidence.
        skip = frozenset({"fail_mode_defaulted"}) if defaulted else frozenset()
        answer = reader.verify(record_path, skip)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return [f"the decision record does not read: {exc}"]
    problems = []
    if answer["decision"] != reader.ALLOW:
        problems.append(f"the decision record fails the reader: {answer['reason']}")
    if reported is not None and recorded != reported["outcome"]:
        problems.append(f"the record says {recorded!r}, the client printed "
                        f"{reported['outcome']!r}")
    if reported is not None and posture != reported.get("posture"):
        problems.append(f"the record states posture {posture!r}, the client printed "
                        f"{reported.get('posture')!r}")
    return problems


def _reported(stdout: str) -> dict[str, Any] | None:
    """The decision the last line reports, with its posture as printed (None if absent).

    A missing posture does not make the decision unreadable: the scenario still
    reports what the client did, and fails on the posture alone.
    """
    lines = [line for line in stdout.strip().splitlines() if line.strip()]
    try:
        answer = json.loads(lines[-1])
        reported = {key: answer[key] for key in REPORT_KEYS}
    except (IndexError, ValueError, KeyError, TypeError):
        return None
    if (reported["outcome"] not in reader.OUTCOMES or reported["basis"] not in reader.BASES
            or not isinstance(reported["halted"], bool)):
        return None
    reported["posture"] = answer.get("posture")
    return reported


def drive(command: list[str], scenario: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    """Run the adapter through one scenario: whether it ran, its failures and the counts."""
    with tempfile.TemporaryDirectory() as work, stubs(scenario) as (point, sink, counts):
        path = Path(work) / "scenario.json"
        record = Path(work) / "record.json"
        path.write_text(json.dumps(scenario, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        env = {**os.environ, ENV_POINT: point, ENV_SINK: sink, ENV_RECORD: str(record)}
        try:
            result = subprocess.run([*command, str(path)], capture_output=True, text=True,
                                    timeout=TIMEOUT_SECONDS, check=False, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, [f"client did not run: {exc}"], counts.summary()
        reported = _reported(result.stdout)
        observed = {**counts.summary(), "recordWritten": record.exists()}
        if result.returncode != 0 or reported is None:
            tail = result.stderr.strip().splitlines()[-1:] if result.stderr else []
            return True, [f"client exited {result.returncode} without reporting a decision "
                          f"{tail}"], observed
        return True, judge(scenario, counts, reported, record), {**observed, **reported}


def check_runtime(client: str | list[str], root: Path = reader.ROOT) -> dict[str, Any]:
    """Drive the client through every scenario and return the report body."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    command = shlex.split(client) if isinstance(client, str) else client
    if not command:
        raise ValueError("client command is empty")
    rows: list[dict[str, Any]] = []
    failed: list[str] = []
    failures: list[str] = []
    executed = 0
    for scenario in reader.scenarios(manifest["vectors"]):
        ran, problems, observed = drive(command, scenario)
        executed += int(ran)
        if problems:
            failed.append(scenario["id"])
        failures.extend(f"{scenario['id']}: {problem}" for problem in problems)
        rows.append({"id": scenario["id"], "kind": "runtime", "observed": observed,
                     "reasons": problems, "status": "FAIL" if problems else "PASS"})
    total = len(rows)
    return {
        "suite": reader.SUITE, "rail": "external", "unit": "runtime scenario",
        "verifier": {"command": command, "vectorsExecuted": executed,
                     "note": "client contract: <client> <scenario.json>, AEV_DECISION_POINT, "
                             "AEV_EFFECT_SINK, AEV_DECISION_RECORD; the last line states "
                             "the posture"},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(failed), "fail": len(failed),
                   "suiteRefusals": 0},
        "vectors": rows, "failures": failures,
    }


def run_runtime(client: str | list[str], report_path: str, root: Path = reader.ROOT) -> int:
    """Write the runtime report; exit 0 only when every scenario ran and passed."""
    report = check_runtime(client, root)
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    for failure in report["failures"]:
        print(failure)
    totals = report["totals"]
    executed = report["verifier"]["vectorsExecuted"]
    print(f"{reader.SUITE}: client ran {executed} of {totals['vectors']} scenarios, "
          f"{totals['conform']} passed, {totals['fail']} failed")
    if not executed:
        return 2
    return 1 if totals["fail"] or executed != totals["vectors"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or reader.SUITE).splitlines()[0])
    parser.add_argument("--runtime", required=True,
                        help="adapter command, run as <client> <scenario.json>")
    parser.add_argument("--report", default="decision-client-runtime-report.json")
    parser.add_argument("--vectors", default=None, help="corpus directory (default: shipped)")
    args = parser.parse_args(argv)
    root = Path(args.vectors) if args.vectors else reader.ROOT
    return run_runtime(args.runtime, args.report, root)


if __name__ == "__main__":
    raise SystemExit(main())
