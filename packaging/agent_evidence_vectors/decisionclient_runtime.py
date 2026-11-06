"""Drive a decision client through the failure-mode matrix against a stub decision point.

The reader in ``decisionclient`` judges a record a client wrote. This module
judges the client itself. For each scenario the corpus pairs with its cases it
starts, on the loopback interface, a decision point that answers exactly as the
scenario says (or a closed port, for ``unreachable``) and a counting effect sink,
runs the client's adapter against both, and counts what the sink received.

The client contract, for an adapter in any language:

- it is run as ``<client> <scenario.json>`` with ``AEV_DECISION_POINT`` set to the
  decision point's base URL, ``AEV_EFFECT_SINK`` set to the sink's base URL and
  ``AEV_DECISION_RECORD`` set to a path it may write its decision record to; it
  must finish within 60 seconds;
- it builds the client in the scenario's ``mode``: ``default`` is the client as it
  ships, with no error-handling option set, and ``strict`` is the client's own
  strictest fail-closed setting; it sets the client's timeout to the scenario's
  ``timeoutMillis``;
- it asks the decision point about the scenario's ``request`` with one POST on
  whatever path the client uses: the point answers every POST, on any path, with
  the scenario's response;
- only when the client allows the action, it performs it once by ``POST
  {sink}/effects`` with a JSON body of ``action`` and ``args``;
- it prints, as the last line of its standard output, one JSON object with
  ``outcome`` (``allow`` or ``deny``), ``basis`` (``policy`` when the decision
  point's verdict decided, ``fallback`` when the client decided because it had no
  usable verdict) and ``halted`` (whether the client stopped the run), and exits 0;
- when it writes a record to ``AEV_DECISION_RECORD``, the record is judged by the
  reader, and its decision must be the one printed.

A scenario passes when the sink received the accepted number of effects, the
printed decision is the accepted one, and any record written passes the reader
and agrees with the printed decision.
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

    class Point(_Quiet):
        def do_POST(self) -> None:  # noqa: N802
            self._body()
            with counts.lock:
                counts.decisions += 1
                counts.paths.append(self.path)
            if response["delayMillis"]:
                time.sleep(response["delayMillis"] / 1000)
            try:
                self._send(response["status"], response["body"].encode("utf-8"))
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
    if reported != wanted:
        problems.append(f"the client reported {reported}; accepted: {wanted}")
    if record_path is not None and record_path.exists():
        try:
            answer = reader.verify(record_path)
            record = json.loads(record_path.read_text(encoding="utf-8"))
            recorded = record["decision"]["outcome"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return [*problems, f"the decision record does not read: {exc}"]
        if answer["decision"] != reader.ALLOW:
            problems.append(f"the decision record fails the reader: {answer['reason']}")
        if reported is not None and recorded != reported["outcome"]:
            problems.append(f"the record says {recorded!r}, the client printed "
                            f"{reported['outcome']!r}")
    return problems


def _reported(stdout: str) -> dict[str, Any] | None:
    lines = [line for line in stdout.strip().splitlines() if line.strip()]
    try:
        answer = json.loads(lines[-1])
        reported = {key: answer[key] for key in REPORT_KEYS}
    except (IndexError, ValueError, KeyError, TypeError):
        return None
    if (reported["outcome"] not in reader.OUTCOMES or reported["basis"] not in reader.BASES
            or not isinstance(reported["halted"], bool)):
        return None
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
                             "AEV_EFFECT_SINK, AEV_DECISION_RECORD"},
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
