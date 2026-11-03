#!/usr/bin/env python3
"""ACS-Core hook probes: what a host's hook shim does when the Guardian answers,
refuses, or is not there.

The wire probes beside this directory drive a Guardian over HTTP. These drive
the other end: the Claude Code shim in the specification repository's
reference implementation (`hosts/claude-code/acs-hook.ts`), the process a host
runs at each hook. A host reads two things from it, the exit code and stdout.
The specification adds a third the host never sees, an audit entry whenever a
step goes on without a decision (section 6.4, under either posture) or without
a session (section 4.1), and the Guardian's own envelope log adds a fourth:
whether the step reached it at all. The probes read all four. The shape of the
audit entry (`outcome`, `posture_source`, `failure.kind`) is the reference
implementation's, from `packages/host-adapter/src/audit-sink.ts`; the
specification requires the entry and leaves its shape to the deployment.

They exist because of one observed run: a hook that exited 0, printed nothing,
sent nothing to the Guardian and wrote no audit entry (agent-control-standard
issue 111, corpus member v564ff5d8d344bea2). A host reads exit 0 with no output
as a hook with no decision to report and lets the step continue, so that run is
indistinguishable from a clean one unless something checks the output. H6 is
that check; every probe that reads an answer fails on it too.

Phases, because the Guardian has to be started and stopped between them:

  up         Guardian running under the default posture: a decision reaches the
             host, a deny travels in the JSON body, and the input contract holds
  down       Guardian unreachable, no stored session: the step proceeds under the
             default posture and the audit entry says so
  deny-up    Guardian running with on_decision_failure deny: a step stores the
             negotiated posture
  deny-down  Guardian stopped, same session: the step is blocked and the audit
             entry says so, under the posture the session negotiated

`run_against_agt.sh` runs the four in order, then `--check-coverage`, which
refuses a run that produced fewer rows than the expectation names. Standard
library only; the shim is run as a subprocess with the hook payload on stdin,
which is how a host runs it.

With --expect FILE the exit status compares each probe's status with the
recorded one, so CI stays green while a known gap is open and goes red the
moment behaviour changes in either direction. Without it: 0 when every MUST
probe and the control pass, 1 when one fails. Either way, 2 when the shim could
not be run at all. --selftest runs every phase against a shim that answers nothing and
exits 0, with no Guardian, and succeeds only if every probe fails. --write-expect
records a finished run's statuses into an expectation file, so none is typed.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

Json = dict[str, Any]
AGT = Path("reference-implementations") / "agt"
HOOKMAP = Path("hosts") / "claude-code" / "claude-code.hookmap.yaml"
DEFAULT_SHIM = "bun run hosts/claude-code/acs-hook.ts"
DOWN_URL = "http://127.0.0.1:1/acs"
SILENT_SHIM = f"{shlex.quote(sys.executable)} -c \"import sys; sys.stdin.read()\""
PHASES = ("up", "down", "deny-up", "deny-down")
DENY_SESSION = "hook-deny"
CHILD_TIMEOUT_S = 60


def hook(event: str, sid: str, command: str, result: str | None = None) -> bytes:
    """A Claude Code hook payload, as the host writes it to the shim's stdin."""
    payload: Json = {"session_id": sid, "hook_event_name": event, "tool_name": "Bash",
                     "tool_input": {"command": command}}
    if result is not None:
        payload["tool_response"] = {"stdout": result}
    return json.dumps(payload).encode()


class Probe:
    def __init__(self, acs: Path, shim: str, guardian: str, out: Path, parallel: int,
                 guardian_log: Path | None = None):
        self.acs = acs
        self.cwd = acs / AGT
        self.shim = shlex.split(shim)
        self.guardian = guardian
        self.guardian_log = guardian_log
        self.out = out
        self.records = out / "hook"
        self.records.mkdir(parents=True, exist_ok=True)
        self.n = len(list(self.records.iterdir()))
        self.parallel = parallel
        self.rows: list[Json] = []
        self.runs: list[Json] = []
        self.unrunnable: str | None = None

    def state(self, name: str, keep: bool = False) -> Path:
        """The audit log and session directory one run uses. Fresh unless `keep`,
        so a second run into the same out directory cannot read the first run's
        entries as its own."""
        path = self.out / "state" / name
        if path.exists() and not keep:
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def env(self, state: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ, ACS_GUARDIAN_URL=self.guardian,
                   ACS_AUDIT_LOG=str(state / "audit.jsonl"),
                   ACS_SESSION_DIR=str(state / "sessions"))
        env.update(extra or {})
        return env

    def spawn(self, state: Path, extra: dict[str, str] | None = None,
              stdin: Any = subprocess.PIPE) -> subprocess.Popen[bytes]:
        return subprocess.Popen(self.shim, cwd=self.cwd, env=self.env(state, extra),
                                stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def run(self, name: str, payload: bytes, state: Path | None = None,
            extra: dict[str, str] | None = None) -> Json:
        """One shim invocation. Records exit code, both streams and the audit log."""
        state = state if state is not None else self.state(name)
        rec: Json = {"name": name, "stdin": payload.decode(),
                     "audit_log": str(state / "audit.jsonl")}
        if extra:
            rec["env"] = extra
        seen = self.log_size()
        try:
            proc = self.spawn(state, extra)
        except OSError as e:
            self.unrunnable = repr(e)
            rec["spawn_error"] = repr(e)
        else:
            rec.update(wait(proc, payload))
        rec["audit"] = audit_entries(state / "audit.jsonl")
        rec["guardian"] = self.envelopes_since(seen)
        return self.record(name, rec)

    def log_size(self) -> int:
        if self.guardian_log is None or not self.guardian_log.exists():
            return 0
        return self.guardian_log.stat().st_size

    def envelopes_since(self, offset: int) -> list[Json] | None:
        """What the Guardian's envelope log gained during one run: method, direction
        and, for a step, the command or outputs sent and the decision returned. The
        Guardian appends each line before it answers, so the run's own traffic is on
        disk by the time the shim has exited. None when no log was given."""
        if self.guardian_log is None:
            return None
        if not self.guardian_log.exists():
            return []
        with self.guardian_log.open("rb") as fh:
            fh.seek(offset)
            lines = fh.read().decode(errors="replace").splitlines()
        out: list[Json] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                out.append({"unparseable": line})
                continue
            envelope = entry.get("envelope") if isinstance(entry, dict) else None
            envelope = envelope if isinstance(envelope, dict) else {}
            summary: Json = {"method": entry.get("method"), "direction": entry.get("direction")}
            params = envelope.get("params")
            payload = params.get("payload") if isinstance(params, dict) else None
            if isinstance(payload, dict):
                summary["raw_command"] = payload.get("raw_command")
                summary["outputs"] = payload.get("outputs")
            result = envelope.get("result")
            if isinstance(result, dict):
                summary["decision"] = result.get("decision")
            out.append(summary)
        return out

    def amend(self, rec: Json, **fields: object) -> None:
        """Add evidence to a record after it was written, and rewrite the file."""
        rec.update(fields)
        path = self.records / str(rec["_file"])
        path.write_text(json.dumps({k: v for k, v in rec.items() if k != "_file"}, indent=2))

    def run_parallel(self, name: str, payload: bytes, count: int) -> Json:
        """`count` shims sharing one session. Each reads its stdin from a file, so every
        one has its whole input the moment it starts and they overlap. Feeding one
        through a pipe and awaiting it before starting the next would run them one at
        a time."""
        state = self.state(name)
        rec: Json = {"name": name, "stdin": payload.decode(), "launched": count,
                     "audit_log": str(state / "audit.jsonl"), "children": []}
        stdin = state / "stdin.json"
        stdin.write_bytes(payload)
        procs: list[subprocess.Popen[bytes]] = []
        try:
            for _ in range(count):
                with stdin.open("rb") as fh:
                    procs.append(self.spawn(state, stdin=fh))
        except OSError as e:
            self.unrunnable = repr(e)
            rec["spawn_error"] = repr(e)
            for proc in procs:
                proc.kill()
        else:
            rec["children"] = [wait(proc, None) for proc in procs]
        rec["audit"] = audit_entries(state / "audit.jsonl")
        return self.record(name, rec)

    def record(self, name: str, rec: Json) -> Json:
        self.n += 1
        path = self.records / f"{self.n:03d}-{name}.json"
        path.write_text(json.dumps(rec, indent=2))
        rec["_file"] = path.name
        children = rec.get("children")
        if isinstance(children, list):
            self.runs.extend({**child, "_file": path.name} for child in children)
        else:
            self.runs.append(rec)
        return rec

    def check(self, pid: str, probe: str, level: str, expected: str, rec: Json, ok: bool,
              observed: str) -> None:
        self.rows.append({"id": pid, "probe": probe, "level": level, "expected": expected,
                          "observed": observed, "status": "PASS" if ok else "FAIL",
                          "record": rec.get("_file")})


def wait(proc: subprocess.Popen[bytes], payload: bytes | None) -> Json:
    """Exit code and both streams; a child that does not exit is killed and recorded."""
    rec: Json = {}
    try:
        stdout, stderr = proc.communicate(payload, timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        rec["timed_out"] = True
    rec.update(exit=proc.returncode, stdout=stdout.decode(errors="replace"),
               stderr=stderr.decode(errors="replace"))
    return rec


def audit_entries(path: Path) -> list[Json]:
    """Every line of the audit log, parsed; a line that is not JSON is kept as text."""
    if not path.exists():
        return []
    out: list[Json] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"unparseable": line})
    return out


def output(rec: Json) -> Json | None:
    """stdout parsed as the one JSON object a host reads back, or None."""
    text = rec.get("stdout") or ""
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def decision(rec: Json) -> str | None:
    out = output(rec)
    if out is None:
        return None
    specific = out.get("hookSpecificOutput")
    if not isinstance(specific, dict):
        return None
    value = specific.get("permissionDecision")
    return value if isinstance(value, str) else None


def answered(rec: Json) -> bool:
    """The shim produced the one thing a host reads as a decision: exit 0 and a JSON object."""
    return rec.get("exit") == 0 and output(rec) is not None


def reached(rec: Json, method: str, decision: str, command: str | None = None,
            result: str | None = None) -> tuple[bool, str]:
    """The Guardian's envelope log shows this run's step arriving and being decided:
    one request for `method` carrying the command or output the hook carried, and
    one response for it carrying `decision`. Without a log nothing is known."""
    entries = rec.get("guardian")
    if entries is None:
        return False, "guardian log: not given"
    requests = [e for e in entries if e.get("method") == method and e.get("direction") == "request"]
    responses = [e for e in entries if e.get("method") == method
                 and e.get("direction") == "response"]
    if command is not None:
        requests = [e for e in requests if e.get("raw_command") == command]
    if result is not None:
        requests = [e for e in requests if any(isinstance(o, dict) and o.get("value") == result
                                               for o in e.get("outputs") or [])]
    decided = [e for e in responses if e.get("decision") == decision]
    ok = len(requests) == 1 and len(responses) == 1 and len(decided) == 1
    short = method.removeprefix("steps/")
    return ok, (f"guardian log: {short} requests={len(requests)} "
                f"responses={[e.get('decision') for e in responses]}")


def describe(rec: Json) -> str:
    if "spawn_error" in rec:
        return f"shim could not be started: {rec['spawn_error']}"
    if rec.get("timed_out"):
        return "shim did not exit within the timeout"
    stdout = rec.get("stdout") or ""
    return (f"exit={rec.get('exit')} stdout_bytes={len(stdout.encode())} "
            f"stderr_bytes={len((rec.get('stderr') or '').encode())} "
            f"decision={decision(rec)} audit_entries={len(rec.get('audit') or [])}")


def field(entry: Json, key: str) -> object:
    """`failure_kind` and `session_failure_kind` read the nested objects; the rest are top level."""
    if key.endswith("_kind"):
        parent = entry.get(key.removesuffix("_kind"))
        return parent.get("kind") if isinstance(parent, dict) else None
    return entry.get(key)


def one_entry(rec: Json, absent: tuple[str, ...] = (), **fields: str) -> tuple[bool, str]:
    """Exactly one parseable audit entry, carrying the given values and none of `absent`."""
    entries = rec.get("audit") or []
    if len(entries) != 1:
        return False, f"wanted exactly one audit entry, found {len(entries)}"
    entry = entries[0]
    if "unparseable" in entry:
        return False, "audit entry is not JSON"
    got = {key: field(entry, key) for key in fields}
    ok = all(got[key] == want for key, want in fields.items())
    ok = ok and not any(key in entry for key in absent)
    shown = " ".join(f"{key}={value}" for key, value in got.items())
    shown += "".join(f" {key}={'present' if key in entry else 'absent'}" for key in absent)
    return ok, "audit " + shown


# --------------------------------------------------------------------------
# Phase: up. The Guardian is running under the default posture.


def probe_up(p: Probe) -> None:
    sid = "hook-up"
    rec = p.run("C0-allow", hook("PreToolUse", sid, "ls -la"))
    ok, log = reached(rec, "steps/toolCallRequest", "allow", command="ls -la")
    p.check("C0", "PreToolUse ls -la with the Guardian up", "control",
            "exit 0, allow, no audit entry; the Guardian saw the request and answered allow",
            rec, answered(rec) and decision(rec) == "allow" and not rec["audit"] and ok,
            f"{describe(rec)}; {log}")
    rec = p.run("H1-deny", hook("PreToolUse", sid, "rm -rf /"))
    ok, log = reached(rec, "steps/toolCallRequest", "deny", command="rm -rf /")
    p.check("H1", "PreToolUse rm -rf / with the Guardian up", "MUST",
            "exit 0, deny in the JSON body, no audit entry; the Guardian saw the request "
            "and answered deny", rec,
            answered(rec) and decision(rec) == "deny" and not rec["audit"] and ok,
            f"{describe(rec)}; {log}")
    rec = p.run("H2-result", hook("PostToolUse", sid, "ls -la", result="README.md"))
    out = output(rec) or {}
    specific = out.get("hookSpecificOutput")
    rendered = isinstance(specific, dict) and specific.get("hookEventName") == "PostToolUse"
    ok, log = reached(rec, "steps/toolCallResult", "allow", result="README.md")
    p.check("H2", "PostToolUse with the Guardian up", "MUST",
            "exit 0, a PostToolUse answer rendered, no audit entry; the Guardian saw the "
            "result and answered allow", rec,
            answered(rec) and rendered and not rec["audit"] and ok, f"{describe(rec)}; {log}")
    probe_input_contract(p)
    probe_silence(p, "up")


def probe_input_contract(p: Probe) -> None:
    """Exit 2 with stderr only, when the shim cannot trust its own input or
    configuration. H3a to H3c and H3e to H3f are the host README's exit-code table;
    H3d is govern-step.ts refusing a hook the hookmap does not map, which it does
    after the handshake, so that one does reach the Guardian. None writes an audit
    entry: nothing proceeded."""
    cases: list[tuple[str, str, bytes, dict[str, str]]] = [
        ("H3a", "stdin that is not JSON", b"not json", {}),
        ("H3b", "payload with no session_id",
         json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_input": {"command": "ls"}}).encode(), {}),
        ("H3c", "session_id that is not a safe path segment", hook("PreToolUse", "../x", "ls"), {}),
        ("H3d", "hook event the hookmap does not map", hook("Notification", "hook-up", "ls"), {}),
        ("H3e", "ACS_HOOKMAP_PATH naming a file that does not exist",
         hook("PreToolUse", "hook-up", "ls"),
         {"ACS_HOOKMAP_PATH": str(p.out / "state" / "no-such-hookmap.yaml")}),
    ]
    for pid, probe, payload, extra in cases:
        rec = p.run(pid, payload, extra=extra)
        p.check(pid, probe, "MUST", "exit 2, nothing on stdout, stderr only, no audit entry", rec,
                refused(rec), describe(rec))
    probe = "a hookmap declaring a permissionDecision Claude Code does not accept"
    broken = broken_hookmap(p)
    if broken is None:
        p.check("H3f", probe, "MUST", "exit 2, nothing on stdout, stderr only, no audit entry",
                {"_file": None}, False,
                "not run: the checkout's hookmap has no `{ value: ask }` literal to break")
        return
    rec = p.run("H3f", hook("PreToolUse", "hook-up", "ls"),
                extra={"ACS_HOOKMAP_PATH": str(broken)})
    p.check("H3f", probe, "MUST", "exit 2, nothing on stdout, stderr only, no audit entry", rec,
            refused(rec), describe(rec))


def refused(rec: Json) -> bool:
    return (rec.get("exit") == 2 and not (rec.get("stdout") or "") and bool(rec.get("stderr"))
            and not rec["audit"])


def broken_hookmap(p: Probe) -> Path | None:
    """The checkout's own hookmap with one output literal the host does not accept:
    the `ask` rendering declares `defer`, which Claude Code's permissionDecision
    does not take. The shim must refuse the file at load. None when the checkout's
    hookmap does not spell the literal this edit looks for, so that H3f fails
    rather than testing some other refusal."""
    source = p.acs / AGT / HOOKMAP
    text = source.read_text() if source.exists() else ""
    literal = "{ value: ask }"
    if literal not in text:
        return None
    target = p.out / "state" / "hookmap-declares-defer.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text.replace(literal, "{ value: defer }", 1))
    return target


def probe_silence(p: Probe, phase: str) -> None:
    """The issue 111 condition: a run that exits 0 and prints nothing. A host reads that as
    a hook with no decision to report and lets the step continue, so no probe here may
    produce it. Counted over every run of the phase so far."""
    silent = [r for r in p.runs if r.get("exit") == 0 and not (r.get("stdout") or "")]
    records = sorted({str(r["_file"]) for r in silent})
    marker: Json = {"_file": None}
    p.check(f"H6-{phase}", f"no run in the {phase} phase exits 0 with nothing on stdout", "MUST",
            "zero such runs", marker, not silent,
            f"silent_runs={len(silent)}" + (f" in {records}" if records else ""))


# --------------------------------------------------------------------------
# Phase: down. The Guardian is unreachable and no session was ever negotiated.


def probe_down(p: Probe) -> None:
    rec = p.run("H4a-request", hook("PreToolUse", "hook-down-a", "ls -la"))
    ok, audit = one_entry(rec, outcome="proceeded", posture="proceed", posture_source="default",
                          method="steps/toolCallRequest", failure_kind="transport",
                          session_failure_kind="handshake_failed")
    p.check("H4a", "PreToolUse with the Guardian unreachable, no stored session", "MUST",
            "exit 0, allow rendered, one audit entry: proceeded under the default posture", rec,
            answered(rec) and decision(rec) == "allow" and ok, f"{describe(rec)}; {audit}")
    rec = p.run("H4b-result", hook("PostToolUse", "hook-down-b", "ls -la", result="README.md"))
    ok, audit = one_entry(rec, outcome="proceeded", posture="proceed", posture_source="default",
                          method="steps/toolCallResult", failure_kind="transport",
                          session_failure_kind="handshake_failed")
    p.check("H4b", "PostToolUse with the Guardian unreachable, no stored session", "MUST",
            "exit 0, an answer rendered, one audit entry: proceeded under the default posture", rec,
            answered(rec) and ok, f"{describe(rec)}; {audit}")
    probe_parallel(p)
    probe_silence(p, "down")


def probe_parallel(p: Probe) -> None:
    """Section 6.4 with ten steps at once: every step that proceeded
    without a decision has its entry, none lost. `seq` is reported and not scored:
    issue 250 measured it colliding under this load, and a race is not a stable verdict."""
    count = p.parallel
    rec = p.run_parallel("H7-parallel", hook("PreToolUse", "hook-down-parallel", "ls -la"), count)
    children = rec["children"]
    entries = rec["audit"]
    exits = [c.get("exit") for c in children]
    decisions = {decision(c) for c in children}
    raw = {c.get("stdout") for c in children}
    parseable = [e for e in entries if "unparseable" not in e]
    rpc_ids = {e.get("rpc_id") for e in parseable}
    seqs = [e.get("seq") for e in parseable]
    ok = (len(children) == count and all(x == 0 for x in exits) and decisions == {"allow"}
          and all(answered(c) for c in children) and len(parseable) == count
          and len(entries) == count and len(rpc_ids) == count)
    p.check("H7", f"{count} PreToolUse shims at once, one session, Guardian unreachable", "MUST",
            f"every exit 0 with allow, {count} parseable audit entries with {count} distinct "
            "rpc_ids", rec, ok,
            f"exits={sorted(set(exits), key=str)} decisions={sorted(decisions, key=str)} "
            f"distinct_stdouts={len(raw)} entries={len(entries)} parseable={len(parseable)} "
            f"distinct_rpc_ids={len(rpc_ids)} distinct_seq={len(set(seqs))} "
            "(seq is observed, not scored)")


# --------------------------------------------------------------------------
# Phases: deny-up and deny-down. One session across a Guardian restart.


def probe_deny_up(p: Probe) -> None:
    state = p.state("deny")
    stored = state / "sessions" / f"{DENY_SESSION}.json"
    rec = p.run("H5a-negotiate", hook("PreToolUse", DENY_SESSION, "ls -la"), state)
    posture = stored_posture(stored)
    p.amend(rec, stored_session={"path": str(stored), "on_decision_failure": posture})
    ok, log = reached(rec, "steps/toolCallRequest", "allow", command="ls -la")
    p.check("H5a", "PreToolUse with the Guardian up under on_decision_failure deny", "MUST",
            "exit 0, allow, the session stores on_decision_failure deny; the Guardian saw "
            "the request", rec,
            answered(rec) and decision(rec) == "allow" and posture == "deny" and ok,
            f"{describe(rec)}; stored on_decision_failure={posture}; {log}")
    probe_silence(p, "deny-up")


def stored_posture(stored: Path) -> str | None:
    if not stored.exists():
        return None
    try:
        value = json.loads(stored.read_text()).get("on_decision_failure")
    except (json.JSONDecodeError, AttributeError):
        return "unreadable"
    return value if isinstance(value, str) else None


def probe_deny_down(p: Probe) -> None:
    state = p.state("deny", keep=True)
    rec = p.run("H5b-blocked", hook("PreToolUse", DENY_SESSION, "ls -la"), state)
    ok, audit = one_entry(rec, absent=("session_failure",), outcome="blocked", posture="deny",
                          posture_source="negotiated", method="steps/toolCallRequest",
                          failure_kind="transport")
    p.check("H5b", "same session, Guardian stopped, negotiated posture deny", "MUST",
            "exit 0, deny rendered, one audit entry: blocked under the negotiated posture", rec,
            answered(rec) and decision(rec) == "deny" and ok, f"{describe(rec)}; {audit}")
    probe_silence(p, "deny-down")


PHASE_PROBES = {"up": probe_up, "down": probe_down, "deny-up": probe_deny_up,
                "deny-down": probe_deny_down}


# --------------------------------------------------------------------------


def exit_status(p: Probe, expect: Path | None) -> int:
    if p.unrunnable:
        print(f"the shim could not be run: {p.unrunnable}", file=sys.stderr)
        return 2
    if expect is None:
        return 1 if any(r["status"] == "FAIL" and r["level"] in ("MUST", "control")
                        for r in p.rows) else 0
    want: dict[str, str] = json.loads(expect.read_text())["status"]
    drift = [(r["id"], want.get(r["id"]), r["status"]) for r in p.rows
             if want.get(r["id"]) != r["status"]]
    for pid, was, now in drift:
        print(f"DRIFT {pid}: expected {was}, observed {now}", file=sys.stderr)
    return 1 if drift else 0


def produced(out: Path) -> dict[str, str]:
    """Probe id to status, over every phase that wrote results into `out`, in phase order."""
    got: dict[str, str] = {}
    for phase in PHASES:
        path = out / f"results-{phase}.json"
        if path.exists():
            got.update((r["id"], r["status"]) for r in json.loads(path.read_text()))
    return got


def check_coverage(expect: Path, out: Path) -> int:
    """Every probe the expectation names was produced by some phase, and nothing
    unexpected was. A row that disappears would otherwise pass unnoticed, since a
    phase compares only the rows it produced."""
    want = set(json.loads(expect.read_text())["status"])
    got = set(produced(out))
    missing, extra = sorted(want - got), sorted(got - want)
    for pid in missing:
        print(f"MISSING {pid}: the expectation names it and no phase produced it", file=sys.stderr)
    for pid in extra:
        print(f"UNEXPECTED {pid}: produced, and the expectation does not name it", file=sys.stderr)
    if not missing and not extra:
        print(f"coverage: every one of the {len(want)} expected probes was produced")
    return 1 if missing or extra else 0


def write_expect(expect: Path, out: Path) -> int:
    """Replace the `status` object of an existing expectation with what the four
    phases in `out` produced. The header (ref, runtime, note) is the author's; the
    statuses are never typed."""
    document = json.loads(expect.read_text())
    missing = [phase for phase in PHASES if not (out / f"results-{phase}.json").exists()]
    if missing:
        print(f"{out} holds no results for {', '.join(missing)}; record a run of all four "
              "phases, not part of one", file=sys.stderr)
        return 2
    got = produced(out)
    document["status"] = got
    expect.write_text(json.dumps(document, indent=2) + "\n")
    print(f"{expect}: {len(got)} statuses recorded from {out}")
    return 0


def selftest(acs: Path, out: Path, parallel: int) -> int:
    """Every phase against a shim that reads stdin and exits 0 with nothing. Every
    probe must fail, or the probes cannot catch the run they were written for."""
    rows: list[Json] = []
    # A Guardian log that stays empty, so the rows that read one fail on what the stub
    # did, not on the log's absence.
    log = out / "selftest" / "guardian-envelopes-none.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("")
    for phase in PHASES:
        # One Probe per phase, as the runner has: H6 counts a phase's own runs.
        p = Probe(acs, SILENT_SHIM, DOWN_URL, out / "selftest", parallel, log)
        PHASE_PROBES[phase](p)
        rows.extend(p.rows)
        if p.unrunnable:
            print(f"selftest: the stub shim could not be run: {p.unrunnable}", file=sys.stderr)
            return 2
    print_rows(rows)
    passing = sorted(r["id"] for r in rows if r["status"] != "FAIL")
    if passing:
        print(f"selftest: a shim that answers nothing passed {passing}", file=sys.stderr)
        return 1
    print(f"selftest: a shim that answers nothing fails all {len(rows)} probes")
    return 0


def print_rows(rows: list[Json]) -> None:
    print("| id | probe | level | expected | observed | status |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['id']} | {r['probe']} | {r['level']} | {r['expected']} | "
              f"{r['observed']} | {r['status']} |")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--acs", required=True, type=Path,
                    help="checkout of GenAI-Security-Project/agent-control-standard")
    ap.add_argument("--shim", default=DEFAULT_SHIM,
                    help=f"the hook command, run from reference-implementations/agt "
                         f"(default: {DEFAULT_SHIM})")
    ap.add_argument("--guardian", default=DOWN_URL,
                    help="ACS_GUARDIAN_URL for the shim; a closed port for the down phases")
    ap.add_argument("--guardian-log", type=Path,
                    help="the running Guardian's ACS_ENVELOPE_LOG; the up phases read it")
    ap.add_argument("--phase", choices=PHASES, help="which phase to run (see the module doc)")
    ap.add_argument("--parallel", type=int, default=10, help="shims started at once in H7")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--expect", type=Path, help="JSON {status: {probe id: PASS|FAIL}}")
    ap.add_argument("--check-coverage", action="store_true",
                    help="after the phases: every probe --expect names was produced")
    ap.add_argument("--write-expect", action="store_true",
                    help="after the phases: record their statuses into --expect")
    ap.add_argument("--selftest", action="store_true",
                    help="run every phase against a shim that answers nothing")
    a = ap.parse_args()
    # Absolute, because the shim runs with its own working directory and reads
    # the audit log and session directory paths from the environment as given.
    a.out = a.out.resolve()
    a.acs = a.acs.resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    if a.selftest:
        return selftest(a.acs, a.out, a.parallel)
    if a.check_coverage or a.write_expect:
        if a.expect is None:
            ap.error("--check-coverage and --write-expect need --expect")
        return write_expect(a.expect, a.out) if a.write_expect else check_coverage(a.expect, a.out)
    if a.phase is None:
        ap.error("--phase is required without --selftest, --check-coverage or --write-expect")
    if a.phase in ("up", "deny-up") and a.guardian_log is None:
        ap.error(f"--phase {a.phase} needs --guardian-log, the Guardian's envelope log")
    log = a.guardian_log.resolve() if a.guardian_log is not None else None
    p = Probe(a.acs, a.shim, a.guardian, a.out, a.parallel, log)
    PHASE_PROBES[a.phase](p)
    (a.out / f"results-{a.phase}.json").write_text(json.dumps(p.rows, indent=2))
    print_rows(p.rows)
    return exit_status(p, a.expect)


if __name__ == "__main__":
    sys.exit(main())
