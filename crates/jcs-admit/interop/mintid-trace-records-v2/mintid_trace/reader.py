"""Read hash-bound MintID trace triples through installed raw admission.

This finite profile checks recorded facts. It does not contact a service, verify
an ICS23/BBS proof, authenticate an operator or infer an external action.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 20 << 20  # Existing jcs-admit/Go adapter default; never widened.
MAX_DEPTH = 128
CHUNK_BYTES = 64 << 10
SCHEMA = "mintid-trace-manifest/2"
META = frozenset(("utc", "unix", "t", "kind"))
REFUSALS = frozenset(("credential_revoked", "witness_not_usable"))
KINDS = frozenset(("agents_minted", "decision", "decision_log", "decision_log_line", "holder_refresh", "identity_credential", "kyc_session", "parameters", "path_done", "ring_at_denial", "stack", "summary", "trigger", "verifier_status", "wait", "source", "build", "policy", "challenge_during_outage"))
PATHS = ("issuer", "kill_switch", "cascade", "emergency", "unreachable")


class Refused(ValueError):
    """A specific input, binding or record refusal."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise Refused(code, detail)


def strict_json(raw: bytes) -> Any:
    """Decode only after raw admission; refuse hostile command responses too."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "DuplicateMember", key)
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise Refused("NonFiniteNumber", value)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refused("InvalidJSON", str(error)) from error


@dataclass(frozen=True)
class Limits:
    """Host-selected whole-record resource policy, never an evidence grade."""

    input_bytes: int
    events: int
    native_calls: int
    native_output_bytes: int
    capture_bytes: int
    capture_files: int

    def __post_init__(self):
        require(all(type(value) is int and value > 0 for value in vars(self).values()), "ResourcePolicy", "positive integer limits required")

    @classmethod
    def from_file(cls, path: Path) -> Limits:
        values = strict_json(read_member(path.parent, path.name, 4096))
        require(type(values) is dict and set(values) == set(cls.__dataclass_fields__), "ResourcePolicy", "exact limit fields required")
        return cls(**values)


def bounded_read(stream, limit: int) -> bytes:
    """Grow with actual bytes, never allocate a cap-sized read buffer."""
    raw = bytearray()
    while block := stream.read(min(CHUNK_BYTES, limit - len(raw) + 1)):
        raw.extend(block)
        require(len(raw) <= limit, "TooLarge", "bounded input")
    return bytes(raw)


def file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_member(directory: Path, filename: str, limit: int = MAX_BYTES) -> bytes:
    """Open one canonical basename without following a symlink; bound reads."""
    require(filename == Path(filename).name and filename not in ("", ".", ".."), "MemberPath", filename)
    require(directory.absolute() == directory.resolve() and directory.is_dir(), "MemberPath", "canonical record directory")
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), "MemberType", filename)
            require(info.st_size <= min(limit, MAX_BYTES), "TooLarge", filename)
            raw = bounded_read(stream, min(limit, MAX_BYTES))
        return raw
    except OSError as error:
        raise Refused("MemberUnavailable", filename) from error


class Admission:
    """Trusted absolute installed commands admit original JSON bytes first."""

    def __init__(self, go: Path, admission: Path, capture: Path, limits: Limits):
        for command in (go, admission):
            require(command.is_absolute() and command.is_file() and os.access(command, os.X_OK), "CommandUnavailable", str(command))
        require(capture.is_absolute() and capture.absolute() == capture.resolve() and capture.parent.is_dir() and not capture.exists(), "CapturePath", "new canonical capture directory under an existing parent")
        try:
            capture.mkdir(mode=0o700)
        except OSError as error:
            raise Refused("CaptureUnavailable", str(capture)) from error
        self.capture = capture
        self.go = go
        self.admission = admission
        self.limits = limits
        self.calls: list[dict[str, Any]] = []
        self.capture_bytes = 0
        self.capture_files = 1  # The capture root consumes an inode too.
        self.native_output_bytes = 0

    def retain(self, path: Path, raw: bytes) -> None:
        require(self.capture_files + 1 <= self.limits.capture_files and self.capture_bytes + len(raw) <= self.limits.capture_bytes, "CaptureBudget", path.name)
        path.write_bytes(raw)
        self.capture_files += 1
        self.capture_bytes += len(raw)

    def directory(self, path: Path) -> None:
        require(self.capture_files + 1 <= self.limits.capture_files, "CaptureBudget", path.name)
        path.mkdir(mode=0o700)
        self.capture_files += 1

    def document(self, raw: bytes, member: str) -> Any:
        require(len(raw) <= MAX_BYTES, "TooLarge", member)
        argv = [str(self.go), "--admission", str(self.admission), "--profile", "ijson", "--max-depth", str(MAX_DEPTH), "--max-bytes", str(MAX_BYTES)]
        require(len(self.calls) < self.limits.native_calls, "NativeCallBudget", member)
        # Reserve a complete normal response, diagnostics and its receipt before
        # work. Unexpected larger output is retained up to the host budget; any
        # enforced stop is explicit and never qualified as complete evidence.
        # Safe I-JSON integer exponent tokens can expand fourfold (1e15 ->
        # 1000000000000000); canonical_hex doubles those bytes. Reserve this
        # writer bound and the finite response envelope, not a twofold guess.
        expected_output = 8 * len(raw) + 4096
        receipt_base = {"member": member, "input_bytes": len(raw), "input_sha256": hashlib.sha256(raw).hexdigest()}
        receipt_bound = {**receipt_base, "native_exit": -2147483648, "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64, "stdout_bytes": self.limits.native_output_bytes, "stderr_bytes": self.limits.native_output_bytes, "native_output_complete": False, "observed_unretained_excess_bytes": 1, "termination_requested": "SIGKILL owned child process group", "native_started": False, "spawn_error": {"errno": 2147483647, "class": "NotADirectoryError"}}
        receipt_reserve = len((json.dumps(receipt_bound, sort_keys=True) + "\n").encode())
        require(self.native_output_bytes + expected_output <= self.limits.native_output_bytes, "NativeOutputBudget", member)
        require(self.capture_files + 5 <= self.limits.capture_files and self.capture_bytes + len(raw) + expected_output + receipt_reserve <= self.limits.capture_bytes, "CaptureBudget", member)
        call = self.capture / f"call-{len(self.calls) + 1:06d}"
        self.directory(call)
        self.retain(call / "stdin.bin", raw)
        complete = True
        allowance = min(self.limits.native_output_bytes - self.native_output_bytes, self.limits.capture_bytes - self.capture_bytes - receipt_reserve)
        spawn_error = None
        child = None
        with (call / "stdin.bin").open("rb") as input_file, (call / "stdout.bin").open("xb") as output, (call / "stderr.bin").open("xb") as errors:
            try:
                child = subprocess.Popen(argv, stdin=input_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            except OSError as error:
                spawn_error = {"errno": error.errno, "class": type(error).__name__}
                complete = False
            with selectors.DefaultSelector() as selection:
                for pipe, target in (() if child is None else ((child.stdout, output), (child.stderr, errors))):
                    os.set_blocking(pipe.fileno(), False)
                    selection.register(pipe, selectors.EVENT_READ, target)
                while selection.get_map():
                    for key, _ in selection.select():
                        block = os.read(key.fd, min(CHUNK_BYTES, allowance + 1))
                        if not block:
                            selection.unregister(key.fileobj); key.fileobj.close(); continue
                        retained = block[:allowance]
                        key.data.write(retained)
                        allowance -= len(retained)
                        if len(retained) != len(block):
                            complete = False
                            # This process group was created by this invocation.
                            # Stop only it; no timeout or foreign-job cancellation.
                            try: os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError: pass
                            for registered in list(selection.get_map().values()):
                                selection.unregister(registered.fileobj); registered.fileobj.close()
                            break
            native_exit = child.wait() if child is not None else None
        sizes = {name: (call / name).stat().st_size for name in ("stdout.bin", "stderr.bin")}
        self.capture_files += 2
        self.capture_bytes += sum(sizes.values())
        self.native_output_bytes += sum(sizes.values())
        receipt = {**receipt_base, "native_exit": native_exit, "stdout_sha256": file_sha(call / "stdout.bin"), "stderr_sha256": file_sha(call / "stderr.bin"), "stdout_bytes": sizes["stdout.bin"], "stderr_bytes": sizes["stderr.bin"], "native_output_complete": complete, "observed_unretained_excess_bytes": 1 if not complete and child is not None else 0, "termination_requested": "SIGKILL owned child process group" if not complete and child is not None else None, "native_started": child is not None, "spawn_error": spawn_error}
        self.retain(call / "receipt.json", (json.dumps(receipt, sort_keys=True) + "\n").encode())
        self.calls.append(receipt)
        require(spawn_error is None, "CommandUnavailable", "native spawn failed; no exit invented")
        require(complete, "NativeOutputBudget", "retained prefix and actual exit; output incomplete")
        require(sizes["stdout.bin"] <= expected_output, "CommandProtocol", "complete oversized output retained")
        require(native_exit == 0 and sizes["stderr.bin"] == 0, "CommandFailed", member)
        with (call / "stdout.bin").open("rb") as stream:
            response = bounded_read(stream, expected_output)
        outcome = strict_json(response)
        require(type(outcome) is dict, "CommandProtocol", "response object")
        if outcome.get("status") == "refused":
            require(set(outcome) == {"status", "stage", "error_class"} and all(type(outcome[key]) is str for key in outcome), "CommandProtocol", "refusal fields")
            raise Refused(outcome["error_class"], member)
        require(set(outcome) == {"status", "stage", "canonical_hex"} and outcome["status"] == "accepted" and outcome["stage"] == "byte-agreement", "CommandProtocol", "accepted fields")
        require(type(outcome["canonical_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})+", outcome["canonical_hex"]) is not None, "CommandProtocol", "canonical bytes")
        # Parse the original bytes, not a writer's replacement. The native
        # adapter already required exact Go/admission canonical agreement.
        value = strict_json(raw)
        require(type(value) in (dict, list), "ObjectOrArrayRequired", member)
        return value


def exact(left: Any, right: Any) -> bool:
    """JSON equality with exact scalar types; bool never stands for int."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(exact(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def stripped(event: dict[str, Any] | None, *drop: str) -> dict[str, Any] | None:
    return None if event is None else {key: value for key, value in event.items() if key not in META and key not in drop}


def one(events: list[dict[str, Any]], kind: str, **match: Any) -> dict[str, Any] | None:
    selected = [event for event in events if event["kind"] == kind and all(exact(event.get(key), value) for key, value in match.items())]
    require(len(selected) <= 1, "AmbiguousEvent", kind)
    return selected[0] if selected else None


def delta(at: Any, origin: Any) -> float | None:
    if at is None or origin is None:
        return None
    require(type(at) in (int, float) and type(origin) in (int, float) and math.isfinite(at) and math.isfinite(origin), "InvalidTime", "relative clock")
    return round(at - origin, 1)


def utc(value: Any) -> str | None:
    """Check a consumed timestamp's shape, without authenticating its clock."""
    require(value is None or type(value) is str, "TimestampShape", "utc")
    return value


def root(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    require(type(entry) is dict, "RootShape", "root object")
    for key in ("status_epoch", "finalized_height", "generated_at_unix"):
        require(entry.get(key) is None or type(entry[key]) is int, "RootShape", key)
    require(entry.get("emergency") is None or type(entry["emergency"]) is bool, "RootShape", "emergency")
    require(entry.get("finalized_at_utc") is None or type(entry["finalized_at_utc"]) is str, "RootShape", "finalized_at_utc")
    return {key: entry.get(key) for key in ("status_epoch", "finalized_height", "generated_at_unix", "finalized_at_utc", "emergency")}


def inspect_events(events: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    decisions: dict[str, dict[str, Any]] = {}
    logs: dict[str, dict[str, Any]] = {}
    for event in events:
        require(type(event) is dict and type(event.get("kind")) is str, "EventShape", "kind")
        if event["kind"] not in ("decision", "decision_log_line"):
            continue
        session = event.get("session_id")
        require(type(session) is str and bool(session), "EventShape", "session identity")
        if event["kind"] == "decision":
            require(session not in decisions, "AmbiguousDecision", session)
            require(type(event.get("accepted")) is bool and type(event.get("reason_code")) is str, "DecisionShape", session)
            require(type(event.get("agent")) is str and bool(event["agent"]), "DecisionShape", "agent")
            require(type(event.get("path")) is str and event["path"] in PATHS, "DecisionShape", "path")
            utc(event.get("utc"))
            require(event.get("chain_height_after") is None or type(event["chain_height_after"]) is int, "DecisionShape", "chain_height_after")
            decisions[session] = event
        else:
            line = event.get("line")
            require(type(line) is dict and session not in logs, "AmbiguousDecisionLog", session)
            require(line.get("session_id") == session and type(line.get("accepted")) is bool, "DecisionLogShape", session)
            for key in ("condition", "root_epoch", "root_height", "root_age_seconds"):
                require(line.get(key) is None or type(line[key]) is int, "DecisionLogShape", key)
            logs[session] = line
    for session, line in logs.items():
        require(session in decisions, "UnboundDecisionLog", session)
        event = decisions[session]
        require(exact(line["accepted"], event["accepted"]) and exact(line.get("reason_code"), event["reason_code"]), "DecisionLogMismatch", session)
    return decisions, logs


def decision(event: dict[str, Any] | None, logs: dict[str, dict[str, Any]], origin: Any, decisions: dict[str, dict[str, Any]], path: str, agent: str | None = None, accepted: bool | None = None) -> dict[str, Any] | None:
    if event is None:
        return None
    require(type(event) is dict and type(event.get("session_id")) is str, "DecisionShape", "summary decision")
    session = event["session_id"]
    require(session in decisions, "UnboundSummaryDecision", str(session))
    recorded = decisions[session]
    # The summary may attach a ring/refusal explanation after the event. The
    # original event fields must still match, including the decision outcome.
    require(all(key in event and exact(event[key], value) for key, value in recorded.items()), "SummaryDecisionMismatch", str(session))
    require(recorded["path"] == path, "DecisionPathMismatch", session)
    require(agent is None or recorded["agent"] == agent, "DecisionAgentMismatch", session)
    require(accepted is None or recorded["accepted"] is accepted, "DecisionOutcomeMismatch", session)
    line = logs.get(session)
    return {"utc": utc(event.get("utc")), "seconds_after_t0": delta(event.get("unix"), origin), "session_id": session, "accepted": event.get("accepted"), "reason_code": event.get("reason_code"), "chain_height_after": event.get("chain_height_after"), "decision_log": None if line is None else {key: line.get(key) for key in ("condition", "root_epoch", "root_height", "root_age_seconds")}}


def refresh(events: list[dict[str, Any]], path: str, agent: str | None, origin: Any, control: bool) -> dict[str, Any]:
    # An absent subject cannot identify an anonymous or named holder.
    selected = [] if agent is None else [event for event in events if event["kind"] == "holder_refresh" and event.get("path") == path and event.get("agent") == agent]
    refused = [event for event in selected if event.get("outcome") in REFUSALS]
    other = [event for event in selected if event.get("outcome") == ("refreshed" if control else "not_refused_within_budget")]
    hit = (refused or other or [None])[0]
    observation = "refused" if refused else hit["outcome"] if hit else "not_recorded"
    return {"observation": observation, "outcome": hit["outcome"] if refused else None, "utc": utc(hit.get("utc")) if hit else None, "seconds_after_t0": delta(hit.get("unix"), origin) if hit else None}


def paths(summary: dict[str, Any], events: list[dict[str, Any]], logs: dict[str, dict[str, Any]], decisions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in summary.get("results", []):
        path = result.get("path")
        require(type(path) is str and path in PATHS and path not in seen, "PathShape", str(path))
        seen.add(path)
        if result.get("skipped"):
            out.append({"path": path, "skipped": result["skipped"]}); continue
        origin = result.get("t0")
        decide = lambda event, clock=origin, agent=None, accepted=None: decision(event, logs, clock, decisions, path, agent, accepted)
        if path == "unreachable":
            during = result.get("during", [])
            for observed in during:
                if observed.get("kind") == "challenge_during_outage":
                    require(any(exact(event, observed) for event in events if event["kind"] == "challenge_during_outage"), "UnboundOutageChallenge", path)
                    require(observed.get("path") == path, "OutagePathMismatch", path)
            out.append({"path": path, "t0_unix": origin, "t0_definition": result.get("t0_def"), "restored_seconds_after_t0": delta(result.get("restored_unix"), origin), "decided_during_outage": [decide(event) for event in during if event.get("kind") == "decision"], "challenges_during_outage": [{"utc": utc(event.get("utc")), "seconds_after_t0": delta(event.get("unix"), origin), "http": event.get("http"), "error": event.get("error")} for event in during if event.get("kind") == "challenge_during_outage"], "first_accepted_after_restore": decide(result.get("first_accepted_after"), result.get("restored_unix"), accepted=True)}); continue
        common = {"t0_unix": origin, "t0_definition": result.get("t0_def"), "bound_seconds": result.get("bound_seconds"), "bound_formula": result.get("bound_formula")}
        require(type(common["bound_seconds"]) in (int, float), "PathShape", "bound")
        if path == "cascade":
            require(type(result.get("per_agent")) is dict and bool(result["per_agent"]), "PathShape", "cascade agents")
            entries = result["per_agent"].items()
        else:
            entries = [(None, result)]
        for agent, item in entries:
            require(type(item) is dict, "PathShape", "agent result")
            no = item.get("first_no")
            last = item.get("last_ok")
            if path == "cascade":
                require(type(agent) is str and bool(agent), "PathShape", "cascade agent")
                require(no is not None or last is not None, "AgentBindingUnavailable", agent)
            last_decision = decide(last, agent=agent, accepted=True)
            no_decision = decide(no, agent=agent, accepted=False)
            selected = no if no is not None else last
            label = agent if path == "cascade" else decisions[selected["session_id"]]["agent"] if selected is not None else None
            if last is not None:
                require(decisions[last["session_id"]]["agent"] == label, "DecisionAgentMismatch", last["session_id"])
            ring = (no or {}).get("ring_at_denial") or []
            if ring:
                ring_event = one(events, "ring_at_denial", path=path, agent=(no or {}).get("agent"))
                require(ring_event is not None and exact(ring_event.get("ring"), ring), "RingBindingMismatch", path)
            carrying = result.get("trigger_root") if path == "cascade" else result.get("carrying_root")
            row = {"path": path, **({"agent": agent} if path == "cascade" else {}), **common, "last_accepted": last_decision, "first_refused": no_decision, "root_at_denial": root(ring[-1]) if ring else None, "root_carrying_revocation": root(carrying), "refresh_refused_seconds_after_t0": delta(item.get("refresh_failed_at"), origin) if label is not None else None}
            attribution = {"revoked": {"agent": label, "refresh": refresh(events, path, label, origin, False)}, "control": None}
            if path == "issuer" and result.get("control") is not None:
                require(type(result["control"]) is list, "PathShape", "issuer control")
                controls = [decide(event, agent="sibling_control") for event in result["control"]]
                require(all(event is not None for event in controls), "DecisionShape", "issuer control")
                yes = [event for event in controls if event.get("accepted") is True]
                no_control = next((event for event in controls if event.get("accepted") is False), None)
                # The published trace names the refreshed decision separately.
                # Binding that role does not authenticate credential identity.
                after_control = decide(result.get("control_refreshed"), agent="sibling_refreshed", accepted=True)
                row["control_never_revoked"] = {"last_accepted": yes[-1] if yes else None, "first_refused": no_control, "after_refresh": after_control}
                attribution["control"] = {"agent": "sibling_control", "refused": no_control, "refresh": refresh(events, path, "sibling_control", origin, True), "after_refresh": after_control}
            row["attribution"] = attribution
            out.append(row)
    return out


def derive(stem: str, events: list[dict[str, Any]], stated: Any, files: dict[str, str]) -> dict[str, Any]:
    """Independently project the finite published manifest-v2 contract."""
    decisions, logs = inspect_events(events)
    stack = one(events, "stack") or {}
    source = one(events, "source")
    build = one(events, "build")
    policy = one(events, "policy")
    before = stripped(one(events, "verifier_status", when="before"), "when")
    after = stripped(one(events, "verifier_status", when="after"), "when")
    parameters = stripped(one(events, "parameters"))
    summary = one(events, "summary")
    require(summary is not None and type(summary.get("results")) is list, "MissingSummary", stem)
    require(stated is None or type(stated) is dict and set(stated) <= {"source_revision", "services_revision"} and all(type(value) is str and bool(value) for value in stated.values()), "StatedShape", stem)
    deployment = {"target": stem.split("-")[2], "chain_id": stack.get("chain_id"), "issuer_id": stack.get("issuer_id"), "verifier_id": stack.get("verifier_id"), "kyc_provider": stack.get("kyc_provider"), "endpoints": {key: stack.get(key) for key in ("issuer_url", "verifier_url", "rpc", "relay")}, "build": stripped(build), "parameters": parameters, **{key: (before or {}).get(key) for key in ("max_root_age_seconds", "heartbeat_seconds", "max_height_lag")}}
    if build and type(build.get("issuer")) is dict:
        services = {}
        for name in ("verifier", "issuer"):
            served = build.get(name) or {}; revision = served.get("source_revision"); fallback = (source or {}).get("services_revision_stated") or None
            services[name] = {"source_revision": revision if revision not in (None, "", "unknown") else fallback, "release": served.get("release") if revision not in (None, "", "unknown") else None, "basis": "build-info" if revision not in (None, "", "unknown") else "stated" if fallback else None}
        deployment["services"] = services
    policy_fields = None
    if policy:
        policy_fields = {key: policy.get(key) for key in ("claim_policy", "issuer_policy", "sha256")}
        # MintID's declared policy digest uses Python's sorted compact JSON.
        # It is not relabeled as an RFC8785/JCS digest.
        encoded = json.dumps({key: policy[key] for key in ("claim_policy", "issuer_policy")}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        require(policy.get("sha256") == hashlib.sha256(encoded).hexdigest(), "PolicyHashMismatch", stem)
    projected_decisions = []
    for event in events:
        if event["kind"] == "decision":
            line = logs.get(event["session_id"], {})
            projected_decisions.append({**{key: event.get(key) for key in ("utc", "path", "agent", "attempt", "accepted", "reason_code")}, **{key: line.get(key) for key in ("condition", "root_epoch", "root_height", "root_age_seconds")}})
    return {"schema": SCHEMA, "record": stem, "derived": source is None, "started_utc": utc(events[0].get("utc")), "source": stripped(source), "stated": stated, "deployment": deployment, "policy": policy_fields, "verifier_status": {"before": before, "after": after}, "decision_log_source": (one(events, "decision_log") or {}).get("source"), "paths": paths(summary, events, logs, decisions), "decisions": projected_decisions, "files": files}


def summary_disclosure(raw: bytes, stem: str, projected: dict[str, Any]) -> dict[str, Any]:
    """Check original Markdown disclosures without treating prose as JSON."""
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise Refused("SummaryEncoding", stem) from error
    require(f"Raw events: `{stem}.jsonl`" in text, "SummaryDisclosure", "raw event member")
    chain = projected["deployment"]["chain_id"]
    require(f"Chain `{chain}`" in text, "SummaryDisclosure", "chain label")
    rows = [line for line in text.splitlines() if line.startswith("| Field |") or line.startswith("| Source |") or line.startswith("| Revision |")]
    require(any(line.startswith("| Source |") for line in rows), "SummaryDisclosure", "source narrative")
    return {"original_sha256": hashlib.sha256(raw).hexdigest(), "raw_member_and_chain_disclosures_match": True, "authority_narrative_rows": rows, "narrative_identity_authenticated": False, "prose_semantic_grade": "not-performed"}


def _read_record(directory: Path, stem: str, admission: Admission) -> dict[str, Any]:
    require(re.fullmatch(r"revocation-trace-(?:local|testnet)-[0-9]{8}T[0-9]{6}Z", stem) is not None, "RecordName", stem)
    names = [stem + suffix for suffix in (".manifest.json", ".jsonl", ".md")]
    members = admission.capture / "members"
    admission.directory(members)
    raw = {}
    remaining = admission.limits.input_bytes
    for name in names:
        require(remaining > 0, "InputBudget", name)
        original = read_member(directory, name, min(MAX_BYTES, remaining))
        raw[name] = original; remaining -= len(original)
        admission.retain(members / name, original)
    # BytesIO iterates lines without making a second full list of raw rows.
    import io
    event_count = sum(1 for _ in io.BytesIO(raw[names[1]]))
    require(event_count <= admission.limits.events, "EventBudget", stem)
    require(event_count + 1 <= admission.limits.native_calls, "NativeCallBudget", stem)
    manifest = admission.document(raw[names[0]], names[0])
    require(type(manifest) is dict and manifest.get("schema") == SCHEMA and manifest.get("record") == stem, "ManifestShape", stem)
    hashes = {name: hashlib.sha256(raw[name]).hexdigest() for name in names[1:]}
    require(exact(manifest.get("files"), hashes), "MemberHashMismatch", stem)
    events = []
    for number, line in enumerate(io.BytesIO(raw[names[1]]), 1):
        line = line.removesuffix(b"\n").removesuffix(b"\r")
        require(bool(line.strip()), "BlankEvent", f"line {number}")
        event = admission.document(line, f"{names[1]}:{number}")
        require(type(event) is dict and type(event.get("kind")) is str and event["kind"] in KINDS, "EventShape", str(number))
        events.append(event)
    require(bool(events), "EmptyRecord", stem)
    projected = derive(stem, events, manifest.get("stated"), hashes)
    require(exact(manifest, projected), "ManifestEventMismatch", stem)
    disclosure = summary_disclosure(raw[names[2]], stem, projected)
    return {"schema": "jcs-admit.mintid-trace-consumer.v1", "profile": "mintid-trace-records-v2", "status": "accepted", "record": stem, "member_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}, "event_count": len(events), "source": projected["source"], "stated": projected["stated"], "deployment": projected["deployment"], "policy": projected["policy"], "paths": projected["paths"], "decision_count": len(projected["decisions"]), "summary_disclosure": disclosure, "admission_calls": admission.calls, "resource_usage": {"input_bytes": sum(map(len, raw.values())), "events": len(events), "native_calls": len(admission.calls), "native_output_bytes": admission.native_output_bytes, "capture_bytes": admission.capture_bytes, "capture_files": admission.capture_files}, "does_not_assert": ["authenticated operator or source/build identity", "independent operation or custody", "chain state or ICS23/BBS proof validity", "authority beyond the recorded verifier outcomes", "target bytes or external action effects", "truth of all Markdown prose", "independent chain observation of roots declared in the JSONL summary", "a real unreachable-authority workload from the original three records"]}


def read_record(directory: Path, stem: str, admission: Admission) -> dict[str, Any]:
    """Return a clear shape refusal for malformed untrusted nested records."""
    try:
        return _read_record(directory, stem, admission)
    except Refused:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, RecursionError) as error:
        raise Refused("RecordShape", type(error).__name__) from error
