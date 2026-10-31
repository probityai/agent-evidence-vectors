"""Private byte custody and receiver observations, separate from study scoring.

The stream parser is bounded; the original stream is not truncated. A native
terminal event, a wait observation and a driver closure are different facts.
No timestamp in this module authenticates a native or outside clock.
"""

from __future__ import annotations

import datetime as dt
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import uuid

PARSE_LIMIT = 8 * 1024 * 1024
JSON_LIMIT = 16 * 1024 * 1024
EVENT_CATEGORIES = {"thread.started", "turn.started", "item.started",
                    "item.updated", "item.completed", "turn.completed", "turn.failed", "error"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def finite(value):
        result = float(value)
        require(math.isfinite(result), "non-finite JSON number")
        return result

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                      parse_float=finite,
                      parse_constant=lambda _: require(False, "non-finite JSON number"))


def open_regular(path, flags=os.O_RDONLY, mode=0o600):
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("evidence must be a regular file")
    return os.fdopen(descriptor, "rb" if flags == os.O_RDONLY else "wb")


def read_small(path, limit=JSON_LIMIT):
    with open_regular(path) as stream:
        chunks, size = [], 0
        while chunk := stream.read(min(65536, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, "JSON or prompt exceeds parsing budget")
    return b"".join(chunks)


def file_binding(path):
    checksum, size = hashlib.sha256(), 0
    with open_regular(path) as stream:
        while chunk := stream.read(65536):
            checksum.update(chunk)
            size += len(chunk)
    return {"sha256": checksum.hexdigest(), "bytes": size}


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def attempt_lock(directory, shared=False, create=False):
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), "attempt directory must be a real directory")
    flags = os.O_RDWR | (os.O_CREAT | os.O_EXCL if create else 0)
    with open_regular(directory / "writer.lock", flags) as stream:
        try:
            fcntl.flock(stream.fileno(), (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("attempt has an active writer or reader") from error
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def exclusive_write(path, data):
    with open_regular(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def atomic_write(path, value, fault=lambda _: None):
    path = Path(path)
    require(not path.is_symlink(), "projection destination is a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".projection-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        fault("during_projection_replace")
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_projection(directory, path, record, fault=lambda _: None):
    """Replace derived records only; never redirect a projection into evidence."""
    directory, path = Path(directory).resolve(), Path(path)
    destination = path.resolve()
    if destination.is_relative_to(directory):
        require(destination.parent == directory and destination.suffix == ".json" and
                destination.name not in {"invocation.json", "response-metadata.json"},
                "projection cannot replace original evidence")
    if path.exists():
        previous = strict_json(read_small(path))
        require(isinstance(previous, dict) and previous.get("schema_version") == 2 and
                previous.get("attempt") == record["attempt"] and "events" in previous,
                "projection cannot replace another original or attempt")
    atomic_write(path, record, fault)


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {
        "attempt_id", "task_id", "mode", "repetition", "suite_sha256", "client", "argv", "cwd"},
        "invocation manifest fields differ")
    require(str(uuid.UUID(value["attempt_id"])) == value["attempt_id"], "noncanonical attempt UUID")
    require(isinstance(value["task_id"], str) and re.fullmatch(r"D[0-9]{2}", value["task_id"]), "literal task ID required")
    require(value["mode"] in ("navigation", "open_search"), "unknown discovery mode")
    require(type(value["repetition"]) is int and value["repetition"] > 0, "positive repetition required")
    require(isinstance(value["suite_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["suite_sha256"]), "invalid suite digest")
    require(isinstance(value["client"], str) and 0 < len(value["client"]) <= 4096, "client description required")
    require(isinstance(value["argv"], list) and value["argv"] and
            all(isinstance(arg, str) and "\x00" not in arg for arg in value["argv"]), "argv must be literal strings")
    require(isinstance(value["cwd"], str) and Path(value["cwd"]).is_absolute(), "absolute working directory required")


def read_process_identity(pid):
    """Read identity or expose absence/read failure to the recovery caller."""
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    record = Path(f"/proc/{pid}/stat").read_text()
    fields = record[record.rfind(")") + 2:].split()
    return {"boot_id": boot, "pid": pid, "start_ticks": int(fields[19])}


def process_identity(pid):
    """Record a nullable launch identity when a short-lived child raced the read."""
    try:
        return read_process_identity(pid)
    except (OSError, ValueError, IndexError):
        return {"boot_id": None, "pid": pid, "start_ticks": None}


class Journal:
    def __init__(self, directory, utc=None, monotonic=None, append=False):
        self.directory = Path(directory)
        self.utc = utc or (lambda: dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
        self.monotonic = monotonic or time.monotonic_ns
        self.origin = self.monotonic()
        self.clock_id = str(uuid.uuid4())
        self.sequence = 0
        self.previous = None
        if append:
            rows, partial = read_journal(self.directory)
            require(not partial, "cannot append beyond a partial journal line")
            self.sequence = len(rows)
            self.previous = digest(read_small(self.directory / "receiver-journal.jsonl").splitlines(keepends=True)[-1]) if rows else None
        flags = os.O_WRONLY | (os.O_APPEND if append else os.O_CREAT | os.O_EXCL)
        self.stream = open_regular(self.directory / "receiver-journal.jsonl", flags)
        sync_directory(self.directory)

    def append(self, kind, facts):
        row = {"sequence": self.sequence, "previous_sha256": self.previous,
               "kind": kind, "observed_at": self.utc(),
               "receiver_clock_id": self.clock_id,
               "monotonic_elapsed_ns": self.monotonic() - self.origin, "facts": facts}
        data = canonical(row)
        self.stream.write(data)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.previous = digest(data)
        self.sequence += 1
        return row

    def close(self):
        self.stream.close()

    def refresh_cursor(self):
        """Reconcile a completed write interrupted before cursor advancement."""
        self.stream.flush()
        os.fsync(self.stream.fileno())
        rows, partial = read_journal(self.directory)
        if not partial:
            self.sequence = len(rows)
            self.previous = digest(read_small(self.directory / "receiver-journal.jsonl").splitlines(keepends=True)[-1]) if rows else None
        return rows, partial


def parse_event(data, oversized=False):
    if oversized:
        return None, "oversized"
    try:
        event = strict_json(data)
        require(isinstance(event, dict) and isinstance(event.get("type"), str), "event type required")
        answer = event.get("item", {})
        if event["type"] == "item.completed" and isinstance(answer, dict) and answer.get("type") == "agent_message":
            require(isinstance(answer.get("text"), str), "agent message text required")
            answer["text"].encode("utf-8")
        return event, "parsed"
    except (ValueError, UnicodeError, RecursionError):
        return None, "invalid"


def answer_bytes(event):
    item = event.get("item") if event else None
    if event and event["type"] == "item.completed" and isinstance(item, dict) and item.get("type") == "agent_message":
        return item["text"].encode("utf-8")
    return None


def event_facts(offset, length, checksum, event, state):
    return {"offset": offset, "length": length, "sha256": checksum,
            "parse_state": state, "event_type": event["type"] if event else None}


class EventReceiver:
    """Retain chunks first, then observe complete ranges with bounded parsing."""
    def __init__(self, directory, journal, fault=lambda _: None, parse_limit=PARSE_LIMIT):
        self.directory, self.journal, self.fault = Path(directory), journal, fault
        self.limit = parse_limit
        self.stream = open_regular(self.directory / "native-events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        sync_directory(self.directory)
        self.offset = self.length = 0
        self.checksum = hashlib.sha256()
        self.buffer = bytearray()

    def feed(self, chunk):
        self.stream.write(chunk)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        # Only LF closes JSONL; CR is part of the retained original range.
        segments = re.findall(rb"[^\n]*\n|[^\n]+$", chunk)
        for segment in segments:
            self.checksum.update(segment)
            self.length += len(segment)
            if self.length <= self.limit:
                self.buffer.extend(segment)
            else:
                self.buffer.clear()
            if segment.endswith(b"\n"):
                self.finish_line()

    def finish_line(self):
        event, state = parse_event(bytes(self.buffer), self.length > self.limit)
        facts = event_facts(self.offset, self.length, self.checksum.hexdigest(), event, state)
        if event and event["type"] in {"turn.completed", "turn.failed", "error"}:
            self.fault("after_terminal_bytes_before_observation")
        answer = answer_bytes(event)
        if answer is not None:
            exclusive_write(self.directory / f"answer-{self.offset:016d}.txt", answer)
            self.fault("after_answer_file_write_before_observation")
        self.journal.append("native_event", facts)
        if event and event["type"] in {"turn.completed", "turn.failed", "error"}:
            self.fault("after_terminal_observation_before_wait")
        self.offset += self.length
        self.length = 0
        self.buffer.clear()
        self.checksum = hashlib.sha256()

    def close(self):
        self.stream.close()


def scan_events(path, limit=PARSE_LIMIT):
    """Yield exact complete ranges; report a partial last line separately."""
    offset = length = 0
    checksum, buffer = hashlib.sha256(), bytearray()
    with open_regular(path) as stream:
        while chunk := stream.read(65536):
            for segment in re.findall(rb"[^\n]*\n|[^\n]+$", chunk):
                length += len(segment)
                checksum.update(segment)
                if length <= limit:
                    buffer.extend(segment)
                else:
                    buffer.clear()
                if segment.endswith(b"\n"):
                    event, state = parse_event(bytes(buffer), length > limit)
                    yield event_facts(offset, length, checksum.hexdigest(), event, state), event
                    offset += length
                    length = 0
                    checksum, buffer = hashlib.sha256(), bytearray()
    if length:
        yield event_facts(offset, length, checksum.hexdigest(), None, "incomplete"), None


def read_journal(directory, binding=None):
    path = Path(directory) / "receiver-journal.jsonl"
    if binding is None:
        data = read_small(path, JSON_LIMIT)
    else:
        require(type(binding["bytes"]) is int and 0 <= binding["bytes"] <= JSON_LIMIT, "journal prefix exceeds parsing budget")
        with open_regular(path) as stream:
            data = stream.read(binding["bytes"])
        require(len(data) == binding["bytes"] and digest(data) == binding["sha256"], "journal prefix binding differs")
    rows, previous, clocks = [], None, {}
    lines = data.splitlines(keepends=True)
    partial = bool(lines and not lines[-1].endswith(b"\n"))
    for line in lines[:-1] if partial else lines:
        row = strict_json(line)
        require(isinstance(row, dict) and set(row) == {"sequence", "previous_sha256", "kind", "observed_at", "receiver_clock_id", "monotonic_elapsed_ns", "facts"}, "journal fields differ")
        require(type(row["sequence"]) is int and row["sequence"] == len(rows) and row["previous_sha256"] == previous, "journal chain differs")
        clock = row["receiver_clock_id"]
        require(isinstance(clock, str) and str(uuid.UUID(clock)) == clock, "receiver clock UUID required")
        require(type(row["monotonic_elapsed_ns"]) is int and row["monotonic_elapsed_ns"] >= clocks.get(clock, 0), "monotonic clock order differs")
        require(row["kind"] in {"prepared", "launched", "native_event", "native_wait", "driver_closure", "contract"}, "unknown journal kind")
        stamp = row["observed_at"]
        require(isinstance(stamp, str) and stamp.endswith("Z") and dt.datetime.fromisoformat(stamp).utcoffset() == dt.timedelta(0), "UTC observation required")
        require(isinstance(row["facts"], dict), "journal facts must be an object")
        rows.append(row)
        previous, clocks[clock] = digest(line), row["monotonic_elapsed_ns"]
    return rows, partial


def observation(row):
    return None if row is None else {"sequence": row["sequence"], "observed_at": row["observed_at"],
                                     "receiver_clock_id": row["receiver_clock_id"],
                                     "monotonic_elapsed_ns": row["monotonic_elapsed_ns"]}


def derive_record(directory, journal_binding=None):
    directory = Path(directory)
    require(not directory.is_symlink() and directory.is_dir(), "attempt directory must be a real directory")
    manifest = strict_json(read_small(directory / "invocation.json"))
    validate_manifest(manifest)
    rows, partial = read_journal(directory, journal_binding)
    require(rows and rows[0]["kind"] == "prepared", "prepared observation missing")
    require(sum(row["kind"] == "prepared" for row in rows) == 1, "duplicate prepared observation")
    launched = [row for row in rows if row["kind"] == "launched"]
    require(len(launched) <= 1 and (not launched or launched[0]["sequence"] == 1), "launch observation order differs")
    if launched:
        identity = launched[0]["facts"]
        require(set(identity) == {"boot_id", "pid", "start_ticks"} and type(identity["pid"]) is int and identity["pid"] > 0,
                "invalid recorded process identity")
        require(identity["boot_id"] is None or (isinstance(identity["boot_id"], str) and str(uuid.UUID(identity["boot_id"])) == identity["boot_id"]), "invalid boot identity")
        require(identity["start_ticks"] is None or (type(identity["start_ticks"]) is int and identity["start_ticks"] > 0), "invalid process start identity")
    require(not (directory / "driver-source").is_symlink(), "source directory is a symlink")
    expected = {"invocation": file_binding(directory / "invocation.json"),
                "prompt": file_binding(directory / "prompt.txt"),
                "driver_sources": {name: file_binding(directory / "driver-source" / name)
                                   for name in ("discovery_capture.py", "discovery_capture_journal.py")}}
    require(rows[0]["facts"] == expected, "prepared source bindings differ")
    event_rows = [row for row in rows if row["kind"] == "native_event"]
    require(not event_rows or launched, "native events precede launch")
    events, responses, index = [], [], 0
    for facts, event in scan_events(directory / "native-events.jsonl"):
        row = event_rows[index] if index < len(event_rows) else None
        if row is not None:
            require(row["facts"] == facts and facts["parse_state"] != "incomplete", "native range or source binding differs")
            index += 1
        events.append({**facts, "observation": observation(row)})
        answer = answer_bytes(event)
        if answer is not None:
            answer_path = directory / f"answer-{facts['offset']:016d}.txt"
            if answer_path.exists():
                require(file_binding(answer_path) == {"sha256": digest(answer), "bytes": len(answer)}, "answer bytes differ from native event text")
            require(row is None or answer_path.exists(), "observed answer capture missing")
            responses.append({"origin": "native_event_text", "event_offset": facts["offset"],
                              "sha256": digest(answer), "bytes": len(answer), "observation": observation(row)})
    require(index == len(event_rows), "journal observes absent native bytes")
    waits = [row for row in rows if row["kind"] == "native_wait"]
    closures = [row for row in rows if row["kind"] == "driver_closure"]
    require(len(waits) <= 1 and len(closures) <= 1, "duplicate closure observations")
    if waits:
        require(launched and waits[0]["sequence"] > launched[0]["sequence"] and
                all(row["sequence"] < waits[0]["sequence"] for row in event_rows), "native wait order differs")
        require(set(waits[0]["facts"]) == {"exit_code"} and type(waits[0]["facts"]["exit_code"]) is int, "invalid wait observation")
    if closures:
        require(set(closures[0]["facts"]) == {"state"} and closures[0]["facts"]["state"] in {"completed", "interrupted"}, "invalid driver closure")
        require(waits and closures[0]["sequence"] > waits[0]["sequence"], "driver closure precedes native wait")
    contracts = [row for row in rows if row["kind"] == "contract"]
    require(len(contracts) <= 1, "duplicate contract observation")
    contract = {"origin": "supplied_metadata", "state": "not_evaluated", "metadata": None,
                "selection": None, "refusal": None, "refusal_detail": None, "validator_sources": None, "observation": None}
    if contracts:
        from discovery_capture_v2 import metadata_result
        row = contracts[0]
        require(row == rows[-1], "contract must be the final journal observation")
        contract = metadata_result(directory / "response-metadata.json")
        require(row["facts"] == contract, "metadata or contract result differs")
        contract = {**contract, "observation": observation(row)}
    return {"schema_version": 2, "attempt": {key: manifest[key] for key in ("attempt_id", "task_id", "mode", "repetition", "suite_sha256")},
            "sources": {"invocation": expected["invocation"], "prompt": expected["prompt"],
                        "driver_sources": expected["driver_sources"], "native_events": file_binding(directory / "native-events.jsonl"),
                        "stderr": file_binding(directory / "native-stderr.txt"), "journal": journal_binding or file_binding(directory / "receiver-journal.jsonl")},
            "journal_partial_tail": partial, "events": events,
            "response": {"state": "absent" if not responses else "observed" if len(responses) == 1 else "multiple", "captures": responses},
            "contract": contract,
            "native_closure": {"state": "exit_observed" if waits else "unknown", "exit_code": waits[0]["facts"]["exit_code"] if waits else None, "observation": observation(waits[0]) if waits else None},
            "driver_closure": {"state": closures[0]["facts"]["state"] if closures else "unknown", "observation": observation(closures[0]) if closures else None}}


def project(directory):
    """Derive under a shared lease; never race an original-byte append."""
    with attempt_lock(directory, shared=True):
        return derive_record(directory)
