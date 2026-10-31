"""Synthetic local children exercise custody; these are not study attempts."""

import datetime as dt
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import discovery_capture as driver
import discovery_capture_journal as custody


def invocation(tmp_path, body, code=0):
    child = tmp_path / "child.py"
    child.write_text("import sys\nsys.stdin.buffer.read()\n" + body + f"\nsys.exit({code})\n")
    manifest = tmp_path / "input.json"
    manifest.write_bytes(custody.canonical({"attempt_id": str(uuid.uuid4()), "task_id": "D01", "mode": "navigation", "repetition": 1,
        "suite_sha256": "1" * 64, "client": "synthetic-author-control", "argv": [sys.executable, str(child)], "cwd": str(tmp_path)}))
    prompt = tmp_path / "prompt.txt"
    prompt.write_bytes(b"synthetic private prompt\n")
    return manifest, prompt


def answer_body():
    return "import json\nprint(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'private answer'}}), flush=True)\nprint(json.dumps({'type':'turn.completed'}), flush=True)"


@pytest.mark.parametrize("code", [0, 7])
def test_native_exit_and_response_are_separate(tmp_path, code):
    manifest, prompt = invocation(tmp_path, answer_body(), code)
    attempt = tmp_path / "attempt"
    record, status = driver.capture(manifest, prompt, attempt)
    assert status == 0
    assert record["response"]["state"] == "observed"
    assert record["native_closure"]["exit_code"] == code
    assert record["driver_closure"]["state"] == "completed"
    assert record["contract"]["state"] == "not_evaluated"
    assert (attempt / "prompt.txt").read_bytes() == prompt.read_bytes()
    assert (attempt / "answer-0000000000000000.txt").read_bytes() == b"private answer"
    assert os.stat(attempt).st_mode & 0o777 == 0o700
    assert all(os.stat(path).st_mode & 0o777 == (0o700 if path.is_dir() else 0o600) for path in attempt.iterdir())
    with pytest.raises(FileExistsError):
        driver.capture(manifest, prompt, attempt)


def test_receiver_bounded_original_bytes_and_incomplete_tail(tmp_path):
    journal = custody.Journal(tmp_path)
    receiver = custody.EventReceiver(tmp_path, journal, parse_limit=128)
    original = b'{"type":"turn.completed","private":"' + b"x" * 5000 + b'"}\n{"type":'
    for start in range(0, len(original), 37):
        receiver.feed(original[start:start + 37])
        assert len(receiver.buffer) <= 128
    receiver.close()
    journal.close()
    assert (tmp_path / "native-events.jsonl").read_bytes() == original
    rows, partial = custody.read_journal(tmp_path)
    assert not partial and rows[0]["facts"]["parse_state"] == "oversized"
    events = list(custody.scan_events(tmp_path / "native-events.jsonl", limit=128))
    assert events[0][0] == rows[0]["facts"]
    assert events[1][0]["parse_state"] == "incomplete"


def test_receiver_clock_adjustment_does_not_change_order(tmp_path):
    utc = iter(["2026-10-05T20:00:02Z", "2026-10-05T20:00:01Z"])
    monotonic = iter([100, 101, 102])
    journal = custody.Journal(tmp_path, lambda: next(utc), lambda: next(monotonic))
    journal.append("native_event", {})
    journal.append("native_event", {})
    journal.close()
    rows, _ = custody.read_journal(tmp_path)
    assert rows[0]["observed_at"] > rows[1]["observed_at"]
    assert rows[0]["monotonic_elapsed_ns"] < rows[1]["monotonic_elapsed_ns"]


def test_strict_json_and_regular_file_boundary(tmp_path):
    for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
        with pytest.raises(ValueError):
            custody.strict_json(data)
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError):
        custody.read_small(path)
    real = tmp_path / "real"
    real.write_bytes(b"{}")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        custody.read_small(link)


def test_projection_refuses_native_tamper(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    driver.capture(manifest, prompt, attempt)
    source = attempt / "native-events.jsonl"
    source.write_bytes(source.read_bytes().replace(b"private answer", b"changed answer"))
    with pytest.raises(ValueError, match="binding differs"):
        custody.project(attempt)


def test_partial_native_event_is_not_a_terminal_fact(tmp_path):
    manifest, prompt = invocation(tmp_path, "sys.stdout.write('{\"type\":\"turn.completed\"')")
    record, _ = driver.capture(manifest, prompt, tmp_path / "attempt")
    assert record["events"][0]["parse_state"] == "incomplete"
    assert record["events"][0]["observation"] is None
    assert record["response"]["state"] == "absent"
    assert record["native_closure"]["exit_code"] == 0


def test_atomic_projection_failure_preserves_previous_bytes(tmp_path):
    output = tmp_path / "record.json"
    output.write_bytes(b"previous exact bytes")
    def fail(_):
        raise RuntimeError("synthetic projection fault")
    with pytest.raises(RuntimeError):
        custody.atomic_write(output, {"new": True}, fail)
    assert output.read_bytes() == b"previous exact bytes"
    assert list(tmp_path.iterdir()) == [output]


def test_cli_capture_project_and_refusals(tmp_path):
    manifest, prompt = invocation(tmp_path, "sys.stderr.write('private error\\n')")
    attempt = tmp_path / "attempt"
    assert driver.main(["capture", "--manifest", str(manifest), "--prompt", str(prompt), "--attempt-dir", str(attempt)]) == 0
    assert driver.main(["project", "--attempt-dir", str(attempt), "--output", str(tmp_path / "projection.json")]) == 0
    assert (attempt / "native-stderr.txt").read_bytes() == b"private error\n"
    assert driver.main(["capture", "--attempt-dir", str(attempt)]) == 2
    assert driver.main(["project", "--attempt-dir", str(attempt)]) == 2
    assert driver.main(["project", "--attempt-dir", str(tmp_path / "missing"), "--output", str(tmp_path / "x")]) == 2


def test_empty_prompt_and_multiple_answers(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body() + "\n" + answer_body())
    prompt.write_bytes(b"")
    record, _ = driver.capture(manifest, prompt, tmp_path / "attempt")
    assert record["response"]["state"] == "multiple"
    assert sum(row["event_type"] == "turn.completed" for row in record["events"]) == 2
    assert custody.process_identity(999999999)["start_ticks"] is None


@pytest.mark.parametrize("event,state", [(b'[]', "invalid"), (b'{"type":"item.completed","item":{"type":"agent_message","text":7}}', "invalid"),
                                          (b'{"type":"metrics","usage":1.5}', "parsed"), (b'{"type":"metrics","usage":1e999}', "invalid")])
def test_native_parser_keeps_legitimate_floats(event, state):
    assert custody.parse_event(event)[1] == state


def test_journal_chain_and_clock_refuse_tampering(tmp_path):
    journal = custody.Journal(tmp_path)
    journal.append("native_event", {})
    journal.append("native_event", {})
    journal.close()
    path = tmp_path / "receiver-journal.jsonl"
    data = path.read_bytes()
    rows = [custody.strict_json(line) for line in data.splitlines()]
    rows[1]["previous_sha256"] = "0" * 64
    path.write_bytes(b"".join(custody.canonical(row) for row in rows))
    with pytest.raises(ValueError, match="chain"):
        custody.read_journal(tmp_path)
    path.write_bytes(data + b'{"partial":')
    observed, partial = custody.read_journal(tmp_path)
    assert len(observed) == 2 and partial


def test_owned_interrupt_observes_actual_child_wait(tmp_path):
    manifest, prompt = invocation(tmp_path, "import time\ntime.sleep(60)")
    def interrupt(point):
        if point == "after_launch_identity":
            raise KeyboardInterrupt
    record, status = driver.capture(manifest, prompt, tmp_path / "attempt", interrupt)
    assert status == 130
    assert record["driver_closure"]["state"] == "interrupted"
    assert record["native_closure"]["state"] == "exit_observed"
    assert record["native_closure"]["exit_code"] != 0


def test_child_can_close_stdin_early_without_losing_stdout(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body())
    child = tmp_path / "child.py"
    child.write_text("import os\nos.close(0)\n" + answer_body())
    prompt.write_bytes(b"x" * 200000)
    record, _ = driver.capture(manifest, prompt, tmp_path / "attempt")
    assert record["response"]["state"] == "observed"
