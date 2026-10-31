"""Real local driver crashes and explicit private-to-public byte selection."""

import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tracemalloc

import pytest

from test_discovery_capture import invocation, answer_body
from test_discovery_capture_v2 import retained, selection
import discovery_capture as driver
import discovery_capture_journal as custody
import discovery_capture_recovery as recovery
import discovery_capture_v2 as reader


FAULTS = ("after_launch_identity", "after_answer_file_write_before_observation",
          "after_terminal_bytes_before_observation", "after_terminal_observation_before_wait",
          "after_wait_before_observation", "after_wait_observation_before_driver_close", "during_projection_replace")


@pytest.mark.parametrize("point", FAULTS)
def test_actual_driver_crashes_preserve_four_fact_boundaries(tmp_path, point):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    controller = tmp_path / "fault-driver.py"
    controller.write_text(f"import os,sys\nsys.path.insert(0,{str(Path(driver.__file__).parent)!r})\nimport discovery_capture\n"
        "def fault(point):\n    if point == sys.argv[4]:\n        os._exit(86)\n"
        "discovery_capture.capture(sys.argv[1],sys.argv[2],sys.argv[3],fault)\n")
    result = subprocess.run([sys.executable, str(controller), str(manifest), str(prompt), str(attempt), point], timeout=15)
    assert result.returncode == 86
    original = {path.relative_to(attempt).as_posix(): custody.file_binding(path) for path in attempt.rglob("*") if path.is_file()}
    supplement = recovery.recover(attempt, tmp_path / "recovery.json")
    record = supplement["record"]
    assert record["contract"]["state"] == "not_evaluated"
    expected_native = "exit_observed" if point in {"after_wait_observation_before_driver_close", "during_projection_replace"} else "unknown"
    assert record["native_closure"]["state"] == expected_native
    assert record["driver_closure"]["state"] == ("completed" if point == "during_projection_replace" else "unknown")
    if point == "after_answer_file_write_before_observation":
        assert record["response"]["state"] == "observed"
        assert record["response"]["captures"][0]["observation"] is None
    if point != "after_launch_identity":
        assert record["response"]["state"] == "observed"
    custody.write_projection(attempt, tmp_path / "recovered-record.json", record)
    assert reader.check_record(tmp_path / "recovered-record.json", attempt) == record
    assert original == {path.relative_to(attempt).as_posix(): custody.file_binding(path) for path in attempt.rglob("*") if path.is_file()}
    with pytest.raises(FileExistsError):
        recovery.recover(attempt, tmp_path / "recovery.json")


def test_partial_journal_and_original_response_are_not_repaired(tmp_path):
    attempt = retained(tmp_path)
    journal = attempt / "receiver-journal.jsonl"
    original = journal.read_bytes()
    # Preserve the genuine wait row as a torn final observation, rather than
    # inventing a wait result from the already retained native terminal event.
    lines = original.splitlines(keepends=True)
    wait_index = next(i for i, line in enumerate(lines) if custody.strict_json(line)["kind"] == "native_wait")
    torn = b"".join(lines[:wait_index]) + lines[wait_index][:25]
    journal.write_bytes(torn)
    supplement = recovery.recover(attempt, tmp_path / "supplement.json")
    assert journal.read_bytes() == torn
    assert supplement["record"]["journal_partial_tail"]
    assert supplement["record"]["native_closure"]["state"] == "unknown"
    assert supplement["record"]["driver_closure"]["state"] == "unknown"
    assert supplement["record"]["response"]["state"] == "observed"
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(custody.canonical(selection()))
    with pytest.raises(ValueError, match="partial"):
        reader.retain_contract(attempt, metadata)
    assert not (attempt / "response-metadata.json").exists()


def test_pid_start_and_boot_mismatch_against_actual_owned_identity():
    actual = custody.read_process_identity(os.getpid())
    assert recovery.identity_status(actual) == "identity_present"
    # Simulate a recorded prior PID incarnation while reading the real current
    # PID. This does not claim that the kernel actually reused a PID in this run.
    prior = {**actual, "start_ticks": actual["start_ticks"] + 1}
    assert recovery.identity_status(prior) == "not_original_identity"
    prior = {**actual, "boot_id": "00000000-0000-0000-0000-000000000000"}
    assert recovery.identity_status(prior) == "not_original_identity"
    assert recovery.identity_status(None) == "unknown"
    assert recovery.identity_status({**actual, "start_ticks": None}) == "unknown"
    assert recovery.identity_status(actual, lambda _: {**actual, "boot_id": None}) == "unknown"
    assert recovery.identity_status(actual, lambda _: {**actual, "start_ticks": None}) == "unknown"
    def denied(_):
        raise PermissionError("synthetic read denial")
    assert recovery.identity_status(actual, denied) == "unknown"


def test_public_export_excludes_native_preferences_and_literal_metadata(tmp_path):
    sentinel = "synthetic-private-preference-sentinel"
    body = f"print('{{\"type\":\"{sentinel}\",\"private\":\"{sentinel}\"}}')\n" + answer_body().replace("private answer", sentinel)
    manifest, prompt = invocation(tmp_path, body, code=7)
    prompt.write_bytes(sentinel.encode())
    attempt = tmp_path / "attempt"
    driver.capture(manifest, prompt, attempt)
    metadata = tmp_path / "metadata.json"
    value = selection()
    value["profile_ids"] = [sentinel + "/invalid"]
    metadata.write_bytes(custody.canonical(value))
    record = reader.retain_contract(attempt, metadata)
    assert record["contract"]["refusal_detail"] == "Selection violates pattern at /profile_ids/0."
    assert sentinel.encode() in (attempt / "response-metadata.json").read_bytes()
    report = recovery.export_public(reader.check_record(attempt / "record.json", attempt), tmp_path / "public.json")
    data = (tmp_path / "public.json").read_bytes()
    assert sentinel.encode() not in data
    assert str(tmp_path).encode() not in data
    assert "selection" not in report["contract"]
    assert report["contract"]["origin"] == "supplied_metadata"
    assert report["events"][0]["category"] == "other"
    assert report["native_closure"]["exit_code"] == 7
    assert report["approved_pages"] == []
    with pytest.raises(ValueError):
        recovery.export_public(record, tmp_path / "public.json")


def page_approval(tmp_path):
    root = tmp_path / "pages"
    root.mkdir()
    body = b"Explicitly reviewed synthetic public page body.\n"
    (root / "page.txt").write_bytes(body)
    page = {"path": "page.txt", "sha256": custody.digest(body), "bytes": len(body),
            "url": "https://example.com/page", "output_name": "page.txt"}
    approval = tmp_path / "approval.json"
    approval.write_bytes(custody.canonical({"schema_version": 1, "reviewed": True, "pages": [page]}))
    return root, approval, page, body


def test_public_pages_require_exact_explicit_manifest(tmp_path):
    attempt = retained(tmp_path)
    root, approval, page, body = page_approval(tmp_path)
    report = recovery.export_public(custody.project(attempt), tmp_path / "public.json", approval, root)
    assert (tmp_path / "public.json.pages" / "page.txt").read_bytes() == body
    assert report["approved_pages"] == [{key: page[key] for key in ("output_name", "sha256", "bytes", "url")}]
    assert "path" not in report["approved_pages"][0]


@pytest.mark.parametrize("change", ["hash", "escape", "symlink", "unreviewed", "credentials", "duplicate", "oversized"])
def test_page_export_refuses_before_public_copy(tmp_path, change):
    attempt = retained(tmp_path)
    root, approval, page, _ = page_approval(tmp_path)
    manifest = custody.strict_json(approval.read_bytes())
    if change == "hash":
        page["sha256"] = "0" * 64
    elif change == "escape":
        page["path"] = "../prompt.txt"
    elif change == "symlink":
        (root / "page.txt").unlink()
        (root / "page.txt").symlink_to(attempt / "prompt.txt")
    elif change == "unreviewed":
        manifest["reviewed"] = False
    elif change == "credentials":
        page["url"] = "https://private:secret@example.com/page"
    elif change == "duplicate":
        manifest["pages"].append(page)
    elif change == "oversized":
        page["bytes"] = custody.PARSE_LIMIT + 1
    manifest["pages"][0] = page
    approval.write_bytes(custody.canonical(manifest))
    with pytest.raises(ValueError):
        recovery.export_public(custody.project(attempt), tmp_path / "public.json", approval, root)
    assert not (tmp_path / "public.json").exists()
    assert not (tmp_path / "public.json.pages").exists()


def test_recovery_and_public_cli(tmp_path):
    attempt = retained(tmp_path)
    assert driver.main(["recover", "--attempt-dir", str(attempt), "--output", str(tmp_path / "supplement.json")]) == 0
    assert driver.main(["recover", "--attempt-dir", str(attempt)]) == 2
    assert driver.main(["recover", "--attempt-dir", str(attempt), "--output", str(attempt / "bad.json")]) == 2
    args = ["export-public", "--record", str(attempt / "record.json"), "--attempt-dir", str(attempt)]
    assert reader.main(args) == 2
    assert reader.main(args + ["--output", str(tmp_path / "public.json")]) == 0
    assert reader.main(args + ["--output", str(tmp_path / "bad.json"), "--page-root", str(tmp_path)]) == 2
    assert reader.main(["check", "--record", str(attempt / "record.json"), "--attempt-dir", str(attempt), "--output", str(tmp_path / "bad.json")]) == 2


def test_actual_oversized_native_line_is_retained_without_parsing(tmp_path):
    body = f"sys.stdout.write('{{\"type\":\"private-event\",\"blob\":\"' + 'x' * {custody.PARSE_LIMIT} + '\"}}\\n')\n" + answer_body()
    manifest, prompt = invocation(tmp_path, body)
    record, _ = driver.capture(manifest, prompt, tmp_path / "attempt")
    assert record["events"][0]["length"] > custody.PARSE_LIMIT
    assert record["events"][0]["parse_state"] == "oversized"
    assert record["response"]["state"] == "observed"
    assert record["sources"]["native_events"]["bytes"] > custody.PARSE_LIMIT
    reader.check_record(tmp_path / "attempt" / "record.json", tmp_path / "attempt")


def test_invalid_metadata_validation_has_a_bounded_error_budget(tmp_path):
    attempt = retained(tmp_path)
    metadata = tmp_path / "many-errors.json"
    value = selection()
    value["component_ids"] = [7] * 100000
    metadata.write_bytes(custody.canonical(value))
    reader.retain_contract(attempt, metadata)
    tracemalloc.start()
    try:
        result = reader.metadata_result(attempt / "response-metadata.json")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result["state"] == "invalid" and result["refusal"] == "invalid_contract"
    assert peak < custody.JSON_LIMIT
    assert custody.file_binding(attempt / "response-metadata.json") == custody.file_binding(metadata)
    (tmp_path / "validation-budget.json").write_bytes(custody.canonical({"invalid_entries": 100000, "peak_traced_bytes": peak,
                                                                      "budget_bytes": custody.JSON_LIMIT, "original_bytes_retained": True}))


def test_small_reads_do_not_allocate_the_whole_parsing_budget(tmp_path):
    source = tmp_path / "small-input"
    source.write_bytes(b"x" * 200001)
    tracemalloc.start()
    try:
        data = custody.read_small(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert data == b"x" * 200001
    assert peak < 4 * len(data)
    (tmp_path / "small-read-allocation.json").write_bytes(custody.canonical({"input_bytes": len(data), "peak_traced_bytes": peak}))


def test_retained_validator_sources_are_bound(tmp_path):
    attempt = retained(tmp_path)
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(custody.canonical(selection()))
    record = reader.retain_contract(attempt, metadata)
    assert record["contract"]["validator_sources"]["discovery_capture_v2.py"] == custody.file_binding(attempt / "contract-source" / "discovery_capture_v2.py")
    source = attempt / "contract-source" / "discovery-capture-v2.schema.json"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="contract result differs"):
        reader.check_record(attempt / "record.json", attempt)


def test_interrupt_after_wait_observation_does_not_duplicate_closure(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    def interrupt(point):
        if point == "after_wait_observation_before_driver_close":
            raise KeyboardInterrupt
    record, status = driver.capture(manifest, prompt, attempt, interrupt)
    assert status == 130
    rows, _ = custody.read_journal(attempt)
    assert sum(row["kind"] == "native_wait" for row in rows) == 1
    assert sum(row["kind"] == "driver_closure" for row in rows) == 1
    assert record["native_closure"]["exit_code"] == 0
    assert record["driver_closure"]["state"] == "interrupted"


def test_interrupt_during_a_torn_observation_keeps_the_original_prefix(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    torn_bytes = b'{"synthetic-torn-observation":'
    def interrupt(point):
        if point == "after_terminal_bytes_before_observation":
            with (attempt / "receiver-journal.jsonl").open("ab") as stream:
                stream.write(torn_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            raise KeyboardInterrupt
    record, status = driver.capture(manifest, prompt, attempt, interrupt)
    assert status == 130
    assert (attempt / "receiver-journal.jsonl").read_bytes().endswith(torn_bytes)
    assert record["journal_partial_tail"]
    assert record["native_closure"]["state"] == "unknown"
    assert record["driver_closure"]["state"] == "unknown"


def test_complete_wait_write_before_cursor_advance_is_reconciled(tmp_path, monkeypatch):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    original = custody.Journal.append
    def interrupt_after_write(self, kind, facts):
        if kind != "native_wait":
            return original(self, kind, facts)
        row = {"sequence": self.sequence, "previous_sha256": self.previous, "kind": kind,
               "observed_at": self.utc(), "receiver_clock_id": self.clock_id,
               "monotonic_elapsed_ns": self.monotonic() - self.origin, "facts": facts}
        self.stream.write(custody.canonical(row))
        self.stream.flush()
        os.fsync(self.stream.fileno())
        raise KeyboardInterrupt
    monkeypatch.setattr(custody.Journal, "append", interrupt_after_write)
    record, status = driver.capture(manifest, prompt, attempt)
    assert status == 130
    rows, _ = custody.read_journal(attempt)
    assert sum(row["kind"] == "native_wait" for row in rows) == 1
    assert record["native_closure"]["exit_code"] == 0
    assert record["driver_closure"]["state"] == "interrupted"
    reader.check_record(attempt / "record.json", attempt)


def test_missing_boot_is_unknown_and_missing_owned_pid_is_absent():
    actual = custody.read_process_identity(os.getpid())
    def missing_boot(_):
        raise FileNotFoundError(2, "synthetic missing boot", "/proc/sys/kernel/random/boot_id")
    def missing_pid(pid):
        raise FileNotFoundError(2, "synthetic missing PID", f"/proc/{pid}/stat")
    assert recovery.identity_status(actual, missing_boot) == "unknown"
    assert recovery.identity_status(actual, missing_pid) == "not_original_identity"


def test_actual_own_process_sigint_after_durable_wait(tmp_path):
    manifest, prompt = invocation(tmp_path, answer_body())
    attempt = tmp_path / "attempt"
    controller = tmp_path / "sigint-driver.py"
    controller.write_text(f"import os,sys,signal\nsignal.signal(signal.SIGINT,signal.default_int_handler)\nsys.path.insert(0,{str(Path(driver.__file__).parent)!r})\nimport discovery_capture\n"
        "def interrupt(point):\n    if point == 'after_wait_observation_before_driver_close':\n        os.kill(os.getpid(),signal.SIGINT)\n"
        "record,status=discovery_capture.capture(sys.argv[1],sys.argv[2],sys.argv[3],interrupt)\nraise SystemExit(status)\n")
    result = subprocess.run([sys.executable, str(controller), str(manifest), str(prompt), str(attempt)], timeout=15)
    assert result.returncode == 130
    record = reader.check_record(attempt / "record.json", attempt)
    assert record["native_closure"]["exit_code"] == 0
    assert record["driver_closure"]["state"] == "interrupted"
    rows, _ = custody.read_journal(attempt)
    assert sum(row["kind"] == "native_wait" for row in rows) == 1


def run_owned_controller(command, attempt, receipt_path, timeout):
    process = subprocess.Popen(command)
    receipt = {"controller_pid": process.pid, "timed_out": False, "native_identity_matched": False,
               "native_kill_requested": False}
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        receipt["timed_out"] = True
        raise
    finally:
        try:
            if (attempt / "receiver-journal.jsonl").exists():
                rows, _ = custody.read_journal(attempt)
                identities = [row["facts"] for row in rows if row["kind"] == "launched"]
                if identities:
                    identity = identities[0]
                    receipt["recorded_native_identity"] = identity
                    try:
                        current = custody.read_process_identity(identity["pid"])
                        matched = identity["boot_id"] is not None and identity["start_ticks"] is not None and current == identity
                        receipt["native_identity_matched"] = matched
                        if matched:
                            os.kill(identity["pid"], signal.SIGKILL)
                            receipt["native_kill_requested"] = True
                    except FileNotFoundError:
                        receipt["native_identity_absent"] = True
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            receipt["controller_returncode"] = process.wait()
            custody.exclusive_write(receipt_path, custody.canonical(receipt))


@pytest.mark.parametrize("scenario", ["interrupt", "unexpected", "timeout"])
def test_cleanup_reaps_only_its_sigterm_ignoring_child(tmp_path, scenario):
    ready = tmp_path / "child-ready"
    body = f"import signal,time\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath({str(ready)!r}).write_text('ready')\nwhile True: time.sleep(0.05)\n"
    manifest, prompt = invocation(tmp_path, body)
    # The ordinary answer fixture reads stdin first. This child must install
    # its hostile signal handler before the receiver's post-launch fault.
    (tmp_path / "child.py").write_text(body)
    attempt = tmp_path / "attempt"
    controller = tmp_path / "cleanup-driver.py"
    controller.write_text(f"import os,sys,signal,time\nfrom pathlib import Path\nsignal.signal(signal.SIGINT,signal.default_int_handler)\nsignal.signal(signal.SIGTERM,signal.default_int_handler)\nsys.path.insert(0,{str(Path(driver.__file__).parent)!r})\nimport discovery_capture\n"
        f"def fault(point):\n    if point == 'after_launch_identity':\n        end=time.monotonic()+5\n        while not Path({str(ready)!r}).exists():\n            assert time.monotonic()<end\n            time.sleep(0.01)\n"
        + {"interrupt": "        os.kill(os.getpid(),signal.SIGINT)\n", "unexpected": "        raise ValueError('synthetic unexpected failure')\n", "timeout": "        time.sleep(30)\n"}[scenario]
        + "try:\n    record,status=discovery_capture.capture(sys.argv[1],sys.argv[2],sys.argv[3],fault)\nexcept ValueError:\n    raise SystemExit(2)\nraise SystemExit(status)\n")
    started = time.monotonic()
    command = [sys.executable, str(controller), str(manifest), str(prompt), str(attempt)]
    receipt_path = tmp_path / "fixture-controller-cleanup.json"
    if scenario == "timeout":
        with pytest.raises(subprocess.TimeoutExpired):
            run_owned_controller(command, attempt, receipt_path, 1.5)
        receipt = custody.strict_json(receipt_path.read_bytes())
        assert receipt["timed_out"] and receipt["native_identity_matched"] and receipt["native_kill_requested"]
        returncode = receipt["controller_returncode"]
    else:
        returncode = run_owned_controller(command, attempt, receipt_path, 10)
    assert time.monotonic() - started < 8
    assert ready.read_text() == "ready"
    rows, _ = custody.read_journal(attempt)
    identity = next(row["facts"] for row in rows if row["kind"] == "launched")
    assert recovery.identity_status(identity) == "not_original_identity"
    record = custody.project(attempt)
    if scenario != "unexpected":
        assert returncode == 130
        assert record["native_closure"]["exit_code"] == -9
        assert record["driver_closure"]["state"] == "interrupted"
        reader.check_record(attempt / "record.json", attempt)
    else:
        assert returncode == 2
        assert record["native_closure"]["state"] == record["driver_closure"]["state"] == "unknown"
        assert not (attempt / "record.json").exists()
