"""Actual installed commands check original triples and hostile record controls."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import stat
import tracemalloc
import unittest
from pathlib import Path
from mintid_trace.reader import Admission, Limits, MAX_BYTES, Refused, read_member, read_record, root

RECORDS = Path(os.environ["MINTID_RECORDS"])
GO = Path(os.environ["MINTID_GO"])
ADMISSION = Path(os.environ["MINTID_ADMISSION"])
STEMS = ("revocation-trace-local-20261004T122943Z", "revocation-trace-testnet-20261004T153434Z", "revocation-trace-testnet-20261005T022948Z")
LIMITS = Limits(1 << 20, 256, 257, 2 << 20, 4 << 20, 2048)


class ReaderControls(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ["MINTID_CAPTURE_ROOT"]) / self.id().split(".")[-1]
        self.directory = base / "fixture"
        self.directory.mkdir(parents=True)
        self.stem = STEMS[2]
        for suffix in (".jsonl", ".manifest.json", ".md"):
            (self.directory / (self.stem + suffix)).write_bytes((RECORDS / (self.stem + suffix)).read_bytes())
        self.capture = base / "native"
        self.selected = Admission(GO, ADMISSION, self.capture, LIMITS)

    def tearDown(self):
        facts = []
        if self.directory.is_symlink():
            (self.capture.parent / "fixture-directory-facts.json").write_text(json.dumps({"symlink": True, "target": os.readlink(self.directory)}) + "\n")
            return
        for name in (self.stem + suffix for suffix in (".manifest.json", ".jsonl", ".md")):
            if Path(name).name != name:
                facts.append({"name": name, "not_opened": "noncanonical basename"}); continue
            path = self.directory / name
            try:
                info = path.lstat()
                fact = {"name": name, "mode": info.st_mode, "bytes": info.st_size, "regular": stat.S_ISREG(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode)}
                if stat.S_ISLNK(info.st_mode): fact["link_target"] = os.readlink(path)
            except FileNotFoundError:
                fact = {"name": name, "missing": True}
            facts.append(fact)
        (self.directory.parent / "fixture-facts.json").write_text(json.dumps(facts, indent=2) + "\n")

    def manifest(self):
        return json.loads((self.directory / (self.stem + ".manifest.json")).read_bytes())

    def save_manifest(self, value):
        (self.directory / (self.stem + ".manifest.json")).write_text(json.dumps(value, indent=2) + "\n")

    def mutate_manifest(self, callback):
        value = self.manifest(); callback(value); self.save_manifest(value)

    def events(self):
        return [json.loads(line) for line in (self.directory / (self.stem + ".jsonl")).read_bytes().splitlines()]

    def save_raw(self, raw):
        (self.directory / (self.stem + ".jsonl")).write_bytes(raw)
        self.mutate_manifest(lambda value: value["files"].update({self.stem + ".jsonl": hashlib.sha256(raw).hexdigest()}))

    def save_events(self, events):
        self.save_raw(b"".join(json.dumps(event).encode() + b"\n" for event in events))

    def refuse(self, code=None):
        with self.assertRaises(Refused) as caught:
            read_record(self.directory, self.stem, self.selected)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception.code

    def test_MTRV2_001_original_local(self):
        value = read_record(RECORDS, STEMS[0], self.selected)
        self.assertEqual(value["event_count"], 198)
        self.assertEqual(value["decision_count"], 85)
        self.assertIsNone(value["source"]); self.assertIsNone(value["policy"])
        cascade = [row for row in value["paths"] if row["path"] == "cascade"]
        self.assertEqual([row["attribution"]["revoked"]["refresh"]["observation"] for row in cascade], ["not_recorded", "not_recorded"])
        self.assertEqual(len(self.selected.calls), 199)

    def test_MTRV2_002_original_testnet_first(self):
        value = read_record(RECORDS, STEMS[1], self.selected)
        self.assertEqual(value["event_count"], 75)
        self.assertEqual(value["decision_count"], 23)
        cascade = [row for row in value["paths"] if row["path"] == "cascade"]
        self.assertEqual([row["attribution"]["revoked"]["refresh"]["observation"] for row in cascade], ["refused", "not_recorded"])
        self.assertEqual(value["stated"]["services_revision"], "08ca3d829665")

    def test_MTRV2_003_original_testnet_second(self):
        value = read_record(RECORDS, STEMS[2], self.selected)
        issuer = next(row for row in value["paths"] if row["path"] == "issuer")
        self.assertEqual(issuer["first_refused"]["reason_code"], "status_root_stale")
        self.assertEqual(issuer["attribution"]["revoked"]["refresh"]["outcome"], "credential_revoked")
        self.assertEqual(issuer["attribution"]["control"]["refresh"]["observation"], "not_recorded")
        self.assertIs(issuer["control_never_revoked"]["after_refresh"]["accepted"], True)
        self.assertFalse(value["summary_disclosure"]["narrative_identity_authenticated"])
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_004_changed_summary_bytes(self):
        with (self.directory / (self.stem + ".md")).open("ab") as stream: stream.write(b"changed")
        self.refuse("MemberHashMismatch")

    def test_MTRV2_005_changed_event_bytes(self):
        with (self.directory / (self.stem + ".jsonl")).open("ab") as stream: stream.write(b"{}\n")
        self.refuse("MemberHashMismatch")

    def test_MTRV2_006_missing_declared_member(self):
        (self.directory / (self.stem + ".md")).unlink()
        self.refuse("MemberUnavailable")

    def test_MTRV2_007_escaped_duplicate_manifest_member(self):
        member = self.directory / (self.stem + ".manifest.json")
        member.write_bytes(member.read_bytes().replace(b'"schema":', b'"\\u0073chema":"other","schema":', 1))
        self.refuse("DuplicateMember"); self.assertEqual(len(self.selected.calls), 1)

    def test_MTRV2_008_scalar_manifest(self):
        (self.directory / (self.stem + ".manifest.json")).write_bytes(b"null")
        self.refuse("ObjectOrArrayRequired")

    def test_MTRV2_009_nonfinite_manifest(self):
        # I-JSON first refuses the integral 1e309 token as UnsafeInteger.
        member = self.directory / (self.stem + ".manifest.json")
        member.write_bytes(member.read_bytes().replace(b'"derived": true', b'"derived": 1e309', 1))
        self.refuse("UnsafeInteger")

    def test_MTRV2_010_symlink_member(self):
        target = self.directory / "sentinel.txt"; target.write_bytes(b"must not be opened")
        member = self.directory / (self.stem + ".md"); member.unlink(); member.symlink_to(target)
        self.refuse("MemberUnavailable"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_011_record_path_escape(self):
        self.stem = "../" + self.stem
        self.refuse("RecordName"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_012_unknown_manifest_field(self):
        self.mutate_manifest(lambda value: value.update({"unknown_authority": True}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_013_promoted_stated_source(self):
        self.mutate_manifest(lambda value: value.update({"source": {"revision": value["stated"]["source_revision"]}, "derived": False}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_014_unrecorded_refresh_promoted_to_revocation(self):
        def mutate(value):
            row = next(row for row in value["paths"] if row.get("agent") == "cascade_agent_1")
            row["attribution"]["revoked"]["refresh"]["observation"] = "refused"
        self.mutate_manifest(mutate); self.refuse("ManifestEventMismatch")

    def test_MTRV2_015_boolean_root_count(self):
        self.mutate_manifest(lambda value: value.update({"derived": 1}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_016_failed_native_command(self):
        command = self.directory / "failed-command"; command.write_text("#!/bin/sh\nexit 7\n"); command.chmod(0o700)
        self.selected = Admission(command, ADMISSION, self.directory / "other-capture", LIMITS)
        self.refuse("CommandFailed"); self.assertEqual(self.selected.calls[0]["native_exit"], 7)

    def test_MTRV2_017_malformed_command_response(self):
        command = self.directory / "malformed-command"; command.write_text("#!/bin/sh\nprintf '%s' '{\"status\":true}'\n"); command.chmod(0o700)
        self.selected = Admission(command, ADMISSION, self.directory / "other-capture", LIMITS); self.refuse("CommandProtocol")

    def test_MTRV2_018_duplicate_event_before_parse(self):
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"shadow","\\u006bind":"stack"', 1)
        self.save_raw(raw); self.refuse("DuplicateMember"); self.assertEqual(len(self.selected.calls), 2)

    def test_MTRV2_019_duplicate_decision_log_identity(self):
        events = self.events(); line = copy.deepcopy(next(event for event in events if event["kind"] == "decision_log_line")); events.insert(-1, line)
        self.save_events(events); self.refuse("AmbiguousDecisionLog")

    def test_MTRV2_020_excessive_native_nesting(self):
        raw = b'{"kind":"stack","nested":' + b'[' * 129 + b'0' + b']' * 129 + b'}\n'
        self.save_raw(raw); self.refuse("TooDeep")

    def test_MTRV2_021_unsafe_integer_event(self):
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"stack","number":9007199254740993', 1)
        self.save_raw(raw); self.refuse("UnsafeInteger")

    def test_MTRV2_022_nonfinite_event(self):
        # Keep the native I-JSON policy refusal; do not relabel it.
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"stack","number":1e309', 1)
        self.save_raw(raw); self.refuse("UnsafeInteger")

    def test_MTRV2_023_invalid_utf8_event(self):
        self.save_raw(b'{"kind":"stack","bad":"\xed\xa0\x80"}\n'); self.refuse("StringNotScalar")

    def test_MTRV2_024_boolean_deciding_condition(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision_log_line")["line"]["condition"] = True
        self.save_events(events)
        self.mutate_manifest(lambda value: value["decisions"][0].update({"condition": True}))
        self.refuse("DecisionLogShape")

    def test_MTRV2_025_integer_decision_boolean(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision")["accepted"] = 1
        self.save_events(events); self.refuse("DecisionShape")

    def test_MTRV2_026_unbound_summary_decision(self):
        events = self.events(); events[-1]["results"][0]["first_no"]["session_id"] = "invented"
        self.save_events(events); self.refuse("UnboundSummaryDecision")

    def test_MTRV2_027_duplicate_files_map(self):
        member = self.directory / (self.stem + ".manifest.json"); member.write_bytes(member.read_bytes().replace(b'"files":', b'"files":{},"files":', 1)); self.refuse("DuplicateMember")

    def test_MTRV2_028_declared_path_escape(self):
        self.mutate_manifest(lambda value: value["files"].update({"../sentinel.txt": "0" * 64}))
        self.refuse("MemberHashMismatch")

    def test_MTRV2_029_symlink_directory(self):
        alias = self.directory / "alias"; alias.symlink_to(RECORDS, target_is_directory=True)
        self.directory = alias; self.refuse("MemberPath")

    def test_MTRV2_030_bounded_member(self):
        with (self.directory / (self.stem + ".md")).open("wb") as stream: stream.truncate(MAX_BYTES + 1)
        self.refuse("TooLarge"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_031_rehashed_false_summary_disclosure(self):
        raw = (self.directory / (self.stem + ".md")).read_bytes().replace(b"Raw events:", b"Other events:")
        (self.directory / (self.stem + ".md")).write_bytes(raw)
        self.mutate_manifest(lambda value: value["files"].update({self.stem + ".md": hashlib.sha256(raw).hexdigest()}))
        self.refuse("SummaryDisclosure")

    def test_MTRV2_032_missing_summary_event(self):
        self.save_events(self.events()[:-1]); self.refuse("MissingSummary")

    def test_MTRV2_033_ambiguous_source_event(self):
        events = self.events(); events.insert(-1, {"kind": "source", "revision": "a"}); events.insert(-1, {"kind": "source", "revision": "b"})
        self.save_events(events); self.refuse("AmbiguousEvent")

    def test_MTRV2_034_ring_detached_from_native_event(self):
        events = self.events(); events[-1]["results"][0]["first_no"]["ring_at_denial"][-1]["status_epoch"] += 1
        self.save_events(events); self.refuse("RingBindingMismatch")

    def test_MTRV2_035_wrong_policy_digest(self):
        events = self.events(); events.insert(-1, {"kind": "policy", "claim_policy": [], "issuer_policy": {}, "sha256": "0" * 64})
        self.save_events(events); self.refuse("PolicyHashMismatch")

    def test_MTRV2_036_decision_log_outcome_disagreement(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision_log_line")["line"]["accepted"] = False
        self.save_events(events); self.refuse("DecisionLogMismatch")

    def test_MTRV2_037_unreachable_transport_is_not_denial(self):
        events = self.events(); outage = {"path": "unreachable", "t0": 100.0, "t0_def": "authored unavailable-authority control", "restored_unix": 104.0, "during": [{"kind": "challenge_during_outage", "path": "unreachable", "utc": "authored", "unix": 101.0, "http": 503, "error": "unavailable"}], "first_accepted_after": None}
        events[-1]["results"].append(outage); events.insert(-1, copy.deepcopy(outage["during"][0])); self.save_events(events)
        expected = {"path": "unreachable", "t0_unix": 100.0, "t0_definition": "authored unavailable-authority control", "restored_seconds_after_t0": 4.0, "decided_during_outage": [], "challenges_during_outage": [{"utc": "authored", "seconds_after_t0": 1.0, "http": 503, "error": "unavailable"}], "first_accepted_after_restore": None}
        self.mutate_manifest(lambda value: value["paths"].append(expected))
        result = read_record(self.directory, self.stem, self.selected)
        self.assertEqual(result["paths"][-1], expected)
        self.assertEqual(result["decision_count"], 23)

    def test_MTRV2_038_outage_invented_decision(self):
        events = self.events(); events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "during": [{"kind": "decision", "session_id": "invented", "accepted": False}]})
        self.save_events(events); self.refuse("UnboundSummaryDecision")

    def test_MTRV2_039_fifo_member(self):
        member = self.directory / (self.stem + ".md"); member.unlink(); os.mkfifo(member)
        self.refuse("MemberType"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_040_small_member_allocation(self):
        member = self.directory / "one-byte"; member.write_bytes(b"x")
        tracemalloc.start()
        try:
            self.assertEqual(read_member(self.directory, member.name), b"x")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        (self.directory / "allocation.json").write_text(json.dumps({"bytes": 1, "peak_python_bytes": peak}) + "\n")
        self.assertLess(peak, 1 << 20)

    def test_MTRV2_041_oversized_complete_output_retained(self):
        command = self.directory / "oversized-command"
        command.write_text("#!/bin/sh\nhead -c 4200 /dev/zero\nprintf diagnostic >&2\nexit 7\n"); command.chmod(0o700)
        selected = Admission(command, ADMISSION, self.directory / "output-capture", LIMITS)
        with self.assertRaises(Refused) as caught: selected.document(b"{}", "authored-oversized-command")
        self.assertEqual(caught.exception.code, "CommandProtocol")
        self.assertEqual(selected.calls[0]["native_exit"], 7)
        self.assertTrue(selected.calls[0]["native_output_complete"])
        self.assertEqual((selected.capture / "call-000001/stdout.bin").read_bytes(), b"\0" * 4200)
        self.assertEqual((selected.capture / "call-000001/stderr.bin").read_bytes(), b"diagnostic")

    def test_MTRV2_042_malformed_root_is_not_unknown(self):
        events = self.events(); events[-1]["results"][0]["carrying_root"] = False
        self.save_events(events); self.refuse("RootShape")
        for value in (False, 0, []):
            with self.assertRaises(Refused): root(value)
        self.assertIsNone(root(None))

    def test_MTRV2_043_boolean_bound_chain_height(self):
        events = self.events(); denial = events[-1]["results"][0]["first_no"]
        native = next(event for event in events if event.get("kind") == "decision" and event.get("session_id") == denial["session_id"])
        native["chain_height_after"] = True; denial["chain_height_after"] = True
        self.save_events(events); self.refuse("DecisionShape")

    def test_MTRV2_044_unrelated_forced_event_not_agent_authority(self):
        events = self.events(); event = copy.deepcopy(events[-1]["results"][0]["first_no"])
        event.pop("ring_at_denial", None); event.update(agent="authored-other-agent", session_id="authored-unrelated-agent")
        events.insert(0, event); self.save_events(events)
        def update(value):
            value["started_utc"] = event["utc"]
            value["decisions"].insert(0, {**{key: event.get(key) for key in ("utc", "path", "agent", "attempt", "accepted", "reason_code")}, **{key: None for key in ("condition", "root_epoch", "root_height", "root_age_seconds")}})
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        self.assertEqual(result["paths"][0]["attribution"]["revoked"]["agent"], "agent_issuer")
        self.assertEqual(result["paths"][0]["attribution"]["revoked"]["refresh"]["outcome"], "credential_revoked")

    def test_MTRV2_045_event_budget_before_native_calls(self):
        self.save_raw(b'{"kind":"wait"}\n' * 257)
        self.refuse("EventBudget"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_046_native_call_budget_before_work(self):
        self.selected = Admission(GO, ADMISSION, self.directory / "call-budget", Limits(1 << 20, 256, 75, 2 << 20, 4 << 20, 2048))
        self.refuse("NativeCallBudget"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_047_native_output_budget_before_work(self):
        self.selected = Admission(GO, ADMISSION, self.directory / "output-budget", Limits(1 << 20, 256, 257, 1, 4 << 20, 2048))
        self.refuse("NativeOutputBudget"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_048_capture_file_budget_before_work(self):
        self.selected = Admission(GO, ADMISSION, self.directory / "file-budget", Limits(1 << 20, 256, 257, 2 << 20, 4 << 20, 3))
        self.refuse("CaptureBudget"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_049_combined_output_budget_prefix_exit_retained(self):
        command = self.directory / "combined-command"
        command.write_text("#!/bin/sh\nprintf stderr-first >&2\nhead -c 65536 /dev/zero\n"); command.chmod(0o700)
        selected = Admission(command, ADMISSION, self.directory / "combined-capture", Limits(1 << 20, 256, 257, 16384, 4 << 20, 2048))
        with self.assertRaises(Refused) as caught: selected.document(b"{}", "authored-combined-budget")
        self.assertEqual(caught.exception.code, "NativeOutputBudget")
        receipt = selected.calls[0]
        self.assertFalse(receipt["native_output_complete"])
        self.assertEqual(receipt["stdout_bytes"] + receipt["stderr_bytes"], 16384)
        self.assertEqual(receipt["observed_unretained_excess_bytes"], 1)
        self.assertIs(type(receipt["native_exit"]), int)
        self.assertIsNotNone(receipt["termination_requested"])

    def test_MTRV2_050_dense_invalid_event_fails_immediately(self):
        self.save_raw(b'{}\n' * 200)
        self.refuse("EventShape"); self.assertEqual(len(self.selected.calls), 2)

    def test_MTRV2_051_resource_policy_boolean_refuses(self):
        with self.assertRaises(Refused): Limits(True, 256, 257, 2 << 20, 4 << 20, 2048)

    def test_MTRV2_052_input_budget_before_native_calls(self):
        self.selected = Admission(GO, ADMISSION, self.directory / "input-budget", Limits(1, 256, 257, 2 << 20, 4 << 20, 2048))
        self.refuse("TooLarge"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_053_native_integer_exponent_output_expansion(self):
        raw = b"[" + b"1e15," * 1023 + b"1e15]"
        value = self.selected.document(raw, "authored-safe-exponent-array")
        self.assertEqual(len(value), 1024)
        self.assertEqual(value[0], 1000000000000000)
        receipt = self.selected.calls[0]
        self.assertGreater(receipt["stdout_bytes"], 2 * len(raw) + 4096)
        self.assertTrue(receipt["native_output_complete"])

    def test_MTRV2_054_capture_byte_budget_before_native_calls(self):
        total = sum((self.directory / (self.stem + suffix)).stat().st_size for suffix in (".manifest.json", ".jsonl", ".md"))
        self.selected = Admission(GO, ADMISSION, self.directory / "byte-budget", Limits(1 << 20, 256, 257, 2 << 20, total, 2048))
        self.refuse("CaptureBudget"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_055_duplicate_resource_policy_refuses(self):
        path = self.directory / "limits.json"
        path.write_bytes(b'{"events":1,"events":2}')
        with self.assertRaises(Refused): Limits.from_file(path)

    def test_MTRV2_056_unsupported_kind_fails_immediately(self):
        self.save_raw(b'{"kind":"unknown-authority"}\n' * 200)
        self.refuse("EventShape"); self.assertEqual(len(self.selected.calls), 2)

    def test_MTRV2_057_metadata_reservation_before_work(self):
        sentinel = self.directory / "child-started"
        command = self.directory / "sentinel-command"
        command.write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\nprintf '{}'\n"); command.chmod(0o700)
        selected = Admission(command, ADMISSION, self.directory / "metadata-capture", Limits(1 << 20, 256, 257, 2 << 20, 12000, 2048))
        with self.assertRaises(Refused) as caught: selected.document(b"{}", "authored-long-label-" + "x" * 20000)
        self.assertEqual(caught.exception.code, "CaptureBudget")
        self.assertFalse(sentinel.exists()); self.assertEqual(selected.calls, [])

    def test_MTRV2_058_failed_native_spawn_has_no_invented_exit(self):
        command = self.directory / "invalid-executable"
        command.write_bytes(b"not an executable\n"); command.chmod(0o700)
        selected = Admission(command, ADMISSION, self.directory / "spawn-capture", LIMITS)
        with self.assertRaises(Refused) as caught: selected.document(b"{}", "authored-invalid-executable")
        self.assertEqual(caught.exception.code, "CommandUnavailable")
        receipt = selected.calls[0]
        self.assertFalse(receipt["native_started"]); self.assertFalse(receipt["native_output_complete"])
        self.assertIsNone(receipt["native_exit"]); self.assertGreater(receipt["spawn_error"]["errno"], 0)

    def test_MTRV2_059_jsonl_original_whitespace_retained(self):
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes()
        original_first = raw.split(b"\n", 1)[0]
        self.save_raw(raw.replace(b"\n", b"\r\r\n", 1))
        result = read_record(self.directory, self.stem, self.selected)
        self.assertEqual(result["event_count"], 75)
        self.assertEqual((self.capture / "call-000002/stdin.bin").read_bytes(), original_first + b"\r")

    def test_MTRV2_060_directory_inodes_count_before_native_work(self):
        selected = Admission(GO, ADMISSION, self.directory / "inode-capture", Limits(1 << 20, 256, 257, 2 << 20, 4 << 20, 7))
        with self.assertRaises(Refused) as caught: read_record(self.directory, self.stem, selected)
        self.assertEqual(caught.exception.code, "CaptureBudget")
        self.assertEqual(selected.calls, [])
        self.assertEqual(1 + len(list(selected.capture.rglob("*"))), 5)

    def test_MTRV2_061_cascade_key_cannot_relabel_bound_agent(self):
        events = self.events()
        agents = next(row for row in events[-1]["results"] if row["path"] == "cascade")["per_agent"]
        agents["authored-contradictory-cascade-agent"] = agents.pop("cascade_agent_1")
        self.save_events(events); self.refuse("DecisionAgentMismatch")
        self.assertEqual(len(self.selected.calls), 76)

    def timestamp_shape(self, value):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        issuer["carrying_root"]["finalized_at_utc"] = value
        self.save_events(events)
        self.refuse("RootShape"); self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_062_boolean_root_timestamp(self):
        self.timestamp_shape(False)

    def rebind_decision(self, events, session, **changed):
        # Change both the actual event and its summary copies, so exact event
        # equality cannot conceal an agent/path contradiction in the control.
        def visit(value):
            if type(value) is dict:
                if value.get("kind") == "decision" and value.get("session_id") == session:
                    value.update(changed)
                for item in value.values(): visit(item)
            elif type(value) is list:
                for item in value: visit(item)
        visit(events)

    def test_MTRV2_063_cascade_decision_wrong_enclosing_path(self):
        events = self.events()
        item = next(row for row in events[-1]["results"] if row["path"] == "cascade")["per_agent"]["cascade_agent_1"]
        self.rebind_decision(events, item["first_no"]["session_id"], path="emergency")
        self.save_events(events); self.refuse("DecisionPathMismatch")

    def test_MTRV2_064_issuer_control_bound_agent(self):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        self.rebind_decision(events, issuer["control"][0]["session_id"], agent="authored-unrelated-control-agent")
        self.save_events(events); self.refuse("DecisionAgentMismatch")

    def test_MTRV2_065_cascade_without_actual_identity(self):
        events = self.events()
        item = next(row for row in events[-1]["results"] if row["path"] == "cascade")["per_agent"]["cascade_agent_1"]
        item.update(first_no=None, last_ok=None)
        self.save_events(events); self.refuse("AgentBindingUnavailable")

    def test_MTRV2_066_boolean_actual_agent(self):
        events = self.events(); session = next(event["session_id"] for event in events if event["kind"] == "decision")
        self.rebind_decision(events, session, agent=False)
        self.save_events(events); self.refuse("DecisionShape")

    def test_MTRV2_067_integer_root_timestamp(self):
        self.timestamp_shape(0)

    def test_MTRV2_068_array_root_timestamp(self):
        self.timestamp_shape([])

    def test_MTRV2_069_object_root_timestamp(self):
        self.timestamp_shape({})

    def test_MTRV2_070_cascade_last_accepted_bound_agent(self):
        events = self.events()
        item = next(row for row in events[-1]["results"] if row["path"] == "cascade")["per_agent"]["cascade_agent_1"]
        self.rebind_decision(events, item["last_ok"]["session_id"], agent="authored-unrelated-last-agent")
        self.save_events(events); self.refuse("DecisionAgentMismatch")

    def test_MTRV2_071_issuer_decision_wrong_enclosing_path(self):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        self.rebind_decision(events, issuer["first_no"]["session_id"], path="cascade")
        self.save_events(events); self.refuse("DecisionPathMismatch")

    def test_MTRV2_072_refreshed_control_is_separate_bound_role(self):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        self.rebind_decision(events, issuer["control_refreshed"]["session_id"], agent="sibling_control")
        self.save_events(events); self.refuse("DecisionAgentMismatch")

    def test_MTRV2_073_nullable_root_timestamp(self):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        issuer["carrying_root"]["finalized_at_utc"] = None
        self.save_events(events)
        def update(value):
            row = next(row for row in value["paths"] if row["path"] == "issuer")
            row["root_carrying_revocation"]["finalized_at_utc"] = None
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        issuer = next(row for row in result["paths"] if row["path"] == "issuer")
        self.assertIsNone(issuer["root_carrying_revocation"]["finalized_at_utc"])
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_074_fractional_root_timestamp_string(self):
        events = self.events(); stamp = "2026-10-05T02:31:57.125Z"
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        issuer["carrying_root"]["finalized_at_utc"] = stamp
        self.save_events(events)
        def update(value):
            row = next(row for row in value["paths"] if row["path"] == "issuer")
            row["root_carrying_revocation"]["finalized_at_utc"] = stamp
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        issuer = next(row for row in result["paths"] if row["path"] == "issuer")
        self.assertEqual(issuer["root_carrying_revocation"]["finalized_at_utc"], stamp)
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_075_revoked_acceptance_binds_same_actual_agent(self):
        events = self.events()
        row = next(row for row in events[-1]["results"] if row["path"] == "kill_switch")
        self.rebind_decision(events, row["last_ok"]["session_id"], agent="authored-other-accepted-agent")
        self.save_events(events); self.refuse("DecisionAgentMismatch")
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_076_refusal_cannot_be_last_acceptance(self):
        events = self.events()
        row = next(row for row in events[-1]["results"] if row["path"] == "kill_switch")
        row["last_ok"] = copy.deepcopy(row["first_no"])
        self.save_events(events); self.refuse("DecisionOutcomeMismatch")

    def test_MTRV2_077_acceptance_cannot_be_first_refusal(self):
        events = self.events()
        row = next(row for row in events[-1]["results"] if row["path"] == "kill_switch")
        row["first_no"] = copy.deepcopy(row["last_ok"])
        self.save_events(events); self.refuse("DecisionOutcomeMismatch")

    def test_MTRV2_078_refreshed_control_requires_actual_acceptance(self):
        events = self.events()
        issuer = next(row for row in events[-1]["results"] if row["path"] == "issuer")
        session = issuer["control_refreshed"]["session_id"]
        self.rebind_decision(events, session, accepted=False)
        for event in events:
            if event["kind"] == "decision_log_line" and event["session_id"] == session:
                event["line"]["accepted"] = False
        self.save_events(events); self.refuse("DecisionOutcomeMismatch")

    def test_MTRV2_079_restoration_acceptance_requires_actual_acceptance(self):
        events = self.events()
        decision = {"kind": "decision", "session_id": "authored-refused-after-restore", "path": "unreachable", "agent": "authored-outage-agent", "utc": "authored", "unix": 105.0, "accepted": False, "reason_code": "status_root_stale", "chain_height_after": None}
        events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "restored_unix": 104.0, "during": [], "first_accepted_after": copy.deepcopy(decision)})
        events.insert(-1, decision)
        self.save_events(events); self.refuse("DecisionOutcomeMismatch")

    def test_MTRV2_080_outage_challenge_binds_enclosing_path(self):
        events = self.events()
        challenge = {"kind": "challenge_during_outage", "path": "issuer", "utc": "authored", "unix": 101.0, "http": 503, "error": "unavailable"}
        events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "restored_unix": 104.0, "during": [copy.deepcopy(challenge)], "first_accepted_after": None})
        events.insert(-1, challenge)
        self.save_events(events); self.refuse("OutagePathMismatch")

    def test_MTRV2_081_generic_during_outage_preserves_actual_refusal(self):
        events = self.events()
        decision = {"kind": "decision", "session_id": "authored-during-outage", "path": "unreachable", "agent": "authored-outage-agent", "utc": "authored", "unix": 101.0, "accepted": False, "reason_code": "status_root_stale", "chain_height_after": None}
        events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "t0_def": "authored outage", "restored_unix": 104.0, "during": [copy.deepcopy(decision)], "first_accepted_after": None})
        events.insert(-1, decision); self.save_events(events)
        expected_decision = {"utc": "authored", "seconds_after_t0": 1.0, "session_id": "authored-during-outage", "accepted": False, "reason_code": "status_root_stale", "chain_height_after": None, "decision_log": None}
        expected = {"path": "unreachable", "t0_unix": 100.0, "t0_definition": "authored outage", "restored_seconds_after_t0": 4.0, "decided_during_outage": [expected_decision], "challenges_during_outage": [], "first_accepted_after_restore": None}
        def update(value):
            value["paths"].append(expected)
            value["decisions"].append({"utc": "authored", "path": "unreachable", "agent": "authored-outage-agent", "attempt": None, "accepted": False, "reason_code": "status_root_stale", "condition": None, "root_epoch": None, "root_height": None, "root_age_seconds": None})
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        self.assertEqual(result["paths"][-1], expected)
        self.assertIs(result["paths"][-1]["decided_during_outage"][0]["accepted"], False)
        self.assertIsNone(result["paths"][-1]["first_accepted_after_restore"])
        self.assertEqual(result["decision_count"], 24)
        self.assertEqual(len(self.selected.calls), 77)

    def test_MTRV2_082_boolean_decision_timestamp(self):
        events = self.events(); session = next(event["session_id"] for event in events if event["kind"] == "decision")
        self.rebind_decision(events, session, utc=False)
        self.save_events(events); self.refuse("TimestampShape")

    def test_MTRV2_083_boolean_started_timestamp(self):
        events = self.events(); events[0]["utc"] = False
        self.save_events(events); self.refuse("TimestampShape")

    def test_MTRV2_084_array_selected_refresh_timestamp(self):
        events = self.events()
        event = next(event for event in events if event["kind"] == "holder_refresh" and event["path"] == "issuer")
        event["utc"] = []
        self.save_events(events); self.refuse("TimestampShape")

    def test_MTRV2_085_object_outage_challenge_timestamp(self):
        events = self.events()
        challenge = {"kind": "challenge_during_outage", "path": "unreachable", "utc": {}, "unix": 101.0, "http": 503, "error": "unavailable"}
        events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "restored_unix": 104.0, "during": [copy.deepcopy(challenge)], "first_accepted_after": None})
        events.insert(-1, challenge)
        self.save_events(events); self.refuse("TimestampShape")

    def test_MTRV2_086_nullable_consumed_timestamps_remain_unknown(self):
        events = self.events(); events[0]["utc"] = None
        row = next(row for row in events[-1]["results"] if row["path"] == "kill_switch")
        session = row["first_no"]["session_id"]
        index = [event["session_id"] for event in events if event["kind"] == "decision"].index(session)
        self.rebind_decision(events, session, utc=None)
        next(event for event in events if event["kind"] == "holder_refresh" and event["path"] == "issuer")["utc"] = None
        challenge = {"kind": "challenge_during_outage", "path": "unreachable", "utc": None, "unix": 101.0, "http": 503, "error": "unavailable"}
        events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "t0_def": "authored unknown clock", "restored_unix": 104.0, "during": [copy.deepcopy(challenge)], "first_accepted_after": None})
        events.insert(-1, challenge); self.save_events(events)
        expected = {"path": "unreachable", "t0_unix": 100.0, "t0_definition": "authored unknown clock", "restored_seconds_after_t0": 4.0, "decided_during_outage": [], "challenges_during_outage": [{"utc": None, "seconds_after_t0": 1.0, "http": 503, "error": "unavailable"}], "first_accepted_after_restore": None}
        def update(value):
            value["started_utc"] = None; value["decisions"][index]["utc"] = None
            next(row for row in value["paths"] if row["path"] == "kill_switch")["first_refused"]["utc"] = None
            next(row for row in value["paths"] if row["path"] == "issuer")["attribution"]["revoked"]["refresh"]["utc"] = None
            value["paths"].append(expected)
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        self.assertIsNone(next(row for row in result["paths"] if row["path"] == "kill_switch")["first_refused"]["utc"])
        self.assertIsNone(next(row for row in result["paths"] if row["path"] == "issuer")["attribution"]["revoked"]["refresh"]["utc"])
        self.assertEqual(result["paths"][-1], expected)
        self.assertEqual(len(self.selected.calls), 77)


    def unknown_selected_subject(self, refresh_agent):
        events = self.events()
        row = next(row for row in events[-1]["results"] if row["path"] == "kill_switch")
        row["last_ok"] = None; row["first_no"] = None
        holder = next(event for event in events if event["kind"] == "holder_refresh" and event["path"] == "kill_switch")
        if refresh_agent == "absent":
            holder.pop("agent")
        elif refresh_agent == "null":
            holder["agent"] = None
        else:
            self.assertEqual(holder["agent"], "agent_kill_switch")
        self.save_events(events)
        unknown = {"observation": "not_recorded", "outcome": None, "utc": None, "seconds_after_t0": None}
        def update(value):
            projected = next(row for row in value["paths"] if row["path"] == "kill_switch")
            projected.update(last_accepted=None, first_refused=None, root_at_denial=None, refresh_refused_seconds_after_t0=None)
            projected["attribution"]["revoked"] = {"agent": None, "refresh": unknown}
        self.mutate_manifest(update)
        result = read_record(self.directory, self.stem, self.selected)
        projected = next(row for row in result["paths"] if row["path"] == "kill_switch")
        self.assertIsNone(projected["last_accepted"]); self.assertIsNone(projected["first_refused"])
        self.assertIsNone(projected["attribution"]["revoked"]["agent"])
        self.assertEqual(projected["attribution"]["revoked"]["refresh"], unknown)
        self.assertIsNone(projected["refresh_refused_seconds_after_t0"])
        self.assertEqual(result["decision_count"], 23)
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_087_absent_holder_cannot_identify_unknown_subject(self):
        self.unknown_selected_subject("absent")

    def test_MTRV2_088_null_holder_cannot_identify_unknown_subject(self):
        self.unknown_selected_subject("null")

    def test_MTRV2_089_named_holder_cannot_identify_unknown_subject(self):
        self.unknown_selected_subject("named")


if __name__ == "__main__":
    unittest.main(verbosity=2)
