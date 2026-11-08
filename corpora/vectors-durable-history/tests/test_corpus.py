"""The corpus regenerates, forces every check, and refuses the two verifiers the
field ships today: a replay of the history against the workflow code, and the
one consistency check an outsider can run on an exported history with no key."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/durable-history/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("durable_history_corpus", ROOT / "check_vectors.py")
generator = _load("durable_history_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import durablehistory  # noqa: E402

CONTRACT = ("contract_id_missing", "contract_id_unknown", "malformed_record")
# Edits that are defects at two layers: switching off the first check names the
# second, which is the check the edit also trips.
LAYERED = {
    "reset-fork-exported-instead": "witnessed_run_missing_from_history",
    "completion-before-schedule": "witnessed_effect_missing",
    "codec-stripped-and-edited": "history_args_differ_from_permitted",
    "store-edit-amount": "model_request_differs_from_witnessed",
    "consistent-rewrite": "model_request_differs_from_witnessed",
    "scheduled-tool-changed": "model_request_differs_from_witnessed",
}
# The break-it attacks a replay passes: A4-i to A4-iv, the store edit, and a reset.
REPLAY_PASSES = {"model-args-edited", "result-edited", "tool-code-changed",
                 "consistent-rewrite", "store-edit-amount", "reset-fork-exported-instead"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import durablehistory as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    return manifest


def _record(entry: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(
        (ROOT / entry["path"] / "record.json").read_text(encoding="utf-8"))
    return record


def _denied(reasons: tuple[str, ...] = ()) -> set[str]:
    return {e["id"] for e in _manifest()["vectors"] if e["expected"]["decision"] == "deny"
            and e["expected"]["reason"] not in reasons}


def _commands(run: Any) -> list[tuple[str, str]]:
    return [(e["attributes"]["activityId"], e["attributes"]["activityType"])
            for e in run.events if e["eventType"] == durablehistory.SCHEDULED]


def _replays_clean(record: dict[str, Any]) -> bool:
    """A replay against the deployed workflow code, modelled exactly: the server's
    structural read of the event sequence, then activity id and type compared
    with the commands the code issues, and never an input or a result."""
    code = _commands(durablehistory.Run(generator.number(generator.events())))
    try:
        runs = durablehistory._runs(record)
    except (KeyError, TypeError, StopIteration, AttributeError, IndexError):
        return False
    return bool(runs) and all(
        not durablehistory._sequence_broken(run) and _commands(run) == code for run in runs)


def _keyless_mismatch(record: dict[str, Any]) -> bool:
    """The check an outsider can run on an export with no key: each call the model
    asked for must be the call the history then scheduled."""
    try:
        runs = durablehistory._runs(record)
        for run in runs:
            asked: dict[str, tuple[str, Any]] = {}
            for activity, event in run.scheduled.items():
                done = run.completion(activity)
                if (event["attributes"]["activityType"] == durablehistory.MODEL_ACTIVITY
                        and done and done["attributes"]["result"]["encoding"] == "json/plain"):
                    for call in done["attributes"]["result"]["data"]["toolCalls"]:
                        asked[call["callId"]] = (call["tool"], call["args"])
            for event in run.scheduled.values():
                attrs = event["attributes"]
                if (attrs["input"]["encoding"] != "json/plain"
                        or not attrs["activityType"].startswith("tool:")):
                    continue
                call = attrs["input"]["data"]
                seen = (attrs["activityType"][len("tool:"):], call["args"])
                if call["callId"] in asked and asked[call["callId"]] != seen:
                    return True
    except (KeyError, TypeError, StopIteration, AttributeError, IndexError):
        return False
    return False


class TestDurableHistoryCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_contract_id_is_the_published_one(self) -> None:
            assert durablehistory.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "deny"}
            assert reasons == set(durablehistory.CHECKS)

        def test_both_export_shapes_are_read(self) -> None:
            sources = {export["source"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "allow"
                       for export in _record(e)["exports"]}
            assert sources == set(durablehistory.SOURCES)

    class TestFailingCases:
        @pytest.mark.parametrize("name", durablehistory.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_its_own_check_alone(self) -> None:
            """Switching off the one check a denied case names turns it into an
            allow, or, for an edit that is a defect at two layers, names the
            second check it trips."""
            for entry in _manifest()["vectors"]:
                reason = entry["expected"]["reason"]
                if entry["expected"]["decision"] != "deny" or reason in CONTRACT:
                    continue
                answer = durablehistory.verify(
                    ROOT / entry["path"] / "record.json", frozenset({reason}))
                if entry["id"] in LAYERED:
                    assert answer == {"decision": "deny", "reason": LAYERED[entry["id"]]}
                else:
                    assert answer == {"decision": "allow", "reason": "consistent"}, entry["id"]

        def test_replay_lets_the_history_attacks_through(self) -> None:
            """A replay passes every edit the break-it run made to a history, the
            changed tool code and the reset fork; it catches only the edits that
            change the event sequence or the activity commands."""
            entries = {e["id"]: e for e in _manifest()["vectors"]}
            passed = {name for name in _denied(CONTRACT) if _replays_clean(_record(entries[name]))}
            assert REPLAY_PASSES <= passed
            controls = {e["id"] for e in entries.values()
                        if e["expected"]["decision"] == "allow"}
            assert {"event-moved", "event-dropped-leaving-gap", "completion-before-schedule",
                    "second-completion-for-one-schedule", "injected-refund-activity",
                    "witnessed-activity-removed", "scheduled-tool-changed"}.isdisjoint(passed)
            assert {c for c in controls if not _replays_clean(_record(entries[c]))} == {
                "allow-ungated-tool-without-permit"}

        def test_keyless_outsider_check_catches_only_the_model_request_edit(self) -> None:
            entries = _manifest()["vectors"]
            caught = {e["id"] for e in entries if _keyless_mismatch(_record(e))}
            denied = _denied()
            assert caught & denied == {"model-args-edited"}
            # And it refuses an approved override that the witnessed record explains.
            assert caught - denied == {"allow-approved-argument-override"}

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "history_reset"}))\nsys.exit(1)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "allow"}
            assert controls and controls <= _failed(errors)

        def test_verifier_that_allows_everything_fails_every_denial(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "allow.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                              '"reason": "consistent"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert _failed(errors) == _denied()

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-clean-run" / "record.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-clean-run: fixture digest mismatch" in errors
