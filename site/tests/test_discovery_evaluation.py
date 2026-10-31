"""Finite receipt controls; these do not run discovery clients or search."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import discovery_evaluation as reader


@pytest.fixture
def suite():
    value, sha = reader.read_json(reader.DEFAULT_SUITE)
    reader.check_suite(value)
    return value, sha


def retain(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"path": name, "sha256": reader.digest(raw), "bytes": len(raw)}


def attempt(root, task, mode="navigation", repetition=1, review="accepted"):
    prefix = f"{task['id']}-{mode}-{repetition}"
    source_url = "https://example.org/a-retained-public-recipe"
    value = {
        "task_id": task["id"], "mode": mode, "repetition": repetition,
        "started_at": "2026-10-05T01:00:00Z", "ended_at": "2026-10-05T01:00:01Z",
        "status": "answered", "start_url": "https://github.com/probityai" if mode == "navigation" else None,
        "queries": [] if mode == "navigation" else [task["prompt"]],
        "navigation_choices": ["https://example.org/component", source_url],
        "prompt_capture": retain(root, prefix + "-prompt.txt", task["prompt"].encode()),
        "response_capture": retain(root, prefix + "-response.txt", b"SYNTHETIC TEST ANSWER; no client ran."),
        "sources_accessed": [{"url": source_url, "capture": retain(root, prefix + "-source.txt", b"SYNTHETIC SOURCE")}],
        "response": {"component_ids": task["expected"]["component_ids"].copy(),
                     "profile_ids": task["expected"]["profile_ids"].copy(),
                     "recipe_url": source_url, "command": "example --fixture"},
        "command_execution": None,
        "review": {"state": review, "reviewer": "synthetic reviewer", "checks": {
            "component_selection": True, "recipe_usability": True,
            "claim_accuracy": True, "source_support": True},
            "decision_capture": retain(root, prefix + "-review.txt", b"SYNTHETIC TEST REVIEW")},
    }
    if review == "pending":
        value["review"].update(reviewer=None, checks=None, decision_capture=None)
    elif review == "rejected":
        value["review"]["checks"]["claim_accuracy"] = False
    return value


def session(suite, attempts=(), kind="agent"):
    value, sha = suite
    return {"schema_version": 1, "suite_id": value["id"], "suite_sha256": sha,
            "client": {"kind": kind, "name": "synthetic test client", "version": "test",
                       "model": "synthetic model" if kind == "agent" else None,
                       "familiarity": "unfamiliar_declared"},
            "operator": {"id": "fixture-author", "relationship": "author"},
            "answer_key_access": "exposed", "attempts": list(attempts)}


def checked_report(suite, packet, root):
    value, sha = suite
    reader.check_session(packet, value, sha, root)
    return reader.report(value, sha, packet)


def _commit_here(revision: str) -> str:
    """The commit in this checkout that holds a source-repository commit (IMPORTED-COMMITS.tsv)."""
    imported = reader.ROOT / "IMPORTED-COMMITS.tsv"
    if imported.exists():
        for line in imported.read_text().splitlines():
            if line and not line.startswith("#"):
                source, here = line.split()
                if source == revision:
                    return here
    return revision


def test_closed_schema_and_source_bound_task_inventory(suite):
    schema, _ = reader.read_json(reader.SCHEMA)
    Draft202012Validator.check_schema(schema)
    value, _ = suite
    assert len(value["tasks"]) == 25
    assert {c for task in value["tasks"] for c in task["expected"]["component_ids"]} == {
        "atlas", "vocabulary", "vectors", "observer", "verify", "admission", "jcs-admit", "dsse"}
    reference = value["reference_catalog"]
    revision = _commit_here(reference["url"].split("/blob/", 1)[1].split("/", 1)[0])
    prefix = subprocess.check_output(["git", "-C", str(reader.ROOT), "rev-parse", "--show-prefix"], text=True).strip()
    raw = subprocess.check_output(["git", "-C", str(reader.ROOT), "show", f"{revision}:{prefix}data/catalog.json"])
    assert reader.digest(raw) == reference["sha256"]
    assert len(raw) == reference["bytes"]
    catalog = json.loads(raw)
    components = {row["id"] for row in catalog["components"]}
    profiles = {row["id"] for row in catalog["profiles"]}
    for task in value["tasks"]:
        assert set(task["expected"]["component_ids"]) <= components
        assert set(task["expected"]["profile_ids"]) <= profiles


def test_empty_baseline_preserves_both_fixed_denominators(suite):
    value, sha = suite
    result = reader.report(value, sha)
    assert result["retained_attempt_packets"] == 0
    assert result["reported_discovery_attempts"] == 0
    assert len(result["first_attempts"]) == 50
    for mode in reader.MODES:
        measured = result["modes"][mode]
        assert measured["accepted_fraction"] == {"numerator": 0, "denominator": 25}
        assert measured["outcomes"]["not_executed"] == 25
        assert measured["agent_target"] == "not_established"


def test_prompts_omit_the_answer_key(suite):
    value, sha = suite
    exported = reader.prompt_packet(value, sha, "navigation", False)
    assert len(exported["tasks"]) == 25
    assert exported["start_urls"] == value["navigation_start_urls"]
    assert all(set(task) == {"id", "prompt", "prompt_sha256"} for task in exported["tasks"])
    assert "expected" not in json.dumps(exported)
    human = reader.prompt_packet(value, sha, "navigation", True)
    assert [task["id"] for task in human["tasks"]] == value["human_walkthrough_tasks"]
    assert reader.prompt_packet(value, sha, "open_search", False)["start_urls"] == []


@pytest.mark.parametrize("accepted,expected", [(22, "not_met"), (23, "met")])
def test_declared_agent_threshold_uses_all_fixed_first_attempts(suite, tmp_path, accepted, expected):
    value, _ = suite
    attempts = [attempt(tmp_path, task, review="accepted" if i < accepted else "rejected")
                for i, task in enumerate(value["tasks"])]
    result = checked_report(suite, session(suite, attempts), tmp_path)
    assert result["modes"]["navigation"]["agent_target"] == expected
    assert result["modes"]["open_search"]["agent_target"] == "not_established"
    assert result["operator"]["relationship"] == "author"
    assert "no identity" in result["scope"]


def test_missing_or_pending_task_never_meets_complete_suite_target(suite, tmp_path):
    value, _ = suite
    attempts = [attempt(tmp_path, task) for task in value["tasks"][:-1]]
    packet = session(suite, attempts)
    result = checked_report(suite, packet, tmp_path)
    assert result["modes"]["navigation"]["agent_target"] == "not_established"
    packet["attempts"].append(attempt(tmp_path, value["tasks"][-1], review="pending"))
    result = checked_report(suite, packet, tmp_path)
    assert result["modes"]["navigation"]["outcomes"]["review_pending"] == 1
    assert result["modes"]["navigation"]["agent_target"] == "not_established"


def test_author_check_cannot_become_agent_or_human_navigation_success(suite, tmp_path):
    value, _ = suite
    attempts = [attempt(tmp_path, task) for task in value["tasks"]]
    result = checked_report(suite, session(suite, attempts, "author_check"), tmp_path)
    assert result["modes"]["navigation"]["agent_target"] == "not_established"
    assert result["modes"]["navigation"]["human_navigation_target"] == "not_established"
    assert result["author_check_packets"] == 25
    assert result["reported_discovery_attempts"] == 0


def test_repeats_do_not_replace_failed_first_attempt(suite, tmp_path):
    task = suite[0]["tasks"][0]
    first = attempt(tmp_path, task, review="rejected")
    repeat = attempt(tmp_path, task, repetition=2)
    result = checked_report(suite, session(suite, [first, repeat]), tmp_path)
    assert result["modes"]["navigation"]["accepted_fraction"]["numerator"] == 0
    assert result["repeats"][0]["changed_outcome"] is True
    assert result["repeats"][0]["first_outcome"] == "failed"


@pytest.mark.parametrize("hop_count,expected", [(2, "met"), (3, "not_met")])
def test_five_declared_unfamiliar_human_walkthroughs(suite, tmp_path, hop_count, expected):
    value, _ = suite
    attempts = [attempt(tmp_path, task) for task in value["tasks"]
                if task["id"] in value["human_walkthrough_tasks"]]
    for row in attempts:
        row["navigation_choices"] = ["https://example.org/choice"] * hop_count
    result = checked_report(suite, session(suite, attempts, "human"), tmp_path)
    assert result["modes"]["navigation"]["human_navigation_target"] == expected
    assert result["modes"]["navigation"]["agent_target"] == "not_established"


@pytest.mark.parametrize("change,reason", [
    (lambda a: a["response"].update(component_ids=["vectors"]), "component_mismatch"),
    (lambda a: a["response"].update(profile_ids=["made-up-profile"]), "profile_mismatch"),
    (lambda a: a["response"].update(command=None), "no_recipe_command"),
    (lambda a: a["response"].update(recipe_url="https://example.org/not-accessed"), "recipe_source_not_retained"),
    (lambda a: a.update(sources_accessed=[]), "no_retained_source"),
    (lambda a: a.update(status="error"), "client_error"),
])
def test_bad_retrieval_remains_a_failure_even_with_an_accepted_review(suite, tmp_path, change, reason):
    task = suite[0]["tasks"][0]
    row = attempt(tmp_path, task)
    change(row)
    result = checked_report(suite, session(suite, [row]), tmp_path)
    measured = next(item for item in result["first_attempts"]
                    if item["task_id"] == task["id"] and item["mode"] == "navigation")
    assert measured["outcome"] == "failed"
    assert reason in measured["reasons"]


@pytest.mark.parametrize("change", [
    lambda p: p.update(suite_sha256="0" * 64),
    lambda p: p["attempts"].append(copy.deepcopy(p["attempts"][0])),
    lambda p: p["attempts"][0].update(task_id="D99"),
    lambda p: p["attempts"][0].update(repetition=2),
    lambda p: p["attempts"][0].update(start_url="https://example.org/answer-key"),
    lambda p: p["attempts"][0].update(queries=["undeclared search in navigation"]),
    lambda p: p["attempts"][0].update(ended_at="2026-10-04T01:00:00Z"),
    lambda p: p["attempts"][0]["review"]["checks"].update(claim_accuracy=False),
    lambda p: p["attempts"][0].update(unknown_projection="ignored"),
    lambda p: p["client"].update(kind="outside_verified"),
    lambda p: p["operator"].update(relationship="independent_authenticated"),
    lambda p: p["attempts"][0].update(repetition=True),
])
def test_refuse_ambiguous_identity_scope_and_attempt_accounting(suite, tmp_path, change):
    row = attempt(tmp_path, suite[0]["tasks"][0])
    packet = session(suite, [row])
    change(packet)
    with pytest.raises(ValueError):
        reader.check_session(packet, suite[0], suite[1], tmp_path)


@pytest.mark.parametrize("kind", ["substituted", "missing", "traversal", "symlink", "wrong_size"])
def test_retained_native_capture_controls(suite, tmp_path, kind):
    row = attempt(tmp_path, suite[0]["tasks"][0])
    capture = row["response_capture"]
    path = tmp_path / capture["path"]
    if kind == "substituted":
        path.write_bytes(b"S" * capture["bytes"])
    elif kind == "missing":
        path.unlink()
    elif kind == "traversal":
        capture["path"] = "subdir/../../outside"
    elif kind == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / row["prompt_capture"]["path"])
    else:
        capture["bytes"] -= 1
    with pytest.raises((ValueError, OSError)):
        reader.check_session(session(suite, [row]), suite[0], suite[1], tmp_path)


def test_same_length_prompt_substitution_refuses_after_repinned_hash(suite, tmp_path):
    row = attempt(tmp_path, suite[0]["tasks"][0])
    capture = row["prompt_capture"]
    raw = b"x" * capture["bytes"]
    (tmp_path / capture["path"]).write_bytes(raw)
    capture["sha256"] = reader.digest(raw)
    with pytest.raises(ValueError, match="prompt differs"):
        reader.check_session(session(suite, [row]), suite[0], suite[1], tmp_path)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}',
                                  b'{"x":-Infinity}', b'{"x":1e999}', b'{"x":1.0}',
                                  b'[1]', b'\xff', b'{', b'[' * 2000])
def test_strict_external_json_boundary(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        reader.read_json(path)


def test_report_never_executes_a_retained_command(suite, tmp_path):
    row = attempt(tmp_path, suite[0]["tasks"][0])
    command = f"touch {tmp_path / 'must-not-exist'}"
    row["response"]["command"] = command
    row["command_execution"] = {"command": command, "exit_code": 0,
                                "stdout": retain(tmp_path, "claimed-stdout.txt", b"declared test output"),
                                "stderr": retain(tmp_path, "claimed-stderr.txt", b"")}
    result = checked_report(suite, session(suite, [row]), tmp_path)
    assert result["reported_command_executions"] == 1
    assert not (tmp_path / "must-not-exist").exists()


def test_cli_reports_empty_session_without_inventing_results(tmp_path):
    args = [sys.executable, str(reader.ROOT / "tools/discovery_evaluation.py"), "report",
            "--session", str(reader.ROOT / "examples/discovery-evaluation/no-attempts.json"),
            "--evidence-root", str(tmp_path)]
    process = subprocess.run(args, capture_output=True, text=True, check=False)
    assert process.returncode == 0 and process.stderr == ""
    assert json.loads(process.stdout)["reported_discovery_attempts"] == 0
    process = subprocess.run(args[:-2], capture_output=True, text=True, check=False)
    assert process.returncode == 2 and process.stdout == ""
    assert "REFUSED" in process.stderr


def test_suite_rejects_unknown_source_and_duplicate_identity(suite):
    value = copy.deepcopy(suite[0])
    value["tasks"][0]["expected"]["source_ids"] = ["not-in-source-table"]
    with pytest.raises(ValueError, match="unknown reference source"):
        reader.check_suite(value)
    value = copy.deepcopy(suite[0])
    value["tasks"][1]["id"] = value["tasks"][0]["id"]
    with pytest.raises(ValueError, match="repeats a task"):
        reader.check_suite(value)
