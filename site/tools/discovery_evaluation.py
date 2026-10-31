#!/usr/bin/env python3
"""Check retained discovery attempts and report fixed task denominators.

This reader does not run a browser, search engine, model or advertised command.
It checks local evidence bytes and reported reviewer decisions. Operator roles,
unfamiliarity, source access, clocks and answer-key exposure remain declarations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = ROOT / "data/discovery-tasks.json"
SCHEMA = ROOT / "data/discovery-evaluation.schema.json"
MODES = ("open_search", "navigation")
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    """Refuse one invalid retained-packet condition."""
    if not condition:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Return the SHA-256 of exact bytes."""
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse ambiguous JSON members instead of selecting a last value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "JSON repeats a member")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    """Refuse the non-JSON constants accepted by Python's default decoder."""
    raise ValueError(f"JSON contains nonfinite constant {value}")


def reject_float(value: str) -> None:
    """Keep the packet's integer counters exact, including exponent overflow."""
    raise ValueError("JSON floating-point numbers are outside this packet contract")


def read_json(path: Path) -> tuple[dict[str, Any], str]:
    """Read bounded UTF-8 JSON and preserve its exact file digest."""
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES, "JSON input exceeds the byte limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant, parse_float=reject_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid UTF-8 JSON") from error
    require(isinstance(value, dict), "JSON root must be an object")
    return value, digest(raw)


def check_shape(value: dict[str, Any], name: str) -> None:
    """Check a closed suite or session against the maintained local schema."""
    schema, _ = read_json(SCHEMA)
    selected = {"$ref": f"#/$defs/{name}", "$defs": schema["$defs"]}
    validator = Draft202012Validator(selected)
    error = next(validator.iter_errors(value), None)
    if error:
        where = "/".join(str(part) for part in error.absolute_path) or "root"
        raise ValueError(f"Invalid {name} at {where}: {error.validator}")


def public_url(value: str) -> None:
    """Check HTTPS URL syntax; this does not establish public accessibility."""
    try:
        url = urlsplit(value)
        require(url.scheme == "https" and bool(url.hostname), "Source URL must use HTTPS")
        require(url.username is None and url.password is None, "Source URL has credentials")
        require(url.port in (None, 443), "Source URL has an unsupported port")
    except ValueError as error:
        raise ValueError("Invalid public source URL") from error


def check_suite(suite: dict[str, Any]) -> None:
    """Check the fixed task identities and their source/rubric references."""
    check_shape(suite, "suite")
    ids = [task["id"] for task in suite["tasks"]]
    require(len(set(ids)) == len(ids), "Suite repeats a task ID")
    source_ids = [source["id"] for source in suite["sources"]]
    require(len(set(source_ids)) == len(source_ids), "Suite repeats a source ID")
    for source in suite["sources"]:
        public_url(source["url"])
    for task in suite["tasks"]:
        require(set(task["expected"]["source_ids"]) <= set(source_ids),
                "Task names an unknown reference source")
    require(set(suite["human_walkthrough_tasks"]) <= set(ids), "Unknown human walkthrough task")
    require(tuple(suite["modes"]) == MODES, "Suite must preserve both discovery modes")
    for url in suite["navigation_start_urls"]:
        public_url(url)


def capture_bytes(capture: dict[str, Any], evidence_root: Path) -> bytes:
    """Check a retained file without following an escape or a symbolic link."""
    path = PurePosixPath(capture["path"])
    require(not path.is_absolute() and all(part not in (".", "..") for part in capture["path"].split("/"))
            and "\\" not in capture["path"], "Capture path must stay below the evidence root")
    root = evidence_root.resolve(strict=True)
    target = root
    for part in path.parts:
        target = target / part
        require(not target.is_symlink(), "Capture path follows a symbolic link")
    require(target.resolve(strict=True).is_relative_to(root), "Capture path escapes its root")
    require(target.is_file(), "Capture must be a regular file")
    require(capture["bytes"] <= MAX_CAPTURE_BYTES, "Capture exceeds the byte limit")
    with target.open("rb") as stream:
        raw = stream.read(capture["bytes"] + 1)
    require(len(raw) == capture["bytes"], "Capture byte count differs")
    require(digest(raw) == capture["sha256"], "Capture digest differs")
    return raw


def check_attempt(attempt: dict[str, Any], task: dict[str, Any], suite: dict[str, Any],
                  evidence_root: Path) -> None:
    """Bind a declared attempt to the exact prompt and retained native files."""
    prompt = capture_bytes(attempt["prompt_capture"], evidence_root)
    require(prompt == task["prompt"].encode("utf-8"), "Attempt prompt differs from the fixed task")
    response = capture_bytes(attempt["response_capture"], evidence_root)
    require(attempt["status"] != "answered" or bool(response), "Answered attempt has no retained response")
    start = datetime.fromisoformat(attempt["started_at"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(attempt["ended_at"].replace("Z", "+00:00"))
    require(end >= start, "Attempt ends before it starts")
    if attempt["mode"] == "navigation":
        require(attempt["start_url"] in suite["navigation_start_urls"], "Unknown navigation start")
        require(not attempt["queries"], "Navigation attempt declares an open-search query")
    else:
        require(attempt["start_url"] is None and bool(attempt["queries"]),
                "Open search needs its actual query and no navigation start")
    for url in attempt["navigation_choices"]:
        public_url(url)
    for source in attempt["sources_accessed"]:
        public_url(source["url"])
        capture_bytes(source["capture"], evidence_root)
    execution = attempt["command_execution"]
    if execution is not None:
        require(execution["command"] == attempt["response"]["command"],
                "Executed command differs from the reported recipe")
        capture_bytes(execution["stdout"], evidence_root)
        capture_bytes(execution["stderr"], evidence_root)
    review = attempt["review"]
    if review["state"] != "pending":
        decision = capture_bytes(review["decision_capture"], evidence_root)
        require(bool(decision), "Completed review has no retained decision")
        accepted = all(review["checks"].values())
        require(accepted == (review["state"] == "accepted"), "Review state contradicts its checks")


def check_session(session: dict[str, Any], suite: dict[str, Any], suite_sha: str,
                  evidence_root: Path) -> None:
    """Refuse changed criteria, duplicate attempts or invalid retained files."""
    check_shape(session, "session")
    require(session["suite_sha256"] == suite_sha and session["suite_id"] == suite["id"],
            "Session is bound to a different suite")
    tasks = {task["id"]: task for task in suite["tasks"]}
    seen: set[tuple[str, str, int]] = set()
    for attempt in session["attempts"]:
        key = (attempt["task_id"], attempt["mode"], attempt["repetition"])
        require(key not in seen, "Session repeats a task/mode/repetition")
        seen.add(key)
        require(attempt["task_id"] in tasks, "Attempt names an unknown task")
        check_attempt(attempt, tasks[attempt["task_id"]], suite, evidence_root)
    for task_id, mode, repetition in seen:
        require(repetition == 1 or (task_id, mode, 1) in seen,
                "Repeated attempt lacks its first attempt")


def attempt_outcome(attempt: dict[str, Any], task: dict[str, Any]) -> tuple[str, list[str]]:
    """Keep failed retrievals and unfinished reviews distinct from acceptance."""
    if attempt["status"] == "error":
        return "failed", ["client_error"]
    if attempt["review"]["state"] == "pending":
        return "review_pending", []
    if attempt["review"]["state"] == "rejected":
        return "failed", ["reviewer_rejected"]
    response, expected = attempt["response"], task["expected"]
    reasons = []
    if set(response["component_ids"]) != set(expected["component_ids"]):
        reasons.append("component_mismatch")
    if set(response["profile_ids"]) != set(expected["profile_ids"]):
        reasons.append("profile_mismatch")
    source_urls = {source["url"] for source in attempt["sources_accessed"]}
    if not source_urls:
        reasons.append("no_retained_source")
    if expected["delivery"] == "recipe":
        if not response["command"] or not response["command"].strip():
            reasons.append("no_recipe_command")
        if response["recipe_url"] not in source_urls:
            reasons.append("recipe_source_not_retained")
    return ("failed", reasons) if reasons else ("review_accepted", [])


def mode_summary(rows: list[dict[str, Any]], suite: dict[str, Any], client: dict[str, Any] | None,
                 mode: str) -> dict[str, Any]:
    """Use each fixed first attempt once; repeats do not improve its score."""
    counts = Counter(row["outcome"] for row in rows)
    accepted = counts["review_accepted"]
    complete = not (counts["not_executed"] or counts["review_pending"])
    target = "not_established"
    if complete and client is not None and client["kind"] == "agent":
        target = "met" if accepted * 100 >= len(rows) * suite["agent_target_percent"] else "not_met"
    human = [row for row in rows if row["task_id"] in suite["human_walkthrough_tasks"]]
    human_target = "not_established"
    if mode == "navigation" and client is not None and client["kind"] == "human":
        if all(row["outcome"] not in {"not_executed", "review_pending"} for row in human):
            if client["familiarity"] == "unfamiliar_declared":
                good = all(row["outcome"] == "review_accepted" and
                           row["navigation_choices"] <= suite["human_navigation_choices"] for row in human)
                human_target = "met" if good else "not_met"
    return {"fixed_tasks": len(rows), "outcomes": {name: counts[name] for name in
            ("not_executed", "review_pending", "failed", "review_accepted")},
            "accepted_fraction": {"numerator": accepted, "denominator": len(rows)},
            "agent_target": target, "human_navigation_target": human_target}


def report(suite: dict[str, Any], suite_sha: str, session: dict[str, Any] | None = None) -> dict[str, Any]:
    """Report a checked session, or an explicit baseline with no attempts."""
    attempts = session["attempts"] if session is not None else []
    by_key = {(a["task_id"], a["mode"], a["repetition"]): a for a in attempts}
    tasks = {task["id"]: task for task in suite["tasks"]}
    rows = []
    for mode in MODES:
        for task in suite["tasks"]:
            attempt = by_key.get((task["id"], mode, 1))
            outcome, reasons = attempt_outcome(attempt, task) if attempt else ("not_executed", [])
            rows.append({"task_id": task["id"], "mode": mode, "outcome": outcome,
                         "reasons": reasons, "navigation_choices": len(attempt["navigation_choices"]) if attempt else None})
    repeats = []
    for attempt in attempts:
        if attempt["repetition"] > 1:
            outcome, reasons = attempt_outcome(attempt, tasks[attempt["task_id"]])
            first = by_key[(attempt["task_id"], attempt["mode"], 1)]
            first_outcome, _ = attempt_outcome(first, tasks[attempt["task_id"]])
            repeats.append({"task_id": attempt["task_id"], "mode": attempt["mode"],
                            "repetition": attempt["repetition"], "outcome": outcome,
                            "first_outcome": first_outcome, "changed_outcome": first_outcome != outcome,
                            "reasons": reasons})
    client = session["client"] if session else None
    return {"schema_version": 1, "suite_id": suite["id"], "suite_sha256": suite_sha,
            "scope": "Retained local bytes and declared reviewer outcomes; no identity, clock or independent-operation authentication.",
            "client": client, "operator": session["operator"] if session else None,
            "answer_key_access": session["answer_key_access"] if session else "not_recorded",
            "retained_attempt_packets": len(attempts),
            "reported_discovery_attempts": len(attempts) if client is not None and client["kind"] in {"human", "agent"} else 0,
            "author_check_packets": len(attempts) if client is not None and client["kind"] == "author_check" else 0,
            "reported_command_executions": sum(a["command_execution"] is not None for a in attempts),
            "modes": {mode: mode_summary([row for row in rows if row["mode"] == mode], suite, client, mode)
                      for mode in MODES}, "first_attempts": rows, "repeats": repeats}


def prompt_packet(suite: dict[str, Any], suite_sha: str, mode: str, human_only: bool) -> dict[str, Any]:
    """Export prompts and allowed starting points without the review key."""
    tasks = suite["tasks"]
    if human_only:
        tasks = [task for task in tasks if task["id"] in suite["human_walkthrough_tasks"]]
    return {"suite_id": suite["id"], "suite_sha256": suite_sha, "mode": mode,
            "source_rule": "Use public sources only; retain accessed bytes, queries and navigation choices.",
            "start_urls": suite["navigation_start_urls"] if mode == "navigation" else [],
            "tasks": [{"id": task["id"], "prompt": task["prompt"],
                       "prompt_sha256": digest(task["prompt"].encode("utf-8"))} for task in tasks]}


def main(argv: list[str] | None = None) -> int:
    """Run a local check without invoking tools or commands from a receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "prompts", "report"))
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--session", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--mode", choices=MODES, default="navigation")
    parser.add_argument("--human-walkthroughs", action="store_true")
    args = parser.parse_args(argv)
    try:
        suite, suite_sha = read_json(args.suite)
        check_suite(suite)
        session = None
        if args.session is not None:
            require(args.evidence_root is not None, "Session needs an evidence root")
            session, _ = read_json(args.session)
            check_session(session, suite, suite_sha, args.evidence_root)
        if args.operation == "check":
            result = {"suite_id": suite["id"], "suite_sha256": suite_sha,
                      "tasks": len(suite["tasks"]), "session_checked": session is not None}
        elif args.operation == "prompts":
            require(session is None, "Prompt export does not take a session")
            result = prompt_packet(suite, suite_sha, args.mode, args.human_walkthroughs)
        else:
            result = report(suite, suite_sha, session)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, RecursionError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
