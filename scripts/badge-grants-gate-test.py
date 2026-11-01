#!/usr/bin/env python3
"""Tests for scripts/badge-grants-gate.py.

A valid grant passes. Each way a grant can stop meeting the evidence rule is
applied to a copy of the valid ledger and must turn the gate red with the
expected message, so the gate cannot pass while one of its rules is missing.
The shipped ledger must also pass.

Run with: python3 scripts/badge-grants-gate-test.py
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
GATE = HERE / "badge-grants-gate.py"
_spec = importlib.util.spec_from_file_location("badge_grants_gate", GATE)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

WORKFLOW = "probityai/example/.github/workflows/conformance.yml"
Ledger = dict[str, Any]
Change = Callable[[Ledger], None]
SHA = "a" * 40
OTHER_SHA = "b" * 40


def digest(char: str) -> str:
    return "sha256:" + char * 64


def valid_ledger() -> Ledger:
    return {
        "schema": "badge-grants-v1",
        "policy": {
            "reusable_workflow": WORKFLOW,
            "runner_environment": "github-hosted",
            "issuer": "https://token.actions.githubusercontent.com",
            "events": ["push", "schedule", "workflow_dispatch"],
        },
        "workflows": [
            {"sha": SHA, "activated": "2026-11-01T00:00:00Z", "sunset": None, "revocation": None}
        ],
        "replay_environments": ["replay-env-1"],
        "grants": [
            {
                "project": "Example",
                "repository": "example-org/example",
                "repository_id": 4242,
                "default_branch": "main",
                "granted": "2026-11-05",
                "status": "active",
                "basis": "applicant-originated",
                "consent_url": "https://github.com/example-org/example/pull/1",
                "evidence": {
                    "job_workflow_ref": f"{WORKFLOW}@{SHA}",
                    "workflow_ref": "example-org/example/.github/workflows/ci.yml@refs/heads/main",
                    "runner_environment": "github-hosted",
                    "event_name": "push",
                    "ref": "refs/heads/main",
                    "sha": "c" * 40,
                    "run_id": 99,
                    "run_attempt": 1,
                    "repository": "example-org/example",
                    "repository_id": 4242,
                    "issuer": "https://token.actions.githubusercontent.com",
                    "integrated_time": "2026-11-04T12:00:00Z",
                    "result": "pass",
                    "covered_members": ["vectors-example"],
                    "receipt_digest": digest("1"),
                    "execution_bundle_digest": digest("2"),
                    "candidate_closure_digest": digest("3"),
                    "corpus_digest": digest("4"),
                    "expectation_digest": digest("5"),
                    "release_manifest_digest": digest("6"),
                },
            }
        ],
    }


def mutate(change: Change) -> list[str]:
    ledger = valid_ledger()
    change(ledger)
    errors: list[str] = gate.check(ledger)
    return errors


def evidence(ledger: Ledger) -> Ledger:
    found: Ledger = ledger["grants"][0]["evidence"]
    return found


def revoke(effect: str, since: str | None = None) -> Change:
    def apply(ledger: Ledger) -> None:
        ledger["workflows"][0]["revocation"] = {"effect": effect, "since": since}

    return apply


def set_evidence(key: str, value: object) -> Change:
    def apply(ledger: Ledger) -> None:
        evidence(ledger)[key] = value

    return apply


def replay(ledger: Ledger) -> None:
    ledger["grants"][0]["basis"] = "replay-qualified"


def replay_ok(ledger: Ledger) -> None:
    replay(ledger)
    evidence(ledger)["replay_record_digest"] = digest("7")
    evidence(ledger)["replay_environment"] = "replay-env-1"


def drop(key: str) -> Change:
    def apply(ledger: Ledger) -> None:
        del evidence(ledger)[key]

    return apply


def replay_unregistered(ledger: Ledger) -> None:
    replay_ok(ledger)
    evidence(ledger)["replay_environment"] = "x"


def withdraw(ledger: Ledger) -> None:
    ledger["grants"][0] = {"repository": "example-org/example", "status": "withdrawn"}


def duplicate(ledger: Ledger) -> None:
    ledger["grants"].append(copy.deepcopy(ledger["grants"][0]))


def failures() -> list[str]:
    problems: list[str] = []

    def expect_pass(label: str, errors: list[str]) -> None:
        if errors:
            problems.append(f"{label}: expected a pass, got {errors}")

    def expect_fail(label: str, errors: list[str], needle: str) -> None:
        if not any(needle in message for message in errors):
            problems.append(f"{label}: expected a failure naming {needle!r}, got {errors}")

    expect_pass("valid grant", gate.check(valid_ledger()))
    expect_pass("valid replay-qualified grant", mutate(replay_ok))
    expect_pass("revocation that only stops future minting", mutate(revoke("future-mint")))
    expect_pass(
        "revocation that starts after the receipt",
        mutate(revoke("invalidate", "2026-12-01T00:00:00Z")),
    )

    cases = [
        (
            "tag instead of SHA",
            set_evidence("job_workflow_ref", f"{WORKFLOW}@v1.0.0"),
            "full commit SHA",
        ),
        (
            "other workflow",
            set_evidence("job_workflow_ref", f"other/repo/.github/workflows/x.yml@{SHA}"),
            "not the registered workflow",
        ),
        (
            "SHA not on the allowlist",
            set_evidence("job_workflow_ref", f"{WORKFLOW}@{OTHER_SHA}"),
            "not on the allowlist",
        ),
        (
            "self-hosted runner",
            set_evidence("runner_environment", "self-hosted"),
            "runner_environment",
        ),
        (
            "pull_request_target",
            set_evidence("event_name", "pull_request_target"),
            "not a permitted event",
        ),
        ("workflow_run", set_evidence("event_name", "workflow_run"), "not a permitted event"),
        ("wrong issuer", set_evidence("issuer", "https://example.org"), "issuer"),
        ("repository mismatch", set_evidence("repository", "attacker/fork"), "evidence.repository"),
        ("repository id mismatch", set_evidence("repository_id", 1), "repository_id"),
        ("unprotected branch", set_evidence("ref", "refs/heads/feature"), "default branch"),
        (
            "caller workflow outside the repository",
            set_evidence("workflow_ref", "attacker/fork/.github/workflows/ci.yml@refs/heads/main"),
            "workflow_ref",
        ),
        ("short commit", set_evidence("sha", "abc123"), "full lowercase commit SHA"),
        ("bad run id", set_evidence("run_id", 0), "run_id"),
        ("failed result", set_evidence("result", "fail"), "result must be pass"),
        ("no covered members", set_evidence("covered_members", []), "covered_members"),
        ("bad digest", set_evidence("corpus_digest", "md5:00"), "corpus_digest"),
        ("missing digest", drop("release_manifest_digest"), "missing release_manifest_digest"),
        (
            "receipt before activation",
            set_evidence("integrated_time", "2026-10-01T00:00:00Z"),
            "before its workflow SHA was activated",
        ),
        (
            "receipt after sunset",
            lambda led: led["workflows"][0].update(sunset="2026-11-02T00:00:00Z"),
            "after its workflow SHA was sunset",
        ),
        ("suspended workflow", revoke("suspend"), "suspended"),
        (
            "invalidating revocation",
            revoke("invalidate", "2026-11-03T00:00:00Z"),
            "revoked from a time",
        ),
        ("replay basis without a replay record", replay, "replay_record_digest"),
        (
            "replay environment not registered",
            replay_unregistered,
            "registered replay environment",
        ),
        (
            "no registered reusable workflow",
            lambda led: led["policy"].update(reusable_workflow=None),
            "no reusable workflow is registered",
        ),
        ("no consent", lambda led: led["grants"][0].update(consent_url=""), "consent_url"),
        (
            "unknown basis",
            lambda led: led["grants"][0].update(basis="self-declared"),
            "basis must be",
        ),
        ("unknown status", lambda led: led["grants"][0].update(status="pending"), "status must be"),
        ("withdrawn without a reason", withdraw, "withdrawn grant needs"),
        ("grant listed twice", duplicate, "listed twice"),
        ("wrong schema", lambda led: led.update(schema="v0"), "schema"),
        (
            "malformed allowlist entry",
            lambda led: led["workflows"][0].update(sha="short"),
            "workflows[0].sha",
        ),
    ]
    for label, change, needle in cases:
        expect_fail(label, mutate(change), needle)

    shipped = subprocess.run(
        [sys.executable, str(GATE)], capture_output=True, text=True, check=False
    )
    if shipped.returncode != 0:
        problems.append(
            f"shipped ledger: expected exit 0, got {shipped.returncode}: {shipped.stderr}"
        )
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "ledger.json"
        bad.write_text("{", encoding="utf-8")
        unreadable = subprocess.run(
            [sys.executable, str(GATE), "--ledger", str(bad)],
            capture_output=True,
            text=True,
            check=False,
        )
        if unreadable.returncode != 2:
            problems.append(f"unreadable ledger: expected exit 2, got {unreadable.returncode}")
        bad.write_text(
            json.dumps(mutate_to_dict(set_evidence("event_name", "workflow_run"))), encoding="utf-8"
        )
        refused = subprocess.run(
            [sys.executable, str(GATE), "--ledger", str(bad)],
            capture_output=True,
            text=True,
            check=False,
        )
        if refused.returncode != 1:
            problems.append(f"failing ledger: expected exit 1, got {refused.returncode}")
    return problems


def mutate_to_dict(change: Change) -> Ledger:
    ledger = valid_ledger()
    change(ledger)
    return ledger


def main() -> int:
    problems = failures()
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print("badge-grants-gate-test: every rule turns the gate red when broken")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
