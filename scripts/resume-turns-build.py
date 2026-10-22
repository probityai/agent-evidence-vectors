#!/usr/bin/env python3
"""Build the frozen resumed-task corpus: turn ownership, artifact replay, repeated effects.

Every case starts from one intact resumed task: a root agent delegates to a
``single_turn`` worker, the worker's tool asks for confirmation, the user approves,
and the run resumes. Each case changes one thing and states the answer it expects
on each axis.

    python scripts/resume-turns-build.py           # write the corpus
    python scripts/resume-turns-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.invocation_axes.reader import sha256_tag  # noqa: E402
from agent_evidence_vectors.resume_turns.reader import AXES, INDEPENDENT, SCHEMA  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/resume_turns/corpus"
E = "ESTABLISHED"
C = "CONTRADICTED"
N = "NOT_ESTABLISHED"


def _part(text: str) -> str:
    return sha256_tag(text.encode("utf-8"))


P_CALL = _part("call: close_ticket OPS-4127")
P_ASK = _part("requires confirmation")
P_RESULT = _part("ticket OPS-4127 closed")
P_HEADER = _part("report header")
P_BODY1 = _part("report body v1")
P_BODY2 = _part("report body v2")


def _task(**override: Any) -> dict[str, Any]:
    task: dict[str, Any] = {
        "schema": SCHEMA,
        "agents": {
            "root": {"parent": None, "mode": "chat"},
            "worker": {"parent": "root", "mode": "single_turn"},
        },
        "paused_by": "worker",
        "resumed_turn": [
            {"author": "worker", "to": "root", "kind": "function_response"},
            {"author": "root", "to": "user", "kind": "message"},
        ],
        "artifact_snapshots": {"tool-log": [P_CALL, P_ASK]},
        "resumed_response_artifacts": [
            {"artifact_id": "tool-log", "op": "append", "parts": [P_CALL, P_ASK, P_RESULT]}
        ],
        "emitted_artifacts": {"tool-log": [P_RESULT]},
        "effects": [
            {"action_id": "close-OPS-4127", "source": INDEPENDENT, "observed": "status=closed"}
        ],
    }
    task.update(override)
    return task


def _expect(*words: str) -> dict[str, str]:
    out: dict[str, str] = {axis: word for axis, word in zip(AXES, words, strict=True)}
    out.update({"effect_correctness": N, "observation_coverage": N})
    return out


def _second_effect() -> list[dict[str, Any]]:
    one = {"action_id": "close-OPS-4127", "source": INDEPENDENT, "observed": "status=closed"}
    return [one, dict(one, observed="status=closed (second write, reopen_count reset)")]


def _cases() -> list[dict[str, Any]]:
    replaced = [{"artifact_id": "report", "op": "replace", "parts": [P_HEADER, P_BODY2]}]
    rows: list[tuple[str, str, str, dict[str, Any], dict[str, str]]] = [
        (
            "intact_resume",
            "all",
            "The worker returns its result to the root, the root answers the user, only the"
            " new tool-log part is emitted, and the tool ran once.",
            _task(),
            _expect(E, E, E),
        ),
        (
            "paused_single_turn_agent_answers_user",
            "turn_owner",
            "The paused single_turn worker answers the user itself, and the root's call to it"
            " never gets a response.",
            _task(resumed_turn=[{"author": "worker", "to": "user", "kind": "message"}]),
            _expect(C, E, E),
        ),
        (
            "task_mode_worker_returns_to_delegator",
            "turn_owner",
            "The same flow with a task-mode worker.",
            _task(
                agents={
                    "root": {"parent": None, "mode": "chat"},
                    "worker": {"parent": "root", "mode": "task"},
                }
            ),
            _expect(E, E, E),
        ),
        (
            "chat_sub_agent_keeps_its_turn",
            "turn_owner",
            "A chat sub-agent keeps sticky routing: answering the user itself is correct.",
            _task(
                agents={
                    "root": {"parent": None, "mode": "chat"},
                    "worker": {"parent": "root", "mode": "chat"},
                },
                resumed_turn=[{"author": "worker", "to": "user", "kind": "message"}],
            ),
            _expect(E, E, E),
        ),
        (
            "delegation_mode_unrecorded",
            "turn_owner",
            "The record does not say how the worker was delegated, so ownership is undecidable.",
            _task(agents={"root": {"parent": None, "mode": "chat"}, "worker": {"parent": "root"}}),
            _expect(N, E, E),
        ),
        (
            "earlier_turn_artifacts_replayed",
            "artifact_replay",
            "The resumed response carries the whole task, and the earlier call and its"
            " confirmation request are emitted again with the result. The tool still ran once.",
            _task(emitted_artifacts={"tool-log": [P_CALL, P_ASK, P_RESULT]}),
            _expect(E, C, E),
        ),
        (
            "replaced_artifact_shares_leading_part",
            "artifact_replay",
            "A report replaced under the same id keeps its header; the replacement must be"
            " emitted whole, not only the parts after the shared header.",
            _task(
                artifact_snapshots={"tool-log": [P_CALL, P_ASK], "report": [P_HEADER, P_BODY1]},
                resumed_response_artifacts=replaced,
                emitted_artifacts={"report": [P_BODY2]},
            ),
            _expect(E, C, E),
        ),
        (
            "replaced_artifact_emitted_whole",
            "artifact_replay",
            "The same replacement emitted whole.",
            _task(
                artifact_snapshots={"tool-log": [P_CALL, P_ASK], "report": [P_HEADER, P_BODY1]},
                resumed_response_artifacts=replaced,
                emitted_artifacts={"report": [P_HEADER, P_BODY2]},
            ),
            _expect(E, E, E),
        ),
        (
            "appended_part_equal_to_an_earlier_one",
            "artifact_replay",
            "A new part equal in content to an earlier one, at a new position, is new.",
            _task(
                resumed_response_artifacts=[
                    {"artifact_id": "tool-log", "op": "append", "parts": [P_CALL, P_ASK, P_ASK]}
                ],
                emitted_artifacts={"tool-log": [P_ASK]},
            ),
            _expect(E, E, E),
        ),
        (
            "no_earlier_snapshot",
            "artifact_replay",
            "Nothing records what was emitted before the pause, so replay is undecidable.",
            _task(artifact_snapshots=None),
            _expect(E, N, E),
        ),
        (
            "second_effect_hidden_by_deduplicated_display",
            "repeated_effect",
            "Only the new artifact part is shown, but the observer saw the tool write twice:"
            " clean display, repeated effect.",
            _task(effects=_second_effect()),
            _expect(E, E, C),
        ),
        (
            "replayed_artifacts_and_a_second_effect",
            "repeated_effect",
            "Both faults at once, each reported on its own axis.",
            _task(
                emitted_artifacts={"tool-log": [P_CALL, P_ASK, P_RESULT]},
                effects=_second_effect(),
            ),
            _expect(E, C, C),
        ),
        (
            "effect_reported_only_by_the_tool",
            "repeated_effect",
            "The only effect record is the tool's own report.",
            _task(
                effects=[
                    {"action_id": "close-OPS-4127", "source": "tool", "observed": "ok"},
                    {"action_id": "close-OPS-4127", "source": "tool", "observed": "ok"},
                ]
            ),
            _expect(E, E, N),
        ),
    ]
    cases = []
    for cid, axis, desc, task, exp in rows:
        task = copy.deepcopy(task)
        if task.get("artifact_snapshots") is None:
            task.pop("artifact_snapshots", None)
        cases.append({"id": cid, "axis": axis, "description": desc, "task": task, "expected": exp})
    return cases


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def build() -> dict[str, str]:
    """Return every corpus file's text, manifest last."""
    files = {"cases.json": _dump({"schema": "aev-resumed-task-cases/v1", "cases": _cases()})}
    files["manifest.json"] = _dump(
        {
            "schema": "aev-resumed-task-corpus/v1",
            "members": {n: sha256_tag(t.encode("utf-8")) for n, t in sorted(files.items())},
        }
    )
    return files


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check exit 1 if the committed files differ."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    files = build()
    if args.check:
        stale = [
            n
            for n, t in files.items()
            if not (CORPUS / n).exists() or (CORPUS / n).read_text() != t
        ]
        if stale:
            print(f"stale corpus members: {stale}", file=sys.stderr)
            return 1
        return 0
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (CORPUS / name).write_text(text)
    print(f"wrote {len(files)} files, {len(_cases())} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
