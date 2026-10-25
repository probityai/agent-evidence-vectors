#!/usr/bin/env python3
"""Build the frozen evaluation-result corpus: cases that pin score direction, evidence
origin and held-out status.

Every case is one input (the attributes of one or more ``gen_ai.evaluation.result`` events
and the evidence items each rests on) with the reading and reason codes a correct reader
derives. The expected answers are written out here by hand; no reader produces them.

Positive cases state one way an input is read cleanly. Each negative case starts from a
positive twin and makes exactly one change, its defect; the case carries ``repair``, the
operations that undo it, and the tests prove the repaired input is the twin and reads as
the twin does. A negative that still refused after its repair would be refusing for a
reason other than the one it names.

    python scripts/eval-result-build.py           # write the corpus
    python scripts/eval-result-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.claim_record.ops import mutate  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/eval_result/corpus"
AGENT = "agent-7"
P = "gen_ai.evaluation."


def _set(*path: Any, value: Any) -> dict[str, Any]:
    return {"op": "set", "path": list(path), "value": value}


def _del(*path: Any) -> dict[str, Any]:
    return {"op": "del", "path": list(path)}


def _scored(
    name: str, value: float, direction: str, evaluator: str, version: str
) -> dict[str, Any]:
    return {
        "attributes": {
            P + "name": name,
            P + "score.value": value,
            P + "score.direction": direction,
            P + "evaluator.id": evaluator,
            P + "evaluator.version": version,
        }
    }


def _reading(
    name: str,
    better: str = "unknown",
    origins: tuple[str, ...] = (),
    verification: tuple[str, ...] = (),
    held_out: str = "unknown",
) -> dict[str, Any]:
    return {
        "name": name,
        "better": better,
        "origins": list(origins),
        "any_self_reported": "self_reported" in origins,
        "verification": list(verification),
        "held_out": held_out,
    }


def _expected(
    readings: list[dict[str, Any]],
    reasons: tuple[str, ...] = (),
    ordering: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"readings": readings, "ordering": ordering, "reasons": list(reasons)}


def _verdict(verdict: str) -> dict[str, Any]:
    return {"compared": [0, 1], "verdict": verdict}


def _positives() -> list[dict[str, Any]]:
    tox = [
        _scored("toxicity", 0.2, "minimize", "tox-judge", "3"),
        _scored("toxicity", 0.7, "minimize", "tox-judge", "3"),
    ]
    corr = [
        _scored("correctness", 0.6, "maximize", "corr-judge", "2"),
        _scored("correctness", 0.9, "maximize", "corr-judge", "2"),
    ]
    mixed = {
        "attributes": {
            P + "name": "task_completion",
            P + "score.label": "pass",
            P + "input.origin": ["evaluator_obtained", "self_reported"],
        },
        "evidence": [
            {"ref": "junit-report-1", "origin": "evaluator_obtained", "produced_by": "evaluator-1"},
            {"ref": "reward-file", "origin": "self_reported", "produced_by": AGENT},
        ],
    }
    checked = {
        "attributes": {P + "name": "task_completion", P + "score.label": "pass"},
        "evidence": [
            {
                "ref": "reward-file",
                "origin": "self_reported",
                "produced_by": AGENT,
                "verified_by": "auditor-1",
            }
        ],
    }

    def held(**attrs: Any) -> dict[str, Any]:
        return {"attributes": {P + "name": "accuracy", **attrs}}

    return [
        {
            "id": "direction-minimize-orders-lower-first",
            "group": "score-direction",
            "about": (
                "Two results of one evaluator declare minimize, so the lower score is the "
                "better one."
            ),
            "input": {"agent_id": AGENT, "results": tox, "compare": [0, 1]},
            "expected": _expected(
                [_reading("toxicity", "lower")] * 2, ordering=_verdict("first_better")
            ),
        },
        {
            "id": "direction-maximize-orders-higher-first",
            "group": "score-direction",
            "about": (
                "Two results of one evaluator declare maximize, so the higher score is "
                "the better one."
            ),
            "input": {"agent_id": AGENT, "results": corr, "compare": [0, 1]},
            "expected": _expected(
                [_reading("correctness", "higher")] * 2, ordering=_verdict("second_better")
            ),
        },
        {
            "id": "origins-mixed-listed-per-item",
            "group": "evidence-origin",
            "about": (
                "A result resting on tests the evaluator ran and a reward file the agent "
                "wrote lists both origins."
            ),
            "input": {"agent_id": AGENT, "results": [mixed]},
            "expected": _expected(
                [
                    _reading(
                        "task_completion",
                        origins=("evaluator_obtained", "self_reported"),
                        verification=("none", "none"),
                    )
                ]
            ),
        },
        {
            "id": "verifier-distinct-origin-unchanged",
            "group": "producer-and-verifier",
            "about": (
                "An auditor checked the agent's reward file. The origin stays "
                "self_reported and the verifier is a separate field."
            ),
            "input": {"agent_id": AGENT, "results": [checked]},
            "expected": _expected(
                [
                    _reading(
                        "task_completion",
                        origins=("self_reported",),
                        verification=("independent_party",),
                    )
                ]
            ),
        },
        {
            "id": "held-out-true-required",
            "group": "held-out",
            "about": "The relying party requires a held-out item set and the result declares true.",
            "input": {
                "agent_id": AGENT,
                "rule": {"require_held_out": True},
                "results": [held(**{P + "items.held_out": True})],
            },
            "expected": _expected([_reading("accuracy", held_out="held_out")]),
        },
        {
            "id": "held-out-absent-without-requirement",
            "group": "held-out",
            "about": (
                "No requirement and no declaration: the status is unknown, which is not a "
                "refusal and not false."
            ),
            "input": {"agent_id": AGENT, "results": [held()]},
            "expected": _expected([_reading("accuracy", held_out="unknown")]),
        },
        {
            "id": "held-out-false-without-requirement",
            "group": "held-out",
            "about": "An explicit false is a status of its own: the item set was not held out.",
            "input": {"agent_id": AGENT, "results": [held(**{P + "items.held_out": False})]},
            "expected": _expected([_reading("accuracy", held_out="not_held_out")]),
        },
    ]


def _negatives() -> list[dict[str, Any]]:
    t = "direction-minimize-orders-lower-first"
    c = "direction-maximize-orders-higher-first"
    pr = "origins-mixed-listed-per-item"
    ck = "verifier-distinct-origin-unchanged"
    h = "held-out-true-required"
    d = P + "score.direction"
    unordered = {"compared": [0, 1], "verdict": "not_comparable"}
    tox_unknown = [_reading("toxicity")] * 2
    return [
        {
            "id": "direction-undeclared-not-inferred-from-name",
            "twin": t,
            "group": "score-direction",
            "about": (
                "Neither result declares a direction. A toxicity score looks lower-is-"
                "better, and a reader still does not infer it."
            ),
            "defect": [_del("results", 0, "attributes", d), _del("results", 1, "attributes", d)],
            "expected": _expected(tox_unknown, ("direction_undeclared",), unordered),
        },
        {
            "id": "direction-value-not-registered",
            "twin": t,
            "group": "score-direction",
            "about": "A direction other than maximize or minimize is refused, not guessed.",
            "defect": [_set("results", 0, "attributes", d, value="lower_is_better")],
            "expected": _expected(
                [_reading("toxicity"), _reading("toxicity", "lower")],
                ("direction_invalid",),
                unordered,
            ),
        },
        {
            "id": "direction-snapshots-disagree",
            "twin": c,
            "group": "score-direction",
            "about": (
                "Two results of one evaluator id and version declare opposite directions, "
                "so neither order can be trusted."
            ),
            "defect": [_set("results", 1, "attributes", d, value="minimize")],
            "expected": _expected(
                [_reading("correctness", "higher"), _reading("correctness", "lower")],
                ("direction_conflict",),
                unordered,
            ),
        },
        {
            "id": "compare-across-evaluator-versions",
            "twin": c,
            "group": "score-direction",
            "about": (
                "The two results come from different evaluator versions, so their scores "
                "are not on one footing."
            ),
            "defect": [_set("results", 1, "attributes", P + "evaluator.version", value="3")],
            "expected": _expected(
                [_reading("correctness", "higher")] * 2, ("evaluator_differs",), unordered
            ),
        },
        {
            "id": "origin-collapsed-to-one-value",
            "twin": pr,
            "group": "evidence-origin",
            "about": (
                "The result declares one origin while its items rest on two. A mixed "
                "result lists every origin."
            ),
            "defect": [
                _set("results", 0, "attributes", P + "input.origin", value="evaluator_obtained")
            ],
            "expected": _expected(
                [
                    _reading(
                        "task_completion",
                        origins=("evaluator_obtained", "self_reported"),
                        verification=("none", "none"),
                    )
                ],
                ("origin_mismatch",),
            ),
        },
        {
            "id": "origin-missing-on-item",
            "twin": ck,
            "group": "evidence-origin",
            "about": "An evidence item with no origin is not read as independent.",
            "defect": [_del("results", 0, "evidence", 0, "origin")],
            "expected": _expected(
                [_reading("task_completion", verification=("independent_party",))],
                ("origin_missing",),
            ),
        },
        {
            "id": "origin-value-not-registered",
            "twin": ck,
            "group": "evidence-origin",
            "about": "An origin outside the four registered values is refused.",
            "defect": [_set("results", 0, "evidence", 0, "origin", value="trusted")],
            "expected": _expected(
                [_reading("task_completion", verification=("independent_party",))],
                ("origin_invalid",),
            ),
        },
        {
            "id": "verifier-same-as-producer",
            "twin": ck,
            "group": "producer-and-verifier",
            "about": (
                "The agent that wrote the reward file also names itself as the verifier. "
                "That is not a second party."
            ),
            "defect": [_set("results", 0, "evidence", 0, "verified_by", value=AGENT)],
            "expected": _expected(
                [
                    _reading(
                        "task_completion",
                        origins=("self_reported",),
                        verification=("not_independent",),
                    )
                ],
                ("self_verified",),
            ),
        },
        {
            "id": "verifier-identity-upgrades-origin",
            "twin": ck,
            "group": "producer-and-verifier",
            "about": (
                "The item is relabelled external because an auditor checked it. The agent "
                "still produced it."
            ),
            "defect": [_set("results", 0, "evidence", 0, "origin", value="external")],
            "expected": _expected(
                [
                    _reading(
                        "task_completion",
                        origins=("external",),
                        verification=("independent_party",),
                    )
                ],
                ("origin_contradicts_producer",),
            ),
        },
        {
            "id": "held-out-absent-is-unknown-not-false",
            "twin": h,
            "group": "held-out",
            "about": (
                "The relying party requires a held-out set and the result is silent. "
                "Silence is unknown, and unknown fails the requirement."
            ),
            "defect": [_del("results", 0, "attributes", P + "items.held_out")],
            "expected": _expected(
                [_reading("accuracy", held_out="unknown")], ("held_out_unknown",)
            ),
        },
        {
            "id": "held-out-false-fails-the-requirement",
            "twin": h,
            "group": "held-out",
            "about": "An explicit false is a different refusal from silence.",
            "defect": [_set("results", 0, "attributes", P + "items.held_out", value=False)],
            "expected": _expected(
                [_reading("accuracy", held_out="not_held_out")], ("not_held_out",)
            ),
        },
        {
            "id": "held-out-string-is-not-a-boolean",
            "twin": h,
            "group": "held-out",
            "about": 'The string "false" is not coerced either way.',
            "defect": [_set("results", 0, "attributes", P + "items.held_out", value="false")],
            "expected": _expected(
                [_reading("accuracy", held_out="invalid")], ("held_out_invalid",)
            ),
        },
    ]


def build() -> dict[str, bytes]:
    """Return every corpus file by path relative to the corpus directory."""
    positives = [{**c, "kind": "positive"} for c in _positives()]
    by_id = {c["id"]: c for c in positives}
    negatives = []
    for case in _negatives():
        twin = by_id[case["twin"]]
        mutated, repair = mutate(twin["input"], case["defect"])
        negatives.append(
            {
                "id": case["id"],
                "kind": "negative",
                "group": case["group"],
                "about": case["about"],
                "twin": case["twin"],
                "defect": case["defect"],
                "repair": repair,
                "input": mutated,
                "expected": case["expected"],
            }
        )
    cases = {
        "schema": "aev-evaluation-result-cases/v1",
        "cases": copy.deepcopy(positives) + negatives,
    }
    body = (json.dumps(cases, indent=2, sort_keys=True) + "\n").encode()
    manifest = {
        "schema": "aev-evaluation-result-manifest/v1",
        "members": {"cases.json": "sha256:" + hashlib.sha256(body).hexdigest()},
    }
    return {
        "cases.json": body,
        "manifest.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
    }


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check exit 1 if the committed files differ."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    built = build()
    if args.check:
        on_disk = {
            str(p.relative_to(CORPUS)): p.read_bytes() for p in CORPUS.rglob("*") if p.is_file()
        }
        if on_disk != built:
            stale = sorted(
                set(on_disk) ^ set(built) | {k for k in built if on_disk.get(k) != built[k]}
            )
            print(f"evaluation-result corpus differs from the builder: {stale}", file=sys.stderr)
            return 1
        return 0
    for name, data in built.items():
        path = CORPUS / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
