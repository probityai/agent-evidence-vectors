"""Judge one resumed agent task on three separate claims.

When an agent run pauses (a tool asks for confirmation, a delegated sub-agent waits
for the user) and later resumes, three different things can go wrong, and a record
that mixes them up will report one as another:

* ``turn_owner``: the turn after a paused delegated sub-agent belongs to the agent
  that delegated to it. A sub-agent in a delegated mode (``task`` or
  ``single_turn``) that answers the user directly, or takes the user's next
  message, has taken a turn it does not own.
* ``artifact_replay``: the resumed turn's emitted artifacts carry only what is new.
  A part is new unless it equals, at the same position, the part last emitted under
  the same artifact id. An artifact REPLACED under the same id is new whole, even
  when its first parts equal the old ones; an APPENDED artifact is new from the end
  of the old parts on.
* ``repeated_effect``: each logical action (``action_id``) had at most one effect,
  as an independent observer recorded it. A replayed artifact is not a repeated
  effect, and suppressing a replayed artifact must not hide a real second effect.

Each claim answers ``ESTABLISHED``, ``CONTRADICTED`` or ``NOT_ESTABLISHED``, and the
reader never reads a case's expected answer. Two properties stay ``NOT_ESTABLISHED``
in every case: ``effect_correctness`` (whether the effect was the right one) and
``observation_coverage`` (whether the observer saw every effect).
"""

from __future__ import annotations

from typing import Any

from ..invocation_axes.reader import MalformedInput, canonical, parse_strict, sha256_tag

__all__ = ["AXES", "NON_CLAIMS", "MalformedInput", "evaluate", "parse_strict", "summary"]

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

AXES = ("turn_owner", "artifact_replay", "repeated_effect")
NON_CLAIMS = ("effect_correctness", "observation_coverage")
SCHEMA = "aev-resumed-task/v1"
DELEGATED_MODES = frozenset({"task", "single_turn"})
INDEPENDENT = "independent_observer"


def _result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"result": status, "reason": reason}
    out.update(extra)
    return out


def _delegator(agents: dict[str, Any], name: str) -> str | None:
    """The agent that owns the turn after `name` pauses: its parent if delegated."""
    agent = agents.get(name)
    if agent is None:
        raise MalformedInput(f"event author {name!r} is not a declared agent")
    mode = agent.get("mode")
    if mode is None:
        return None
    return agent.get("parent") if mode in DELEGATED_MODES else name


def judge_turn_owner(task: dict[str, Any]) -> dict[str, Any]:
    """After the pause, the next agent to speak must be the paused agent's delegator.

    The paused agent may still run as part of the delegator's call (it resumes and
    returns its result to the delegator), which the record shows as an event with
    ``to`` naming the delegator. What it may not do is answer the user.
    """
    agents = task["agents"]
    paused = task["paused_by"]
    owner = _delegator(agents, paused)
    if owner is None:
        return _result(NOT_ESTABLISHED, "delegation_mode_unrecorded", agent=paused)
    for event in task["resumed_turn"]:
        if event.get("to") == "user":
            if event["author"] == owner:
                return _result(ESTABLISHED, "turn_owner_answers_the_user", owner=owner)
            return _result(
                CONTRADICTED, "turn_taken_by_non_owner", author=event["author"], owner=owner
            )
    return _result(NOT_ESTABLISHED, "nobody_answered_the_user")


def _new_parts(emitted: list[str], previous: list[str], op: str) -> list[str]:
    """The parts of an artifact that were not already emitted."""
    if op == "replace":
        return list(emitted)
    if op != "append":
        raise MalformedInput(f"artifact operation {op!r} is not append or replace")
    start = 0
    for part, old in zip(emitted, previous, strict=False):
        if part != old:
            break
        start += 1
    return list(emitted[start:])


def judge_replay(task: dict[str, Any]) -> dict[str, Any]:
    """Each artifact in the resumed response must be emitted as exactly its new parts."""
    snapshots = task.get("artifact_snapshots")
    if snapshots is None:
        return _result(NOT_ESTABLISHED, "no_earlier_snapshot_recorded")
    response = task["resumed_response_artifacts"]
    emitted = task["emitted_artifacts"]
    for art in response:
        aid = art["artifact_id"]
        want = _new_parts(art["parts"], snapshots.get(aid, []), art.get("op", "append"))
        got = emitted.get(aid, [])
        if got == want:
            continue
        if len(got) > len(want) and got[len(got) - len(want) :] == want:
            return _result(CONTRADICTED, "earlier_parts_emitted_again", artifact_id=aid)
        if len(got) < len(want) and want[len(want) - len(got) :] == got:
            return _result(
                CONTRADICTED, "replacement_emitted_without_its_leading_parts", artifact_id=aid
            )
        return _result(CONTRADICTED, "emitted_parts_differ", artifact_id=aid)
    extra = sorted(set(emitted) - {a["artifact_id"] for a in response})
    if extra:
        return _result(CONTRADICTED, "artifact_not_in_the_response", artifact_id=extra[0])
    return _result(ESTABLISHED, "only_new_parts_emitted")


def judge_effect(task: dict[str, Any]) -> dict[str, Any]:
    """At most one independently observed effect per logical action."""
    effects = task.get("effects")
    if not effects:
        return _result(NOT_ESTABLISHED, "no_effect_record")
    counts: dict[str, int] = {}
    for effect in effects:
        if effect.get("source") != INDEPENDENT:
            continue
        counts[effect["action_id"]] = counts.get(effect["action_id"], 0) + 1
    if not counts:
        return _result(NOT_ESTABLISHED, "effects_reported_only_by_the_tool")
    repeated = sorted(a for a, n in counts.items() if n > 1)
    if repeated:
        return _result(CONTRADICTED, "action_had_a_second_effect", action_id=repeated[0])
    return _result(ESTABLISHED, "one_effect_per_action", actions=len(counts))


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    """Judge one case. ``case['expected']`` is never read here."""
    task = case.get("task")
    if not isinstance(task, dict) or task.get("schema") != SCHEMA:
        raise MalformedInput(f"case task is not {SCHEMA}")
    out: dict[str, Any] = {
        "task_digest": sha256_tag(canonical(task)),
        "turn_owner": judge_turn_owner(task),
        "artifact_replay": judge_replay(task),
        "repeated_effect": judge_effect(task),
    }
    for prop in NON_CLAIMS:
        out[prop] = _result(NOT_ESTABLISHED, "outside_this_corpus")
    return out


def summary(actual: dict[str, Any]) -> dict[str, str]:
    """The per-axis and non-claim result words, in a fixed order."""
    return {key: actual[key]["result"] for key in (*AXES, *NON_CLAIMS)}
