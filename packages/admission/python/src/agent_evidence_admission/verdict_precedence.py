"""Strictest-wins resolution of the verdicts that several policies give one action.

The order, from least to most strict, is ``allow`` < ``constrain`` < ``require_approval`` < ``block`` <
``halt``. ``docs/VERDICT-PRECEDENCE.md`` is the normative text and ``vectors/precedence/manifest.json``
holds its conflict vectors. The rules, each held by a vector:

* the strictest verdict wins, and the answer does not depend on the order the policies answered in;
* every policy that gave the winning verdict is reported, sorted by identifier;
* an empty set of answers is no decision and never ``allow``;
* an unregistered or differently spelled verdict is refused, never read as ``allow``;
* a check that failed without producing a verdict of its own (``{"policy": ..., "failed": true}``)
  counts as ``block``;
* ``deny`` from a two-valued decision point counts as ``block``, and nothing else is rewritten;
* a ``constrain`` names its constraint, and the resolution of a ``constrain`` carries every constraint
  of every policy that gave it, sorted and without repeats.

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Least to most strict. The vocabulary registry's ``decision_verdict`` carries the same list.
ORDER = ("allow", "constrain", "require_approval", "block", "halt")
_ALIASES = {"deny": "block"}


class PrecedenceInputError(ValueError):
    """The answers could not be resolved; the reason is a stable code. No decision is made."""


@dataclass(frozen=True)
class Resolution:
    """The winning verdict, the policies that gave it, and the constraints when the verdict is ``constrain``."""

    verdict: str
    policies: tuple[str, ...]
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"verdict": self.verdict, "policies": list(self.policies), "constraints": list(self.constraints)}


def _verdict_of(answer: object) -> tuple[str, str, str | None]:
    if not isinstance(answer, dict):
        raise PrecedenceInputError("answer-not-an-object")
    policy = answer.get("policy")
    if not isinstance(policy, str) or not policy:
        raise PrecedenceInputError("policy-missing")
    if "verdict" not in answer:
        if answer.get("failed") is True:
            return policy, "block", None
        raise PrecedenceInputError(f"verdict-missing:{policy}")
    given = answer["verdict"]
    verdict = _ALIASES.get(given, given) if isinstance(given, str) else None
    if verdict not in ORDER:
        raise PrecedenceInputError(f"unregistered-verdict:{given}")
    constraint = answer.get("constraint")
    if verdict == "constrain" and not (isinstance(constraint, str) and constraint):
        raise PrecedenceInputError(f"constraint-missing:{policy}")
    return policy, verdict, constraint if verdict == "constrain" else None


def resolve(answers: list[dict]) -> Resolution:
    """The resolution of ``answers``; raises ``PrecedenceInputError`` for an input that has none."""
    if not isinstance(answers, list) or not answers:
        raise PrecedenceInputError("no-decision")
    seen: set[str] = set()
    given: list[tuple[str, str, str | None]] = []
    for answer in answers:
        policy, verdict, constraint = _verdict_of(answer)
        if policy in seen:
            raise PrecedenceInputError(f"policy-answered-twice:{policy}")
        seen.add(policy)
        given.append((policy, verdict, constraint))
    winner = max((verdict for _, verdict, _ in given), key=ORDER.index)
    deciding = sorted(policy for policy, verdict, _ in given if verdict == winner)
    constraints = sorted({c for _, verdict, c in given if verdict == "constrain" and c is not None}) if winner == "constrain" else []
    return Resolution(winner, tuple(deciding), tuple(constraints))
