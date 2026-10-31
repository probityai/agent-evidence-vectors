"""Naming a scope boundary by what its vectors ARE, never by the slug they were authored under.

WHY THIS MODULE EXISTS. The rego admission rail is a strict SUBSET verifier, so two
sets have to be written down beside it: the reject vectors it ADMITS because their
defect lives in a layer rego cannot reach, and the accept vectors it cannot fully
vouch for. Both used to be `dict[slug, reason]` tables keyed on the corpus's authoring
names -- "bad-402-root-no-domain-separation", "ok-029-artifact-with-records".

suiteRevision 28 deleted those names. Every vector is now `statements/v<digest>.json`
and MANIFEST.json carries no trace of the slugs, because measured over the retired
layout the identifier predicted accept-or-reject on its own. So `v["id"] not in
_TABLE` became true for every vector at once, and the tables selected the EMPTY
SET. That is the dangerous shape rather than a loud one: `every v in
data.corpus_vectors.reject_denylisted { ... }` over an empty collection is vacuously
true, so the test that exists to prove each denylisted vector really is admitted went
on reporting PASS while asserting nothing at all.

WHAT A FAMILY NAMES. A `ScopeFamily` names its vectors by the manifest's own
answer-neutral fields -- which `aee-c-NN` spec conditions the vector forces, and the
exact `expected` object a conforming rail must produce -- plus, where those two do not
separate the family from its siblings, a predicate over the statement's own content.
No path, no slug and NO DIGEST appears in a family: substituting a content address for
a slug would rebuild the identical defect one layer down, since the next regeneration
moves every digest exactly as this one moved every name. Condition ids are stable
across precisely the change that broke the old axis, and they are answer-neutral by
construction: the same id appears on the accept and the reject side of the rule it
names.

WHY EACH FAMILY DECLARES A COUNT. Resolution alone would turn a hand-checked boundary
into whatever the corpus currently happens to contain. The count is the ratchet the
slug table used to provide: a corpus that gains a vector inside a declared family, or
a policy that gains power over one and moves it out, makes the measurement disagree
with the declaration and REFUSES here -- rather than silently widening or hollowing
the boundary. An empty selection is the same refusal and the one this module was
written for.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any


class ScopeUnresolved(Exception):
    """A declared scope family did not select the vectors it declares."""


@dataclass(frozen=True)
class ScopeFamily:
    """One scope boundary, named by manifest metadata plus an optional shape.

    ``what`` is the prose reason the boundary exists, carried through to the emitted
    document so a reader of `corpus_vectors.json` still sees why a vector sits where
    it does. ``conditions`` and ``expected`` are the manifest's own fields. ``shape``
    reads a PARSED statement and answers whether it carries the property under test;
    it is needed only where conditions and expected do not separate a family from a
    sibling that the rail genuinely evaluates. ``shape_says`` spells that predicate
    for whoever has to re-derive the family from the corpus generators.
    """

    what: str
    conditions: frozenset[str]
    expected: dict[str, Any]
    count: int
    shape: Callable[[dict[str, Any]], bool] | None = None
    shape_says: str = ""
    _extra: tuple[str, ...] = field(default=(), repr=False)

    def says(self) -> str:
        conds = ", ".join(sorted(self.conditions)) or "(no conditions)"
        tail = f" AND {self.shape_says}" if self.shape is not None else ""
        return f"{conds} expecting {json.dumps(self.expected, sort_keys=True)}{tail}"


def _metadata_matches(family: ScopeFamily, vector: dict[str, Any]) -> bool:
    if frozenset(vector.get("conditions", ())) != family.conditions:
        return False
    return vector.get("expected") == family.expected


def resolve(
    families: Sequence[ScopeFamily],
    vectors: Iterable[dict[str, Any]],
    statement_of: Callable[[dict[str, Any]], dict[str, Any] | None],
    *,
    label: str,
) -> dict[str, str]:
    """Map vector id -> scope reason, refusing loudly rather than selecting nothing.

    ``vectors`` are manifest entries already narrowed to the kind and the exclusions
    the caller applies (a vector the caller drops before resolution must not be
    counted by a family, which is why the narrowing happens outside). ``statement_of``
    parses one, answering None for bytes that are not JSON text at all -- those can
    never satisfy a shape predicate and are not an error here.

    Every family must select exactly the number of vectors it declares, and no vector
    may be claimed by two families. Both are refusals: a family that selects nothing
    has stopped asserting its boundary, and a boundary nobody asserts reads exactly
    like one that holds.
    """
    resolved: dict[str, str] = {}
    owner: dict[str, ScopeFamily] = {}
    pool = list(vectors)
    problems: list[str] = []

    for family in families:
        hits: list[dict[str, Any]] = []
        for vector in pool:
            if not _metadata_matches(family, vector):
                continue
            if family.shape is not None:
                statement = statement_of(vector)
                if statement is None or not family.shape(statement):
                    continue
            hits.append(vector)

        if len(hits) != family.count:
            got = ", ".join(sorted(v["id"] for v in hits)) or "NOTHING"
            problems.append(
                f"{label}: the family {family.says()!r} declares {family.count} "
                f"vector(s) and the corpus selects {len(hits)} ({got}). "
                f"Reason on record: {family.what!r}. Either the corpus moved under "
                f"this boundary or the rail's reach changed; re-derive the family "
                f"from the corpus rather than deleting the declaration."
            )
            continue

        for vector in hits:
            previous = owner.get(vector["id"])
            if previous is not None:
                problems.append(
                    f"{label}: {vector['id']} is claimed by two families, "
                    f"{previous.says()!r} and {family.says()!r}. A vector with two "
                    f"reasons has one of them wrong."
                )
                continue
            owner[vector["id"]] = family
            resolved[vector["id"]] = family.what

    if problems:
        raise ScopeUnresolved("\n".join(problems))
    return resolved


# ---------------------------------------------------------------------------
# Shape predicates. Each separates ONE vector from siblings that carry the same
# conditions and the same expected object but whose defect the rail does reach.
# ---------------------------------------------------------------------------


def _decoded_payload(record: Any) -> dict[str, Any] | None:
    """One observation record's payload as a JSON object, or None.

    A payload that is not base64, not JSON, or not an object answers None rather than
    raising: that is a different defect from the one a shape predicate is separating,
    and a predicate that crashed on it would turn a resolvable family into an
    unresolvable one. Every fault here -- binascii.Error, UnicodeDecodeError,
    JSONDecodeError -- is a ValueError, so the one clause covers them without
    swallowing anything broader.
    """
    if not isinstance(record, dict):
        return None
    raw = record.get("payload")
    if not isinstance(raw, str):
        return None
    try:
        decoded = json.loads(base64.b64decode(raw, validate=True))
    except ValueError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _record_payloads(statement: dict[str, Any]) -> list[dict[str, Any]]:
    """Every observation-record payload that decodes into a JSON object."""
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return []
    records = predicate.get("observationRecords")
    if not isinstance(records, list):
        return []
    return [p for p in (_decoded_payload(r) for r in records) if p is not None]


def env_without_substrate(statement: dict[str, Any]) -> bool:
    """The observationEnvironment carries no substrate member at all.

    Separates the missing-substrate vector from its four siblings under aee-c-78,
    which drop catchPolicy, networkPosture or corpus instead -- absences the rego
    binding contract does state.
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False
    env = predicate.get("observationEnvironment")
    return isinstance(env, dict) and "substrate" not in env


def all_rows_substrate_basis(statement: dict[str, Any]) -> bool:
    """Every attackResults row rests on basis "substrate", and there is at least one.

    Separates the substrate-basis orphaned-interception vector from the artifact-only
    sibling under aee-c-95, which rego reaches through the artifact arm.
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False
    rows = predicate.get("attackResults")
    if not isinstance(rows, list) or not rows:
        return False
    return all(isinstance(r, dict) and r.get("basis") == "substrate" for r in rows)


def arming_without_assessed_attacks(statement: dict[str, Any]) -> bool:
    """Some carried arming record omits aeeAssessedAttacks entirely.

    Separates the absent-member vector from the two siblings under aee-c-99 whose
    aeeAssessedAttacks is present and merely unsorted or later-undeclared -- both
    shapes rego reads off members already in reach.
    """
    return any(
        payload.get("aeeKind") == "arming" and "aeeAssessedAttacks" not in payload
        for payload in _record_payloads(statement)
    )
