"""Judge a record's values against the registry, by meta.open_value_rule.

    from agent_evidence_vocabulary import registry
    index = registry.load()
    registry.check_value(index, "observation_vantage", "substrate", record_digest)
    registry.resolve_verdict(index, {"class": "fail", "parent": "fail"}, record_digest)

``record_digest`` is the hex SHA-256 the record carries as registryDigest, or
None when it carries none. The rule has three cases: the record names the
registry this index was made from (exact), names none (exact, as before the
rule), or names another registry (tolerant, by the term's criticality). The
exact digests a verifier holds can be widened with ``known_digests``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources

OK = "ok"
DEGRADED = "degraded"
IGNORED = "ignored"
MALFORMED = "malformed"


@dataclass(frozen=True)
class Judgement:
    """What a verifier does with one value. ``value`` is always preserved."""

    outcome: str
    value: str
    reason: str
    meaning: str | None = None


def load() -> dict:
    """The registry index shipped with this package."""
    return json.loads(resources.files(__package__ or "agent_evidence_vocabulary").joinpath("registry.json").read_text("utf-8"))


def digest_of(source: bytes) -> str:
    """The registryDigest of a registry file's exact bytes."""
    return hashlib.sha256(source).hexdigest()


def _exact(index: dict, record_digest: str | None, known_digests: frozenset[str]) -> bool:
    return record_digest is None or record_digest == index["source_sha256"] or record_digest in known_digests


def check_value(index: dict, term: str, value: str, record_digest: str | None,
                known_digests: frozenset[str] = frozenset()) -> Judgement:
    """Judge ``value`` of the closed term ``term``."""
    entry = index["terms"].get(term)
    if entry is None or entry["values"] is None:
        raise KeyError(f"{term} is not a term with registered values")
    if value in entry["values"]:
        return Judgement(OK, value, "registered", meaning=value)
    if _exact(index, record_digest, known_digests):
        return Judgement(MALFORMED, value, "unregistered under the registry the record names")
    if entry["criticality"] == "critical":
        return Judgement(DEGRADED, value, "unregistered value of a critical term under another registry")
    return Judgement(IGNORED, value, "unregistered value of an informational term under another registry")


def resolve_verdict(index: dict, verdict: dict, record_digest: str | None,
                    known_digests: frozenset[str] = frozenset()) -> Judgement:
    """Judge a verdict {class, parent}; ``meaning`` is the parent it counts as."""
    classes = index["verdict_classes"]
    code, parent = verdict.get("class"), verdict.get("parent")
    if parent not in classes["parents"]:
        return Judgement(MALFORMED, str(code), f"parent {parent!r} is not a value of {classes['parent_term']}")
    if code == parent:
        return Judgement(OK, code, "parent", meaning=parent)
    child = classes["children"].get(code)
    if child is not None:
        if child["parent"] != parent:
            return Judgement(MALFORMED, code, f"registered under {child['parent']}, carried under {parent}")
        return Judgement(OK, code, "registered child", meaning=parent)
    if _exact(index, record_digest, known_digests):
        return Judgement(MALFORMED, str(code), "unregistered child under the registry the record names")
    return Judgement(OK, str(code), "unregistered child read as its parent", meaning=parent)
