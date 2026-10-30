#!/usr/bin/env python3
"""Check restoration-evidence records and bundles, and replay this corpus.

    python3 vectors-restart-records/check_vectors.py
    python3 vectors-restart-records/check_vectors.py --record statement.json
    python3 vectors-restart-records/check_vectors.py --bundle <directory>

With no argument it replays every member of MANIFEST.json and exits 0 only when
every verdict and reason match the manifest. ``--record`` checks one decoded
in-toto Statement against the predicate document its ``predicateType`` names;
``--bundle`` checks every ``*.json`` statement in a directory as one bundle of
the restoration-evidence/v1 profile. Both print one JSON object carrying
``verdict`` and ``reason`` and exit 0 for accept, 1 for reject, 2 when the input
cannot be read as a record or a bundle at all.

Every rule of the five predicate documents and the bundle rules B1 to B7 of
``profiles/restoration-evidence.md`` is applied in table order, and the first
rule that fails is the reason. Standard library only, so that a reader who
installed nothing can run it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HOST = "https://probityai.github.io/agent-evidence-vectors"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

R1 = "incident-action-authorization"
R2 = "revocation-sweep"
R3 = "re-enable-decision"
R4 = "joint-authority"
RB = "revocation-boundary"
NAMES = (R1, R2, R3, R4, RB)
TYPE = {name: f"{HOST}/predicate/v1/{name}" for name in NAMES}
NAME_OF_TYPE = {uri: name for name, uri in TYPE.items()}
DOCUMENT = {name: f"spec/predicates/{name}.md" for name in NAMES}
PROFILE = "profiles/restoration-evidence.md"

#: The values the vocabulary registry defines for the terms these predicates
#: use (packages/vocabulary/registry.json). Rule 3 of each document checks
#: these and nothing else.
REGISTRY: dict[str, frozenset[str]] = {
    "response_function": frozenset({"monitoring_increase", "restriction", "isolation", "pause",
                                    "remediation", "restoration"}),
    "pause_hold": frozenset({"held", "in_flight_unknown", "effect_after_pause",
                             "residual_state_remains", "not_established"}),
    "restoration_decision": frozenset({"resume_full", "resume_staged", "remain_restricted",
                                       "not_established"}),
    "revocation_state": frozenset({"issued", "enforced_observed", "use_after_revocation",
                                   "not_established"}),
    "intent_binding": frozenset({"committed_before_execution", "asserted_after_execution"}),
    "independence_basis": frozenset({"independent_sources", "subject_supplied", "undeclared"}),
    "set_sufficiency": frozenset({"sufficient", "insufficient", "not_assessed"}),
}

#: Values the predicate documents close themselves. Rule 2 checks these.
ROLES = frozenset({"advised", "authorised", "executed", "accountable"})
AUTHORITY = frozenset({"role_grant", "policy_preauthorised", "contract_third_party",
                       "executive_approval", "unknown"})
PART_STATES = frozenset({"revoked", "retained", "unassessed"})
COVERAGE = frozenset({"complete_verified", "issued_after_only", "partial", "unknown"})
SINK_KINDS = frozenset({"database", "filesystem", "http_endpoint", "subprocess", "queue",
                        "other"})
VANTAGES = frozenset({"sink_side", "agent_side"})
RESULTS = frozenset({"no_post_revocation_commit_observed", "post_revocation_commit_observed",
                     "not_established"})
SLOTS = frozenset({
    "actorObjective", "persistence", "rootCause", "affectedScope", "assetIntegrity",
    "restoredAssetsClean", "containmentReproof", "incidentReplay", "restoreOrder",
    "postRestartMonitoring", "exclusiveControl", "controlsNotDegraded", "residualRisk",
    "seniorApproval", "multiPartyAuthorization", "ownerConfirmation",
})
SCOPE_KEYS = ("agents", "tools", "routes", "credentials")
COUNT_KEYS = ("attempts", "inFlightAtRevocation", "postRevocationCommits", "replaysAttempted",
              "replaysCommitted")

#: Each document's Rules table, in order: (rule, code). The tests hold these
#: equal to the tables in the documents themselves.
RULES: dict[str, tuple[tuple[str, str], ...]] = {
    R1: (("1", "statement-malformed"), ("2", "predicate-malformed"),
         ("3", "closed-vocabulary-violation"), ("4", "no-authoriser"),
         ("5", "no-accountable-party"), ("6", "authority-basis-missing"),
         ("7", "authorization-window-inverted"), ("8", "intent-not-committed-before"),
         ("9", "authorization-expired"), ("10", "induced-effects-unobserved")),
    R2: (("1", "statement-malformed"), ("2", "predicate-malformed"),
         ("3", "closed-vocabulary-violation"), ("4", "denominator-union-mismatch"),
         ("5", "revocation-entries-mismatch"), ("6", "coverage-claim-exceeds-proof"),
         ("7", "coverage-claim-incomplete")),
    R3: (("1", "statement-malformed"), ("2", "predicate-malformed"),
         ("3", "closed-vocabulary-violation"), ("4", "evidence-slot-missing"),
         ("5", "evidence-slot-unexplained"), ("6", "no-approver"),
         ("7", "partial-without-scope"), ("8", "full-with-scope")),
    R4: (("1", "statement-malformed"), ("2", "predicate-malformed"),
         ("3", "closed-vocabulary-violation"), ("4", "authority-basis-missing"),
         ("5", "single-organization"), ("6", "party-acts-outside-assignment")),
    RB: (("1", "statement-malformed"), ("2", "predicate-malformed"),
         ("3", "closed-vocabulary-violation"), ("4", "revocation-outside-window"),
         ("5", "counts-inconsistent"), ("6", "result-contradicts-counts"),
         ("7", "observer-not-at-sink")),
}
BUNDLE_RULES: tuple[tuple[str, str], ...] = (
    ("B1", "the record's own code"), ("B2", "predecessor-not-carried"),
    ("B3", "predecessor-type-mismatch"), ("B4", "predecessor-cycle"),
    ("B5", "incident-mismatch"), ("B6", "predecessor-issued-later"),
    ("B7", "restored-credential-unswept"),
)
ACCEPTED = {R1: "authorization-recorded", R2: "sweep-recorded", R3: "decision-recorded",
            R4: "assignment-recorded", RB: "boundary-recorded"}
BUNDLE_ACCEPTED = "bundle-consistent"

TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
URL_RE = re.compile(r"^https://[^\s]+$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

Json = Any


class Unreadable(Exception):
    """The input is not a record or a bundle at all (exit 2, no verdict)."""


# --------------------------------------------------------------------------
# Strict JSON and value shapes


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"non-standard number {name}")


def strict_json(data: bytes) -> Json:
    """Parse strict JSON: UTF-8, no duplicate member at any depth, no NaN."""
    text = data.decode("utf-8")
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)


def _exact(value: Json, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> bool:
    return (isinstance(value, dict) and set(required) <= set(value)
            and set(value) <= set(required) | set(optional))


def _text(value: Json) -> bool:
    return isinstance(value, str) and len(value) > 0


def _string(value: Json) -> bool:
    return isinstance(value, str)


def _url(value: Json) -> bool:
    return isinstance(value, str) and URL_RE.match(value) is not None


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _time(value: Json) -> bool:
    if not isinstance(value, str) or TIME_RE.match(value) is None:
        return False
    try:
        _instant(value)
    except ValueError:
        return False
    return True


def _sha(value: Json) -> bool:
    return (_exact(value, ("sha256",)) and isinstance(value["sha256"], str)
            and SHA_RE.match(value["sha256"]) is not None)


def _count(value: Json) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _list(value: Json, item: Callable[[Json], bool], *, min_items: int = 0) -> bool:
    return isinstance(value, list) and len(value) >= min_items and all(item(v) for v in value)


def _sorted_unique_texts(value: Json, *, min_items: int = 0) -> bool:
    return (_list(value, _text, min_items=min_items) and value == sorted(value)
            and len(set(value)) == len(value))


def _roles(value: Json) -> bool:
    return (_sorted_unique_texts(value, min_items=1)
            and all(role in ROLES for role in value))


def _descriptor(value: Json) -> bool:
    return (_exact(value, ("digest",), ("uri", "mediaType")) and _sha(value["digest"])
            and all(_text(value[k]) for k in ("uri", "mediaType") if k in value))


def _ref(value: Json) -> bool:
    return _exact(value, ("issuer", "id")) and _url(value["issuer"]) and _text(value["id"])


# --------------------------------------------------------------------------
# Rule 1, and the members every predicate shares


def _statement(statement: Json) -> str | None:
    """Rule 1 of every document: the predicate name, or None when malformed."""
    if not _exact(statement, ("_type", "subject", "predicateType", "predicate")):
        return None
    if statement["_type"] != STATEMENT_TYPE:
        return None
    name = NAME_OF_TYPE.get(statement["predicateType"]) if _string(
        statement["predicateType"]) else None
    subject_ok = _list(statement["subject"], lambda s: _exact(s, ("digest",), ("name",))
                       and _sha(s["digest"]) and ("name" not in s or _text(s["name"])),
                       min_items=1)
    if name is None or not subject_ok or not isinstance(statement["predicate"], dict):
        return None
    return name


COMMON = ("incident", "producer", "issuedAt", "registryDigest", "doesNotAssert")


def _common(p: dict[str, Any]) -> bool:
    incident = p["incident"]
    return (_exact(incident, ("issuer", "id"), ("related",)) and _url(incident["issuer"])
            and _text(incident["id"])
            and ("related" not in incident or _list(incident["related"], _ref))
            and _exact(p["producer"], ("id",)) and _url(p["producer"]["id"])
            and _time(p["issuedAt"]) and _sha(p["registryDigest"])
            and _list(p["doesNotAssert"], _text))


def _predecessors(value: Json, *, needs: str | None = None) -> bool:
    ok = _list(value, lambda r: _exact(r, ("predicateType", "digest"))
               and r["predicateType"] in NAME_OF_TYPE and _sha(r["digest"]), min_items=1)
    return ok and (needs is None or any(r["predicateType"] == TYPE[needs] for r in value))


# --------------------------------------------------------------------------
# R1 incident-action-authorization


def _r1_effects(value: Json) -> bool:
    if not isinstance(value, dict) or not _string(value.get("declared")):
        return False
    declared = value["declared"]
    if declared == "listed":
        return (_exact(value, ("declared", "items"))
                and _list(value["items"], _text, min_items=1)
                and len(set(value["items"])) == len(value["items"]))
    if declared == "none_observed":
        return (_exact(value, ("declared",), ("observation",))
                and ("observation" not in value or _sha(value["observation"])))
    return declared == "unknown" and _exact(value, ("declared",))


def _r1_party(value: Json) -> bool:
    return (_exact(value, ("id", "roles"), ("authorityBasis", "independenceBasis"))
            and _text(value["id"]) and _roles(value["roles"])
            and ("authorityBasis" not in value or value["authorityBasis"] in AUTHORITY)
            and ("independenceBasis" not in value or _string(value["independenceBasis"])))


def _r1_shape(p: dict[str, Any]) -> bool:
    keys = (*COMMON, "action", "parties", "authorizedAt", "notAfter", "intentBinding")
    if not _exact(p, keys, ("executedAt", "pause")) or not _common(p):
        return False
    action = p["action"]
    return (_exact(action, ("functions", "targets", "inducedEffects"))
            and _sorted_unique_texts(action["functions"], min_items=1)
            and _list(action["targets"], lambda t: _exact(t, ("id",)) and _text(t["id"]),
                      min_items=1)
            and _r1_effects(action["inducedEffects"])
            and _list(p["parties"], _r1_party, min_items=1)
            and _time(p["authorizedAt"]) and _time(p["notAfter"])
            and ("executedAt" not in p or _time(p["executedAt"]))
            and _string(p["intentBinding"])
            and ("pause" not in p or (_exact(p["pause"], ("hold", "holdProof"))
                                      and _string(p["pause"]["hold"])
                                      and _sha(p["pause"]["holdProof"]))))


def _r1_vocabulary(p: dict[str, Any]) -> bool:
    return (all(f in REGISTRY["response_function"] for f in p["action"]["functions"])
            and p["intentBinding"] in REGISTRY["intent_binding"]
            and ("pause" not in p or p["pause"]["hold"] in REGISTRY["pause_hold"])
            and all(party["independenceBasis"] in REGISTRY["independence_basis"]
                    for party in p["parties"] if "independenceBasis" in party))


def _holders(p: dict[str, Any], role: str) -> list[dict[str, Any]]:
    return [party for party in p["parties"] if role in party["roles"]]


def _r1_intent(p: dict[str, Any]) -> bool:
    if p["intentBinding"] != "committed_before_execution" or "executedAt" not in p:
        return True
    return _instant(p["executedAt"]) >= _instant(p["authorizedAt"])


def _r1_rules(p: dict[str, Any]) -> list[Callable[[], bool]]:
    return [
        lambda: _r1_shape(p),
        lambda: _r1_vocabulary(p),
        lambda: bool(_holders(p, "authorised")),
        lambda: bool(_holders(p, "accountable")),
        lambda: all("authorityBasis" in party for party in _holders(p, "authorised")),
        lambda: _instant(p["authorizedAt"]) <= _instant(p["notAfter"]),
        lambda: _r1_intent(p),
        lambda: "executedAt" not in p or _instant(p["executedAt"]) <= _instant(p["notAfter"]),
        lambda: (p["action"]["inducedEffects"]["declared"] != "none_observed"
                 or "observation" in p["action"]["inducedEffects"]),
    ]


# --------------------------------------------------------------------------
# R2 revocation-sweep


def _r2_revocation(value: Json) -> bool:
    return (_exact(value, ("credential", "revokedAt", "evidence", "relyingParties"))
            and _text(value["credential"]) and _time(value["revokedAt"])
            and _descriptor(value["evidence"])
            and _list(value["relyingParties"], lambda r: _exact(r, ("id", "state"))
                      and _text(r["id"]) and _string(r["state"])))


def _r2_shape(p: dict[str, Any]) -> bool:
    keys = (*COMMON, "predecessors", "population", "partition", "revocations", "coverage")
    if not _exact(p, keys) or not _common(p):
        return False
    coverage = p["coverage"]
    return (_predecessors(p["predecessors"], needs=R1)
            and _exact(p["population"], ("credentials",))
            and _sorted_unique_texts(p["population"]["credentials"], min_items=1)
            and _list(p["partition"], lambda part: _exact(part, ("state", "credentials"))
                      and part["state"] in PART_STATES
                      and _list(part["credentials"], _text, min_items=1), min_items=1)
            and _list(p["revocations"], _r2_revocation)
            and _exact(coverage, ("claim",), ("issuedAfter",)) and coverage["claim"] in COVERAGE
            and ("issuedAfter" not in coverage or _time(coverage["issuedAfter"])))


def _part_members(p: dict[str, Any], state: str | None = None) -> list[str]:
    return [c for part in p["partition"] if state in (None, part["state"])
            for c in part["credentials"]]


def _r2_rules(p: dict[str, Any]) -> list[Callable[[], bool]]:
    population = p["population"]["credentials"] if isinstance(p.get("population"), dict) else []
    return [
        lambda: _r2_shape(p),
        lambda: all(rp["state"] in REGISTRY["revocation_state"]
                    for entry in p["revocations"] for rp in entry["relyingParties"]),
        lambda: sorted(_part_members(p)) == sorted(population),
        lambda: (sorted(e["credential"] for e in p["revocations"])
                 == sorted(_part_members(p, "revoked"))),
        lambda: (p["coverage"]["claim"] != "complete_verified"
                 or sorted(_part_members(p, "revoked")) == sorted(population)),
        lambda: p["coverage"]["claim"] != "issued_after_only" or "issuedAfter" in p["coverage"],
    ]


# --------------------------------------------------------------------------
# R3 re-enable-decision


def _r3_slot(value: Json) -> bool:
    if isinstance(value, dict) and "notAddressed" in value:
        return _exact(value, ("notAddressed",)) and _string(value["notAddressed"])
    return _descriptor(value)


def _r3_shape(p: dict[str, Any]) -> bool:
    keys = (*COMMON, "predecessors", "restoration", "approvers", "setSufficiency", "evidence")
    if not _exact(p, keys) or not _common(p):
        return False
    restoration = p["restoration"]
    return (_predecessors(p["predecessors"])
            and _exact(restoration, ("decision",), ("restoredScope",))
            and _string(restoration["decision"])
            and ("restoredScope" not in restoration
                 or (_exact(restoration["restoredScope"], SCOPE_KEYS)
                     and all(_sorted_unique_texts(restoration["restoredScope"][k])
                             for k in SCOPE_KEYS)))
            and _list(p["approvers"], lambda a: _exact(a, ("id", "roles", "independenceBasis"))
                      and _text(a["id"]) and _roles(a["roles"])
                      and _string(a["independenceBasis"]))
            and _string(p["setSufficiency"])
            and isinstance(p["evidence"], dict)
            and all(_r3_slot(v) for v in p["evidence"].values()))


def _scope_size(restoration: dict[str, Any]) -> int:
    scope = restoration.get("restoredScope")
    return sum(len(scope[k]) for k in SCOPE_KEYS) if scope else 0


def _r3_rules(p: dict[str, Any]) -> list[Callable[[], bool]]:
    return [
        lambda: _r3_shape(p),
        lambda: (p["restoration"]["decision"] in REGISTRY["restoration_decision"]
                 and p["setSufficiency"] in REGISTRY["set_sufficiency"]
                 and all(a["independenceBasis"] in REGISTRY["independence_basis"]
                         for a in p["approvers"])),
        lambda: set(p["evidence"]) == SLOTS,
        lambda: all(v["notAddressed"] != "" for v in p["evidence"].values()
                    if "notAddressed" in v),
        lambda: any("authorised" in a["roles"] for a in p["approvers"]),
        lambda: (p["restoration"]["decision"] != "resume_staged"
                 or _scope_size(p["restoration"]) > 0),
        lambda: (p["restoration"]["decision"] != "resume_full"
                 or "restoredScope" not in p["restoration"]),
    ]


# --------------------------------------------------------------------------
# R4 joint-authority


def _r4_party(value: Json) -> bool:
    return (_exact(value, ("id", "organization", "correlationId", "assets"),
                   ("authorityBasis",))
            and all(_text(value[k]) for k in ("id", "organization", "correlationId"))
            and ("authorityBasis" not in value or value["authorityBasis"] in AUTHORITY)
            and _sorted_unique_texts(value["assets"]))


def _r4_shape(p: dict[str, Any]) -> bool:
    if not _exact(p, (*COMMON, "sharedIndicators", "parties"), ("actions",)) or not _common(p):
        return False
    indicators = p["sharedIndicators"]
    return (_list(indicators, _sha, min_items=1)
            and [i["sha256"] for i in indicators] == sorted(i["sha256"] for i in indicators)
            and _list(p["parties"], _r4_party, min_items=2)
            and ("actions" not in p or _list(
                p["actions"], lambda a: _exact(a, ("party", "asset", "record"))
                and _text(a["party"]) and _text(a["asset"]) and _sha(a["record"]))))


def _r4_assigned(p: dict[str, Any], action: dict[str, Any]) -> bool:
    return any(party["id"] == action["party"] and action["asset"] in party["assets"]
               for party in p["parties"])


def _r4_rules(p: dict[str, Any]) -> list[Callable[[], bool]]:
    return [
        lambda: _r4_shape(p),
        lambda: True,  # no member of this predicate takes a registry-defined value
        lambda: all("authorityBasis" in party for party in p["parties"]),
        lambda: len({party["organization"] for party in p["parties"]}) >= 2,
        lambda: all(_r4_assigned(p, a) for a in p.get("actions", [])),
    ]


# --------------------------------------------------------------------------
# RB revocation-boundary


def _rb_shape(p: dict[str, Any]) -> bool:
    keys = (*COMMON, "sink", "observer", "revocation", "window", "counts", "exclusions",
            "result")
    if not _exact(p, keys, ("predecessors",)) or not _common(p):
        return False
    sink, observer, revocation = p["sink"], p["observer"], p["revocation"]
    return (_exact(sink, ("id", "kind", "commitBoundary")) and _text(sink["id"])
            and sink["kind"] in SINK_KINDS and _text(sink["commitBoundary"])
            and _exact(observer, ("id", "vantage")) and _text(observer["id"])
            and observer["vantage"] in VANTAGES
            and _exact(revocation, ("credential", "effectiveAt", "timeSource"))
            and _text(revocation["credential"]) and _time(revocation["effectiveAt"])
            and _text(revocation["timeSource"])
            and _exact(p["window"], ("start", "end")) and _time(p["window"]["start"])
            and _time(p["window"]["end"])
            and _exact(p["counts"], COUNT_KEYS) and all(_count(p["counts"][k]) for k in COUNT_KEYS)
            and _list(p["exclusions"], lambda e: _exact(e, ("count", "reason"))
                      and _count(e["count"]) and _text(e["reason"]))
            and p["result"] in RESULTS
            and ("predecessors" not in p or _predecessors(p["predecessors"])))


def _rb_result(p: dict[str, Any]) -> bool:
    if p["result"] == "not_established":
        return True
    committed = bool(p["counts"]["postRevocationCommits"] > 0
                     or p["counts"]["replaysCommitted"] > 0)
    observed: bool = p["result"] == "post_revocation_commit_observed"
    return observed == committed


def _rb_rules(p: dict[str, Any]) -> list[Callable[[], bool]]:
    c = p.get("counts", {})
    return [
        lambda: _rb_shape(p),
        lambda: True,  # no member of this predicate takes a registry-defined value
        lambda: (_instant(p["window"]["start"]) <= _instant(p["revocation"]["effectiveAt"])
                 <= _instant(p["window"]["end"])),
        lambda: (c["inFlightAtRevocation"] <= c["attempts"]
                 and c["postRevocationCommits"] <= c["inFlightAtRevocation"]
                 and c["replaysCommitted"] <= c["replaysAttempted"]),
        lambda: _rb_result(p),
        lambda: (p["result"] != "no_post_revocation_commit_observed"
                 or p["observer"]["vantage"] == "sink_side"),
    ]


RULE_CHECKS: dict[str, Callable[[dict[str, Any]], list[Callable[[], bool]]]] = {
    R1: _r1_rules, R2: _r2_rules, R3: _r3_rules, R4: _r4_rules, RB: _rb_rules,
}


# --------------------------------------------------------------------------
# One record


def check_statement(statement: Json) -> tuple[str, str]:
    """Apply one predicate document to a parsed statement: (verdict, reason)."""
    name = _statement(statement)
    if name is None:
        return "reject", "statement-malformed"
    predicate = statement["predicate"]
    for (_, code), rule in zip(RULES[name][1:], RULE_CHECKS[name](predicate), strict=True):
        if not rule():
            return "reject", code
    return "accept", ACCEPTED[name]


def check_record_bytes(data: bytes) -> tuple[str, str]:
    """Check one statement's bytes: strict JSON first, then its document."""
    try:
        statement = strict_json(data)
    except (UnicodeDecodeError, ValueError):
        return "reject", "statement-malformed"
    return check_statement(statement)


# --------------------------------------------------------------------------
# A bundle


def find_cycle(edges: dict[str, list[str]]) -> bool:
    """True when the predecessor graph (record -> records it names) has a cycle."""
    state: dict[str, int] = {}

    def visit(node: str) -> bool:
        state[node] = 1
        for nxt in edges.get(node, []):
            if state.get(nxt) == 1 or (state.get(nxt) is None and visit(nxt)):
                return True
        state[node] = 2
        return False

    return any(state.get(node) is None and visit(node) for node in sorted(edges))


def _incident_keys(predicate: dict[str, Any]) -> set[tuple[str, str]]:
    incident = predicate["incident"]
    keys = {(incident["issuer"], incident["id"])}
    keys.update((r["issuer"], r["id"]) for r in incident.get("related", []))
    return keys


class _Bundle:
    """A bundle whose every record passed B1, indexed for rules B2 to B7."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.names = sorted(files)
        self.statements = {name: strict_json(files[name]) for name in self.names}
        self.kind = {name: NAME_OF_TYPE[s["predicateType"]]
                     for name, s in self.statements.items()}
        self.decisions = [name for name in self.names if self.kind[name] == R3]
        if len(self.decisions) != 1:
            raise Unreadable(f"a bundle carries exactly one {R3} record; this one carries "
                             f"{len(self.decisions)}")
        self.digest = {name: hashlib.sha256(files[name]).hexdigest() for name in self.names}
        self.refs = {name: self.predicate(name).get("predecessors", []) for name in self.names}
        self.resolved: dict[str, list[str]] = {}

    def predicate(self, name: str) -> dict[str, Any]:
        value: dict[str, Any] = self.statements[name]["predicate"]
        return value

    def b2_carried(self) -> bool:
        for name in self.names:
            self.resolved[name] = []
            for ref in self.refs[name]:
                hits = [o for o in self.names if self.digest[o] == ref["digest"]["sha256"]]
                if len(hits) != 1:
                    return False
                self.resolved[name].append(hits[0])
        return True

    def b3_types(self) -> bool:
        return all(self.statements[target]["predicateType"] == ref["predicateType"]
                   for name in self.names
                   for ref, target in zip(self.refs[name], self.resolved[name], strict=True))

    def b4_acyclic(self) -> bool:
        return not find_cycle(self.resolved)

    def b5_incident(self) -> bool:
        anchor = _incident_keys(self.predicate(self.decisions[0]))
        return all(_incident_keys(self.predicate(name)) & anchor for name in self.names)

    def b6_order(self) -> bool:
        return all(_instant(self.predicate(name)["issuedAt"])
                   >= _instant(self.predicate(target)["issuedAt"])
                   for name in self.names for target in self.resolved[name])

    def b7_swept(self) -> bool:
        swept = {c for name in self.names if self.kind[name] == R2
                 for c in self.predicate(name)["population"]["credentials"]}
        scopes = [self.predicate(name)["restoration"].get("restoredScope")
                  for name in self.decisions]
        return all(set(scope["credentials"]) <= swept for scope in scopes if scope)


def check_bundle_files(files: dict[str, bytes]) -> tuple[str, str]:
    """Check a bundle given as {file name: statement bytes}: (verdict, reason)."""
    for name in sorted(files):  # B1
        verdict, reason = check_record_bytes(files[name])
        if verdict != "accept":
            return "reject", reason
    bundle = _Bundle(files)
    rules = (bundle.b2_carried, bundle.b3_types, bundle.b4_acyclic, bundle.b5_incident,
             bundle.b6_order, bundle.b7_swept)
    for (_, code), rule in zip(BUNDLE_RULES[1:], rules, strict=True):
        if not rule():
            return "reject", code
    return "accept", BUNDLE_ACCEPTED


def check_bundle_dir(directory: Path) -> tuple[str, str]:
    files = {p.name: p.read_bytes() for p in sorted(directory.glob("*.json")) if p.is_file()}
    if not files:
        raise Unreadable(f"{directory}: no *.json statement in it")
    return check_bundle_files(files)


# --------------------------------------------------------------------------
# Corpus replay and the command line


def replay(root: Path = HERE) -> list[str]:
    """Every disagreement between this checker and MANIFEST.json, as text."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    for entry in manifest["vectors"]:
        directory = root / entry["path"]
        for file, declared in entry["files"].items():
            if hashlib.sha256((directory / file).read_bytes()).hexdigest() != declared:
                failures.append(f"{entry['id']}: {file} does not match its manifest digest")
        if entry["shape"] == "bundle":
            got = check_bundle_dir(directory)
        else:
            got = check_record_bytes((directory / "statement.json").read_bytes())
        want = (entry["expected"]["verdict"], entry["expected"]["reason"])
        if got != want:
            failures.append(f"{entry['id']}: got {got}, manifest says {want}")
    return failures


def _report(verdict: str, reason: str) -> int:
    print(json.dumps({"verdict": verdict, "reason": reason}, sort_keys=True))
    return 0 if verdict == "accept" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check restoration-evidence records and bundles.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--record", type=Path, help="one decoded in-toto Statement")
    group.add_argument("--bundle", type=Path, help="a directory of statements")
    args = parser.parse_args(argv)
    try:
        if args.record is not None:
            return _report(*check_record_bytes(args.record.read_bytes()))
        if args.bundle is not None:
            return _report(*check_bundle_dir(args.bundle))
    except (OSError, Unreadable) as e:
        print(f"unreadable: {e}", file=sys.stderr)
        return 2
    failures = replay()
    for failure in failures:
        print(f"FAIL {failure}")
    total = len(json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"{'FAIL' if failures else 'PASS'}: {total - len(failures)} of {total} members agree "
          "with MANIFEST.json")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
