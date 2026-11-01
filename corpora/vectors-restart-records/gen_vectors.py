#!/usr/bin/env python3
"""Build the restart-records corpus byte-identically.

    python3 vectors-restart-records/gen_vectors.py

Every member is synthetic: an unsigned in-toto Statement of one predicate of
the restoration-evidence/v1 profile, or a directory of them read as one bundle.
Every identifier is on an example.com or example.org host, and no member
describes a real system or a real incident.

For each predicate there is an accepting control, and each rejecting member
changes exactly one value of that control so that the rule it names is the
first rule that fails. Bundle members change one value of one record of the
accepting bundle, after which every predecessor digest that pointed at the
changed record is recomputed, so that the rule named is still the first to
fail. MANIFEST.json records each change as the path, the value before and the
value after, and the tests revert it and require the control's bytes back.

This module writes cases/, MANIFEST.json and INDEX.md, and nothing else writes
them. Standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent


def _load_checker() -> Any:
    spec = importlib.util.spec_from_file_location("restart_records_checker",
                                                  ROOT / "check_vectors.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("restart_records_checker", module)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()
R1, R2, R3, R4, RB = checker.R1, checker.R2, checker.R3, checker.R4, checker.RB
TYPE = checker.TYPE
SUITE = "restart-records/v1"
#: sha256 of packages/vocabulary/vocabulary.yaml at release 0.8.0, the registry
#: the closed values are expressed in (pages/vocab/v1/registry/ serves it).
REGISTRY_DIGEST = "1c5ff80bd97237a603afc402db692ffe5abe15e4a7f9eca13f20068ada347fdc"
SYNTHETIC = ("Every member is synthetic. Identifiers are on example.com and example.org "
             "hosts, digests are of fixed labelled strings, and no member records a real "
             "system, organisation or incident.")
Path_ = list[str | int]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _label(text: str) -> dict[str, str]:
    """A digest of a fixed synthetic label, standing in for a real artifact."""
    return {"sha256": _sha(f"synthetic restart-records member: {text}".encode())}


def statement_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _statement(name: str, subject: str, predicate: dict[str, Any]) -> dict[str, Any]:
    return {
        "_type": checker.STATEMENT_TYPE,
        "predicateType": TYPE[name],
        "subject": [{"digest": _label(subject), "name": subject}],
        "predicate": predicate,
    }


INCIDENT = {"issuer": "https://ops.example.com/incidents", "id": "synthetic-incident-0001"}
PRODUCER = {"id": "https://records.example.com/producer"}
CRED = "https://idp.example.org/credentials/"
PEOPLE = "https://people.example.com/"
DOES_NOT_ASSERT = {
    R1: ["that the authorizer held the authority the basis names"],
    R2: ["that the population is every credential that existed"],
    R3: ["that any cited evidence shows what its slot names", "that resuming was safe"],
    R4: ["that the parties agreed to the assignment beyond the signer's statement"],
    RB: ["anything about another sink, window or credential"],
}


def _common(name: str, issued: str) -> dict[str, Any]:
    return {"incident": copy.deepcopy(INCIDENT), "producer": dict(PRODUCER),
            "issuedAt": issued, "registryDigest": {"sha256": REGISTRY_DIGEST},
            "doesNotAssert": list(DOES_NOT_ASSERT[name])}


def r1_control() -> dict[str, Any]:
    return _statement(R1, "operation description: pause and restrict agent-a", {
        **_common(R1, "2026-01-10T10:10:00Z"),
        "action": {
            "functions": ["pause", "restriction"],
            "targets": [{"id": "https://agents.example.com/agent-a"}],
            "inducedEffects": {"declared": "none_observed",
                               "observation": _label("induced-effect observation")},
        },
        "parties": [
            {"id": PEOPLE + "responder-a", "roles": ["authorized"],
             "authorityBasis": "role_grant"},
            {"id": PEOPLE + "responder-b", "roles": ["accountable", "executed"]},
        ],
        "authorizedAt": "2026-01-10T10:00:00Z",
        "notAfter": "2026-01-10T18:00:00Z",
        "executedAt": "2026-01-10T10:05:00Z",
        "intentBinding": "committed_before_execution",
        "pause": {"hold": "held", "holdProof": _label("pause hold observation")},
    })


def _revocation(credential: str) -> dict[str, Any]:
    return {"credential": credential, "revokedAt": "2026-01-10T12:00:00Z",
            "evidence": {"digest": _label(f"deny record for {credential}"),
                         "mediaType": "application/json"},
            "relyingParties": [{"id": "https://api.example.org", "state": "enforced_observed"}]}


def r2_control(r1_digest: str) -> dict[str, Any]:
    creds = [CRED + "c-01", CRED + "c-02", CRED + "c-03"]
    return _statement(R2, "population manifest: three credentials", {
        **_common(R2, "2026-01-10T14:00:00Z"),
        "predecessors": [{"predicateType": TYPE[R1], "digest": {"sha256": r1_digest}}],
        "population": {"credentials": creds},
        "partition": [{"state": "revoked", "credentials": creds[:2]},
                      {"state": "retained", "credentials": creds[2:]}],
        "revocations": [_revocation(creds[0]), _revocation(creds[1])],
        "coverage": {"claim": "partial"},
    })


def _evidence() -> dict[str, Any]:
    cited = ("actorObjective", "persistence", "rootCause", "affectedScope", "assetIntegrity",
             "restoredAssetsClean", "incidentReplay", "restoreOrder", "residualRisk",
             "seniorApproval", "ownerConfirmation")
    out: dict[str, Any] = {slot: {"digest": _label(f"evidence for {slot}")} for slot in cited}
    for slot in sorted(checker.SLOTS - set(cited)):
        out[slot] = {"notAddressed": "not addressed in this synthetic decision"}
    return out


def r3_control(r1_digest: str, r2_digest: str) -> dict[str, Any]:
    return _statement(R3, "restored configuration baseline", {
        **_common(R3, "2026-01-12T09:00:00Z"),
        "predecessors": [{"predicateType": TYPE[R1], "digest": {"sha256": r1_digest}},
                         {"predicateType": TYPE[R2], "digest": {"sha256": r2_digest}}],
        "restoration": {"decision": "resume_staged", "restoredScope": {
            "agents": ["https://agents.example.com/agent-a"], "credentials": [CRED + "c-03"],
            "routes": [], "tools": []}},
        "approvers": [{"id": PEOPLE + "approver-x", "roles": ["accountable", "authorized"],
                       "independenceBasis": "independent_sources"}],
        "setSufficiency": "not_assessed",
        "evidence": _evidence(),
    })


def r4_control() -> dict[str, Any]:
    return _statement(R4, "shared indicator set", {
        **_common(R4, "2026-01-11T08:00:00Z"),
        "incident": {"issuer": "https://soc.example.org/incidents", "id": "synthetic-case-17",
                     "related": [copy.deepcopy(INCIDENT)]},
        "sharedIndicators": sorted((_label("indicator one"), _label("indicator two")),
                                   key=lambda d: d["sha256"]),
        "parties": [
            {"id": PEOPLE + "operator-team", "organization": "https://example.com",
             "correlationId": "synthetic-incident-0001", "authorityBasis": "role_grant",
             "assets": ["https://agents.example.com/agent-a"]},
            {"id": "https://people.example.org/platform-team",
             "organization": "https://example.org", "correlationId": "synthetic-case-17",
             "authorityBasis": "contract_third_party", "assets": ["https://api.example.org"]},
        ],
        "actions": [{"party": PEOPLE + "operator-team",
                     "asset": "https://agents.example.com/agent-a",
                     "record": _label("authorization record of the pause")}],
    })


def rb_control() -> dict[str, Any]:
    return _statement(RB, "test plan: one sink, one window", {
        **_common(RB, "2026-01-11T09:00:00Z"),
        "sink": {"id": "https://db.example.com/ledger", "kind": "database",
                 "commitBoundary": "the transaction commit"},
        "observer": {"id": "https://observer.example.com/ledger-reader",
                     "vantage": "sink_side"},
        "revocation": {"credential": CRED + "c-01", "effectiveAt": "2026-01-10T12:00:00Z",
                       "timeSource": "https://time.example.org"},
        "window": {"start": "2026-01-10T11:00:00Z", "end": "2026-01-10T13:00:00Z"},
        "counts": {"attempts": 40, "inFlightAtRevocation": 6, "postRevocationCommits": 0,
                   "replaysAttempted": 3, "replaysCommitted": 0},
        "exclusions": [{"count": 1, "reason": "attempt withdrawn before dispatch"}],
        "result": "no_post_revocation_commit_observed",
    })


# --------------------------------------------------------------------------
# One mutation: set or delete the value at a path


_ABSENT = object()


def get_at(value: Any, path: Path_) -> Any:
    for key in path:
        if isinstance(value, dict):
            if key not in value:
                return _ABSENT
            value = value[key]
        else:
            value = value[key]
    return value


def set_at(value: Any, path: Path_, new: Any) -> None:
    """Set the value at ``path``; ``_ABSENT`` deletes a member."""
    parent = get_at(value, path[:-1])
    key = path[-1]
    if new is _ABSENT:
        del parent[key]
    else:
        parent[key] = copy.deepcopy(new)


def mutation(path: Path_, base: Any, new: Any) -> dict[str, Any]:
    """The manifest record of one change: the path, and the value before and after."""
    out: dict[str, Any] = {"path": list(path)}
    before = get_at(base, path)
    if before is not _ABSENT:
        out["from"] = copy.deepcopy(before)
    if new is not _ABSENT:
        out["to"] = copy.deepcopy(new)
    return out


def apply(base: Any, change: dict[str, Any], *, revert: bool = False) -> Any:
    out = copy.deepcopy(base)
    side = "from" if revert else "to"
    set_at(out, change["path"], change[side] if side in change else _ABSENT)
    return out


# --------------------------------------------------------------------------
# Bundles


BUNDLE_ORDER = ("r1.json", "r2.json", "r3.json", "r4.json", "rb.json")


def relink(records: dict[str, dict[str, Any]], before: dict[str, str]) -> dict[str, bytes]:
    """Serialise a bundle, re-pointing predecessor digests at changed records.

    ``before`` maps each file to the digest it had before the change. Records
    are written in BUNDLE_ORDER, which puts every record after the ones it can
    name, so one pass carries a change through every reference to it.
    """
    moved: dict[str, str] = {}
    out: dict[str, bytes] = {}
    for name in [n for n in BUNDLE_ORDER if n in records]:
        record = copy.deepcopy(records[name])
        for ref in record["predicate"].get("predecessors", []):
            ref["digest"]["sha256"] = moved.get(ref["digest"]["sha256"],
                                                ref["digest"]["sha256"])
        data = statement_bytes(record)
        if _sha(data) != before[name]:
            moved[before[name]] = _sha(data)
        out[name] = data
    return out


def bundle_control(*, optional: bool = False) -> dict[str, dict[str, Any]]:
    r1 = r1_control()
    r2 = r2_control(_sha(statement_bytes(r1)))
    r3 = r3_control(_sha(statement_bytes(r1)), _sha(statement_bytes(r2)))
    records = {"r1.json": r1, "r2.json": r2, "r3.json": r3}
    if optional:
        rb = rb_control()
        rb["predicate"]["predecessors"] = [
            {"predicateType": TYPE[R2], "digest": {"sha256": _sha(statement_bytes(r2))}}]
        rb["predicate"]["issuedAt"] = "2026-01-11T09:00:00Z"
        records.update({"r4.json": r4_control(), "rb.json": rb})
    return records


def mutate_bundle(records: dict[str, dict[str, Any]], change: dict[str, Any], *,
                  revert: bool = False) -> dict[str, bytes]:
    before = {name: _sha(statement_bytes(r)) for name, r in records.items()}
    changed = dict(records)
    changed[change["record"]] = apply(records[change["record"]], change, revert=revert)
    return relink(changed, before)


# --------------------------------------------------------------------------
# The members


def _r1_members() -> list[dict[str, Any]]:
    base = r1_control()
    p = ["predicate"]
    return _record_set(R1, base, "control: an authorization committed before a pause it bounds",
                       [
        ("1", ["_type"], "https://in-toto.io/Statement/v0.1",
         "the statement is not an in-toto Statement v1"),
        ("2", [*p, "note"], "an extra member", "the predicate carries a member the document "
         "does not define"),
        ("3", [*p, "action", "functions"], ["pause", "quarantine"],
         "a response function the registry does not define"),
        ("4", [*p, "parties", 0, "roles"], ["advised"], "no party holds authorized"),
        ("5", [*p, "parties", 1, "roles"], ["executed"], "no party holds accountable"),
        ("6", [*p, "parties", 0, "authorityBasis"], _ABSENT,
         "the authorizing party carries no authority basis"),
        ("7", [*p, "notAfter"], "2026-01-10T09:00:00Z",
         "the authority lapses before it is given"),
        ("8", [*p, "executedAt"], "2026-01-10T09:55:00Z",
         "committed before execution, yet the action ran before the authorization"),
        ("9", [*p, "executedAt"], "2026-01-10T18:00:01Z",
         "the action ran one second after the authority lapsed"),
        ("10", [*p, "action", "inducedEffects", "observation"], _ABSENT,
         "no induced effects observed, and no observation named"),
    ], [
        ("after-the-fact", {"intentBinding": "asserted_after_execution",
                            "executedAt": "2026-01-10T09:55:00Z"},
         "an authorization asserted after the action ran, recorded as such"),
        ("basis-unknown", {"parties": [
            {"id": PEOPLE + "responder-a", "roles": ["authorized"], "authorityBasis": "unknown"},
            {"id": PEOPLE + "responder-b", "roles": ["accountable", "executed"]}]},
         "the authority basis is stated as unknown rather than left out"),
    ])


def _r2_members(r1_digest: str) -> list[dict[str, Any]]:
    base = r2_control(r1_digest)
    p = ["predicate"]
    creds = base["predicate"]["population"]["credentials"]
    return _record_set(R2, base, "control: a partial sweep whose claim matches its partition", [
        ("1", ["_type"], "https://in-toto.io/Statement/v0.1",
         "the statement is not an in-toto Statement v1"),
        ("2", [*p, "population", "credentials"], [creds[1], creds[0], creds[2]],
         "the population list is not sorted"),
        ("3", [*p, "revocations", 0, "relyingParties", 0, "state"], "acknowledged",
         "a revocation state the registry does not define"),
        ("4", [*p, "partition", 1, "credentials"], [CRED + "c-04"],
         "the parts do not add up to the population"),
        ("5", [*p, "revocations"], [_revocation(creds[0])],
         "a revoked credential has no revocation entry"),
        ("6", [*p, "coverage", "claim"], "complete_verified",
         "complete coverage is claimed while one credential is retained"),
        ("7", [*p, "coverage", "claim"], "issued_after_only",
         "an issued-after claim with no issuedAfter time"),
    ], [
        ("issued-after-only", {"coverage": {"claim": "issued_after_only",
                                            "issuedAfter": "2026-01-09T00:00:00Z"}},
         "an issued-after claim that states its time"),
        ("use-after-revocation", {"revocations": [
            _revocation(creds[0]),
            {**_revocation(creds[1]), "relyingParties": [
                {"id": "https://api.example.org", "state": "use_after_revocation"}]}]},
         "a relying party observed using a credential after its revocation, said plainly"),
    ])


def _r3_members(r1_digest: str, r2_digest: str) -> list[dict[str, Any]]:
    base = r3_control(r1_digest, r2_digest)
    p = ["predicate"]
    return _record_set(R3, base, "control: a staged resumption citing some slots and declaring "
                       "the rest not addressed", [
        ("1", ["_type"], "https://in-toto.io/Statement/v0.1",
         "the statement is not an in-toto Statement v1"),
        ("2", [*p, "approvers", 0, "roles"], ["approver"],
         "an approver role the document does not define"),
        ("3", [*p, "setSufficiency"], "adequate",
         "a set-sufficiency value the registry does not define"),
        ("4", [*p, "evidence", "restoreOrder"], _ABSENT, "an evidence slot is left out"),
        ("5", [*p, "evidence", "residualRisk"], {"notAddressed": ""},
         "a slot declared not addressed with an empty reason"),
        ("6", [*p, "approvers", 0, "roles"], ["accountable"], "no approver holds authorized"),
        ("7", [*p, "restoration", "restoredScope"],
         {"agents": [], "credentials": [], "routes": [], "tools": []},
         "a staged resumption whose scope names nothing"),
        ("8", [*p, "restoration", "decision"], "resume_full",
         "a full resumption that also carries a restored scope"),
    ], [
        ("resume-full", {"restoration": {"decision": "resume_full"}},
         "a full resumption with no restored scope"),
        ("remain-restricted", {"restoration": {"decision": "remain_restricted"},
                               "setSufficiency": "insufficient"},
         "a decision to stay restricted, recorded the same way as a resumption"),
    ])


def _r4_members() -> list[dict[str, Any]]:
    base = r4_control()
    p = ["predicate"]
    parties = base["predicate"]["parties"]
    return _record_set(R4, base, "control: two organisations, each acting on its own assets", [
        ("1", ["_type"], "https://in-toto.io/Statement/v0.1",
         "the statement is not an in-toto Statement v1"),
        ("2", [*p, "parties"], [parties[0]], "only one party"),
        ("4", [*p, "parties", 1, "authorityBasis"], _ABSENT,
         "a party carries no authority basis"),
        ("5", [*p, "parties", 1, "organization"], "https://example.com",
         "both parties belong to one organisation"),
        ("6", [*p, "actions", 0, "asset"], "https://api.example.org",
         "a party acts on an asset assigned to the other party"),
    ], [])


def _rb_members() -> list[dict[str, Any]]:
    base = rb_control()
    p = ["predicate"]
    return _record_set(RB, base, "control: no post-revocation commit seen from the sink side", [
        ("1", ["_type"], "https://in-toto.io/Statement/v0.1",
         "the statement is not an in-toto Statement v1"),
        ("2", [*p, "counts", "attempts"], -1, "a negative count"),
        ("4", [*p, "revocation", "effectiveAt"], "2026-01-10T13:30:00Z",
         "the revocation takes effect after the window ends"),
        ("5", [*p, "counts", "inFlightAtRevocation"], 50,
         "more tasks in flight than attempts"),
        ("6", [*p, "counts", "postRevocationCommits"], 1,
         "a post-revocation commit counted and a result saying none was seen"),
        ("7", [*p, "observer", "vantage"], "agent_side",
         "no post-revocation commit claimed from the agent side"),
    ], [
        ("commit-observed", {"counts": {"attempts": 40, "inFlightAtRevocation": 6,
                                        "postRevocationCommits": 1, "replaysAttempted": 3,
                                        "replaysCommitted": 0},
                             "result": "post_revocation_commit_observed"},
         "a post-revocation commit counted and reported"),
        ("not-established", {"observer": {"id": "https://observer.example.com/agent-log",
                                          "vantage": "agent_side"},
                             "result": "not_established"},
         "an agent-side observer that leaves the result not established"),
    ])


def _record_set(name: str, base: dict[str, Any], control_text: str,
                rejects: list[tuple[str, Path_, Any, str]],
                accepts: list[tuple[str, dict[str, Any], str]]) -> list[dict[str, Any]]:
    codes = dict(checker.RULES[name])
    control_id = f"{name}-control"
    members = [{"id": control_id, "shape": "record", "kind": "accept", "predicate": name,
                "document": checker.DOCUMENT[name], "rule": None,
                "expected": {"verdict": "accept", "reason": checker.ACCEPTED[name]},
                "description": control_text + ".", "statement": base}]
    for suffix, changes, text in accepts:
        statement = copy.deepcopy(base)
        statement["predicate"].update(copy.deepcopy(changes))
        members.append({"id": f"{name}-accept-{suffix}", "shape": "record", "kind": "accept",
                        "predicate": name, "document": checker.DOCUMENT[name], "rule": None,
                        "expected": {"verdict": "accept", "reason": checker.ACCEPTED[name]},
                        "description": f"control: {text}.", "statement": statement})
    for rule, path, new, text in rejects:
        change = mutation(path, base, new)
        members.append({"id": f"{name}-{codes[rule]}", "shape": "record",
                        "kind": "reject", "predicate": name, "document": checker.DOCUMENT[name],
                        "rule": rule, "expected": {"verdict": "reject", "reason": codes[rule]},
                        "description": f"{text}.", "base": control_id, "mutation": change,
                        "statement": apply(base, change)})
    return members


def _bundle_members() -> list[dict[str, Any]]:
    base = bundle_control()
    digests = {name: _sha(statement_bytes(r)) for name, r in base.items()}
    codes = dict(checker.BUNDLE_RULES)
    members = [
        {"id": "bundle-consistent", "shape": "bundle", "kind": "accept", "predicate": None,
         "document": checker.PROFILE, "rule": None,
         "expected": {"verdict": "accept", "reason": checker.BUNDLE_ACCEPTED},
         "description": "control: an R3 with the R1 and R2 it names.",
         "files": relink(base, digests)},
        {"id": "bundle-consistent-with-optional-records", "shape": "bundle", "kind": "accept",
         "predicate": None, "document": checker.PROFILE, "rule": None,
         "expected": {"verdict": "accept", "reason": checker.BUNDLE_ACCEPTED},
         "description": ("control: the same bundle with an R4 naming the incident through "
                         "its related pairs and a revocation-boundary record."),
         "files": {name: statement_bytes(r)
                   for name, r in bundle_control(optional=True).items()}},
    ]
    p = ["predicate"]
    rejects: list[tuple[str, str, str, Path_, Any, str]] = [
        ("B1", "coverage-claim-exceeds-proof", "r2.json", [*p, "coverage", "claim"],
         "complete_verified", "the R2 in the bundle fails its own rule 6"),
        ("B2", codes["B2"], "r3.json", [*p, "predecessors", 1, "digest", "sha256"],
         _sha(b"synthetic restart-records member: a record this bundle does not carry"),
         "the R3 names a predecessor digest no record in the bundle has"),
        ("B3", codes["B3"], "r3.json", [*p, "predecessors", 1, "predicateType"], TYPE[R4],
         "the R3 names the R2's digest under another predicate type"),
        ("B5", codes["B5"], "r2.json", [*p, "incident", "id"], "synthetic-incident-0002",
         "the R2 names another incident"),
        ("B6", codes["B6"], "r3.json", [*p, "issuedAt"], "2026-01-10T13:00:00Z",
         "the R3 is issued before the R2 it names"),
        ("B7", codes["B7"], "r3.json", [*p, "restoration", "restoredScope", "credentials"],
         [CRED + "c-09"], "the R3 restores a credential no R2 in the bundle lists"),
    ]
    for rule, reason, record, path, new, text in rejects:
        change = {"record": record, **mutation(path, base[record], new)}
        members.append({"id": f"bundle-{codes[rule] if rule != 'B1' else 'record-' + reason}",
                        "shape": "bundle", "kind": "reject", "predicate": None,
                        "document": checker.PROFILE, "rule": rule,
                        "expected": {"verdict": "reject", "reason": reason},
                        "description": f"{text}.", "base": "bundle-consistent",
                        "mutation": change, "files": mutate_bundle(base, change)})
    return members


#: Rules no member can force, and why. Each is implemented by the checker.
UNFORCED = [
    {"document": checker.DOCUMENT[R4], "rule": "3", "code": "closed-vocabulary-violation",
     "reason": "no member of this predicate takes a registry-defined value; its closed values "
               "are the document's own and rule 2 checks them"},
    {"document": checker.DOCUMENT[RB], "rule": "3", "code": "closed-vocabulary-violation",
     "reason": "no member of this predicate takes a registry-defined value; its closed values "
               "are the document's own and rule 2 checks them"},
    {"document": checker.PROFILE, "rule": "B4", "code": "predecessor-cycle",
     "reason": "a predecessor is named by the sha256 of its bytes, so a cycle among carried "
               "records needs a sha256 fixed point; B2 refuses any reference that does not "
               "resolve first, and the tests exercise the cycle check directly"},
]


def members() -> list[dict[str, Any]]:
    r1_digest = _sha(statement_bytes(r1_control()))
    r2_digest = _sha(statement_bytes(r2_control(r1_digest)))
    return [*_r1_members(), *_r2_members(r1_digest), *_r3_members(r1_digest, r2_digest),
            *_r4_members(), *_rb_members(), *_bundle_members()]


# --------------------------------------------------------------------------
# Writing


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(manifest: dict[str, Any], root: str = str(ROOT)) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_pretty(entries))


def _index(entries: list[dict[str, Any]], counts: dict[str, int]) -> str:
    rows = [
        "# Restart-records corpus index",
        "",
        "Generated by `gen_vectors.py`; do not edit. Every member is synthetic. One row per "
        "member: the document whose rule it forces, the rule, and the verdict and reason a "
        "conformant checker must report.",
        "",
        "| member | kind | document | rule | reason | case |",
        "|---|---|---|---|---|---|",
    ]
    for e in entries:
        rule = e["rule"] or "control"
        rows.append(f"| `{e['id']}` | {e['kind']} | `{e['document']}` | {rule} | "
                    f"`{e['expected']['reason']}` | {e['description']} |")
    total = counts["accept"] + counts["reject"]
    rows += [
        "",
        f"This corpus is {total} vectors, of which {counts['accept']} a conformant verifier "
        f"must not fail closed on and {counts['reject']} it must reject. Here, not failing "
        "closed means reporting the member's accept reason.",
        "",
    ]
    return "\n".join(rows)


def _spec_pins() -> dict[str, str]:
    paths = [checker.PROFILE, *(checker.DOCUMENT[n] for n in checker.NAMES)]
    return {path: _sha((REPO / path).read_bytes()) for path in paths}


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, MANIFEST.json and INDEX.md, and return the manifest."""
    cases = root / "cases"
    if cases.exists():
        shutil.rmtree(cases)
    entries = []
    for member in members():
        files = member.pop("files", None)
        statement = member.pop("statement", None)
        if files is None:
            files = {"statement.json": statement_bytes(statement)}
        directory = cases / member["id"]
        directory.mkdir(parents=True)
        for name, data in files.items():
            (directory / name).write_bytes(data)
        verdict = (checker.check_bundle_files(files) if member["shape"] == "bundle"
                   else checker.check_record_bytes(files["statement.json"]))
        expected = (member["expected"]["verdict"], member["expected"]["reason"])
        if verdict != expected:
            raise SystemExit(f"{member['id']}: the checker says {verdict}, the case {expected}")
        entries.append({**member, "path": f"cases/{member['id']}",
                        "files": {name: _sha(data) for name, data in sorted(files.items())}})
    counts = {"accept": sum(e["kind"] == "accept" for e in entries),
              "reject": sum(e["kind"] == "reject" for e in entries)}
    manifest = {
        "suite": SUITE,
        "profile": "restoration-evidence/v1",
        "synthetic": True,
        "syntheticNote": SYNTHETIC,
        "predicateTypes": [TYPE[n] for n in checker.NAMES],
        "specDigests": _spec_pins(),
        "specAuthority": ("specDigests pins the profile and predicate documents of this "
                          "repository, proposed text in DRAFT, at the bytes the members were "
                          "generated from."),
        "registryDigest": REGISTRY_DIGEST,
        "checker": "check_vectors.py",
        "verifierContract": ("check_vectors.py --record statement.json | --bundle <directory>; "
                             "prints {verdict, reason}; exit 0 accept, 1 reject"),
        "unforcedRules": UNFORCED,
        "counts": counts,
        "corpusDigest": _sha(_pretty(entries)),
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_pretty(manifest))
    (root / "INDEX.md").write_text(_index(entries, counts), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    generate()
