#!/usr/bin/env python3
"""Build the frozen evaluation-claim corpus: profiles, case sets, rules and cases.

Every case is one record (bare, or as the predicate of an in-toto Statement)
judged under one acceptance rule. Positive cases start from one of two base
records and change what the case is about. Each negative case starts from a base
record and makes exactly one change, its defect; the case carries ``repair``, the
JSON operations that undo that change, and the tests prove that the repaired
record is admitted. A negative that still refuses after its repair would be
refusing for some reason other than the one it names.

    python scripts/claim-record-build.py           # write the corpus
    python scripts/claim-record-build.py --check   # exit 1 if it differs
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

from agent_evidence_vectors.claim_record.ops import apply_ops, mutate  # noqa: E402
from agent_evidence_vectors.claim_record.reader import (  # noqa: E402
    CASE_SET_SCHEMA,
    CLAIM_TYPE,
    COORDINATES,
    PROFILE_SCHEMA,
    RULE_SCHEMA,
    STATEMENT_TYPE,
    digest_of,
)

CORPUS = PACKAGING / "agent_evidence_vectors/claim_record/corpus"


def _fixed_digest(label: str) -> str:
    """A stand-in digest from a published recipe, so the corpus rebuilds byte for byte."""
    return "sha256:" + hashlib.sha256(f"aev-claim-record/{label}/v1".encode()).hexdigest()


# --- profiles -----------------------------------------------------------------

BASE_IMMUTABLE = [
    "applicability.case_set",
    "bytes.implementation",
    "bytes.case_set",
    "bytes.verifier",
]
PROFILES = {
    "conformance": {
        "schema": PROFILE_SCHEMA,
        "id": "conformance/v1",
        "description": (
            "A conformance run: an implementation against a pinned case set. No authority "
            "is exercised and no side-effecting action is taken, so epoch and settlement "
            "may be not applicable under the named reasons and no other."
        ),
        "coordinates": list(COORDINATES),
        "not_applicable": {
            "epoch": ["no_authority_exercised"],
            "settlement": ["no_side_effecting_actions"],
        },
        "immutable_references": BASE_IMMUTABLE,
        "exclusion_reasons": ["optional_feature_not_claimed"],
    },
    "execution": {
        "schema": PROFILE_SCHEMA,
        "id": "execution/v1",
        "description": (
            "An evaluation that takes side-effecting actions under delegated authority. "
            "Every coordinate carries a value, and every settled action is bound to its "
            "evidence by digest."
        ),
        "coordinates": list(COORDINATES),
        "not_applicable": {},
        "immutable_references": [*BASE_IMMUTABLE, "settlement.actions[].evidence"],
        "exclusion_reasons": ["optional_feature_not_claimed"],
    },
}


def _profile_ref(name: str) -> dict[str, str]:
    return {"id": PROFILES[name]["id"], "digest": digest_of(PROFILES[name])}


# --- case sets ----------------------------------------------------------------


def _case_set(name: str, revision: str, cases: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "schema": CASE_SET_SCHEMA,
        "name": name,
        "revision": revision,
        "cases": [{"id": cid, "requirement": req} for cid, req in cases],
    }


R1 = _case_set(
    "sample-conformance",
    "1",
    [("c1", "required"), ("c2", "required"), ("c3", "required"), ("c4", "optional")],
)
R2 = _case_set(
    "sample-conformance",
    "2",
    [
        ("c1", "required"),
        ("c2", "required"),
        ("c3", "required"),
        ("c4", "optional"),
        ("c5", "required"),
    ],
)
#: Revision 3 is accepted by the rule but its bytes are not shipped: a record that
#: names it cannot be resolved offline, and is refused rather than read as clean.
R3_UNSHIPPED = _case_set("sample-conformance", "3", [("c1", "required")])
#: A producer's own reduced set that drops a required case. The rule never accepts it.
REDUCED = _case_set(
    "sample-conformance-reduced", "2", [("c1", "required"), ("c2", "required"), ("c4", "optional")]
)
EMPTY = _case_set("empty-suite", "1", [])
CASE_SETS = {"sample-r1": R1, "sample-r2": R2, "sample-reduced": REDUCED, "empty": EMPTY}


def _cs_ref(case_set: dict[str, Any], name: str | None = None) -> dict[str, str]:
    return {
        "name": name or f"{case_set['name']}@{case_set['revision']}",
        "digest": digest_of(case_set),
    }


# --- acceptance rules ---------------------------------------------------------


def _rule(rid: str, profile: str, case_sets: list[dict[str, Any]], vantage: list[str]) -> dict:
    return {
        "schema": RULE_SCHEMA,
        "id": rid,
        "profile": _profile_ref(profile),
        "case_sets": [digest_of(cs) for cs in case_sets],
        "accept_vantage": vantage,
    }


#: A stricter profile whose bytes are not shipped. A rule that pins it cannot be
#: applied offline until the relying party supplies those bytes.
UNSHIPPED_PROFILE = {
    **PROFILES["conformance"],
    "id": "conformance-strict/v1",
    "exclusion_reasons": [],
}

RULES = {
    "conformance": _rule(
        "sample-conformance-substrate", "conformance", [R2, R1, R3_UNSHIPPED], ["substrate"]
    ),
    "conformance-self-report": _rule(
        "sample-conformance-any-vantage", "conformance", [R2], ["substrate", "artifact"]
    ),
    "execution": _rule("sample-execution-substrate", "execution", [R2], ["substrate"]),
    "empty-suite": _rule("empty-suite-substrate", "conformance", [EMPTY], ["substrate"]),
    "unshipped-profile": {
        "schema": RULE_SCHEMA,
        "id": "sample-conformance-strict",
        "profile": {"id": UNSHIPPED_PROFILE["id"], "digest": digest_of(UNSHIPPED_PROFILE)},
        "case_sets": [digest_of(R2)],
        "accept_vantage": ["substrate"],
    },
}

# --- base records -------------------------------------------------------------

IMPLEMENTATION = {"name": "example-implementation", "digest": _fixed_digest("implementation")}
VERIFIER = {"name": "example-verifier", "digest": _fixed_digest("verifier")}
R2_IDS = [c["id"] for c in R2["cases"]]


def _record(profile: str, verdict: str, coordinates: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_type": CLAIM_TYPE,
        "profile": _profile_ref(profile),
        "verdict": verdict,
        "coordinates": coordinates,
    }


def _coords(case_set: dict[str, Any], passed: list[str]) -> dict[str, Any]:
    ids = [c["id"] for c in case_set["cases"]]
    return {
        "applicability": {
            "state": "value",
            "case_set": _cs_ref(case_set),
            "applicable": ids,
            "excluded": [],
        },
        "population": {
            "state": "value",
            "coverage_denominator": len(ids),
            "passed": passed,
            "failed": [],
            "not_run": [],
        },
        "vantage": {
            "state": "value",
            "observation_vantage": "substrate",
            "observer": "ci-runner-outside-the-implementation",
        },
        "bytes": {
            "state": "value",
            "implementation": dict(IMPLEMENTATION),
            "case_set": _cs_ref(case_set),
            "verifier": dict(VERIFIER),
        },
        "epoch": {"state": "not_applicable", "reason": "no_authority_exercised"},
        "settlement": {"state": "not_applicable", "reason": "no_side_effecting_actions"},
    }


def _evidence(label: str) -> dict[str, str]:
    return {"name": f"evidence/{label}", "digest": _fixed_digest(f"evidence/{label}")}


BASE_CONF = _record("conformance", "pass", _coords(R2, list(R2_IDS)))
BASE_EXEC = _record("execution", "pass", _coords(R2, list(R2_IDS)))
BASE_EXEC["coordinates"]["epoch"] = {"state": "value", "initial": "e1", "transitions": []}
BASE_EXEC["coordinates"]["settlement"] = {
    "state": "value",
    "actions": [
        {"id": "a1", "epoch": "e1", "outcome": "committed", "evidence": _evidence("a1")},
        {"id": "a2", "epoch": "e1", "outcome": "not_run", "evidence": _evidence("a2")},
    ],
}


def _statement(record: dict[str, Any], subject_digest: str) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "example-implementation", "digest": {"sha256": subject_digest[7:]}}],
        "predicateType": CLAIM_TYPE,
        "predicate": record,
    }


BASE_STMT = _statement(BASE_CONF, IMPLEMENTATION["digest"])
BASES = {"conformance": BASE_CONF, "execution": BASE_EXEC, "statement": BASE_STMT}
BASE_RULE = {"conformance": "conformance", "execution": "execution", "statement": "conformance"}

A = "ADMITTED"
R = "REFUSED"
C = ("coordinates",)


def _pos(cid, about, description, rule, record, verdict):
    return {
        "id": cid,
        "kind": "positive",
        "about": about,
        "description": description,
        "rule": rule,
        "record": record,
        "expected": {"result": A, "verdict": verdict, "reasons": []},
    }


def _neg(cid, about, description, base, ops, code, rule=None):
    record, repair = mutate(BASES[base], ops)
    return {
        "id": cid,
        "kind": "negative",
        "about": about,
        "description": description,
        "rule": rule or BASE_RULE[base],
        "base": base,
        "record": record,
        "repair": repair,
        "expected": {"result": R, "verdict": None, "reasons": [code]},
    }


def _set(path, value):
    return {"op": "set", "path": list(path), "value": value}


def _del(path):
    return {"op": "del", "path": list(path)}


def _positives() -> list[dict[str, Any]]:
    out = [
        _pos(
            "conformance-full-pass",
            "population",
            "Every applicable case ran and passed.",
            "conformance",
            BASE_CONF,
            "pass",
        ),
        _pos(
            "execution-settled",
            "settlement",
            "Every action carries a resolved outcome bound to its evidence, under the live epoch.",
            "execution",
            BASE_EXEC,
            "pass",
        ),
        _pos(
            "statement-wrapped",
            "bytes",
            "The record rides as the predicate of an in-toto Statement whose subject is the "
            "implementation the bytes coordinate binds.",
            "conformance",
            BASE_STMT,
            "pass",
        ),
    ]

    rec = copy.deepcopy(BASE_CONF)
    pop = rec["coordinates"]["population"]
    pop["passed"], pop["not_run"] = ["c1", "c2", "c3"], ["c4", "c5"]
    rec["verdict"] = "incomplete"
    out.append(
        _pos(
            "incomplete-lists-not-run",
            "population",
            "Two cases did not run; they are listed as not run and the verdict says so.",
            "conformance",
            rec,
            "incomplete",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    pop = rec["coordinates"]["population"]
    pop["passed"], pop["failed"] = ["c1", "c2", "c4", "c5"], ["c3"]
    rec["verdict"] = "fail"
    out.append(
        _pos(
            "fail-stated-honestly",
            "population",
            "One case failed, and the verdict is fail.",
            "conformance",
            rec,
            "fail",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    app = rec["coordinates"]["applicability"]
    app["applicable"] = ["c1", "c2", "c3", "c5"]
    app["excluded"] = [{"id": "c4", "reason": "optional_feature_not_claimed"}]
    pop = rec["coordinates"]["population"]
    pop["coverage_denominator"], pop["passed"] = 4, ["c1", "c2", "c3", "c5"]
    out.append(
        _pos(
            "optional-case-excluded",
            "applicability",
            "The optional case is excluded under the reason the profile authorises.",
            "conformance",
            rec,
            "pass",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    ids = [c["id"] for c in R1["cases"]]
    rec["coordinates"] = _coords(R1, ids)
    out.append(
        _pos(
            "historical-case-set-revision",
            "bytes",
            "The record binds revision 1 by digest. Revision 2 supersedes its name, and the "
            "rule still accepts the old bytes: a superseded name never voids an immutable "
            "revision.",
            "conformance",
            rec,
            "pass",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    rec["coordinates"] = _coords(R1, ids)
    for key in ("applicability", "bytes"):
        rec["coordinates"][key]["case_set"] = {
            "name": "sample-conformance@latest",
            "alias": "latest",
            "digest": digest_of(R1),
        }
    out.append(
        _pos(
            "alias-locates-old-bytes",
            "bytes",
            "The reference carries the alias 'latest', which now names revision 2, and the "
            "digest of revision 1. The digest decides; an alias locates bytes and never "
            "replaces them.",
            "conformance",
            rec,
            "pass",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    rec["coordinates"]["bytes"]["related"] = [
        {"name": "run-log", "uri": "https://example.invalid/runs/latest"}
    ]
    out.append(
        _pos(
            "related-reference-by-tag",
            "bytes",
            "A reference the profile does not hold to byte identity may be a tag or URL: "
            "the referential pin refusal is narrow.",
            "conformance",
            rec,
            "pass",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    rec["coordinates"]["vantage"]["observation_vantage"] = "artifact"
    rec["coordinates"]["vantage"]["observer"] = "the-implementation-itself"
    out.append(
        _pos(
            "self-report-accepted-by-rule",
            "vantage",
            "An artifact-vantage record under a rule that accepts self-report.",
            "conformance-self-report",
            rec,
            "pass",
        )
    )

    rec = copy.deepcopy(BASE_CONF)
    rec["coordinates"]["epoch"] = {"state": "value", "initial": "e1", "transitions": []}
    out.append(
        _pos(
            "epoch-valued-where-optional",
            "epoch",
            "A conformance record may state its epoch even where it could be not applicable.",
            "conformance",
            rec,
            "pass",
        )
    )

    for kind, label in (
        ("revocation", "revoked-after-settlement"),
        ("suspension", "suspended-after-settlement"),
        ("consumption", "approval-consumed-then-renewed"),
    ):
        rec = copy.deepcopy(BASE_EXEC)
        rec["coordinates"]["epoch"]["transitions"] = [
            {"after_action": "a1", "from": "e1", "to": "e2", "kind": kind}
        ]
        rec["coordinates"]["settlement"]["actions"][1]["epoch"] = "e2"
        out.append(
            _pos(
                f"epoch-{label}",
                "epoch",
                f"A {kind} after a1, which settled under e1; a2 then acts under e2.",
                "execution",
                rec,
                "pass",
            )
        )

    rec = copy.deepcopy(EMPTY_INCOMPLETE)
    out.append(
        _pos(
            "empty-suite-incomplete",
            "population",
            "A case set with no cases: nothing applied, and the verdict is incomplete, never pass.",
            "empty-suite",
            rec,
            "incomplete",
        )
    )
    return out


EMPTY_INCOMPLETE = _record("conformance", "incomplete", _coords(EMPTY, []))


def _negatives() -> list[dict[str, Any]]:
    app, pop, vant = C + ("applicability",), C + ("population",), C + ("vantage",)
    byt, ep, st = C + ("bytes",), C + ("epoch",), C + ("settlement",)
    na = {"state": "not_applicable", "reason": "no_side_effecting_actions"}
    red_ids = [c["id"] for c in REDUCED["cases"]]
    out = [
        # MALFORMED_RECORD
        _neg(
            "claim-type-other",
            "envelope",
            "The record names another claim type.",
            "conformance",
            [_set(("claim_type",), "https://example.invalid/other-claim")],
            "MALFORMED_RECORD",
        ),
        _neg(
            "coordinate-state-invented",
            "envelope",
            "A coordinate state outside the defined set.",
            "conformance",
            [_set(vant + ("state",), "assumed")],
            "MALFORMED_RECORD",
        ),
        _neg(
            "coordinate-key-unknown",
            "envelope",
            "An undefined coordinate in the envelope.",
            "conformance",
            [_set(C + ("confidence",), {"state": "value"})],
            "MALFORMED_RECORD",
        ),
        _neg(
            "statement-predicate-type-other",
            "envelope",
            "The Statement names another predicate type.",
            "statement",
            [_set(("predicateType",), "https://example.invalid/other-claim")],
            "MALFORMED_RECORD",
        ),
        # PROFILE_MISMATCH
        _neg(
            "producer-selects-weaker-profile",
            "profile",
            "The rule pins the execution profile; the record names the conformance profile.",
            "execution",
            [_set(("profile",), _profile_ref("conformance"))],
            "PROFILE_MISMATCH",
        ),
        # MISSING_COORDINATE, one per coordinate
        *[
            _neg(
                f"missing-{coord}",
                coord,
                f"The {coord} coordinate is absent.",
                "execution",
                [_del(C + (coord,))],
                "MISSING_COORDINATE",
            )
            for coord in COORDINATES
        ],
        # UNRESOLVED_COORDINATE
        _neg(
            "vantage-unknown",
            "vantage",
            "Vantage is unknown.",
            "conformance",
            [_set(vant, {"state": "unknown"})],
            "UNRESOLVED_COORDINATE",
        ),
        _neg(
            "settlement-unresolved-state",
            "settlement",
            "Settlement as a whole is unresolved.",
            "execution",
            [_set(st, {"state": "unresolved"})],
            "UNRESOLVED_COORDINATE",
        ),
        _neg(
            "bytes-failed",
            "bytes",
            "Byte binding failed and is carried as failed.",
            "conformance",
            [_set(byt, {"state": "failed"})],
            "UNRESOLVED_COORDINATE",
        ),
        # UNAUTHORISED_NOT_APPLICABLE
        _neg(
            "execution-settlement-not-applicable",
            "settlement",
            "A lost-response producer labels settlement not applicable; the execution profile "
            "authorises no such reason.",
            "execution",
            [_set(st, na)],
            "UNAUTHORISED_NOT_APPLICABLE",
        ),
        _neg(
            "epoch-not-applicable-unlisted-reason",
            "epoch",
            "Epoch is not applicable under a reason the profile does not list.",
            "conformance",
            [_set(ep, {"state": "not_applicable", "reason": "not_tracked"})],
            "UNAUTHORISED_NOT_APPLICABLE",
        ),
        _neg(
            "population-not-applicable",
            "population",
            "Population is labelled not applicable; no profile authorises that.",
            "conformance",
            [_set(pop, {"state": "not_applicable", "reason": "no_side_effecting_actions"})],
            "UNAUTHORISED_NOT_APPLICABLE",
        ),
        _neg(
            "epoch-not-applicable-while-acting",
            "epoch",
            "The record takes actions and says no authority was exercised.",
            "conformance",
            [_set(st, copy.deepcopy(BASE_EXEC["coordinates"]["settlement"]))],
            "UNAUTHORISED_NOT_APPLICABLE",
        ),
        # INVALID_REFERENTIAL_PIN
        _neg(
            "implementation-by-tag",
            "bytes",
            "The implementation is named by a mutable tag, with no digest.",
            "conformance",
            [
                _set(
                    byt + ("implementation",),
                    {"name": "example-implementation", "uri": "oci://example.invalid/impl:latest"},
                )
            ],
            "INVALID_REFERENTIAL_PIN",
        ),
        _neg(
            "verifier-digest-short",
            "bytes",
            "The verifier digest is truncated.",
            "conformance",
            [_set(byt + ("verifier", "digest"), VERIFIER["digest"][:19])],
            "INVALID_REFERENTIAL_PIN",
        ),
        _neg(
            "case-set-by-alias-only",
            "applicability",
            "The case set is located by an alias with no digest.",
            "conformance",
            [
                _set(app + ("case_set",), {"name": "sample-conformance", "alias": "latest"}),
                _set(byt + ("case_set",), {"name": "sample-conformance", "alias": "latest"}),
            ],
            "INVALID_REFERENTIAL_PIN",
        ),
        _neg(
            "settlement-evidence-by-url",
            "settlement",
            "Settlement evidence is a URL; the execution profile requires its bytes.",
            "execution",
            [_set(st + ("actions", 0, "evidence"), {"uri": "https://example.invalid/a1"})],
            "INVALID_REFERENTIAL_PIN",
        ),
        # CASE_SET_NOT_ACCEPTED, CASE_SET_UNRESOLVED
        _neg(
            "producer-reduced-case-set",
            "applicability",
            "The producer binds its own reduced case set, which drops a required case.",
            "conformance",
            [
                _set(app + ("case_set",), _cs_ref(REDUCED)),
                _set(byt + ("case_set",), _cs_ref(REDUCED)),
                _set(app + ("applicable",), red_ids),
                _set(pop + ("passed",), red_ids),
                _set(pop + ("coverage_denominator",), len(red_ids)),
            ],
            "CASE_SET_NOT_ACCEPTED",
        ),
        _neg(
            "case-set-bytes-not-supplied",
            "applicability",
            "The rule accepts revision 3, whose bytes were not supplied.",
            "conformance",
            [
                _set(app + ("case_set",), _cs_ref(R3_UNSHIPPED)),
                _set(byt + ("case_set",), _cs_ref(R3_UNSHIPPED)),
            ],
            "CASE_SET_UNRESOLVED",
        ),
        # APPLICABILITY_MISMATCH
        _neg(
            "required-case-excluded",
            "applicability",
            "A required case is excluded so its failure never counts.",
            "conformance",
            [
                _set(app + ("applicable",), ["c1", "c2", "c4", "c5"]),
                _set(app + ("excluded",), [{"id": "c3", "reason": "optional_feature_not_claimed"}]),
                _set(pop + ("passed",), ["c1", "c2", "c4", "c5"]),
                _set(pop + ("coverage_denominator",), 4),
            ],
            "APPLICABILITY_MISMATCH",
        ),
        _neg(
            "case-dropped-from-applicability",
            "applicability",
            "A case of the set is neither applicable nor excluded.",
            "conformance",
            [
                _set(app + ("applicable",), ["c1", "c2", "c3", "c4"]),
                _set(pop + ("passed",), ["c1", "c2", "c3", "c4"]),
                _set(pop + ("coverage_denominator",), 4),
            ],
            "APPLICABILITY_MISMATCH",
        ),
        _neg(
            "exclusion-reason-unlisted",
            "applicability",
            "The optional case is excluded under a reason the profile does not list.",
            "conformance",
            [
                _set(app + ("applicable",), ["c1", "c2", "c3", "c5"]),
                _set(app + ("excluded",), [{"id": "c4", "reason": "flaky"}]),
                _set(pop + ("passed",), ["c1", "c2", "c3", "c5"]),
                _set(pop + ("coverage_denominator",), 4),
            ],
            "APPLICABILITY_MISMATCH",
        ),
        # POPULATION_MISMATCH
        _neg(
            "case-missing-from-results",
            "population",
            "One applicable case appears in no result list, and the denominator still counts it.",
            "conformance",
            [_set(pop + ("passed",), ["c1", "c2", "c3", "c4"])],
            "POPULATION_MISMATCH",
        ),
        _neg(
            "case-listed-twice",
            "population",
            "A case is both passed and failed.",
            "conformance",
            [_set(pop + ("failed",), ["c3"])],
            "POPULATION_MISMATCH",
        ),
        _neg(
            "unexpected-case-in-results",
            "population",
            "The results name a case the case set does not hold.",
            "conformance",
            [_set(pop + ("passed",), [*R2_IDS, "c9"]), _set(pop + ("coverage_denominator",), 6)],
            "POPULATION_MISMATCH",
        ),
        _neg(
            "denominator-drops-not-run",
            "population",
            "The denominator counts only the cases that ran.",
            "conformance",
            [
                _set(pop + ("passed",), ["c1", "c2", "c3"]),
                _set(pop + ("not_run",), ["c4", "c5"]),
                _set(pop + ("coverage_denominator",), 3),
                _set(("verdict",), "incomplete"),
            ],
            "POPULATION_MISMATCH",
        ),
        # ABSENCE_READ_AS_CLEAN
        _neg(
            "not-run-read-as-pass",
            "population",
            "Two cases did not run and the verdict is pass.",
            "conformance",
            [_set(pop + ("passed",), ["c1", "c2", "c3"]), _set(pop + ("not_run",), ["c4", "c5"])],
            "ABSENCE_READ_AS_CLEAN",
        ),
        # VERDICT_CONTRADICTED
        _neg(
            "failure-read-as-pass",
            "population",
            "A case failed and the verdict is pass.",
            "conformance",
            [_set(pop + ("passed",), ["c1", "c2", "c4", "c5"]), _set(pop + ("failed",), ["c3"])],
            "VERDICT_CONTRADICTED",
        ),
        _neg(
            "incomplete-with-nothing-missing",
            "population",
            "Every case ran and passed, and the verdict says incomplete.",
            "conformance",
            [_set(("verdict",), "incomplete")],
            "VERDICT_CONTRADICTED",
        ),
        # VANTAGE_NOT_ACCEPTED
        _neg(
            "self-report-under-substrate-rule",
            "vantage",
            "The implementation observed itself; the rule accepts only substrate vantage.",
            "conformance",
            [
                _set(vant + ("observation_vantage",), "artifact"),
                _set(vant + ("observer",), "the-implementation-itself"),
            ],
            "VANTAGE_NOT_ACCEPTED",
        ),
        # BYTES_MISMATCH
        _neg(
            "bytes-bind-other-case-set",
            "bytes",
            "Applicability resolves revision 2 and the bytes coordinate binds revision 1.",
            "conformance",
            [_set(byt + ("case_set",), _cs_ref(R1))],
            "BYTES_MISMATCH",
        ),
        _neg(
            "statement-subject-other-implementation",
            "bytes",
            "The Statement's subject is not the implementation the claim binds.",
            "statement",
            [_set(("subject", 0, "digest", "sha256"), _fixed_digest("other-implementation")[7:])],
            "BYTES_MISMATCH",
        ),
        # STALE_EPOCH
        _neg(
            "acts-after-revocation",
            "epoch",
            "Authority is revoked after a1, and a2 still acts under the revoked epoch.",
            "execution",
            [
                _set(
                    ep + ("transitions",),
                    [{"after_action": "a1", "from": "e1", "to": "e2", "kind": "revocation"}],
                )
            ],
            "STALE_EPOCH",
        ),
        _neg(
            "consumed-approval-presented-again",
            "epoch",
            "a1 consumes a single-use approval, and a2 presents the same approval.",
            "execution",
            [
                _set(
                    ep + ("transitions",),
                    [{"after_action": "a1", "from": "e1", "to": "e2", "kind": "consumption"}],
                )
            ],
            "STALE_EPOCH",
        ),
        _neg(
            "suspended-agent-acts",
            "epoch",
            "The agent is suspended after a1, and a2 acts under the pre-suspension epoch.",
            "execution",
            [
                _set(
                    ep + ("transitions",),
                    [{"after_action": "a1", "from": "e1", "to": "e2", "kind": "suspension"}],
                )
            ],
            "STALE_EPOCH",
        ),
        # UNSETTLED_OUTCOME
        _neg(
            "lost-reply-unresolved",
            "settlement",
            "a2's reply was lost and its outcome is unresolved.",
            "execution",
            [
                _set(st + ("actions", 1, "outcome"), "unresolved"),
                _del(st + ("actions", 1, "evidence")),
            ],
            "UNSETTLED_OUTCOME",
        ),
        _neg(
            "committed-without-evidence",
            "settlement",
            "a1 says committed and binds no evidence.",
            "execution",
            [_del(st + ("actions", 0, "evidence"))],
            "UNSETTLED_OUTCOME",
        ),
        # UNSETTLED_ACROSS_EPOCH (the cross-coordinate case)
        _neg(
            "unresolved-across-revocation",
            "epoch+settlement",
            "a1 is unresolved when authority is revoked after it; a2 acts under the new epoch.",
            "execution",
            [
                _set(st + ("actions", 0, "outcome"), "unresolved"),
                _del(st + ("actions", 0, "evidence")),
                _set(
                    ep + ("transitions",),
                    [{"after_action": "a1", "from": "e1", "to": "e2", "kind": "revocation"}],
                ),
                _set(st + ("actions", 1, "epoch"), "e2"),
            ],
            "UNSETTLED_ACROSS_EPOCH",
        ),
    ]
    # PROFILE_UNRESOLVED: the rule pins a profile whose bytes were not supplied. The
    # repair returns to a rule whose profile ships, and to that profile's name.
    unres = _neg(
        "profile-bytes-not-supplied",
        "profile",
        "The rule pins a stricter profile whose bytes the verifier was not given; the "
        "record cannot be judged, so it is refused, never read as clean.",
        "conformance",
        [_set(("profile",), dict(RULES["unshipped-profile"]["profile"]))],
        "PROFILE_UNRESOLVED",
        rule="unshipped-profile",
    )
    unres["repair_rule"] = "conformance"
    out.append(unres)
    # ABSENCE_READ_AS_CLEAN on an empty suite: nothing applied and the verdict is pass.
    out.append(
        _neg_from(
            EMPTY_INCOMPLETE,
            "empty-suite-read-as-pass",
            "population",
            "The case set holds no cases, and the verdict is pass.",
            "empty-suite",
            [_set(("verdict",), "pass")],
            "ABSENCE_READ_AS_CLEAN",
        )
    )
    return out


def _neg_from(base, cid, about, description, rule, ops, code):
    record, repair = mutate(base, ops)
    return {
        "id": cid,
        "kind": "negative",
        "about": about,
        "description": description,
        "rule": rule,
        "base": "empty-suite",
        "record": record,
        "repair": repair,
        "expected": {"result": R, "verdict": None, "reasons": [code]},
    }


def build() -> dict[str, bytes]:
    files: dict[str, Any] = {}
    for name, profile in PROFILES.items():
        files[f"profiles/{name}.json"] = profile
    for name, case_set in CASE_SETS.items():
        files[f"case-sets/{name}.json"] = case_set
    for name, rule in RULES.items():
        files[f"rules/{name}.json"] = rule
    cases = _positives() + _negatives()
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "case ids are distinct"
    # Every negative's repair must restore its base exactly; the test re-proves it.
    for case in cases:
        if case["kind"] == "negative":
            base = EMPTY_INCOMPLETE if case["base"] == "empty-suite" else BASES[case["base"]]
            assert apply_ops(case["record"], case["repair"]) == base, case["id"]
    files["cases.json"] = {
        "schema": "aev-claim-record-cases/v1",
        "claim_type": CLAIM_TYPE,
        "bases": {
            "conformance": BASE_CONF,
            "execution": BASE_EXEC,
            "statement": BASE_STMT,
            "empty-suite": EMPTY_INCOMPLETE,
        },
        "cases": cases,
    }
    out = {name: _dump(value) for name, value in files.items()}
    out["manifest.json"] = _dump(
        {
            "schema": "aev-claim-record-manifest/v1",
            "members": {
                name: "sha256:" + hashlib.sha256(data).hexdigest()
                for name, data in sorted(out.items())
            },
        }
    )
    return out


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


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
            print(f"claim-record corpus differs from the builder: {stale}", file=sys.stderr)
            return 1
        return 0
    for name, data in built.items():
        path = CORPUS / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
