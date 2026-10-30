#!/usr/bin/env python3
"""Write the JSON Schemas for the restoration evidence profile's predicates.

    python3 scripts/gen_restart_records_schemas.py [--check]

Each schema checks the shape and the closed values of one decoded in-toto
Statement. The cross-member rules in each predicate document (a claim wider
than its partition, a result that contradicts its counts) are not expressible
here and belong to the checker in ``vectors-restart-records/``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "spec" / "schemas"
HOST = "https://probityai.github.io/agent-evidence-vectors"
STATEMENT = "https://in-toto.io/Statement/v1"

TIME = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"}
TEXT = {"type": "string", "minLength": 1}
URL = {"type": "string", "pattern": r"^https://[^\s]+$"}
SHA = {
    "type": "object",
    "required": ["sha256"],
    "additionalProperties": False,
    "properties": {"sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
}
COUNT = {"type": "integer", "minimum": 0}


def enum(*values: str) -> dict:
    return {"type": "string", "enum": list(values)}


def obj(required: dict, optional: dict | None = None) -> dict:
    props = dict(required)
    props.update(optional or {})
    return {
        "type": "object",
        "required": sorted(required),
        "additionalProperties": False,
        "properties": props,
    }


def ids(min_items: int = 0) -> dict:
    return {"type": "array", "items": TEXT, "uniqueItems": True, "minItems": min_items}


ROLES = {
    "type": "array",
    "minItems": 1,
    "uniqueItems": True,
    "items": enum("accountable", "advised", "authorized", "executed"),
}
AUTHORITY = enum(
    "contract_third_party", "executive_approval", "policy_preauthorized", "role_grant", "unknown"
)
INDEPENDENCE = enum("independent_sources", "subject_supplied", "undeclared")
REF = obj({"issuer": URL, "id": TEXT})
COMMON = {
    "incident": obj({"issuer": URL, "id": TEXT}, {"related": {"type": "array", "items": REF}}),
    "producer": obj({"id": URL}),
    "issuedAt": TIME,
    "registryDigest": SHA,
    "doesNotAssert": {"type": "array", "items": TEXT},
}
PREDECESSORS = {"type": "array", "minItems": 1, "items": obj({"predicateType": URL, "digest": SHA})}
SLOTS = (
    "actorObjective",
    "affectedScope",
    "assetIntegrity",
    "containmentReproof",
    "controlsNotDegraded",
    "exclusiveControl",
    "incidentReplay",
    "multiPartyAuthorization",
    "ownerConfirmation",
    "persistence",
    "postRestartMonitoring",
    "residualRisk",
    "restoreOrder",
    "restoredAssetsClean",
    "rootCause",
    "seniorApproval",
)
DESCRIPTOR = obj({"digest": SHA}, {"uri": TEXT, "mediaType": TEXT})
SLOT = {"oneOf": [DESCRIPTOR, obj({"notAddressed": TEXT})]}


def predicates() -> dict[str, dict]:
    r1 = obj(
        {
            **COMMON,
            "action": obj(
                {
                    "functions": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": enum(
                            "isolation",
                            "monitoring_increase",
                            "pause",
                            "remediation",
                            "restoration",
                            "restriction",
                        ),
                    },
                    "targets": {"type": "array", "minItems": 1, "items": obj({"id": TEXT})},
                    "inducedEffects": {
                        "oneOf": [
                            obj({"declared": enum("listed"), "items": ids(1)}),
                            obj({"declared": enum("none_observed"), "observation": SHA}),
                            obj({"declared": enum("unknown")}),
                        ]
                    },
                }
            ),
            "parties": {
                "type": "array",
                "minItems": 1,
                "items": obj(
                    {"id": TEXT, "roles": ROLES},
                    {"authorityBasis": AUTHORITY, "independenceBasis": INDEPENDENCE},
                ),
            },
            "authorizedAt": TIME,
            "notAfter": TIME,
            "intentBinding": enum("asserted_after_execution", "committed_before_execution"),
        },
        {
            "executedAt": TIME,
            "pause": obj(
                {
                    "hold": enum(
                        "effect_after_pause",
                        "held",
                        "in_flight_unknown",
                        "not_established",
                        "residual_state_remains",
                    ),
                    "holdProof": SHA,
                }
            ),
        },
    )
    r2 = obj(
        {
            **COMMON,
            "predecessors": PREDECESSORS,
            "population": obj({"credentials": ids(1)}),
            "partition": {
                "type": "array",
                "minItems": 1,
                "items": obj(
                    {"state": enum("retained", "revoked", "unassessed"), "credentials": ids(1)}
                ),
            },
            "revocations": {
                "type": "array",
                "items": obj(
                    {
                        "credential": TEXT,
                        "revokedAt": TIME,
                        "evidence": DESCRIPTOR,
                        "relyingParties": {
                            "type": "array",
                            "items": obj(
                                {
                                    "id": TEXT,
                                    "state": enum(
                                        "enforced_observed",
                                        "issued",
                                        "not_established",
                                        "use_after_revocation",
                                    ),
                                }
                            ),
                        },
                    }
                ),
            },
            "coverage": obj(
                {"claim": enum("complete_verified", "issued_after_only", "partial", "unknown")},
                {"issuedAfter": TIME},
            ),
        }
    )
    r3 = obj(
        {
            **COMMON,
            "predecessors": PREDECESSORS,
            "restoration": obj(
                {
                    "decision": enum(
                        "not_established", "remain_restricted", "resume_full", "resume_staged"
                    )
                },
                {
                    "restoredScope": obj(
                        {k: ids() for k in ("agents", "credentials", "routes", "tools")}
                    )
                },
            ),
            "approvers": {
                "type": "array",
                "items": obj({"id": TEXT, "roles": ROLES, "independenceBasis": INDEPENDENCE}),
            },
            "setSufficiency": enum("insufficient", "not_assessed", "sufficient"),
            "evidence": obj({slot: SLOT for slot in SLOTS}),
        }
    )
    r4 = obj(
        {
            **COMMON,
            "sharedIndicators": {"type": "array", "minItems": 1, "items": SHA},
            "parties": {
                "type": "array",
                "minItems": 2,
                "items": obj(
                    {
                        "id": TEXT,
                        "organization": TEXT,
                        "correlationId": TEXT,
                        "authorityBasis": AUTHORITY,
                        "assets": ids(),
                    }
                ),
            },
        },
        {"actions": {"type": "array", "items": obj({"party": TEXT, "asset": TEXT, "record": SHA})}},
    )
    rb = obj(
        {
            **COMMON,
            "sink": obj(
                {
                    "id": TEXT,
                    "kind": enum(
                        "database", "filesystem", "http_endpoint", "other", "queue", "subprocess"
                    ),
                    "commitBoundary": TEXT,
                }
            ),
            "observer": obj({"id": TEXT, "vantage": enum("agent_side", "sink_side")}),
            "revocation": obj({"credential": TEXT, "effectiveAt": TIME, "timeSource": TEXT}),
            "window": obj({"start": TIME, "end": TIME}),
            "counts": obj(
                {
                    k: COUNT
                    for k in (
                        "attempts",
                        "inFlightAtRevocation",
                        "postRevocationCommits",
                        "replaysAttempted",
                        "replaysCommitted",
                    )
                }
            ),
            "exclusions": {"type": "array", "items": obj({"count": COUNT, "reason": TEXT})},
            "result": enum(
                "no_post_revocation_commit_observed",
                "not_established",
                "post_revocation_commit_observed",
            ),
        },
        {"predecessors": PREDECESSORS},
    )
    return {
        "incident-action-authorization": r1,
        "revocation-sweep": r2,
        "re-enable-decision": r3,
        "joint-authority": r4,
        "revocation-boundary": rb,
    }


def schema(name: str, predicate: dict) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{HOST}/schema/{name}/v1",
        "title": f"{name} v1 statement",
        "description": (
            f"Shape and closed values of a decoded statement of {HOST}/predicate/"
            f"v1/{name}. Cross-member rules need the checker."
        ),
        "type": "object",
        "required": ["_type", "subject", "predicateType", "predicate"],
        "additionalProperties": False,
        "properties": {
            "_type": {"const": STATEMENT},
            "subject": {
                "type": "array",
                "minItems": 1,
                "items": obj({"digest": SHA}, {"name": TEXT}),
            },
            "predicateType": {"const": f"{HOST}/predicate/v1/{name}"},
            "predicate": predicate,
        },
    }


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for name, predicate in predicates().items():
        path = HERE / f"{name}-v1.schema.json"
        text = json.dumps(schema(name, predicate), indent=2, sort_keys=True) + "\n"
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(path.name)
        else:
            path.write_text(text, encoding="utf-8")
    if stale:
        print("FAIL: regenerate " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
