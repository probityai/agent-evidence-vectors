"""Bind one explicit report identity and optional context without report selection heuristics."""

import re

from json_profile import canonical, digest, integer, object_fields, parse, require, text

SUBJECT_FIELDS = ("kind", "operation_id", "report_id", "report_digest", "sequence")
REPORT_FIELDS = ("kind", "operation_id", "report_id", "sequence", "body")
CONTEXT_FIELDS = (
    "captured_at",
    "context_id",
    "data_scope",
    "model_initiator",
    "proposal_id",
    "runtime",
    "schema_version",
    "subject",
    "tenant_id",
    "tool_call_hash",
)


def declared_fields(value, names):
    object_fields(value, names)
    for name in names:
        text(value[name])


def validate_context(context):
    """Close the frozen context profile; these declarations are not verified authority."""
    object_fields(context, CONTEXT_FIELDS)
    require(context["schema_version"] == "remora-execution-context-v1", "context_schema")
    for name in ("captured_at", "context_id", "proposal_id", "tenant_id"):
        text(context[name])
    object_fields(context["subject"], ("authority", "principal_id"))
    text(context["subject"]["principal_id"])
    object_fields(context["model_initiator"], ("authority", "model_id", "provider"))
    for name in ("model_id", "provider"):
        text(context["model_initiator"][name])
    object_fields(
        context["runtime"],
        (
            "authority",
            "build_provenance_digest",
            "runtime_identity_hash",
        ),
    )
    object_fields(context["data_scope"], ("authority", "ceiling", "classification", "scope"))
    for name in ("ceiling", "classification"):
        text(context["data_scope"][name])
    scope = context["data_scope"]["scope"]
    require(type(scope) is list, "context_scope_array_required")
    for item in scope:
        text(item)
    for name in ("subject", "model_initiator", "runtime", "data_scope"):
        declared_fields(context[name]["authority"], ("evidence_ref", "issuer", "kind"))
    for value in (
        context["tool_call_hash"],
        context["runtime"]["build_provenance_digest"],
        context["runtime"]["runtime_identity_hash"],
    ):
        require(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "context_digest_profile"
        )


def validate_subject(subject):
    object_fields(subject, SUBJECT_FIELDS)
    require(subject["kind"] == "execution_attempt", "report_specific_attempt_required")
    for name in ("operation_id", "report_id"):
        text(subject[name])
    integer(subject["sequence"], 1)
    require(
        type(subject["report_digest"]) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", subject["report_digest"]),
        "report_digest_required",
    )


def held_report(reports, subject):
    validate_subject(subject)
    require(type(reports) is list and len(reports) <= 1024, "invalid_report_population")
    identities, matches = set(), []
    for report in reports:
        object_fields(report, REPORT_FIELDS)
        identity = tuple(report[name] for name in ("kind", "operation_id", "report_id"))
        require(all(type(v) is str and v.strip() for v in identity), "report_identity_required")
        require(identity not in identities, "duplicate_report_identity")
        identities.add(identity)
        integer(report["sequence"], 1)
        require(type(report["body"]) is dict, "report_body_required")
        if digest(canonical(report)) == subject["report_digest"]:
            matches.append(report)
    require(len(matches) == 1, "selected_report_not_held")
    selected = matches[0]
    require(
        all(selected[name] == subject[name] for name in REPORT_FIELDS if name != "body"),
        "selected_report_identity_mismatch",
    )
    return selected


def bound_context(encoded, report, request):
    if encoded is None:
        require(
            request.get("expected_tenant") is None and request.get("expected_principal") is None,
            "expected_context_missing",
        )
        return None
    require(type(encoded) is str, "context_text_required")
    raw = encoded.encode("utf-8")
    context = parse(raw)
    validate_context(context)
    require(canonical(context) == raw, "context_outside_canonical_profile")
    require(
        report["body"].get("execution_context_digest") == digest(raw).removeprefix("sha256:"),
        "context_report_digest_mismatch",
    )
    for expected, actual in (
        ("expected_tenant", context["tenant_id"]),
        ("expected_principal", context["subject"]["principal_id"]),
    ):
        require(
            request.get(expected) is None or request[expected] == actual,
            "context_identity_mismatch",
        )
    return context
