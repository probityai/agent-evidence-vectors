"""Inspect the frozen M1 binding; native claim meanings and TRACE conformance remain unjudged."""

from binding import bound_context, held_report, validate_subject
from json_profile import Refusal, integer, object_fields, require, shape, text
from signature import verify_envelope

MISSING = ("subject", "runtime", "policy", "data_class", "build_provenance", "cnf")


def validate_request(request):
    object_fields(
        request,
        ("subject", "native_claim", "issued_at", "ingested_at", "producer"),
        ("resolver", "retention", "expected_tenant", "expected_principal"),
    )
    text(request["native_claim"])
    text(request["producer"])
    integer(request["issued_at"], 1_700_000_000)
    integer(request["ingested_at"], 1_700_000_000)
    require(request["ingested_at"] <= request["issued_at"], "ingestion_after_issuance")
    if request.get("resolver") is not None:
        text(request["resolver"])
    if request.get("retention") is not None:
        require(request.get("resolver") is not None, "retention_without_resolver")
        require(request["retention"] == "P1Y", "retention_outside_frozen_profile")


def inspect(input_document):
    shape(input_document)
    object_fields(
        input_document, ("evidence_b64", "execution_context", "reports", "request", "trusted_keys")
    )
    request = input_document["request"]
    validate_request(request)
    report = held_report(input_document["reports"], request["subject"])
    document, evidence_digest, kid = verify_envelope(
        input_document["evidence_b64"], input_document["trusted_keys"]
    )
    object_fields(
        document,
        ("schema_version", "native_claim", "subject", "evidence_selection", "native_result"),
    )
    require(document["schema_version"] == "remora-federation-result-v1", "result_schema")
    require(document["native_claim"] == request["native_claim"], "native_claim_mismatch")
    validate_subject(document["subject"])
    require(document["subject"] == request["subject"], "signed_subject_mismatch")
    selection = document["evidence_selection"]
    object_fields(selection, ("eligible", "selected_digest", "selected_ref", "selection_rule"))
    integer(selection["eligible"], 1)
    require(
        selection["selected_digest"] == request["subject"]["report_digest"],
        "selection_digest_mismatch",
    )
    require(
        selection["selected_ref"] == request["subject"]["report_id"], "selection_identity_mismatch"
    )
    require(selection["selection_rule"] == "explicit_digest", "selection_rule_outside_profile")
    native = document["native_result"]
    object_fields(native, ("status", "reason_code", "vocabulary"))
    for value in native.values():
        text(value)
    context = bound_context(input_document["execution_context"], report, request)
    return {
        "decision": "BOUND",
        "native_claim": document["native_claim"],
        "native_result": native,
        "subject": document["subject"],
        "evidence_selection": selection,
        "result_evidence_digest": evidence_digest,
        "result_signer_kid": kid,
        "bound_context": context,
        "missing_trace_required": sorted(MISSING + (() if context is not None else ("model",))),
        "claim_ceiling": {
            "trace_trust_record": False,
            "trace_conformance_level": None,
            "native_result_re_evaluated": False,
            "workload_identity_verified": False,
            "authority_verified": False,
            "effects_verified": False,
        },
    }


def read(input_document):
    try:
        return inspect(input_document)
    except Refusal as exc:
        return {"decision": "REFUSED", "reason": str(exc), "native_result": None}
