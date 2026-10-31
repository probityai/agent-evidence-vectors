"""Inspect the closed M1 projection without upgrading native declarations."""

from json_profile import canonical, digest, integer, object_fields, require, shape, text

NATIVE_FIELDS = (
    "native_claim",
    "native_result",
    "subject",
    "evidence_selection",
    "result_evidence_digest",
    "result_signer_kid",
)
NON_CLAIMS = (
    "not_a_trace_trust_record",
    "no_trace_conformance_level",
    "references_are_pointers_not_evidence",
    "native_result_is_remora_verifier_output_not_re_evaluated",
    "independent_verification_not_established",
    "runtime_capability_surface_completeness_not_established",
    "effect_not_established_by_this_mapping",
)


def context_projection(context):
    return {
        "digest": digest(canonical(context)),
        "model_authority": {
            k: context["model_initiator"]["authority"][k] for k in ("issuer", "kind")
        },
        "principal_authority": context["subject"]["authority"]["kind"],
        "principal_id": context["subject"]["principal_id"],
        "tenant_id": context["tenant_id"],
    }


def unmapped_projection(context):
    runtime = context["runtime"]
    data = context["data_scope"]
    return {
        "build_provenance_digest": {
            "asserted_by": runtime["authority"]["kind"],
            "value": "sha256:" + runtime["build_provenance_digest"],
            "why_not_mapped": "no_slsa_level_and_artifact_not_verified",
        },
        "runtime_identity_hash": {
            "asserted_by": runtime["authority"]["kind"],
            "value": "sha256:" + runtime["runtime_identity_hash"],
            "why_not_mapped": "not_a_workload_measurement",
        },
        "data_scope": {
            **{k: data[k] for k in ("ceiling", "classification", "scope")},
            "why_not_mapped": "trace_data_class_covers_outputs_remora_scope_does_not",
        },
    }


def check_sidecar(sidecar, observed, referenced):
    context = observed["bound_context"]
    extra = ("execution_context", "available_unmapped") if context is not None else ()
    object_fields(sidecar, NATIVE_FIELDS + ("reference_emitted", "non_claims") + extra)
    for key in NATIVE_FIELDS:
        require(canonical(sidecar[key]) == canonical(observed[key]), "native_sidecar_mismatch")
    require(sidecar["reference_emitted"] is referenced, "reference_emission_mismatch")
    require(sidecar["non_claims"] == list(NON_CLAIMS), "non_claims_changed")
    if context is not None:
        require(
            canonical(sidecar["execution_context"]) == canonical(context_projection(context)),
            "context_sidecar_mismatch",
        )
        require(
            canonical(sidecar["available_unmapped"]) == canonical(unmapped_projection(context)),
            "unmapped_declaration_changed",
        )


def check_reference(references, observed):
    require(type(references) is list and len(references) == 1, "reference_population")
    reference = references[0]
    object_fields(reference, ("id", "digest", "rel", "resolver"), ("retention",))
    require(
        reference["id"] == reference["digest"] == observed["result_evidence_digest"],
        "reference_digest_mismatch",
    )
    require(reference["rel"] == "remora-native-claim-result", "reference_role_mismatch")
    text(reference["resolver"])
    if "retention" in reference:
        require(reference["retention"] == "P1Y", "retention_outside_frozen_profile")


def check_trace(trace, observed):
    require(type(trace) is dict, "trace_object_required")
    require(not set(observed["missing_trace_required"]) & trace.keys(), "invented_required_field")
    context = observed["bound_context"]
    model_field = ("model",) if context is not None else ()
    object_fields(
        trace, ("eat_profile", "iat", "origin", "appraisal") + model_field, ("references",)
    )
    require(trace["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2", "trace_profile")
    integer(trace["iat"], 1_700_000_000)
    origin = trace["origin"]
    object_fields(origin, ("kind", "producer", "source_event_id", "ingested_at"))
    require(origin["kind"] == "third-party-control-plane", "origin_kind")
    text(origin["producer"])
    subject = observed["subject"]
    require(
        origin["source_event_id"] == subject["operation_id"] + "/" + subject["report_id"],
        "origin_identity_mismatch",
    )
    integer(origin["ingested_at"], 1_700_000_000)
    require(origin["ingested_at"] <= trace["iat"], "ingestion_after_issuance")
    appraisal = trace["appraisal"]
    object_fields(appraisal, ("status", "verifier"))
    require(appraisal["status"] == "none", "unsupported_appraisal")
    require(
        appraisal["verifier"]
        == "urn:remora:federation-result-signer:" + observed["result_signer_kid"],
        "appraisal_signer_mismatch",
    )
    if context is not None:
        require(
            canonical(trace["model"])
            == canonical({k: context["model_initiator"][k] for k in ("provider", "model_id")}),
            "model_mismatch",
        )
    if "references" in trace:
        check_reference(trace["references"], observed)


def check_mapping_ceiling(mapping, observed):
    shape(mapping)
    require(observed["decision"] == "BOUND", "binding_required_before_mapping")
    object_fields(
        mapping,
        (
            "schema_version",
            "trace_role",
            "is_trust_record",
            "trace_conformance_level",
            "trace",
            "trace_canonicalization",
            "trace_digest",
            "absent_required",
            "remora",
        ),
    )
    require(mapping["schema_version"] == "remora-trace-mapping-v1", "mapping_schema")
    require(mapping["trace_role"] == "external-evidence-source", "unsupported_trace_role")
    require(mapping["is_trust_record"] is False, "unsupported_trust_record")
    require(mapping["trace_conformance_level"] is None, "unsupported_conformance_level")
    check_trace(mapping["trace"], observed)
    require(
        mapping["trace_canonicalization"] == "remora/jcs-rfc8785-v0", "canonicalization_declaration"
    )
    require(mapping["trace_digest"] == digest(canonical(mapping["trace"])), "trace_digest_mismatch")
    absent = mapping["absent_required"]
    object_fields(absent, observed["missing_trace_required"])
    for value in absent.values():
        text(value)
    check_sidecar(mapping["remora"], observed, "references" in mapping["trace"])
    return True
