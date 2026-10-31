# Tests for agent_change_admission.rego, over the vectors in
# agent_change_admission_vectors.json (written by gen_agent_change_admission_vectors.py).
#
# Each vector carries its input, its consumer pins and the exact set of refusal
# reasons the rule set must return. One test per vector, so a failure names the
# case; `test_every_vector_has_a_test` refuses a vector the generator added and no
# test reads, because a case nobody evaluates looks exactly like a case that passes.

package agent_change_admission_test

import data.agent_change_admission
import rego.v1

vectors := data.agent_change_admission_vectors.cases

reasons_for(name) := r if {
	c := vectors[name]
	r := agent_change_admission.reasons with input as c.input
		with data.change_admission_consumer as c.consumer
}

compliant_for(name) := v if {
	c := vectors[name]
	v := agent_change_admission.isCompliant with input as c.input
		with data.change_admission_consumer as c.consumer
}

holds(name) if {
	want := sort(vectors[name].reasons)
	reasons_for(name) == want
	count(want) == 0
	compliant_for(name) == true
}

holds(name) if {
	want := sort(vectors[name].reasons)
	reasons_for(name) == want
	count(want) > 0
	compliant_for(name) == false
}

tested := {
	"required-gates-empty",
	"wrapper-harness-digest-invalid",
	"statement-predicate-not-object",
	"admitted-with-failed-gate",
	"envelope-bare-admitted",
	"envelope-intoto-admitted",
	"expected-candidate-digest-invalid",
	"field-invalid-admitted",
	"field-invalid-candidate",
	"field-invalid-candidate-digest",
	"field-invalid-checks",
	"field-invalid-corpus-digests",
	"field-invalid-evaluator",
	"field-invalid-evaluator-components-suite-file",
	"field-invalid-exceptions",
	"field-invalid-parent",
	"field-invalid-report-digests",
	"gate-duplicated",
	"gate-missing",
	"image-binding-mismatch",
	"image-binding-pinned",
	"image-binding-unpinned",
	"limit-tampered-payload-passes-this-rule",
	"payload-not-json-object",
	"rejected-with-all-gates-passed",
	"rejection-receipt",
	"required-gate-unknown",
	"required-gates-subset",
	"signature-verification-undeclared",
	"statement-admitted",
	"subject-binding-unknown",
	"subject-digest-mismatch",
	"trusted-keys-unpinned",
	"unsupported-payload-type",
	"unsupported-predicate-bare",
	"unsupported-predicate-statement",
	"unsupported-statement-type",
	"untrusted-key",
	"wrapper-harness-match",
	"wrapper-harness-mismatch",
}

test_every_vector_has_a_test if {
	count(tested) == count(vectors)
	every name, _ in vectors {
		name in tested
	}
}

test_admitted_with_failed_gate if holds("admitted-with-failed-gate")

test_envelope_bare_admitted if holds("envelope-bare-admitted")

test_envelope_intoto_admitted if holds("envelope-intoto-admitted")

test_expected_candidate_digest_invalid if holds("expected-candidate-digest-invalid")

test_field_invalid_admitted if holds("field-invalid-admitted")

test_field_invalid_candidate if holds("field-invalid-candidate")

test_field_invalid_candidate_digest if holds("field-invalid-candidate-digest")

test_field_invalid_checks if holds("field-invalid-checks")

test_field_invalid_corpus_digests if holds("field-invalid-corpus-digests")

test_field_invalid_evaluator if holds("field-invalid-evaluator")

test_field_invalid_evaluator_components_suite_file if holds("field-invalid-evaluator-components-suite-file")

test_field_invalid_exceptions if holds("field-invalid-exceptions")

test_field_invalid_parent if holds("field-invalid-parent")

test_field_invalid_report_digests if holds("field-invalid-report-digests")

test_gate_duplicated if holds("gate-duplicated")

test_gate_missing if holds("gate-missing")

test_image_binding_mismatch if holds("image-binding-mismatch")

test_image_binding_pinned if holds("image-binding-pinned")

test_image_binding_unpinned if holds("image-binding-unpinned")

test_limit_tampered_payload_passes_this_rule if holds("limit-tampered-payload-passes-this-rule")

test_payload_not_json_object if holds("payload-not-json-object")

test_rejected_with_all_gates_passed if holds("rejected-with-all-gates-passed")

test_rejection_receipt if holds("rejection-receipt")

test_required_gate_unknown if holds("required-gate-unknown")

test_required_gates_subset if holds("required-gates-subset")

test_signature_verification_undeclared if holds("signature-verification-undeclared")

test_statement_admitted if holds("statement-admitted")

test_subject_binding_unknown if holds("subject-binding-unknown")

test_subject_digest_mismatch if holds("subject-digest-mismatch")

test_trusted_keys_unpinned if holds("trusted-keys-unpinned")

test_unsupported_payload_type if holds("unsupported-payload-type")

test_unsupported_predicate_bare if holds("unsupported-predicate-bare")

test_unsupported_predicate_statement if holds("unsupported-predicate-statement")

test_unsupported_statement_type if holds("unsupported-statement-type")

test_untrusted_key if holds("untrusted-key")

test_wrapper_harness_match if holds("wrapper-harness-match")

test_wrapper_harness_mismatch if holds("wrapper-harness-mismatch")

test_statement_predicate_not_object if holds("statement-predicate-not-object")

test_wrapper_harness_digest_invalid if holds("wrapper-harness-digest-invalid")

test_required_gates_empty if holds("required-gates-empty")

# A consumer that has pinned nothing admits nothing, whatever the receipt says.
test_unpinned_consumer_admits_nothing if {
	not agent_change_admission.isCompliant with input as vectors["envelope-bare-admitted"].input
		with data.change_admission_consumer as {}
}

# The predicate type is the one the receipts carry, byte for byte.
test_predicate_type_is_the_published_uri if {
	agent_change_admission.predicate_uri == data.agent_change_admission_vectors.predicate_type
}

# Absent a pin, every gate in the closed set is required.
test_default_gates_are_the_closed_set if {
	agent_change_admission.required_gates == agent_change_admission.admission_gates
		with data.change_admission_consumer as {}
}

# The deployment overrides the generated policy-controller manifest appends turn
# a statement with no consumer document into an admissible one, and only that.
test_engine_overrides_stand_in_for_the_consumer_document if {
	c := vectors["image-binding-pinned"]
	agent_change_admission.isCompliant with input as c.input
		with data.change_admission_consumer as {}
		with agent_change_admission.engine_verified_envelope as true
		with agent_change_admission.engine_subject_binding as "image"
		with agent_change_admission.engine_expected_candidate_digest as c.consumer.expected_candidate_digest
}

test_engine_overrides_keep_the_placeholder_closed if {
	c := vectors["image-binding-pinned"]
	r := agent_change_admission.reasons with input as c.input
		with data.change_admission_consumer as {}
		with agent_change_admission.engine_verified_envelope as true
		with agent_change_admission.engine_subject_binding as "image"
		with agent_change_admission.engine_expected_candidate_digest as "PIN-ME-REPLACE-WITH-THE-ADMITTED-HARNESS-DIGEST"
	r == ["expected_candidate_digest_invalid"]
}
