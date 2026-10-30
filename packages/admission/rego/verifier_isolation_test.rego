# Tests for verifier_isolation.rego, one per vector in verifier_isolation_vectors.json.
#
# Written by gen_verifier_isolation_vectors.py; never edit it by hand. A failure names the
# case, and a case the generator drops loses its test in the same write.

package verifier_isolation_test

import data.verifier_isolation
import rego.v1

vectors := data.verifier_isolation_vectors.cases

reasons_for(name) := r if {
	c := vectors[name]
	r := verifier_isolation.reasons with input as c.input
		with data.verifier_isolation_consumer as c.consumer
}

compliant_for(name) := v if {
	c := vectors[name]
	v := verifier_isolation.isCompliant with input as c.input
		with data.verifier_isolation_consumer as c.consumer
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

test_baseline_admitted if holds("baseline-admitted")

test_contract_digest_invalid if holds("contract-digest-invalid")

test_contract_pin_matches if holds("contract-pin-matches")

test_contract_pin_mismatch if holds("contract-pin-mismatch")

test_predicate_type_wrong if holds("predicate-type-wrong")

test_report_missing if holds("report-missing")

test_signature_undeclared if holds("signature-undeclared")

test_statement_type_wrong if holds("statement-type-wrong")

test_vi1_excluded_names_kept if holds("vi1-excluded-names-kept")

test_vi1_trusted_tree_differs if holds("vi1-trusted-tree-differs")

test_vi1_trusted_tree_undeclared if holds("vi1-trusted-tree-undeclared")

test_vi2_assertions_with_submission if holds("vi2-assertions-with-submission")

test_vi2_flag_is_string if holds("vi2-flag-is-string")

test_vi2_groups_kept if holds("vi2-groups-kept")

test_vi2_groups_undeclared if holds("vi2-groups-undeclared")

test_vi2_python_not_isolated if holds("vi2-python-not-isolated")

test_vi2_replay_parent_claims_container_as_verifier if holds("vi2-replay-parent-claims-container-as-verifier")

test_vi2_replay_parent_env_undeclared if holds("vi2-replay-parent-env-undeclared")

test_vi2_replay_parent_on_host if holds("vi2-replay-parent-on-host")

test_vi2_replay_parent_root if holds("vi2-replay-parent-root")

test_vi2_replay_parent_runtime_socket if holds("vi2-replay-parent-runtime-socket")

test_vi2_replay_parent_unrecorded if holds("vi2-replay-parent-unrecorded")

test_vi2_replay_parent_unverified if holds("vi2-replay-parent-unverified")

test_vi2_worker_is_root if holds("vi2-worker-is-root")

test_vi2_worker_is_verifier if holds("vi2-worker-is-verifier")

test_vi2_worker_uid_string if holds("vi2-worker-uid-string")

test_vi3_no_source if holds("vi3-no-source")

test_vi3_not_precleared if holds("vi3-not-precleared")

test_vi3_result_dir_777 if holds("vi3-result-dir-777")

test_vi3_result_dir_group if holds("vi3-result-dir-group")

test_vi3_result_dir_undeclared if holds("vi3-result-dir-undeclared")

test_vi3_two_sources if holds("vi3-two-sources")

test_vi3_written_by_worker if holds("vi3-written-by-worker")

test_vi4_exit_status_alone if holds("vi4-exit-status-alone")

test_vi4_fewer_collected if holds("vi4-fewer-collected")

test_vi4_no_tests if holds("vi4-no-tests")

test_vi4_skipped if holds("vi4-skipped")

test_vi4_skipped_undeclared if holds("vi4-skipped-undeclared")

test_vi5_not_killed if holds("vi5-not-killed")

test_vi5_read_before_kill if holds("vi5-read-before-kill")

test_vi5_remaining if holds("vi5-remaining")

test_vi5_steps_equal if holds("vi5-steps-equal")

test_vi6_destination_kept if holds("vi6-destination-kept")

test_vi6_links_followed if holds("vi6-links-followed")

test_vi6_special_files if holds("vi6-special-files")

test_vi7_env_not_scrubbed if holds("vi7-env-not-scrubbed")

test_vi7_no_scratch_copy if holds("vi7-no-scratch-copy")

test_vi7_worker_evidence if holds("vi7-worker-evidence")

test_vi7_worker_evidence_undeclared if holds("vi7-worker-evidence-undeclared")

test_vi8_reference_in_artifact if holds("vi8-reference-in-artifact")

test_vi8_reference_readable if holds("vi8-reference-readable")

test_vi8_reference_undeclared if holds("vi8-reference-undeclared")

test_vi9_loader_safe_undeclared if holds("vi9-loader-safe-undeclared")

test_vi9_no_loaders if holds("vi9-no-loaders")

test_vi9_unnamed_unsafe_loader if holds("vi9-unnamed-unsafe-loader")

test_vi9_unsafe_loader if holds("vi9-unsafe-loader")

tested := {
	"baseline-admitted",
	"contract-digest-invalid",
	"contract-pin-matches",
	"contract-pin-mismatch",
	"predicate-type-wrong",
	"report-missing",
	"signature-undeclared",
	"statement-type-wrong",
	"vi1-excluded-names-kept",
	"vi1-trusted-tree-differs",
	"vi1-trusted-tree-undeclared",
	"vi2-assertions-with-submission",
	"vi2-flag-is-string",
	"vi2-groups-kept",
	"vi2-groups-undeclared",
	"vi2-python-not-isolated",
	"vi2-replay-parent-claims-container-as-verifier",
	"vi2-replay-parent-env-undeclared",
	"vi2-replay-parent-on-host",
	"vi2-replay-parent-root",
	"vi2-replay-parent-runtime-socket",
	"vi2-replay-parent-unrecorded",
	"vi2-replay-parent-unverified",
	"vi2-worker-is-root",
	"vi2-worker-is-verifier",
	"vi2-worker-uid-string",
	"vi3-no-source",
	"vi3-not-precleared",
	"vi3-result-dir-777",
	"vi3-result-dir-group",
	"vi3-result-dir-undeclared",
	"vi3-two-sources",
	"vi3-written-by-worker",
	"vi4-exit-status-alone",
	"vi4-fewer-collected",
	"vi4-no-tests",
	"vi4-skipped",
	"vi4-skipped-undeclared",
	"vi5-not-killed",
	"vi5-read-before-kill",
	"vi5-remaining",
	"vi5-steps-equal",
	"vi6-destination-kept",
	"vi6-links-followed",
	"vi6-special-files",
	"vi7-env-not-scrubbed",
	"vi7-no-scratch-copy",
	"vi7-worker-evidence",
	"vi7-worker-evidence-undeclared",
	"vi8-reference-in-artifact",
	"vi8-reference-readable",
	"vi8-reference-undeclared",
	"vi9-loader-safe-undeclared",
	"vi9-no-loaders",
	"vi9-unnamed-unsafe-loader",
	"vi9-unsafe-loader",
}

# A vector with no test above would pass unseen.
test_every_vector_has_a_test if {
	count(vectors) == count(tested)
	every name in tested {
		vectors[name]
	}
}
