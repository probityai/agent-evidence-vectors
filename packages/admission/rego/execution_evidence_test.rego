# Unit tests for execution_evidence.rego (v0.6 two-gate subset).
#
# Self-contained: the accept + reject statements are built inline from a v0.6
# clean-PASS template (mirroring the vendored conformance accept vectors), with
# the corpus digest + run-binding computed in-policy via crypto.sha256(json.marshal)
# — the same idiom the module uses — so the fixtures cannot drift from the rules.
# Each reject is a single targeted mutation of the accept, asserted to be DENIED on
# the exact rule that should catch it. All four record CLASSES (arming, sealed,
# interception, examination) are decoded and matched here; what stays out of rego's
# evaluable scope by construction — the RFC-6962 fold, Ed25519 over the DSSE PAE, and
# the strict JCS / I-JSON profile of the payload BYTES — belongs to the offline
# TS/Python verifiers.
#
# THE CONSUMER CONTEXT THIS SUITE RUNS UNDER. The module now REQUIRES the spec's
# out-of-band anchors (see "THE ABSENT-ANCHOR DECISION" in execution_evidence.rego), so
# every assertion here would otherwise be denied for want of a pin rather than for the
# rule under test — which would quietly turn 96 `not isCompliant` assertions into
# tautologies. `test_consumer_pins.json` in this directory therefore mounts
# data.consumer with the template's own corpus and substrate digests, exactly as a real
# consumer pins them, and `opa test` loads it alongside corpus_vectors.json. The suite
# consequently runs as a PINNED consumer by default; the unpinned default, the opt-out
# and the two mismatch arms are asserted explicitly in their own section below, and
# test_consumer_pins_match_template keeps the JSON from drifting from the template.
#
# Run: opa test deploy/admission/rego/ -v
package sigstore

import rego.v1

# ── the v0.6 clean-PASS accept template ──────────────────────────────────────────

_hex := "1111111111111111111111111111111111111111111111111111111111111111"

_manifest := {"classes": {"XA": ["XA-1"]}}

_corpus_digest := crypto.sha256(json.marshal(_manifest))

# The carried networkPosture OBJECT, built once and used both in the statement and in
# the identity below it. The run binding digests this whole object rather than the
# digest member inside it, so a template that spelled the object out in one place and
# its digest in another would let the posture string drift away from the value the
# identity was taken over, and every fixture here would go on passing while measuring a
# statement no producer emits.
_posture_object(digest) := {"posture": "sinkhole", "digest": {"sha256": digest}}

# The carried vocabulary, likewise shared: its digest is a pre-image input.
_vocabulary_object := {"labels": ["egress_captured", "no_egress"], "caught": ["egress_captured"], "digest": {"sha256": _hex}}

# The digest members the template carries verbatim. One map, consumed by the identity
# below and by the input-canonicality fixtures further down, for the same reason the
# module keeps one map: two lists let an input be added to one and not the other.
_default_binding_digests := {
	"catchPolicy": _hex,
	"corpus": _corpus_digest,
	"networkPosture": _hex,
	"runEntropy": _hex,
	"subject": _hex,
	"substrate": _hex,
}

# The run identity for a given posture object and digest map, computed from the same
# literals the statement carries (the same idiom run_identity uses), so the records
# cannot drift from the statement they belong to. The DECLARED binding version has to
# move whenever the implemented construction moves: leave it behind and every fixture
# here binds to an identity the module no longer derives, which reads as a broken
# template rather than as the drift it is.
_identity(posture_object, d) := crypto.sha256(json.marshal({
	"aeeBindingVersion": "2",
	"catchPolicy": d.catchPolicy,
	"corpus": d.corpus,
	"networkPosture": crypto.sha256(json.marshal(posture_object)),
	"observationVocabulary": _vocabulary_object.digest.sha256,
	"runEntropy": d.runEntropy,
	"subject": d.subject,
	"substrate": d.substrate,
}))

_run_identity := _identity(_posture_object(_hex), _default_binding_digests)

_media_type := "application/vnd.example.aee-observation.v1+json"

_record(payload) := {
	"payload": base64.encode(json.marshal(payload)),
	"payloadType": _media_type,
	"signatures": [{"keyid": "example-key", "sig": "AA=="}],
}

# The run-level ABSENCE records that cover a clean row: the substrate says a live
# vantage was armed before injection (arming) and stayed armed to run-end with no
# dropped observation (sealed). A clean row referencing neither is the "nothing
# happened" claim with no evidence anything was watching.
# Both payloads gained the members 0.7 REQUIRES on their kind. They had been absent
# here because nothing read them: the rail checked neither, so a fixture omitting
# them still described a record the rail called valid. Thirty-six tests built on
# these two literals went red the moment the kind rules started reading them, which
# is the fixtures encoding the under-enforcement rather than thirty-six separate
# faults. `aeeAssessedAttacks` names the one identifier `_manifest` declares. The
# seal observes NO attack, and the empty array is the honest spelling of that rather
# than an omission: a substrate holding no probe-to-record correspondence says so on
# the wire.
_arming_payload := {
	"aeeKind": "arming",
	"aeeMethod": "intercepted",
	"aeeRunBinding": _run_identity,
	"armedAt": "2025-12-31T23:59:00Z",
	"aeePostureDigest": _hex,
	"aeeAssessedAttacks": ["XA-1"],
}

_sealed_payload := {
	"aeeKind": "sealed",
	"aeeMethod": "intercepted",
	"aeeRunBinding": _run_identity,
	"aeeStillArmed": true,
	"aeeDropCount": 0,
	"aeePostureDigest": _hex,
	"aeeObservedSet": _hex,
	"aeeObservedAttacks": [],
}

_arming_record := _record(_arming_payload)

_sealed_record := _record(_sealed_payload)

# The accept template is DEFAULT-SAFE by construction: a live-interception clean row
# (basis:substrate + method:intercepted) whose observationRefs resolve to a valid
# arming record AND a covering sealed record, both signature-bearing. The weaker
# shapes (artifact basis, reconstructed method, stripped signatures, uncovered clean
# row) are the rejects below, so the default posture is exercised in both directions.
accept := {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": adversarial_execution_evidence,
	"subject": [{"name": "example-agent-bundle", "digest": {"sha256": _hex}}],
	"predicate": {
		"result": "pass",
		"issuedAt": "2026-01-01T00:00:00Z",
		"observationEnvironment": {
			"catchPolicy": {"digest": {"sha256": _hex}},
			"corpus": {"name": "c", "uri": "pkg:example/c@1", "digest": {"sha256": _corpus_digest}, "manifest": _manifest},
			"networkPosture": _posture_object(_hex),
			"substrate": {"digest": {"sha256": _hex}},
			"runEntropy": {"digest": {"sha256": _hex}},
			"observationVocabulary": _vocabulary_object,
		},
		"coverage": {"assessedClasses": ["XA"], "outOfScope": {}, "routedElsewhere": {}},
		"attackResults": [{"attackId": "XA-1", "containmentObserved": "no_egress", "basis": "substrate", "method": "intercepted", "attribution": "paired", "actualLayer": "none", "observationRefs": [0, 1]}],
		"observationRecords": [_arming_record, _sealed_record],
		"batchRoot": _hex,
	},
}

# The same run, recordless and self-reported: no observationRecords, no batchRoot,
# and the clean row downgraded to artifact/reconstructed. This is the shape the
# empirical audit drove through the reference verifier (every basis set to artifact,
# the records and batch root deleted) — structurally VALID, and the default consumer
# policy must not admit it.
# result is pass_indirect, not pass: the single clean row is indirect in both
# vantage and time, so the recompute floors it below the top value and a fixture
# carrying "pass" would be denied for a recompute mismatch rather than for the
# clean-row rule these tests are named for.
_recordless_artifact := json.remove(
	object.union(accept, {
		"predicate": {
			"result": "pass_indirect",
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "no_egress",
					"basis": "artifact",
					"method": "reconstructed",
					"attribution": "paired",
					"actualLayer": "none",
				},
			],
		},
	}),
	["predicate/observationRecords", "predicate/batchRoot"],
)

# ── helpers ──────────────────────────────────────────────────────────────────────

# The consumer that admits an indirect run. It is TWO declarations, not one: the
# threshold names the token the recompute floors such a statement at, and the row knob
# declines the clean-row provenance obligation. The module denies a document carrying
# only one of them, so this pair is the smallest coherent way to say "I accept
# state-diffing evidence" and every test that needs that posture spells it once, here.
_indirect_consumer := {"accepted_results": ["pass", "pass_indirect"], "admit_unintercepted_clean_rows": true}

_errors_contain(stmt, substr) if {
	some err in errors with input as stmt
	contains(err, substr)
}

# ── the accept vector IS admitted ────────────────────────────────────────────────

test_accept_admitted if {
	isCompliant with input as accept
	count(errors) == 0 with input as accept
}

# ── each reject is DENIED on its exact rule ───────────────────────────────────────

# result recompute: a carried result the recompute does not reproduce.
test_reject_result_mismatch if {
	stmt := object.union(accept, {"predicate": {"result": "fail"}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "does not equal the offline recompute")
}

# coverage integrity: a corpus digest that does not commit the embedded manifest.
test_reject_manifest_digest_tamper if {
	stmt := object.union(accept, {"predicate": {"observationEnvironment": {"corpus": {"digest": {"sha256": _hex}}}}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "does not commit the embedded manifest")
}

# attack-level exhaustion: a class is assessed but one failing attackId is dropped.
test_reject_partial_class_evasion if {
	m := {"classes": {"XA": ["XA-1", "XA-2"]}}
	stmt := object.union(accept, {"predicate": {"observationEnvironment": {"corpus": {"manifest": m, "digest": {"sha256": crypto.sha256(json.marshal(m))}}}}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "attack-level exhaustion")
}

# ── the fail-closed row: VALID and floored at "fail", INVALID only under substrate ──
#
# THE TWO SENTENCES THESE TESTS PIN. "Both fields are REQUIRED on every row and both
# vocabularies are closed: a missing value, or any value outside them, is fail-closed
# exactly as an out-of-vocabulary `containmentObserved` label is: the row forces
# `result` to `fail` and can support nothing stronger." And: "A `basis: substrate` row
# whose `containmentObserved`, `basis`, or `method` is fail-closed (outside the carried
# vocabulary) cannot satisfy the class-match requirement and is therefore invalid; a
# `basis: artifact` fail-closed row sits at the bottom of both orderings as before."
#
# WHAT USED TO STAND HERE AND WHAT IT ASSERTED. Two tests, `test_reject_oov_containment`
# and `test_reject_missing_basis`, each mutating the template to an ARTIFACT row with a
# fail-closed member and asserting a denial with a vocabulary error. Both passed, and
# both were pinning the defect: the rail treated a fail-closed row as a malformed
# STATEMENT, so it called invalid what the spec calls valid-and-failing, and an
# independent implementer's honest `fail` was refused as though it did not parse. A
# denial is not evidence of a correct denial — these two asserted only that SOMETHING
# denied, which the wrong rule satisfies as readily as the right one.
#
# WHAT THE REPLACEMENTS ASSERT INSTEAD, on both sides of the sentence. Each artifact
# case is asserted VALID (bindings_ok AND soundness_ok), recomputed to exactly "fail",
# reproducing its carried "fail", and then denied by the ADMISSION THRESHOLD alone —
# with the recompute error explicitly ABSENT, so a rail that reintroduced the
# statement-scoped vocabulary gate reddens rather than passing on a coincidental
# denial. Each substrate case is asserted INVALID on its own rule. Four members are
# swept per side (absent basis, absent method, unknown basis, unknown method) plus the
# out-of-vocabulary label, because the spec names them in one breath and a fix that
# reached only the member some vector happened to exercise would leave the others.
_fail_closed_stmt(row) := object.union(accept, {
	"predicate": {
		"result": "fail",
		"attackResults": [row],
	},
})

_valid_and_floored_at_fail(row) if {
	stmt := _fail_closed_stmt(row)
	bindings_ok with input as stmt
	soundness_ok with input as stmt
	recomputed_result == "fail" with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "is not one of the result tokens this consumer accepts")
	not _errors_contain(stmt, "does not equal the offline recompute")
}

_invalid_substrate_row(row) if {
	stmt := _fail_closed_stmt(row)
	bindings_ok with input as stmt
	not soundness_ok with input as stmt
	_errors_contain(stmt, "is fail-closed on containmentObserved or method")
}

_artifact_row(extra) := object.union({"attackId": "XA-1", "containmentObserved": "no_egress", "basis": "artifact", "method": "reconstructed", "attribution": "paired", "actualLayer": "none"}, extra)

_substrate_row_fixture(extra) := object.union({"attackId": "XA-1", "containmentObserved": "no_egress", "basis": "substrate", "method": "intercepted", "attribution": "paired", "actualLayer": "none", "observationRefs": [0, 1]}, extra)

# An ARTIFACT row missing `basis` entirely. This is the shape of the published accept
# vector ok-901-row-missing-basis, and the one the rail refused: `bindings_ok` held and
# `soundness_ok` returned undefined.
test_fail_closed_missing_basis_is_valid if {
	_valid_and_floored_at_fail(json.remove(_artifact_row({}), ["basis"]))
}

test_fail_closed_missing_method_is_valid if {
	_valid_and_floored_at_fail(json.remove(_artifact_row({}), ["method"]))
}

test_fail_closed_unknown_basis_is_valid if {
	_valid_and_floored_at_fail(_artifact_row({"basis": "substrate_observed"}))
}

test_fail_closed_unknown_method_is_valid if {
	_valid_and_floored_at_fail(_artifact_row({"method": "example_unknown_method"}))
}

test_fail_closed_oov_label_is_valid if {
	_valid_and_floored_at_fail(_artifact_row({"containmentObserved": "totally-unknown"}))
}

# The other side of the same sentence: the identical faults on a `basis: substrate` row
# leave the class match with nothing to dispatch on, and there the statement IS
# invalid. `basis` is named in that sentence and cannot fire from it — a row whose
# basis is absent or unknown is not a substrate row — which is exactly why the first
# artifact case above is an accept and not a reject.
test_substrate_oov_label_is_invalid if {
	_invalid_substrate_row(_substrate_row_fixture({"containmentObserved": "totally-unknown"}))
}

test_substrate_missing_method_is_invalid if {
	_invalid_substrate_row(json.remove(_substrate_row_fixture({}), ["method"]))
}

test_substrate_unknown_method_is_invalid if {
	_invalid_substrate_row(_substrate_row_fixture({"method": "example_unknown_method"}))
}

# The vocabulary's PRESENCE, which the deleted per-row rule was standing in for. A
# statement carrying no observationVocabulary reads as an empty carried set wherever it
# is consumed, so every row fail-closes and a producer carrying an honest "fail" was
# admitted once the per-row gate went. The published reject bad-601-vocabulary-absent
# is exactly that statement; observation_vocabulary_ok is the rule that states the
# member is required rather than inferring it from a row.
test_reject_vocabulary_absent if {
	stmt := json.remove(
		object.union(accept, {"predicate": {"result": "fail", "attackResults": [_artifact_row({})]}}),
		["predicate/observationEnvironment/observationVocabulary"],
	)
	not observation_vocabulary_ok with input as stmt
	not soundness_ok with input as stmt
	_errors_contain(stmt, "observationVocabulary is absent")
}

# Removed from the MERGED statement rather than from _vocabulary_object: object.union
# deep-merges, so a vocabulary literal with `labels` deleted would have the template's
# own `labels` merged straight back in and the fixture would assert nothing.
#
# THIS FIXTURE IS THE ONE THAT PROVES THE WIRING, and the one above is not. Deleting
# the whole vocabulary also moves the run-identity pre-image, so that statement is
# denied by run_binding_ok whether or not this rule is a conjunct of soundness_ok —
# measured, by dropping the conjunct and watching only this test redden. Deleting
# `labels` alone leaves the carried vocabulary digest and the identity untouched, so
# the only thing standing between it and admission is the rule under test.
test_reject_vocabulary_labels_absent if {
	stmt := json.remove(
		object.union(accept, {"predicate": {"result": "fail", "attackResults": [_artifact_row({})]}}),
		["predicate/observationEnvironment/observationVocabulary/labels"],
	)
	not observation_vocabulary_ok with input as stmt
	not soundness_ok with input as stmt
	_errors_contain(stmt, "observationVocabulary is absent")
}

# actualLayer REQUIRED: a row missing actualLayer.
test_reject_missing_actual_layer if {
	stmt := object.union(accept, {"predicate": {"attackResults": [{"attackId": "XA-1", "containmentObserved": "no_egress", "basis": "artifact", "method": "reconstructed"}]}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "actualLayer")
}

# clean-row layer: a clean-label row whose actualLayer is not "none".
test_reject_clean_row_layer_not_none if {
	stmt := object.union(accept, {"predicate": {"attackResults": [{"attackId": "XA-1", "containmentObserved": "no_egress", "basis": "artifact", "method": "reconstructed", "attribution": "paired", "actualLayer": "policy.egress_sinkhole"}]}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "actualLayer")
}

# type contract: an unknown predicateType is fail-closed.
test_reject_unknown_predicate_type if {
	stmt := object.union(accept, {"predicateType": "https://example.invalid/predicate/v1/bogus"})
	not isCompliant with input as stmt
	_errors_contain(stmt, "unknown or unregistered predicateType")
}

# structural binding: a malformed catch-policy digest.
test_reject_stripped_catch_policy if {
	stmt := object.union(accept, {"predicate": {"observationEnvironment": {"catchPolicy": {"digest": {"sha256": "not-a-hex"}}}}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "catch-policy digest")
}

# ── substrate-carrying rejects (records + run-binding + batch-root) ───────────────

_bad_record := _record(object.union(_arming_payload, {"aeeRunBinding": "deadbeef"}))

# Clean-row coverage still resolves here (the covering predicate reads the record
# CLASS; run_binding_ok owns the binding, for every record rather than the referenced
# ones), so the denial below is attributable to the run-binding rule alone.
_substrate := object.union(accept, {"predicate": {"observationRecords": [_bad_record, _sealed_record]}})

# run-binding: a record's aeeRunBinding does not equal this run's derived identity.
test_reject_run_binding_splice if {
	not isCompliant with input as _substrate
	_errors_contain(_substrate, "run-binding:")
}

# records-absent: a substrate row present but observationRecords empty.
test_reject_substrate_no_records if {
	stmt := json.remove(_substrate, ["predicate/observationRecords", "predicate/batchRoot"])
	not isCompliant with input as stmt
	_errors_contain(stmt, "records-absent")
}

# batch-root: observationRecords present but the predicate-level batchRoot omitted.
test_reject_missing_batch_root if {
	stmt := json.remove(_substrate, ["predicate/batchRoot"])
	not isCompliant with input as stmt
	_errors_contain(stmt, "batch-root")
}

# ── run-binding INPUT canonicality, measured one input at a time ──────────────────
#
# The spec requires each carried run-binding digest member to be lowercase 64-hex and
# taken verbatim. Taken-verbatim is what makes the recompute blind to the shape: a
# producer emitting a non-canonical value derives every record's aeeRunBinding over
# that same value, and the equality then holds. So every fixture below RE-DERIVES the
# run identity over the substituted digest. Without that re-derivation each statement
# would be denied by run_binding_ok for a reason that has nothing to do with the
# input's shape, and the test would be green against a policy carrying no shape rule
# at all, which is exactly how the two published vectors of this shape came to sit on
# the reject denylist.
#
# One test per input, because three of them were already covered by rules written for
# other purposes and covering the one that was noticed is how a class defect becomes a
# recurring one. The carried posture digest is a case of its own now that the identity
# digests the posture OBJECT rather than reading that member: it is no longer a
# pre-image input at all, and it still has to hold its shape, because it is the value
# every covering record's aeePostureDigest is compared against. Its test says so
# directly.
#
# The map these fixtures substitute into is _default_binding_digests, declared with the
# template above so the statement and the identity read one list rather than two.

# The accept template with one or more carried digests substituted and the whole record
# set rebound to the resulting identity. The posture digest the arming and sealed
# payloads carry follows networkPosture, so a posture substitution does not also break
# the covering conditions and muddy the attribution. The identity is taken over the
# posture object this helper actually emits, not over a second object built beside it.
_with_binding_digests(overrides) := stmt if {
	d := object.union(_default_binding_digests, overrides)
	posture := _posture_object(d.networkPosture)
	ident := _identity(posture, d)
	stmt := object.union(accept, {
		"subject": [{"name": "example-agent-bundle", "digest": {"sha256": d.subject}}],
		"predicate": {
			"observationEnvironment": {
				"catchPolicy": {"digest": {"sha256": d.catchPolicy}},
				"corpus": {"digest": {"sha256": d.corpus}},
				"networkPosture": posture,
				"runEntropy": {"digest": {"sha256": d.runEntropy}},
				"substrate": {"digest": {"sha256": d.substrate}},
			},
			"observationRecords": [
				_record(object.union(_arming_payload, {"aeeRunBinding": ident, "aeePostureDigest": d.networkPosture})),
				_record(object.union(_sealed_payload, {"aeeRunBinding": ident, "aeePostureDigest": d.networkPosture})),
			],
		},
	})
}

# A well-formed 64-hex digest carrying letters, and its uppercase spelling. The
# template's own _hex is all ones, so upper() over it is the identity and a fixture
# built that way would substitute nothing at all.
_lower_lettered := "bd34c306e2295a4974787aa2b81e7e95c37580d543cbc47f0b77a026aef7e051"

_truncated := "111111111111111111111111111111111111111111111111111111111111111"

# The control. A rebound statement with nothing substituted must still be admitted,
# so a fixture builder that quietly produced a denied statement cannot make the six
# assertions below pass for free.
test_rebound_helper_admits_the_unsubstituted_statement if {
	isCompliant with input as _with_binding_digests({})
	count(errors) == 0 with input as _with_binding_digests({})
}

# The two inputs the binding chokepoint already patterns. Asserted through the new
# rule as well, so the coverage stops depending on a rule written for another purpose.
test_reject_catch_policy_digest_not_canonical if {
	not run_binding_inputs_ok with input as _with_binding_digests({"catchPolicy": "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"})
}

test_reject_network_posture_digest_not_canonical if {
	not run_binding_inputs_ok with input as _with_binding_digests({"networkPosture": _truncated})
}

# The carried posture digest is no longer a pre-image input, and it is still REQUIRED to
# be lowercase 64-hex. This is the property the tempting form of the version-2 edit
# silently removes. Substituting the computed posture-object digest into the map the
# canonicality rule iterates leaves that rule reading a crypto.sha256 output, which is
# lowercase 64-hex by construction, so it holds on every statement and can no longer
# fail on this member; the carried digest would then travel unchecked while it is still
# compared byte for byte against every covering record's aeePostureDigest. Both
# spellings are asserted, uppercase here and truncated above, because the two are
# different halves of the pattern and a rule can lose one without losing the other.
test_reject_carried_posture_digest_uppercase if {
	# The same value in its canonical spelling is admitted, so the denial below is
	# attributable to the case and not to the substitution.
	isCompliant with input as _with_binding_digests({"networkPosture": _lower_lettered})
	stmt := _with_binding_digests({"networkPosture": upper(_lower_lettered)})
	not run_binding_inputs_ok with input as stmt
	not soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding inputs:")
}

# The posture STRING, which the previous construction left unsigned. Swapping it for
# another REGISTERED value, with every digest member and every record left exactly as
# the template emits them, changes the identity the module derives, so no record binds
# to the run any more. Under the previous construction the pre-image read only
# networkPosture.digest.sha256, and the posture configuration that digest is taken over
# travels nowhere in the statement, so nothing could compare the string against it and
# this statement was admitted. The swap is to a registered value on purpose:
# posture_ok is asserted to hold, so the denial is attributable to the binding rather
# than to the posture vocabulary.
test_reject_posture_swapped_between_registered_values if {
	stmt := object.union(accept, {"predicate": {"observationEnvironment": {"networkPosture": {"posture": "allowlist"}}}})
	posture_ok with input as stmt
	run_binding_inputs_ok with input as stmt
	not run_binding_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding:")
}

# ...and a producer member added beside the posture is inside the binding too, which is
# the other half of what digesting the whole object buys: the object is not a fixed
# shape whose known members are bound and whose unknown ones ride free.
test_reject_posture_producer_member_added_after_binding if {
	stmt := object.union(accept, {"predicate": {"observationEnvironment": {"networkPosture": {"producerNote": "added after the run"}}}})
	posture_ok with input as stmt
	not run_binding_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding:")
}

# The corpus digest is constrained only as a side effect of the manifest recompute,
# whose right-hand side is a crypto.sha256 output and so can never be uppercase. The
# rule states it directly rather than resting on that.
test_reject_corpus_digest_not_canonical if {
	not run_binding_inputs_ok with input as _with_binding_digests({"corpus": upper(_corpus_digest)})
}

# The three that had no shape rule anywhere. bad-608-digest-uppercase is the first of
# these and reached this rail's denylist; the other two are the same defect on the
# inputs nobody looked at.
test_reject_run_entropy_digest_uppercase if {
	# The same value in its canonical spelling is admitted, so the denial below is
	# attributable to the case and not to the substitution.
	isCompliant with input as _with_binding_digests({"runEntropy": _lower_lettered})
	stmt := _with_binding_digests({"runEntropy": upper(_lower_lettered)})
	not isCompliant with input as stmt
	not soundness_ok with input as stmt
	_errors_contain(stmt, "run-binding inputs:")
}

test_reject_subject_digest_truncated if {
	stmt := _with_binding_digests({"subject": _truncated})
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding inputs:")
}

test_reject_substrate_digest_truncated if {
	stmt := _with_binding_digests({"substrate": _truncated})
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding inputs:")
}

# An absent input reads as the empty string through the object.get defaults, which is
# not lowercase 64-hex, so deletion denies on the same rule rather than slipping past
# a check written only against malformed strings.
test_reject_run_entropy_absent_on_a_substrate_statement if {
	stmt := json.remove(_with_binding_digests({}), ["predicate/observationEnvironment/runEntropy"])
	not isCompliant with input as stmt
	_errors_contain(stmt, "run-binding inputs:")
}

# SCOPE: the requirement is substrate-scoped, as it is in the reference verifiers. An
# artifact-basis statement derives no run binding and need not carry runEntropy, which
# is the shape of eight shipped accept vectors, so the rule must be vacuous there.
test_artifact_statement_outside_run_binding_input_rule if {
	run_binding_inputs_ok with input as _recordless_artifact
	stmt := json.remove(_recordless_artifact, ["predicate/observationEnvironment/runEntropy"])
	run_binding_inputs_ok with input as stmt
}

# ── structural signature presence (the zero-signature strip) ──────────────────────
#
# The batchRoot leaves are H(0x00 || PAE) and PAE spans only (payloadType, payload),
# so deleting every signatures[] entry leaves the root unchanged and the statement
# otherwise intact. Presence is byte-pure and needs no key, so it holds in every
# deployment; the signature BYTES are still never checked here (see the module
# header) — a forged sig passes, which is the point of calling this a band-aid.

_unsigned_record := object.union(_arming_record, {"signatures": []})

test_reject_zero_signature_records if {
	stmt := object.union(accept, {"predicate": {"observationRecords": [_unsigned_record, _sealed_record]}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "signatures[] is absent or empty")
}

test_reject_absent_signatures_member if {
	stmt := object.union(accept, {"predicate": {"observationRecords": [json.remove(_arming_record, ["signatures"]), _sealed_record]}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "signatures[] is absent or empty")
}

# A non-array signatures member must not satisfy presence either (count() over a
# string would otherwise read as "one signature").
test_reject_non_array_signatures if {
	stmt := object.union(accept, {"predicate": {"observationRecords": [object.union(_arming_record, {"signatures": "x"}), _sealed_record]}})
	not isCompliant with input as stmt
	_errors_contain(stmt, "signatures[] is absent or empty")
}

# Forged signature bytes DO pass — asserted so the band-aid's honest limit is a
# tested property of the policy, not merely a claim in a comment. The clean-row
# coverage gate does not change this: it reads the record class out of the same
# unverified payload, so a forged pair covers exactly as a real one does.
test_forged_signature_bytes_still_admitted if {
	forged := object.union(_arming_record, {"signatures": [{"keyid": "attacker", "sig": "bm90LWEtc2lnbmF0dXJl"}]})
	stmt := object.union(accept, {"predicate": {"observationRecords": [forged, _sealed_record]}})
	isCompliant with input as stmt
}

# ── clean-row provenance (default: only a live interception) ──────────────────────

# The recordless self-reported statement is structurally sound and DENIED by default.
test_reject_recordless_artifact_clean_row if {
	soundness_ok with input as _recordless_artifact
	not isCompliant with input as _recordless_artifact
	_errors_contain(_recordless_artifact, "clean-row provenance")
}

# Substrate basis is not sufficient on its own: a reconstructed clean row is a state
# diff, not a live interception.
test_reject_substrate_reconstructed_clean_row if {
	stmt := object.union(accept, {
		"predicate": {
			"result": "pass_indirect",
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "no_egress",
					"basis": "substrate",
					"method": "reconstructed",
					"attribution": "paired",
					"actualLayer": "none",
					"observationRefs": [0],
				},
			],
		},
	})
	not isCompliant with input as stmt
	_errors_contain(stmt, "clean-row provenance")
}

# The weaker clean rows are admitted once, and only once, the consumer says so on BOTH
# axes: the threshold admits the token the recompute floors such a statement at, and
# the row knob declines the row-level obligation. Neither declaration implies the other.
test_indirect_consumer_admits_recordless_artifact_clean_row if {
	isCompliant with input as _recordless_artifact
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
}

# Declining the row obligation is NARROW: it relaxes clean-row provenance and nothing
# else.
#
# The record array keeps BOTH records and the row keeps both refs, so the only rule
# left unsatisfied is signature presence. Supplying the unsigned record alone would
# leave the template's second ref dangling, and the denial would then come from the
# out-of-range reference rather than from the rule this test is named for, and a test
# that stays green with the signature rule deleted proves nothing about it. The
# error assertion pins which rule is doing the work.
test_optin_does_not_relax_signature_presence if {
	stmt := object.union(accept, {"predicate": {"observationRecords": [_unsigned_record, _sealed_record]}})
	not isCompliant with input as stmt
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
	_errors_contain(stmt, "signatures[] is absent or empty")
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
}

# A falsy / non-true flag value must NOT open the gate (fail closed on a typo). The
# threshold is relaxed here so the flag is the only thing left between this statement
# and admission, and the string "true" is not a declaration in either direction: it
# fails the literal-true test that opens the gate AND the JSON-type test that counts as
# having answered the row question at all.
test_optin_requires_literal_true if {
	not isCompliant with input as _recordless_artifact
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as "true"
}

# ── the threshold knob, and the MUST that made it a second knob ───────────────────
#
# adversarial-execution-evidence.md: "a consumer relaxing its threshold below `pass`
# MUST additionally key on each clean row's `basis` and `method`", and "a policy
# relaxed to admit `pass_indirect` MUST keep the rule, because the token states that
# some clean row is indirect and never which one."
#
# THE ASSERTION THAT DISCRIMINATES, and it is the first line of the body: the THRESHOLD
# is satisfied and the ROW GATE is not. Under the coupled flag this pair was
# unreachable, because the only arm that admitted `pass_indirect` was the one that also
# turned the row rule into a tautology, so `result_pass` and `clean_row_provenance_ok`
# could never disagree in this direction. Asserting `not isCompliant` alone would stay
# green under the defect — the statement was denied either way, but for the other
# reason — which is why the rule-level assertions are here rather than the verdict
# alone.
test_relaxed_threshold_keeps_the_row_gate if {
	consumer := _fresh_consumer({
		"accepted_results": ["pass", "pass_indirect"],
		"admit_unintercepted_clean_rows": false,
	})

	result_pass with input as _recordless_artifact with data.consumer as consumer
	not clean_row_provenance_ok with input as _recordless_artifact with data.consumer as consumer
	not isCompliant with input as _recordless_artifact with data.consumer as consumer
	_errors_contain(_recordless_artifact, "clean-row provenance") with data.consumer as consumer
}

# ...and the same statement IS admitted once the consumer declines the row obligation
# out loud, so the assertion above is measuring the row gate rather than a threshold
# that never moved.
test_relaxed_threshold_admits_once_the_row_obligation_is_declined if {
	consumer := _fresh_consumer({
		"accepted_results": ["pass", "pass_indirect"],
		"admit_unintercepted_clean_rows": true,
	})
	isCompliant with input as _recordless_artifact with data.consumer as consumer
}

# The row knob no longer moves the ordinal. On its own it is a no-op that an operator
# did not mean to write, and it denies rather than quietly narrowing a deployment whose
# consumer document still carries the old single flag.
test_row_knob_does_not_move_the_threshold if {
	consumer := _fresh_consumer({"admit_unintercepted_clean_rows": true})
	not isCompliant with input as _recordless_artifact with data.consumer as consumer
	not isCompliant with input as accept with data.consumer as consumer
	_errors_contain(accept, "declined the clean-row provenance obligation") with data.consumer as consumer
}

# ...and the ordinal cannot be relaxed with the row question left unanswered.
test_relaxed_threshold_must_answer_the_row_question if {
	consumer := _fresh_consumer({"accepted_results": ["pass", "pass_indirect"]})
	not isCompliant with input as _recordless_artifact with data.consumer as consumer
	not isCompliant with input as accept with data.consumer as consumer
	_errors_contain(accept, "has not said what it requires of a clean row") with data.consumer as consumer
}

# An absent pin takes the spec's own default, which is the strict end of the range: the
# live-interception accept is admitted and the indirect statement is not.
test_threshold_absent_takes_the_spec_default if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({})
	not isCompliant with input as _recordless_artifact with data.consumer as _fresh_consumer({})
	_errors_contain(_recordless_artifact, "is not one of the result tokens this consumer accepts") with data.consumer as _fresh_consumer({})
}

# A pin that is not one of the two admissible thresholds is a typo rather than a
# policy, and it denies a statement the default would have admitted rather than reading
# as absent. Four spellings: a token no admission gate should carry, the empty pin, a
# bare string that comprehends to nothing, and a set that is not downward-closed from
# the top and so names no threshold at all.
test_threshold_pin_of_the_wrong_shape_denies if {
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"accepted_results": ["pass", "degraded"]})
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"accepted_results": []})
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"accepted_results": "pass"})
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"accepted_results": ["pass_indirect"]})
	_errors_contain(accept, "is not an admission threshold over") with data.consumer as _fresh_consumer({"accepted_results": ["pass_indirect"]})
}

# The explicitly-pinned default is the shipped default, spelled out.
test_threshold_pinned_to_the_default_is_the_default if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({"accepted_results": ["pass"]})
	not isCompliant with input as _recordless_artifact with data.consumer as _fresh_consumer({"accepted_results": ["pass"]})
}

# A CAUGHT-label row is out of the gate's scope (its own basis/method is free; such a
# statement is kept out by the result recompute, not by this rule).
test_caught_row_not_subject_to_clean_row_gate if {
	stmt := object.union(accept, {
		"predicate": {
			"result": "fail",
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "egress_captured",
					"basis": "artifact",
					"method": "reconstructed",
					"attribution": "paired",
					"actualLayer": "policy.egress_sinkhole",
				},
			],
		},
	})
	clean_row_provenance_ok with input as stmt
}

# ── clean-row CONSISTENCY, and the row-rewrite attack it narrows ──────────────────
#
# A party holding the outer envelope key but not the substrate's observation key
# cannot forge a record, and does not need to: it rewrites the ROWS. Take a run that
# recomputes to "fail", relabel the caught row clean, set actualLayer to "none", point
# the row at the run-level records, declare result "pass". observationRecords and
# batchRoot come through byte-identical, so every record signature still verifies and
# the class match, which constrains the SHAPE of the reference graph, sees nothing
# wrong. The three assertions below walk that rewrite from the original run through
# both of its forms, and the third is the honest limit rather than a success.

# The original run: a caught row covered by an interception record, recomputing to
# "fail" and therefore never admitted whatever else holds.
_caught_run := object.union(accept, {
	"predicate": {
		"result": "fail",
		"observationRecords": [_arming_record, _sealed_record, _interception_record],
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "egress_captured",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "policy.egress_sinkhole",
				"observationRefs": [2],
			},
		],
	},
})

test_caught_run_sound_but_not_admitted if {
	soundness_ok with input as _caught_run
	not isCompliant with input as _caught_run
	_errors_contain(_caught_run, "is not one of the result tokens this consumer accepts (pass)")
}

# The rewrite that KEEPS citing the interception record. It is still structurally
# valid, and the reference verifiers accept it, yet the consumer refuses it, because the
# substrate signed that it intercepted traffic in this run while the row claims nothing
# was caught, and a consumer is not obliged to pick a half.
_rewritten_citing := object.union(_caught_run, {
	"predicate": {
		"result": "pass",
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "no_egress",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "none",
				"observationRefs": [0, 1, 2],
			},
		],
	},
})

test_reject_row_rewrite_citing_the_interception if {
	soundness_ok with input as _rewritten_citing
	not isCompliant with input as _rewritten_citing
	_errors_contain(_rewritten_citing, "references an interception record")
}

# The rewrite that DELETES the interception record instead of citing it IS ADMITTED,
# and that is asserted here so the rule's limit is a tested property rather than a
# claim in a comment. The surviving arming and sealed records say a vantage was armed
# and stayed armed; they say nothing whatever about what it saw. No contradiction
# survives anywhere in the bytes, so no consumer policy on any rail can find one. The
# reason is structural: an interception record names no attack identifier and no
# outcome, so nothing the substrate signs is bound to the per-row verdict a consumer
# reads. Closing it needs the substrate to sign that binding, which is a change to the
# evidence format rather than to this policy.
_rewritten_deleting := object.union(_caught_run, {
	"predicate": {
		"result": "pass",
		"observationRecords": [_arming_record, _sealed_record],
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "no_egress",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "none",
				"observationRefs": [0, 1],
			},
		],
	},
})

test_row_rewrite_deleting_the_interception_still_admitted if {
	isCompliant with input as _rewritten_deleting
}

# The rule reads the row's LABEL, not its basis or method, so an artifact-basis clean
# row citing an interception is refused on the same terms. Asserted under the
# provenance opt-in so the denial cannot be coming from the provenance gate instead.
test_reject_artifact_clean_row_citing_the_interception if {
	stmt := object.union(_rewritten_citing, {
		"predicate": {
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "no_egress",
					"basis": "artifact",
					"method": "reconstructed",
					"attribution": "paired",
					"actualLayer": "none",
					"observationRefs": [0, 1, 2],
				},
			],
		},
	})
	not isCompliant with input as stmt
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
	_errors_contain(stmt, "references an interception record")
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
}

# A CAUGHT row citing an interception record is the normal, correct shape and must not
# trip the rule. The caught statement above is sound, and the gate that keeps it out
# of an admitted statement is the result recompute.
test_caught_row_citing_interception_not_contradicted if {
	clean_row_uncontradicted_ok with input as _caught_run
}

# ── clean-row COVERAGE validity (spec: a clean row needs arming + covering sealed) ─
#
# This is a VALIDITY gate, not an admission threshold: it lives in soundness_ok, so
# the statements below are not merely un-admitted, they are structurally rejected —
# the same verdict the reference verifiers reach with primary code
# clean-row-uncovered. Every reject here is a single targeted mutation of the accept
# template, whose clean row IS properly covered (test_accept_admitted above is the
# positive anchor; the extra positives below keep each conditional branch honest).

# The exact hole this closes: a clean row whose only referenced record is an
# INTERCEPTION. The row claims "a live vantage saw nothing" and nothing in the
# statement says a vantage was ever armed.
# `aeePayloadCommitment` is required on this kind from 0.7 and had the same history
# as the two payloads above: absent from the fixture because nothing read its shape.
_interception_payload := {"aeeKind": "interception", "aeeMethod": "intercepted", "aeeRunBinding": _run_identity, "aeePayloadCommitment": [_hex]}

_interception_record := _record(_interception_payload)

_one_record(rec) := object.union(accept, {
	"predicate": {
		"observationRecords": [rec],
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "no_egress",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "none",
				"observationRefs": [0],
			},
		],
	},
})

# A sealed record mutated in one member, referenced alongside the good arming record.
_with_sealed(payload) := object.union(accept, {"predicate": {"observationRecords": [_arming_record, _record(payload)]}})

# An arming record mutated in one member, referenced alongside the good sealed record.
_with_arming(payload) := object.union(accept, {"predicate": {"observationRecords": [_record(payload), _sealed_record]}})

_uncovered(stmt) if {
	not soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "clean substrate/intercepted row is uncovered")
}

test_reject_clean_row_covered_only_by_interception if {
	_uncovered(_one_record(_interception_record))
}

test_reject_clean_row_missing_sealed if {
	_uncovered(_one_record(_arming_record))
}

test_reject_clean_row_missing_arming if {
	_uncovered(_one_record(_sealed_record))
}

# ── the sealed-covers conditions, each byte-pure and each its own reject ───────────

test_reject_sealed_still_armed_false if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeStillArmed": false})))
}

# The JSON literal true, not a truthy string: "true" must not cover.
test_reject_sealed_still_armed_non_boolean if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeStillArmed": "true"})))
}

test_reject_sealed_missing_still_armed if {
	_uncovered(_with_sealed(json.remove(_sealed_payload, ["aeeStillArmed"])))
}

# ── the run-level seal (aee-c-96) ─────────────────────────────────────────────────
#
# The three conditions above reach the seal THROUGH a clean row, so a statement
# with no clean row demanded no seal from anybody. These two take the same defects
# to a statement whose every row is caught, which is where the requirement used to
# disappear. `bad-1017-sole-seal-moat-down-all-caught` is the corpus vector for the
# first; the corpus tests catch it too, but they say "some vector" rather than
# which rule, and a rule with no test of its own is a rule the next edit can delete
# quietly.
test_reject_all_caught_sole_seal_moat_down if {
	stmt := _caught_stmt(
		[_interception_record, _record(object.union(_sealed_payload, {"aeeStillArmed": false}))],
		[0],
	)
	not run_seal_present_ok with input as stmt
	not soundness_ok with input as stmt
}

test_reject_substrate_row_with_no_seal_at_all if {
	stmt := _caught_stmt([_interception_record], [0])
	not run_seal_present_ok with input as stmt
	not soundness_ok with input as stmt
}

# The exemption is the reference rail's own precondition: a statement carrying no
# `basis: substrate` row makes no substrate claim, and an unconditional rule would
# deny `ok-007-artifact-only-recordless`, which the corpus accepts.
test_accept_recordless_artifact_statement_needs_no_seal if {
	run_seal_present_ok with input as _recordless_artifact
}

test_reject_sealed_missing_drop_count if {
	_uncovered(_with_sealed(json.remove(_sealed_payload, ["aeeDropCount"])))
}

# A non-zero drop count with NO bound declared beside it covers nothing.
test_reject_sealed_drops_without_bound if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeDropCount": 3})))
}

test_reject_sealed_drops_exceed_bound if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeDropCount": 4, "aeeDropBound": 3})))
}

# ...and the bound branch is not reject-all: drops WITHIN a declared bound cover.
test_accept_sealed_drops_within_bound if {
	stmt := _with_sealed(object.union(_sealed_payload, {"aeeDropCount": 3, "aeeDropBound": 3}))
	clean_row_coverage_ok with input as stmt
	isCompliant with input as stmt
}

# A negative drop count satisfies neither branch, bound or not.
test_reject_sealed_negative_drop_count if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeDropCount": -1, "aeeDropBound": 3})))
}

test_reject_sealed_posture_mismatch if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeePostureDigest": _corpus_digest})))
}

test_reject_sealed_missing_posture if {
	_uncovered(_with_sealed(json.remove(_sealed_payload, ["aeePostureDigest"])))
}

test_reject_sealed_method_reconstructed if {
	_uncovered(_with_sealed(object.union(_sealed_payload, {"aeeMethod": "reconstructed"})))
}

# ── the sealed record's agreement with the row's REFERENCED arming records ─────────
#
# The sealed condition the spec states twice: the posture digest equals the pinned
# one AND the arming record's. The second half is checked against every arming record
# the ROW REFERENCES, not against the subset that ends up covering it, so a row
# citing one good arming record beside a second one that names a different vantage is
# uncovered. Two referenced arming records that disagree about the vantage is what a
# statement looks like when the records of two runs are spliced into one.

# A row citing three records, so the second arming record is genuinely referenced
# rather than merely present in the array.
_three_record_clean_row(records) := object.union(accept, {
	"predicate": {
		"observationRecords": records,
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "no_egress",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "none",
				"observationRefs": [0, 1, 2],
			},
		],
	},
})

# A second live vantage, distinguishable from the first by its producer note and
# agreeing with it about the posture. This is the shipped two-arming-record shape.
_second_arming_record := _record(object.union(_arming_payload, {"producerNote": "example arming vantage b"}))

test_accept_two_agreeing_arming_records if {
	stmt := _three_record_clean_row([_arming_record, _sealed_record, _second_arming_record])
	soundness_ok with input as stmt
	isCompliant with input as stmt
}

test_reject_sealed_disagrees_with_referenced_arming if {
	off := _record(object.union(_arming_payload, {"aeePostureDigest": _corpus_digest}))
	_uncovered(_three_record_clean_row([_arming_record, _sealed_record, off]))
}

# An arming record whose aeePostureDigest is not a STRING names no vantage, so it
# contributes no disagreement. It covers nothing on its own account. The
# reference verifiers build the comparison set the same way, from the referenced
# arming records that carry a posture digest string and no others.
test_accept_referenced_arming_with_non_string_posture_does_not_disagree if {
	odd := _record(object.union(_arming_payload, {"aeePostureDigest": 0}))
	stmt := _three_record_clean_row([_arming_record, _sealed_record, odd])
	soundness_ok with input as stmt
	isCompliant with input as stmt
}

# ── the arming-covers conditions ──────────────────────────────────────────────────

test_reject_arming_missing_armed_at if {
	_uncovered(_with_arming(json.remove(_arming_payload, ["armedAt"])))
}

test_reject_arming_armed_at_after_issued_at if {
	_uncovered(_with_arming(object.union(_arming_payload, {"armedAt": "2026-06-01T00:00:00Z"})))
}

# A non-zero UTC offset parses as a valid instant but is not UTC.
test_reject_arming_armed_at_non_utc_offset if {
	_uncovered(_with_arming(object.union(_arming_payload, {"armedAt": "2026-01-01T04:59:00+05:00"})))
}

# ...and the zero-offset form spelled +00:00 rather than Z still covers.
test_accept_arming_armed_at_explicit_zero_offset if {
	stmt := _with_arming(object.union(_arming_payload, {"armedAt": "2025-12-31T23:59:00+00:00"}))
	clean_row_coverage_ok with input as stmt
	isCompliant with input as stmt
}

test_reject_arming_posture_mismatch if {
	_uncovered(_with_arming(object.union(_arming_payload, {"aeePostureDigest": _corpus_digest})))
}

test_reject_arming_method_reconstructed if {
	_uncovered(_with_arming(object.union(_arming_payload, {"aeeMethod": "reconstructed"})))
}

# Read-first: a carried binding version this module does not implement covers nothing.
#
# THE VERSION NAMED HERE HAS TO MOVE WHENEVER THE IMPLEMENTED CONSTRUCTION MOVES, and
# so does the one in the accept below it. The statement each builds is valid in every
# other respect, so the whole assertion rests on the declared version being on the
# correct side of what the module implements. Left behind, this pair inverts silently:
# the reject names the version that has newly become current, so it builds a statement
# the module accepts and asserts nothing at all, while the accept names a retired
# version and starts measuring the rejection path.
test_reject_arming_unimplemented_binding_version if {
	_uncovered(_with_arming(object.union(_arming_payload, {"aeeBindingVersion": "3"})))
}

test_accept_arming_implemented_binding_version if {
	stmt := _with_arming(object.union(_arming_payload, {"aeeBindingVersion": "2"}))
	clean_row_coverage_ok with input as stmt
	isCompliant with input as stmt
}

# ── the OPTIONAL arming chain members, checked as a set ───────────────────────────

_chained := object.union(_arming_payload, {"aeeRunSeq": 2, "aeePrevRunBinding": _corpus_digest, "aeeChainScope": ["corpus", "subject"]})

test_accept_arming_valid_chain if {
	stmt := _with_arming(_chained)
	clean_row_coverage_ok with input as stmt
	isCompliant with input as stmt
}

test_reject_arming_chain_runseq_zero if {
	_uncovered(_with_arming(object.union(_chained, {"aeeRunSeq": 0})))
}

test_reject_arming_chain_missing_scope if {
	_uncovered(_with_arming(json.remove(_chained, ["aeeChainScope"])))
}

test_reject_arming_chain_scope_unknown_token if {
	_uncovered(_with_arming(object.union(_chained, {"aeeChainScope": ["corpus", "tenant"]})))
}

test_reject_arming_chain_scope_unsorted if {
	_uncovered(_with_arming(object.union(_chained, {"aeeChainScope": ["subject", "corpus"]})))
}

test_reject_arming_chain_scope_duplicate if {
	_uncovered(_with_arming(object.union(_chained, {"aeeChainScope": ["corpus", "corpus"]})))
}

test_reject_arming_chain_prev_not_hex if {
	_uncovered(_with_arming(object.union(_chained, {"aeePrevRunBinding": "not-hex"})))
}

# A chain member present WITHOUT the sequence number it is anchored on is fail-closed.
test_reject_arming_chain_member_without_runseq if {
	_uncovered(_with_arming(object.union(_arming_payload, {"aeeChainScope": ["subject"]})))
}

# ── the reference graph the coverage requirement reads ────────────────────────────

test_reject_clean_row_refs_absent if {
	stmt := object.union(accept, {"predicate": {"attackResults": [json.remove(accept.predicate.attackResults[0], ["observationRefs"])]}})
	_uncovered(stmt)
}

test_reject_clean_row_refs_empty if {
	stmt := object.union(accept, {"predicate": {"attackResults": [object.union(accept.predicate.attackResults[0], {"observationRefs": []})]}})
	_uncovered(stmt)
}

test_reject_clean_row_ref_out_of_range if {
	stmt := object.union(accept, {"predicate": {"attackResults": [object.union(accept.predicate.attackResults[0], {"observationRefs": [0, 1, 7]})]}})
	_uncovered(stmt)
}

test_reject_clean_row_ref_negative if {
	stmt := object.union(accept, {"predicate": {"attackResults": [object.union(accept.predicate.attackResults[0], {"observationRefs": [0, 1, -1]})]}})
	_uncovered(stmt)
}

test_reject_clean_row_ref_non_integer if {
	stmt := object.union(accept, {"predicate": {"attackResults": [object.union(accept.predicate.attackResults[0], {"observationRefs": [0, 1.5]})]}})
	_uncovered(stmt)
}

# A record whose media type is not +json covers nothing, however well-formed the
# payload it carries is.
test_reject_covering_record_media_type if {
	rebranded := object.union(_sealed_record, {"payloadType": "application/octet-stream"})
	_uncovered(object.union(accept, {"predicate": {"observationRecords": [_arming_record, rebranded]}}))
}

# ── the gate's SCOPE: it governs clean substrate/intercepted rows and nothing else ─

# A caught row takes the INTERCEPTION arm of the same class match (asserted in its
# own section below); the clean-row gate must not fire on it, and must not be a back
# door either — the result recompute is what keeps a caught row out of an ADMITTED
# statement.
test_caught_row_out_of_coverage_gate_scope if {
	stmt := _caught_stmt([_interception_record, _sealed_record], [0])
	clean_row_coverage_ok with input as stmt
	caught_row_coverage_ok with input as stmt
	soundness_ok with input as stmt
	not isCompliant with input as stmt
}

# An artifact-basis clean row carries no substrate claim, so it is out of scope too.
test_artifact_clean_row_out_of_coverage_gate_scope if {
	clean_row_coverage_ok with input as _recordless_artifact
}

# Declining the row obligation relaxes PROVENANCE (an admission threshold) and must NOT
# relax COVERAGE (a validity rule) — an uncovered clean row is malformed under every
# consumer policy. Both consumer declarations are made here so the denial cannot be
# coming from the coherence guard on the pair.
test_optin_does_not_relax_clean_row_coverage if {
	stmt := _one_record(_interception_record)
	not isCompliant with input as stmt
		with data.consumer.accepted_results as ["pass", "pass_indirect"]
		with data.consumer.admit_unintercepted_clean_rows as true
}

# ── the CAUGHT + RECONSTRUCTED arms of the same class match ───────────────────────
#
# A caught label forces the recompute to "fail", so a caught statement is never
# ADMITTED whatever its coverage. Its class match is therefore a VALIDITY question
# and the positive anchors below assert `soundness_ok`, not `isCompliant` — without
# them these two arms could pass by rejecting every caught and reconstructed row.

_examination_payload := {"aeeKind": "examination", "aeeMethod": "reconstructed", "aeeRunBinding": _run_identity}

_examination_record := _record(_examination_payload)

# A caught (result:"fail") statement whose single substrate/intercepted row cites the
# supplied records at the supplied indices.
_caught_stmt(records, refs) := object.union(accept, {
	"predicate": {
		"result": "fail",
		"observationRecords": records,
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "egress_captured",
				"basis": "substrate",
				"method": "intercepted",
				"attribution": "paired",
				"actualLayer": "policy.egress_sinkhole",
				"observationRefs": refs,
			},
		],
	},
})

_caught_uncovered(stmt) if {
	not soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "caught substrate/intercepted row is uncovered")
}

# The positive anchor: a genuine caught row covered by an interception record IS
# structurally sound (and is kept out of admission by the result recompute alone).
test_accept_caught_row_covered_by_interception if {
	stmt := _caught_stmt([_interception_record, _sealed_record], [0])
	caught_row_coverage_ok with input as stmt
	soundness_ok with input as stmt
}

# The exact hole this closes: a caught row whose only referenced record is the run's
# ARMING record. Something was armed; nothing says this attack was intercepted.
test_reject_caught_row_covered_only_by_arming if {
	_caught_uncovered(_caught_stmt([_arming_record], [0]))
}

test_reject_caught_row_covered_only_by_sealed if {
	_caught_uncovered(_caught_stmt([_sealed_record], [0]))
}

test_reject_caught_row_covered_only_by_examination if {
	_caught_uncovered(_caught_stmt([_examination_record], [0]))
}

# ── the reference graph, now read on a CAUGHT row too ─────────────────────────────

test_reject_caught_row_refs_empty if {
	_caught_uncovered(_caught_stmt([_interception_record], []))
}

test_reject_caught_row_refs_absent if {
	stmt := json.remove(_caught_stmt([_interception_record], [0]), ["predicate/attackResults/0/observationRefs"])
	_caught_uncovered(stmt)
}

test_reject_caught_row_ref_out_of_range if {
	_caught_uncovered(_caught_stmt([_interception_record], [0, 4]))
}

test_reject_caught_row_ref_negative if {
	_caught_uncovered(_caught_stmt([_interception_record], [-1]))
}

test_reject_caught_row_ref_non_integer if {
	_caught_uncovered(_caught_stmt([_interception_record], [0.5]))
}

# ── the interception class's own constraints ──────────────────────────────────────

# A record whose media type is not +json covers nothing, interception or otherwise.
test_reject_interception_wrong_media_type if {
	rebranded := object.union(_interception_record, {"payloadType": "application/octet-stream"})
	_caught_uncovered(_caught_stmt([rebranded], [0]))
}

test_reject_interception_missing_kind if {
	_caught_uncovered(_caught_stmt([_record(json.remove(_interception_payload, ["aeeKind"]))], [0]))
}

test_reject_interception_missing_method if {
	_caught_uncovered(_caught_stmt([_record(json.remove(_interception_payload, ["aeeMethod"]))], [0]))
}

test_reject_interception_out_of_vocabulary_method if {
	_caught_uncovered(_caught_stmt([_record(object.union(_interception_payload, {"aeeMethod": "inferred"}))], [0]))
}

# ── the RECONSTRUCTED arm: an examination record, whatever the row's label ────────

_clean_reconstructed(records, refs) := object.union(accept, {
	"predicate": {
		"result": "pass_indirect",
		"observationRecords": records,
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "no_egress",
				"basis": "substrate",
				"method": "reconstructed",
				"attribution": "paired",
				"actualLayer": "none",
				"observationRefs": refs,
			},
		],
	},
})

_caught_reconstructed(records, refs) := object.union(accept, {
	"predicate": {
		"result": "fail",
		"observationRecords": records,
		"attackResults": [
			{
				"attackId": "XA-1",
				"containmentObserved": "egress_captured",
				"basis": "substrate",
				"method": "reconstructed",
				"attribution": "paired",
				"actualLayer": "policy.egress_sinkhole",
				"observationRefs": refs,
			},
		],
	},
})

_reconstructed_uncovered(stmt) if {
	not soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "method:reconstructed is uncovered")
}

# A reconstructed CLEAN row takes the examination arm, NOT arming + sealed: covered
# by an examination record it is structurally sound, and the default clean-row
# PROVENANCE gate is what keeps it out of an admitted statement.
test_accept_reconstructed_clean_row_covered_by_examination if {
	stmt := _clean_reconstructed([_examination_record, _sealed_record], [0])
	reconstructed_row_coverage_ok with input as stmt
	clean_row_coverage_ok with input as stmt
	soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "clean-row provenance")
}

# ...and the same row citing the arming + sealed pair instead is INVALID: the
# clean-row rule does not govern a reconstructed row, and its own arm is unsatisfied.
test_reject_reconstructed_clean_row_covered_by_arming_and_sealed if {
	stmt := _clean_reconstructed([_arming_record, _sealed_record], [0, 1])
	clean_row_coverage_ok with input as stmt
	_reconstructed_uncovered(stmt)
}

test_accept_caught_reconstructed_row_covered_by_examination if {
	stmt := _caught_reconstructed([_examination_record, _sealed_record], [0])
	reconstructed_row_coverage_ok with input as stmt
	caught_row_coverage_ok with input as stmt
	soundness_ok with input as stmt
}

test_reject_caught_reconstructed_row_covered_by_interception if {
	_reconstructed_uncovered(_caught_reconstructed([_interception_record], [0]))
}

# An examination record signed `intercepted` violates its class and covers nothing.
test_reject_examination_signed_intercepted if {
	rec := _record(object.union(_examination_payload, {"aeeMethod": "intercepted"}))
	_reconstructed_uncovered(_caught_reconstructed([rec], [0]))
}

test_reject_reconstructed_row_refs_empty if {
	_reconstructed_uncovered(_caught_reconstructed([_examination_record], []))
}

test_reject_reconstructed_row_ref_out_of_range if {
	_reconstructed_uncovered(_caught_reconstructed([_examination_record], [3]))
}

# ── every REFERENCED payload must be readable, not merely the covering one ────────

test_reject_unreadable_record_beside_a_covering_one if {
	opaque := object.union(_interception_record, {"payloadType": "application/octet-stream"})
	stmt := _caught_stmt([_interception_record, opaque], [0, 1])
	caught_row_coverage_ok with input as stmt
	not soundness_ok with input as stmt
	_errors_contain(stmt, "references a record this policy cannot read")
}

# ...and the same shape with both records readable is sound (not reject-all).
test_accept_two_readable_referenced_records if {
	stmt := _caught_stmt([_interception_record, _arming_record, _sealed_record], [0, 1])
	referenced_records_ok with input as stmt
	soundness_ok with input as stmt
}

# An ARTIFACT row is outside the coverage requirements entirely, so a reference it
# carries is not read here (the recordless artifact statement stays sound).
test_artifact_row_outside_referenced_records_rule if {
	referenced_records_ok with input as _recordless_artifact
	soundness_ok with input as _recordless_artifact
}

# ── the method cap ────────────────────────────────────────────────────────────────

_capped(stmt) if {
	not soundness_ok with input as stmt
	not isCompliant with input as stmt
	_errors_contain(stmt, "method cap")
}

_weak_interception := _record(object.union(_interception_payload, {"aeeMethod": "reconstructed"}))

# An interception record signed `reconstructed` is a VALID record — it satisfies the
# class match — but it caps the row it covers at `reconstructed`, so a row claiming
# `intercepted` on it alone is invalid.
test_reject_method_cap_single_record if {
	stmt := _caught_stmt([_weak_interception], [0])
	caught_row_coverage_ok with input as stmt
	_capped(stmt)
}

# The cap reads the WEAKEST covering record: one good interception does not rescue a
# row that also rests on a reconstructed one.
test_reject_method_cap_multi_record if {
	stmt := _caught_stmt([_interception_record, _weak_interception], [0, 1])
	caught_row_coverage_ok with input as stmt
	_capped(stmt)
}

# ...and a referenced record that COVERS NOTHING caps nothing: an examination record
# cited beside a covering interception leaves the row at `intercepted`.
test_accept_non_covering_record_does_not_cap if {
	stmt := _caught_stmt([_interception_record, _examination_record, _sealed_record], [0, 1])
	method_cap_ok with input as stmt
	soundness_ok with input as stmt
}

# The cap never fires on a row that already claims `reconstructed` — it is already at
# the bottom of the ordering.
test_accept_reconstructed_row_never_capped if {
	stmt := _caught_reconstructed([_examination_record, _sealed_record], [0])
	method_cap_ok with input as stmt
	soundness_ok with input as stmt
}

# The clean arm cannot be capped either: an arming or sealed record must itself be
# `intercepted` to cover at all, so the shipped accept template is uncapped.
test_accept_clean_row_never_capped if {
	method_cap_ok with input as accept
	isCompliant with input as accept
}

# ── policy-replay anchors (consumer data.consumer) on the clean accept ─────────────

test_stale_catch_policy_rejected if {
	not isCompliant with input as accept
		with data.consumer.expected_catch_policy_digest as "0000000000000000000000000000000000000000000000000000000000000000"
	_errors_contain(accept, "does not equal the pinned expected_catch_policy_digest") with data.consumer.expected_catch_policy_digest as "0000000000000000000000000000000000000000000000000000000000000000"
}

test_stale_posture_rejected if {
	not isCompliant with input as accept
		with data.consumer.allowed_network_postures as {"no_network", "allowlist"}
}

test_allowed_posture_admitted if {
	isCompliant with input as accept
		with data.consumer.allowed_network_postures as {"sinkhole"}
}

# ── consumer anchors: the pinned corpus + substrate (spec MUST) ───────────────────
#
# spec "Consumer policy obligations": a consumer MUST pin, out of band, the corpus and
# substrate digests it expects and MUST compare them at consumption. Everything else
# this module checks about the corpus is self-consistency, which costs an
# envelope-key-only attacker nothing (see the erasure section below).

# A well-formed digest that is not the template's corpus or substrate digest.
_other_hex := "2222222222222222222222222222222222222222222222222222222222222222"

# The pins mounted by test_consumer_pins.json must BE the template's own digests. If
# the template ever changes shape, this reddens instead of letting the whole suite
# silently start running as an anchor-mismatched consumer.
test_consumer_pins_match_template if {
	data.consumer.expected_corpus_digest == _corpus_digest
	data.consumer.expected_substrate_digest == _hex
	data.consumer.demanded_classes == ["XA"]
}

# Supplied and matching: admitted. This is the posture the rest of the suite runs in.
test_anchor_pinned_and_matching_admitted if {
	consumer_anchors_ok with input as accept
	isCompliant with input as accept
	count(errors) == 0 with input as accept
}

# Supplied and MISMATCHED, corpus arm: denied, and attributed to the corpus anchor.
test_anchor_corpus_mismatch_denied if {
	not isCompliant with input as accept
		with data.consumer.expected_corpus_digest as _other_hex
	_errors_contain(accept, "does not equal the pinned expected_corpus_digest") with data.consumer.expected_corpus_digest as _other_hex
}

# Supplied and MISMATCHED, substrate arm: denied separately, on its own message.
test_anchor_substrate_mismatch_denied if {
	not isCompliant with input as accept
		with data.consumer.expected_substrate_digest as _other_hex
	_errors_contain(accept, "does not equal the pinned expected_substrate_digest") with data.consumer.expected_substrate_digest as _other_hex
}

# A statement carrying NO substrate digest cannot satisfy a pinned substrate anchor
# either — the equality is undefined, which fail-closes rather than matching.
test_anchor_missing_substrate_digest_denied if {
	stmt := json.remove(accept, ["predicate/observationEnvironment/substrate"])
	not isCompliant with input as stmt
	_errors_contain(stmt, "does not equal the pinned expected_substrate_digest")
}

# ── the absent-anchor decision, asserted in both directions ───────────────────────
#
# DECIDED: absence DENIES. The spec's obligation is a MUST on the consumer, and a
# policy that treats an absent MUST as vacuously satisfied has implemented a SHOULD.
# The full argument, including why the two older anchors keep the permissive default,
# is in "THE ABSENT-ANCHOR DECISION" in execution_evidence.rego.
test_anchor_absent_denied_by_default if {
	not isCompliant with input as accept with data.consumer as {}
	_errors_contain(accept, "no expected corpus digest is pinned") with data.consumer as {}
	_errors_contain(accept, "no expected substrate digest is pinned") with data.consumer as {}
}

# One pin without the other is still an unpinned consumer for the missing arm.
test_anchor_partial_pin_denied if {
	not isCompliant with input as accept
		with data.consumer as {"expected_corpus_digest": _corpus_digest}
	_errors_contain(accept, "no expected substrate digest is pinned") with data.consumer as {"expected_corpus_digest": _corpus_digest}
}

# The opt-out is EXPLICIT and re-opens exactly this hole, which is why it must be said
# rather than fallen into.
test_anchor_absent_admitted_under_explicit_optout if {
	isCompliant with input as accept
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true}
}

# ...and it is literal-true, so a typo fails closed (same posture as the clean-row
# opt-in).
test_anchor_optout_requires_literal_true if {
	not isCompliant with input as accept
		with data.consumer as {"allow_unpinned_anchors": "true", "allow_unpinned_scope": true}
}

# The opt-out is NARROW: it excuses an ABSENT pin, never a MISMATCHED one. A consumer
# that named a context is held to it.
test_anchor_optout_does_not_excuse_mismatch if {
	not isCompliant with input as accept
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true, "expected_corpus_digest": _other_hex}
	not isCompliant with input as accept
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true, "expected_substrate_digest": _other_hex}
}

# ── the demanded-scope pin, and the withdrawal it is the only answer to ───────────
#
# A producer that withdraws a class rather than failing it emits a statement
# byte-identical to the one an honest producer with no coverage of that class emits.
# There is therefore no pair of vectors here, and there cannot be: the discrimination
# is entirely in the consumer context, so the SAME statement is read twice under two
# demands, exactly as the anchor tests read one statement under a matching and a
# mismatching pin.
#
# The fixture is artifact-basis and recordless on purpose. That is the shape the
# measurement found the two readings collapse onto, and it also keeps the statement
# free of records that would have to be rebound, so the verdicts below are
# attributable to the scope rule alone.
_gap_manifest := {"classes": {"XA": ["XA-1"], "XB": ["XB-1"]}}

_gap_disclosing := json.remove(
	object.union(accept, {
		"predicate": {
			"result": "degraded",
			"observationEnvironment": {
				"corpus": {
					"manifest": _gap_manifest,
					"digest": {"sha256": crypto.sha256(json.marshal(_gap_manifest))},
				},
			},
			"coverage": {
				"assessedClasses": ["XA"],
				"outOfScope": {},
				"routedElsewhere": {"XB": "handled by the platform team"},
			},
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "no_egress",
					"basis": "artifact",
					"method": "reconstructed",
					"attribution": "paired",
					"actualLayer": "none",
				},
			],
		},
	}),
	["predicate/observationRecords", "predicate/batchRoot"],
)

_demand(classes) := {
	"demanded_classes": classes,
	"expected_corpus_digest": crypto.sha256(json.marshal(_gap_manifest)),
	"expected_substrate_digest": _hex,
}

# The statement is VALID under both readings. The pin is an admission gate and not a
# validity one, for the same reason the corpus anchor is: validity is a function of
# carried bytes and holds identically for every consumer, and here the bytes are
# provably the same bytes an honest producer emits.
test_demanded_scope_is_not_a_validity_gate if {
	soundness_ok with input as _gap_disclosing
	soundness_ok with input as _gap_disclosing with data.consumer as _demand(["XA", "XB"])
}

# A class this deployment never demanded, disclosed as handled elsewhere: the scope
# rule has nothing to say, which is the honest gap being left alone.
test_undemanded_class_disclosed_is_not_a_scope_failure if {
	demanded_scope_ok with input as _gap_disclosing with data.consumer as _demand(["XA"])
}

# The same bytes, read by a deployment that demanded the class: refused, and the error
# names the class rather than the shape of the statement.
test_demanded_class_withdrawn_is_denied if {
	not demanded_scope_ok with input as _gap_disclosing with data.consumer as _demand(["XA", "XB"])
	_errors_contain(_gap_disclosing, "asked for and did not get") with data.consumer as _demand(["XA", "XB"])
}

# What the rule reaches that the shipped pass-only threshold cannot. A gap-disclosing
# statement recomputes to "degraded" and is denied by result_pass under EVERY demand,
# so on this rail the disclosure form never reaches the scope rule. The form that does
# is a clean PASS over a corpus whose manifest never declared the demanded class at
# all: every other rule in the module holds, the result is "pass", and only the demand
# refuses it.
test_demanded_class_absent_from_the_corpus_denies_a_passing_statement if {
	isCompliant with input as accept with data.consumer as _template_demand(["XA"])
	not isCompliant with input as accept with data.consumer as _template_demand(["XA", "XB"])
	soundness_ok with input as accept with data.consumer as _template_demand(["XA", "XB"])
	_errors_contain(accept, "asked for and did not get") with data.consumer as _template_demand(["XA", "XB"])
}

_template_demand(classes) := {
	"demanded_classes": classes,
	"expected_corpus_digest": _corpus_digest,
	"expected_substrate_digest": _hex,
}

# A passing statement that assessed MORE than any single demand names. The two fixtures
# above both carry a demanded set equal to the assessed set, so neither can tell a
# subset comparison from an equality one, and a rule written as equality passed both.
# This one separates them: a deployment that asked for one class must admit a run that
# assessed it and another beside it, or the demand has quietly become a ceiling as well
# as a floor and every producer adding a class breaks every consumer.
_two_class_manifest := {"classes": {"XA": ["XA-1"], "XB": ["XB-1"]}}

# The identity the two-class statement's records must bind to, derived over the same
# posture object and digest map `_with_binding_digests` uses, so the two cannot drift.
_two_class_identity := _identity(
	_posture_object(_default_binding_digests.networkPosture),
	object.union(
		_default_binding_digests,
		{"corpus": crypto.sha256(json.marshal(_two_class_manifest))},
	),
)

# This statement assesses TWO classes, so its arming record has to declare both
# identifiers. `_with_binding_digests` rebuilds the record set from `_arming_payload`,
# which declares only the one identifier the single-class manifest carries, and the
# run-level subset rule reads the record against the coverage the statement actually
# claims. Overriding the record here rather than widening the shared payload keeps
# every other fixture on the single-class declaration it is written for.
_two_class_assessed := object.union(
	_with_binding_digests({"corpus": crypto.sha256(json.marshal(_two_class_manifest))}),
	{
		"predicate": {
			"observationEnvironment": {"corpus": {"manifest": _two_class_manifest}},
			"observationRecords": [
				_record(object.union(_arming_payload, {
					"aeeRunBinding": _two_class_identity,
					"aeeAssessedAttacks": ["XA-1", "XB-1"],
				})),
				_record(object.union(_sealed_payload, {"aeeRunBinding": _two_class_identity})),
			],
			"coverage": {"assessedClasses": ["XA", "XB"], "outOfScope": {}, "routedElsewhere": {}},
			"attackResults": [
				{
					"attackId": "XA-1",
					"containmentObserved": "no_egress",
					"basis": "substrate",
					"method": "intercepted",
					"attribution": "paired",
					"actualLayer": "none",
					"observationRefs": [0, 1],
				},
				{
					"attackId": "XB-1",
					"containmentObserved": "no_egress",
					"basis": "substrate",
					"method": "intercepted",
					"attribution": "paired",
					"actualLayer": "none",
					"observationRefs": [0, 1],
				},
			],
		},
	},
)

_two_class_demand(classes) := {
	"demanded_classes": classes,
	"expected_corpus_digest": crypto.sha256(json.marshal(_two_class_manifest)),
	"expected_substrate_digest": _hex,
}

test_demand_is_a_lower_bound_not_an_equality if {
	isCompliant with input as _two_class_assessed with data.consumer as _two_class_demand(["XA"])
	isCompliant with input as _two_class_assessed with data.consumer as _two_class_demand(["XA", "XB"])
	not isCompliant with input as _two_class_assessed with data.consumer as _two_class_demand(["XA", "XC"])
}

# ── the absent-scope decision, asserted in both directions ────────────────────────
#
# DECIDED: absence DENIES, and the argument is not the one the corpus and substrate
# anchors rest on. It is at the rule in execution_evidence.rego: an unpinned corpus
# anchor still leaves a consumer every self-consistency rule in the module, while an
# unpinned scope demand leaves it nothing at all, because the attack is invisible in
# the bytes by construction.
test_demanded_scope_absent_denied_by_default if {
	not isCompliant with input as accept
		with data.consumer as {"expected_corpus_digest": _corpus_digest, "expected_substrate_digest": _hex}
	_errors_contain(accept, "no demanded scope is pinned") with data.consumer as {"expected_corpus_digest": _corpus_digest, "expected_substrate_digest": _hex}
}

test_demanded_scope_absent_admitted_under_explicit_optout if {
	isCompliant with input as accept
		with data.consumer as {"expected_corpus_digest": _corpus_digest, "expected_substrate_digest": _hex, "allow_unpinned_scope": true}
}

# Literal true, so a typo fails closed, the same posture as the anchor opt-out and
# the clean-row opt-in.
test_demanded_scope_optout_requires_literal_true if {
	not isCompliant with input as accept
		with data.consumer as {"expected_corpus_digest": _corpus_digest, "expected_substrate_digest": _hex, "allow_unpinned_scope": "true"}
}

# An EMPTY demand is not a demand. It admits every withdrawal exactly as the opt-out
# does, and says nothing about the cost, so it lands on the not-pinned arm rather than
# being read as a consumer that genuinely requires no class.
test_demanded_scope_empty_pin_is_not_a_pin if {
	not isCompliant with input as accept with data.consumer as _template_demand([])
	_errors_contain(accept, "no demanded scope is pinned") with data.consumer as _template_demand([])
}

# ...and neither is a value of the wrong shape. A bare string comprehends to the empty
# set here, which fails closed onto the same arm instead of silently demanding nothing.
test_demanded_scope_non_array_pin_is_not_a_pin if {
	not isCompliant with input as accept with data.consumer as _template_demand("XA")
	_errors_contain(accept, "no demanded scope is pinned") with data.consumer as _template_demand("XA")
}

# The opt-out is NARROW, like the anchor one: it excuses an ABSENT demand, never an
# unmet one. A consumer that named a class is held to it.
test_demanded_scope_optout_does_not_excuse_an_unmet_demand if {
	not isCompliant with input as accept
		with data.consumer as object.union(_template_demand(["XA", "XB"]), {"allow_unpinned_scope": true})
}

# ── the instant profile: one rule, two fields, two independent halves ─────────────
#
# The published corpus vendored under this directory PREDATES the vectors that pin the
# zero-offset spellings, so the behavior is held here instead. That is deliberate and
# is the reason these tests are unusually literal about the spellings they drive.
_with_issued(v) := object.union(accept, {"predicate": {"issuedAt": v}})

_with_armed(v) := object.union(accept, {
	"predicate": {
		"observationRecords": [
			_record(object.union(_arming_payload, {"armedAt": v})),
			_sealed_record,
		],
	},
})

# A NEGATIVE ZERO OFFSET IS CONFORMANT. The pattern this replaces matched `Z` or
# `+00:00` and denied `-00:00`, a spelling every reference rail accepts: it names the
# same instant and says only that the offset to local time is unknown, which is a fact
# about where the producer stood rather than about when it signed. All three spellings
# are one instant and the profile treats them as one.
test_instant_profile_admits_every_zero_offset_spelling_on_issued_at if {
	every v in ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00-00:00"] {
		isCompliant with input as _with_issued(v) with data.consumer as _fresh_consumer({})
	}
}

test_instant_profile_admits_every_zero_offset_spelling_on_armed_at if {
	every v in ["2025-12-31T23:59:00Z", "2025-12-31T23:59:00+00:00", "2025-12-31T23:59:00-00:00"] {
		isCompliant with input as _with_armed(v) with data.consumer as _fresh_consumer({})
	}
}

# The ZONE half, which is the falsifiable one on this rail: a non-zero offset names a
# real instant and is still outside the profile. Driven on both fields, because the
# defect being corrected was that only one of them carried the rule.
test_instant_profile_refuses_a_non_zero_offset_on_both_fields if {
	not isCompliant with input as _with_issued("2026-01-01T00:00:00+05:00") with data.consumer as _fresh_consumer({})
	_errors_contain(_with_issued("2026-01-01T00:00:00+05:00"), "instant profile")
	not isCompliant with input as _with_armed("2025-12-31T23:59:00+05:00") with data.consumer as _fresh_consumer({})
}

# The CASE half. On this rail OPA's own parser also refuses a lowercase designator, so
# these inputs are refused twice over and no input distinguishes the pattern from the
# parser; the assertion is kept because the behavior is what the rails agree on, and
# the redundancy is recorded at the rule rather than discovered later.
test_instant_profile_refuses_a_lowercase_designator_on_both_fields if {
	not isCompliant with input as _with_issued("2026-01-01T00:00:00z") with data.consumer as _fresh_consumer({})
	not isCompliant with input as _with_armed("2025-12-31T23:59:00z") with data.consumer as _fresh_consumer({})
}

test_instant_profile_refuses_a_lowercase_separator if {
	not isCompliant with input as _with_issued("2026-01-01t00:00:00Z") with data.consumer as _fresh_consumer({})
}

test_instant_profile_refuses_a_leap_second if {
	not isCompliant with input as _with_issued("2026-01-01T00:00:60Z") with data.consumer as _fresh_consumer({})
}

# Fractional seconds stay INSIDE the profile, matching the reference rails. Recorded as
# an accept so a later tightening on this rail cannot drift away from them in silence.
test_instant_profile_admits_fractional_seconds if {
	isCompliant with input as _with_issued("2026-01-01T00:00:00.500Z") with data.consumer as _fresh_consumer({})
}

# The issue timestamp is REQUIRED and carries the profile in its own right, so a
# statement is refused for its spelling whether or not it carries a record that would
# have compared against it.
test_instant_profile_requires_the_issue_timestamp if {
	stmt := json.remove(accept, ["predicate/issuedAt"])
	not isCompliant with input as stmt with data.consumer as _fresh_consumer({})
	_errors_contain(stmt, "instant profile")
}

# ...and RECORDLESS is where that clause earns its keep, which the first spelling of
# these tests missed. On a statement carrying an arming record the profile is reached
# twice: `issued_at_ok` states it, and `_armed_at_ok` also parses issuedAt to compare
# against, so removing the rule from soundness_ok left every assertion above green and
# only the corpus test went red. An artifact-only statement has no arming record, no
# ordering comparison, and therefore exactly one rule standing between a misspelled
# issue timestamp and admission. That is the shape the reference rails reject too, and
# it is the one this test drives.
test_instant_profile_on_a_statement_with_no_records if {
	consumer := _fresh_consumer(_indirect_consumer)
	isCompliant with input as _recordless_artifact with data.consumer as consumer
	bad := object.union(_recordless_artifact, {"predicate": {"issuedAt": "2026-01-01T00:00:00+05:00"}})
	not isCompliant with input as bad with data.consumer as consumer
	_errors_contain(bad, "instant profile") with data.consumer as consumer
}

# THE ASYMMETRY IS GONE. The defect this replaces was two rules for one profile: the
# armed timestamp pinned a zero offset and the issue timestamp pinned nothing, so the
# identical string was refused on one field and admitted on the other a few members
# away. Both directions are asserted on both fields, which is what a single shared rule
# buys and what two patterns would eventually lose.
test_instant_profile_does_not_differ_between_the_two_fields if {
	not isCompliant with input as _with_issued("2026-01-01T00:00:00+05:00") with data.consumer as _fresh_consumer({})
	not isCompliant with input as _with_armed("2025-12-31T23:59:00+05:00") with data.consumer as _fresh_consumer({})
	isCompliant with input as _with_issued("2026-01-01T00:00:00-00:00") with data.consumer as _fresh_consumer({})
	isCompliant with input as _with_armed("2025-12-31T23:59:00-00:00") with data.consumer as _fresh_consumer({})
}

# ── freshness: both bounds, measured from the substrate-signed instant ────────────
#
# The template's armedAt is 2025-12-31T23:59:00Z and its issuedAt is one minute later,
# so the issuance lag is sixty seconds and the evidence age grows with the calendar.
# Every bound below is chosen so the assertion does not depend on the date: the
# admitting age bound is over a century wide and the denying one is an hour, against a
# timestamp that is already in the past and only recedes further.
_fresh_consumer(extra) := object.union(
	{
		"expected_corpus_digest": _corpus_digest,
		"expected_substrate_digest": _hex,
		"allow_unpinned_scope": true,
	},
	extra,
)

# The mutation the whole section exists for: a party holding only the envelope key
# rewrites issuedAt, which is the one temporal value no substrate signature covers.
_issued_far_future := object.union(accept, {"predicate": {"issuedAt": "2099-01-01T00:00:00Z"}})

test_freshness_unpinned_is_vacuous if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({})
}

test_issuance_lag_within_the_bound_is_admitted if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
}

# The defect, as a rule. Moving issuedAt forward preserves the armedAt ordering the
# spec mandates and defeats any window read off issuedAt; measured against the signed
# armedAt it is the one edit that cannot help, because it can only widen the distance.
test_issuance_lag_denies_a_restated_run if {
	not isCompliant with input as _issued_far_future with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
	_errors_contain(_issued_far_future, "max_issuance_lag_hours") with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
}

# ...and it is the SIGNED operand doing the work, not the bound merely being small: the
# same statement under the same bound is admitted once issuedAt is back where the
# producer put it.
test_issuance_lag_reads_the_signed_operand if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
	not isCompliant with input as _issued_far_future with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
}

# A pinned consumer handed a statement with no arming record is DENIED. This is the
# honesty condition of the pair: such a statement carries no substrate-signed instant,
# so it supports no claim about its own age, and falling back to issuedAt would hand
# the decision to the party the bound exists to constrain. The opt-in is set so the
# only thing standing between this statement and admission is the freshness rule.
test_freshness_denies_a_statement_with_no_arming_record if {
	consumer := _fresh_consumer(object.union(_indirect_consumer, {"max_issuance_lag_hours": 1}))
	isCompliant with input as _recordless_artifact with data.consumer as _fresh_consumer(_indirect_consumer)
	not isCompliant with input as _recordless_artifact with data.consumer as consumer
	_errors_contain(_recordless_artifact, "carries no arming record") with data.consumer as consumer
}

# A pin that is not a positive number is a typo rather than a bound, and it denies
# rather than reading as absent.
test_freshness_pin_of_the_wrong_shape_denies if {
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"max_issuance_lag_hours": "1"})
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"max_evidence_age_hours": 0})
}

# The bounds quantify over EVERY arming record, so a second vantage armed six years
# before the run cannot be ignored by selecting the newest instant.
_stale_arming_record := _record(object.union(_arming_payload, {"armedAt": "2020-01-01T00:00:00Z"}))

_two_vantages := object.union(accept, {"predicate": {"observationRecords": [_arming_record, _sealed_record, _stale_arming_record]}})

test_issuance_lag_quantifies_over_every_arming_record if {
	not isCompliant with input as _two_vantages with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
}

# An arming record whose armedAt will not parse makes the quantified body undefined,
# which denies. A record the bound cannot read is not a record the bound is satisfied by.
#
# The unreadable record is deliberately one the row does NOT reference, and the first
# spelling of this test got that wrong in a way worth recording. Written with the bad
# record in the referenced pair, the statement is already denied by clean-row coverage,
# because `_arming_covers` demands a zero-offset armedAt no later than issuedAt and an
# unparseable value satisfies neither. The test passed with the freshness rule deleted,
# so it was measuring the coverage rule under a freshness name. An UNREFERENCED arming
# record is invisible to the coverage rules and visible to these bounds, which is
# exactly the difference the quantifier introduces and the only place this behavior is
# reachable.
_unparseable_arming := _record(object.union(_arming_payload, {"armedAt": "yesterday"}))

_unreadable_second_vantage := object.union(accept, {"predicate": {"observationRecords": [_arming_record, _sealed_record, _unparseable_arming]}})

test_freshness_denies_an_unparseable_armed_at if {
	isCompliant with input as _unreadable_second_vantage with data.consumer as _fresh_consumer({})
	not isCompliant with input as _unreadable_second_vantage with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
}

test_evidence_age_admits_within_a_generous_bound if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({"max_evidence_age_hours": 1000000})
}

test_evidence_age_denies_evidence_older_than_the_bound if {
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"max_evidence_age_hours": 1})
	_errors_contain(accept, "max_evidence_age_hours") with data.consumer as _fresh_consumer({"max_evidence_age_hours": 1})
}

# The age bound reads the signed instant too, so restating the run does not refresh it.
# This is the assertion that would have failed on the shipped Kyverno window.
test_evidence_age_is_not_refreshed_by_moving_issuedat if {
	not isCompliant with input as _issued_far_future with data.consumer as _fresh_consumer({"max_evidence_age_hours": 1})
}

# The two bounds are independent: the lag can be satisfied while the age is not, which
# is the case that proves the lag bound does not stand in for a recency bound.
test_lag_and_age_are_separate_controls if {
	isCompliant with input as accept with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1})
	not isCompliant with input as accept with data.consumer as _fresh_consumer({"max_issuance_lag_hours": 1, "max_evidence_age_hours": 1})
}

# ── the corpus erasure, and the substitution the anchor is really for ─────────────
#
# An envelope-key-only attacker empties attackResults, empties every coverage map,
# replaces corpus.manifest with {"classes":{}}, RECOMPUTES corpus.digest (free — hashing
# needs no key), deletes observationRecords / batchRoot / runEntropy and declares
# result: "pass". Every self-consistency rule in the module once held on it: the digest
# commits the emptied manifest, an empty partition is trivially disjoint, an empty
# attackId set trivially exhausts an empty manifest, and the recompute over zero rows
# yields "pass". This shape returned isCompliant: true with an empty errors set, and it
# is now MALFORMED rather than merely un-admitted, because a corpus declaring no adversarial
# input is not an adversarial corpus, which is where the reference verifiers put it too
# (primary code corpus-manifest-no-attacks).
_erased_manifest := {"classes": {}}

# The manifest is REMOVED before the union rather than overwritten by it: object.union
# merges objects recursively, so unioning an empty classes map over a populated one
# leaves the populated one untouched — the emptying has to be a removal.
_erased := object.union(
	json.remove(accept, [
		"predicate/observationRecords",
		"predicate/batchRoot",
		"predicate/observationEnvironment/runEntropy",
		"predicate/observationEnvironment/corpus/manifest",
	]),
	{
		"predicate": {
			"result": "pass",
			"attackResults": [],
			"coverage": {"assessedClasses": [], "outOfScope": {}, "routedElsewhere": {}},
			"observationEnvironment": {
				"corpus": {
					"manifest": _erased_manifest,
					"digest": {"sha256": crypto.sha256(json.marshal(_erased_manifest))},
				},
			},
		},
	},
)

# The named-class variant of the same erasure: a manifest carrying a real class name
# whose attack list is empty. It declares exactly as many attacks as the empty classes
# object, none at all, while reading far more plausibly, which is why the rule counts
# identifiers rather than classes. Everything else about it is self-consistent: the
# single class is assessed, and an empty attackResults exhausts an empty class.
_named_empty_manifest := {"classes": {"XA": []}}

_named_empty := object.union(
	json.remove(accept, [
		"predicate/observationRecords",
		"predicate/batchRoot",
		"predicate/observationEnvironment/corpus/manifest",
	]),
	{
		"predicate": {
			"result": "pass",
			"attackResults": [],
			"coverage": {"assessedClasses": ["XA"], "outOfScope": {}, "routedElsewhere": {}},
			"observationEnvironment": {
				"corpus": {
					"manifest": _named_empty_manifest,
					"digest": {"sha256": crypto.sha256(json.marshal(_named_empty_manifest))},
				},
			},
		},
	},
)

# Both forms are MALFORMED, and the error assertion pins that they are rejected for
# declaring no attack rather than for a partition or exhaustion fault.
test_reject_erasure_declares_no_attacks if {
	not soundness_ok with input as _erased
	not isCompliant with input as _erased
	_errors_contain(_erased, "declares no attack identifier in any class")
}

test_reject_named_class_declaring_no_attacks if {
	not soundness_ok with input as _named_empty
	not isCompliant with input as _named_empty
	_errors_contain(_named_empty, "declares no attack identifier in any class")
}

# The rule's value over the anchor: it holds under EVERY consumer posture, including
# the unpinned one the anchor cannot help. A consumer that declines to pin used to get
# the erasure admitted again; it no longer does.
test_erasure_denied_even_when_consumer_declines_to_pin if {
	not isCompliant with input as _erased
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true}
	not isCompliant with input as _named_empty
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true}
}

# The vector the anchor is REALLY for, now that the vacuous end of the family is
# malformed. The same envelope-key-only party SUBSTITUTES a weaker corpus, one real
# class carrying one trivial attack identifier the run duly passes, and re-hashes it. The
# result is perfectly well formed: it declares an attack, the partition holds, the
# exhaustion holds, and the clean row is covered by an arming and sealed pair. Nothing
# in the bytes tells the substitute from the real corpus, which is the whole argument
# for pinning one out of band.
#
# The substitution has to carry the run binding with it, because the run identity
# commits the corpus digest: leave the records alone and run_binding_ok
# catches the swap. That is not a defense, and the rewrite below is what shows why.
# The identity is a plain hash of carried values, so the attacker recomputes it as
# freely as the module does, and rewrites each record's aeeRunBinding to match. The
# rewritten records no longer verify against the substrate's key, and nothing in this
# path ever checks a record signature, so it costs the attacker nothing. This is the
# module header's "What this policy cannot know" stated as an executable fixture.
_substituted_manifest := {"classes": {"XA": ["XA-TRIVIAL"]}}

_substituted_corpus_digest := crypto.sha256(json.marshal(_substituted_manifest))

_substituted_run_identity := _identity(
	_posture_object(_hex),
	object.union(_default_binding_digests, {"corpus": _substituted_corpus_digest}),
)

_rebound(payload) := _record(object.union(payload, {"aeeRunBinding": _substituted_run_identity}))

_substituted := object.union(
	json.remove(accept, ["predicate/observationEnvironment/corpus/manifest"]),
	{
		"predicate": {
			"attackResults": [
				{
					"attackId": "XA-TRIVIAL",
					"containmentObserved": "no_egress",
					"basis": "substrate",
					"method": "intercepted",
					"attribution": "paired",
					"actualLayer": "none",
					"observationRefs": [0, 1],
				},
			],
			# The arming record declares the SUBSTITUTED manifest's identifier. An
			# attacker who recomputes the identity and rewrites every record's
			# binding rewrites the declaration with it at no extra cost, so leaving
			# the original identifier here would make the substitution fail for a
			# reason the attacker would never hand us. That would weaken the
			# fixture, whose whole point is that the substitution SUCCEEDS.
			"observationRecords": [
				_rebound(object.union(_arming_payload, {"aeeAssessedAttacks": ["XA-TRIVIAL"]})),
				_rebound(_sealed_payload),
			],
			"observationEnvironment": {
				"corpus": {
					"manifest": _substituted_manifest,
					"digest": {"sha256": _substituted_corpus_digest},
				},
			},
		},
	},
)

# Leaving the records untouched is caught by the run binding, so the rewrite above is
# doing real work and the substitution is not passing for a trivial reason.
test_substituted_corpus_without_rebinding_is_caught_by_run_binding if {
	stmt := object.union(_substituted, {"predicate": {"observationRecords": [_arming_record, _sealed_record]}})
	not soundness_ok with input as stmt
	_errors_contain(stmt, "aeeRunBinding does not equal this run's derived identity")
}

test_substituted_corpus_is_structurally_sound if {
	bindings_ok with input as _substituted
	soundness_ok with input as _substituted
	result_pass with input as _substituted
	clean_row_provenance_ok with input as _substituted
}

# The pinned corpus anchor — a value that is NOT in the bytes — is what denies it.
test_substituted_corpus_denied_by_corpus_anchor if {
	not isCompliant with input as _substituted
	_errors_contain(_substituted, "does not equal the pinned expected_corpus_digest")
}

# ...and a consumer that declines to pin gets the substitution admitted. Kept as a live
# assertion so the cost of the opt-out is a tested property, not a claim in a comment.
test_substituted_corpus_admitted_when_consumer_declines_to_pin if {
	isCompliant with input as _substituted
		with data.consumer as {"allow_unpinned_anchors": true, "allow_unpinned_scope": true}
}

# ── one known type, and the fail-closed answer to everything else ─────────────────
#
# This bundle knows one predicate type. The three tests below are what that claim
# costs: the set has exactly one member, a statement of any other type is refused
# with the unknown-type error, and a stray result token does not buy admission for
# a type the policy does not recognize.

test_known_predicate_types_is_exactly_the_evidence_type if {
	known_predicate_types == {"https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"}
	count(verdict_types_requiring_catch_policy) == 0
	admissible_types == known_predicate_types
}

test_other_namespace_type_with_result_pass_rejected if {
	stmt := {"predicateType": "https://example.invalid/predicate/v1/some-other-verdict", "predicate": {"result": "pass", "verdict": "pass"}}
	not isCompliant with input as stmt
	_errors_contain(stmt, "unknown or unregistered predicateType")
}

test_other_namespace_type_does_not_bind if {
	stmt := {"predicateType": "https://example.invalid/predicate/v1/some-other-provenance", "predicate": {}}
	not bindings_ok with input as stmt
	not isCompliant with input as stmt
}

# ── corpus-driven wiring (data.corpus_vectors, projected from aee-v06) ─────────────
#
# The inline fixtures above hand-build one targeted mutation per rule. These tests
# instead drive the WHOLE published v0.6 conformance corpus, as projected by
# gen_corpus_vectors.py, through the SAME policy, so the corpus is a live gate rather
# than dead data. The reject oracle is `not (bindings_ok AND soundness_ok)` and NOT
# `not isCompliant`, so a policy that silently became reject-everything would still be
# caught by the accept-side assertions, which require every fully-sound result==pass
# accept to be isCompliant.

_bind_and_sound(s) if {
	bindings_ok with input as s
	soundness_ok with input as s
}

# The corpus is a VALIDITY corpus: every vector carries its OWN corpus and substrate
# digests, so there is no single consumer context to pin across it, and a pin read out
# of the vector under test would be circular — it would assert nothing. The
# corpus-driven admission tests therefore run under the EXPLICIT unpinned opt-out, the
# same declaration a real consumer has to make to run without anchors. The demanded
# scope is declined here for the same reason and one more: the vectors carry different
# corpus manifests, so there is no class name every vector could be demanded to have
# assessed, and demanding the classes of the vector under test would again be circular.
# Two consequences worth stating rather than leaving implicit: neither pin reclassifies
# a single corpus vector (both are admission gates, not validity ones, so `soundness_ok`
# and the whole reject/denylist oracle are untouched by them), and these tests do not
# double as coverage of either. That lives in its own section above.
_corpus_consumer := {"allow_unpinned_anchors": true, "allow_unpinned_scope": true}

# The same declines, plus the pair a consumer needs to admit an indirect run:
# a threshold that names `pass_indirect` AND the row knob that declines the clean-row
# obligation. Either one alone denies, which is the point of them being two knobs, so
# the corpus consumer that opts in has to carry both.
_corpus_consumer_optin := object.union(_corpus_consumer, _indirect_consumer)

# Every accept binds: the structural contract holds across the whole accept side,
# including the vectors rego's narrower vocabulary cannot fully vouch for.
test_corpus_accepts_all_bind if {
	every v in data.corpus_vectors.accept {
		bindings_ok with input as v.statement
	}
}

# Accept scope is honest in BOTH directions: a regoSound accept binds AND is sound; a
# regoSound:false accept binds but is NOT sound (the exclusion is a real rego-scope
# boundary, not a hidden bug — a future policy that gained power over one would fail).
_accept_scope_row_ok(v) if {
	v.regoSound == true
	bindings_ok with input as v.statement
	soundness_ok with input as v.statement
}

_accept_scope_row_ok(v) if {
	v.regoSound == false
	bindings_ok with input as v.statement
	not soundness_ok with input as v.statement
}

test_corpus_accepts_scope_honest if {
	every v in data.corpus_vectors.accept {
		_accept_scope_row_ok(v)
	}
}

# The fully-sound result==pass accepts are ADMITTED once the consumer opts in to
# unintercepted clean rows. This is the anti-hollow anchor: a reject-all bug fails
# these loudly. The opt-in is applied here because the corpus is a VALIDITY corpus —
# it deliberately includes valid pass accepts whose clean rows are reconstructed or
# artifact-basis, which the DEFAULT consumer policy does not admit (asserted
# separately below).
_pass_admit_row_ok(v) if {
	v.regoSound == true
	v.expected.result == "pass"
	isCompliant with input as v.statement
		with data.consumer as _corpus_consumer_optin
}

_pass_admit_row_ok(v) if v.regoSound == false

_pass_admit_row_ok(v) if v.expected.result != "pass"

test_corpus_pass_accepts_admitted if {
	every v in data.corpus_vectors.accept {
		_pass_admit_row_ok(v)
	}
}

# ── the DEFAULT consumer policy over the same corpus ──────────────────────────────
#
# The corpus's accepts whose clean rows are NOT live interceptions: a substrate basis
# with a reconstructed method, an artifact basis that is recordless (the self-reported
# shape the audit exploited), the same recordless artifact shape carried by a vector
# whose subject is the negative-zero UTC offset on issuedAt, and two indirect
# clean-artifact shapes. The recompute floors exactly these at "pass_indirect", so the
# set is DERIVED from that property rather than listed.
#
# It used to be listed, by authoring slug, and that is what this comment is really
# about. suiteRevision 28 renamed every vector to a content address and the five names
# below matched nothing at all. `_accept_vector(name)` then resolved to undefined, the
# `every` body could not hold, and the by-name test failed loudly -- but only because
# the sibling equality test happened to compare the pin against a derived set. Take
# that sibling away and a name set matching nothing is an `every` over an empty
# collection, which is vacuously true: the default-posture gate would have reported
# PASS while checking no vector at all.
_sound_indirect_accepts := {v.name |
	some v in data.corpus_vectors.accept
	v.regoSound == true
	v.expected.result == "pass_indirect"
}

_accept_vector(name) := v if {
	some v in data.corpus_vectors.accept
	v.name == name
}

# Each derived vector is structurally sound (so the denial is attributable to the
# clean-row gate alone), DENIED by default, and ADMITTED under the explicit opt-in.
test_corpus_unintercepted_clean_pass_denied_by_default if {
	every name in _sound_indirect_accepts {
		v := _accept_vector(name)
		v.expected.result == "pass_indirect"
		soundness_ok with input as v.statement
		not isCompliant with input as v.statement
			with data.consumer as _corpus_consumer
		isCompliant with input as v.statement
			with data.consumer as _corpus_consumer_optin
	}
}

# THE DERIVED SET MUST NOT BE EMPTY, AND ITS SIZE IS PINNED.
#
# Deriving the set closes the drift the old by-name pin had -- a new indirect accept
# is now swept in automatically instead of being missed by a list nobody updated --
# but a derivation has a failure mode a list does not: if the property stops selecting
# anything, every `every` above it passes while asserting nothing. The count is the
# guard for that, and it is the same ratchet the by-name pin provided in the direction
# that mattered: a corpus that gains or loses one of these shapes reddens here and has
# to be looked at, rather than quietly changing what the default posture is proven
# against.
test_unintercepted_clean_set_is_the_pinned_size if {
	count(_sound_indirect_accepts) == 5
}

# Every OTHER fully-sound result==pass accept is admitted with NO opt-in — the
# anti-hollow anchor for the shipped default posture, and the proof that the new gate
# denies exactly the unintercepted shapes and nothing else.
_default_pass_admit_row_ok(v) if v.regoSound == false

_default_pass_admit_row_ok(v) if v.expected.result != "pass"

_default_pass_admit_row_ok(v) if {
	v.regoSound == true
	v.expected.result == "pass"
	isCompliant with input as v.statement
		with data.consumer as _corpus_consumer
}

test_corpus_live_pass_accepts_admitted_by_default if {
	every v in data.corpus_vectors.accept {
		_default_pass_admit_row_ok(v)
	}
}

# Every observation record in the whole corpus carries at least one signature, so the
# presence gate moves no vector across the accept/reject line — it closes the strip,
# which the corpus does not contain a vector for. Asserted so a future corpus that
# DOES add a zero-signature vector reddens here instead of silently reclassifying.
test_corpus_records_all_carry_signatures if {
	every v in data.corpus_vectors.accept {
		record_signatures_ok with input as v.statement
	}
}

# Every evaluable reject trips the binding/soundness oracle (not isCompliant — see
# header). The evaluable set spans result-recompute, coverage integrity, binding,
# vocab-presence, run-binding, substrate-records, the whole coverage-validity class
# match (refs, interception/examination/arming+sealed, the method cap), batch-root
# presence, and env-completeness.
test_corpus_rejects_all_denied if {
	every v in data.corpus_vectors.reject {
		not _bind_and_sound(v.statement)
	}
}

# Every denylisted reject really IS admitted by the policy (defect lives in a layer
# rego cannot reach). This proves the denylist hides no rego-evaluable reject: if the
# policy ever gains power over one of these, it stops being admitted and this reddens,
# forcing the denylist back into sync with the corpus.
test_corpus_denylist_justified if {
	every v in data.corpus_vectors.reject_denylisted {
		_bind_and_sound(v.statement)
	}
}
