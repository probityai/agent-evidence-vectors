# Agent change admission: admit a harness version only on a signed decision that admitted it.
#
# WHAT THIS DECIDES. An agent harness (its system prompt, procedures, the guards
# that block tool calls, its tool allowlist) changes by proposal. An evaluator
# decides whether to admit each proposal and signs that decision as an
# agent-change-admission v1 receipt, whose predicate type is
#
#   https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md
#
# This module is the deploy-side rule: a harness version is admitted only when a
# receipt for exactly that version says it was admitted, every gate the consumer
# requires is recorded and passed, the decision is internally consistent, and the
# signer is a key the consumer pins. It is a separate rule set from the
# adversarial-execution-evidence oracle beside it and shares no rule with it.
#
# THREE INPUT FORMS, one decision object.
#
#   1. An in-toto Statement v1, the form Kyverno and sigstore policy-controller
#      hand a policy after their own key authority has verified the envelope:
#      {_type, subject, predicateType, predicate}. The decision is `predicate`.
#   2. A DSSE envelope {payloadType, payload, signatures}, the form the issuer
#      writes. Two carriages are read:
#        application/vnd.in-toto+json         the payload is form 1;
#        application/vnd.ratchet.decision+json the payload is the decision itself,
#                                              carrying `predicateType` at its top.
#   3. A deploy-gate wrapper {envelope, harness_digest}: form 2 plus the digest of
#      the harness the caller is about to deploy, which must equal the decision's
#      `candidate_digest`.
#
# WHAT THIS MODULE CANNOT KNOW, stated before anything relies on it. Rego has no
# Ed25519. This module never checks a signature's bytes. On form 2 and 3 it checks
# that some signature NAMES a keyid the consumer pins, which says nothing unless a
# verifier checked those bytes under that key first: an envelope whose payload was
# edited after signing passes every rule here, and the vector
# `limit-tampered-payload-passes-this-rule` holds that fact in place so nobody
# reads more into a pass than it carries. The consumer therefore states, as
# `signature_verified_upstream`, that a verifier ran before this rule (the
# engine's key authority, or an offline verifier of the receipt),
# and an undeclared consumer admits nothing. Neither layer establishes that the
# evaluations ran or that the reports a decision names are true; a valid receipt
# means the pinned key signed exactly this decision.
#
# CONSUMER PINS, read from data.change_admission_consumer:
#   signature_verified_upstream  true when a verifier checked the envelope signature
#                                under the pinned key before this rule. Required.
#   trusted_keyids               lowercase hex SHA-256 of each pinned raw Ed25519
#                                public key. Required for forms 2 and 3. A
#                                statement (form 1) carries no keyid; there the
#                                engine's authority key is the pin.
#   required_gates               the gates this deployment requires, a subset of
#                                the closed set below. Absent: all six.
#   subject_binding              "candidate" (absent): a statement's first subject
#                                is the candidate harness, as the predicate
#                                specifies. "image": the statement is attached to a
#                                container image, the engine binds it to that image,
#                                and the harness digest is pinned instead.
#   expected_candidate_digest    the harness digest this deployment admits. Required
#                                under "image" binding, compared whenever present.
#
# Every refusal is a string in `errors`; `isCompliant` holds when there is none.
# Reasons shared with the reference verifier carry its spelling:
# unsupported_payload_type, payload_not_json_object, untrusted_key,
# unsupported_predicate, payload_field_invalid:<field>, gate_missing:<gate>,
# admitted_with_failed_gate:<gate>, rejected_with_all_gates_passed. The rest are
# this rule's own: a consistent rejection is refused as not_admitted.

package agent_change_admission

import rego.v1

predicate_uri := "https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md"

statement_type := "https://in-toto.io/Statement/v1"

bare_payload_type := "application/vnd.ratchet.decision+json"

intoto_payload_type := "application/vnd.in-toto+json"

# The closed gate set. A check named outside it (the issuer records `cost`) is
# informational and is never a gate.
admission_gates := {"replay", "heldout", "no_regression", "benign_twins", "overfit_lint", "authority"}

hex64 := `^[0-9a-f]{64}$`

# A digest-map key: one to two hundred characters, no control character. The
# reference verifier applies the same pattern.
map_key := `^[^\x00-\x1f\x7f]{1,200}$`

default consumer := {}

consumer := data.change_admission_consumer if is_object(data.change_admission_consumer)

# A deployment whose policy body cannot carry a data document (policy-controller)
# overrides these three in the generated manifest. Everywhere else they stay at
# their defaults and the consumer document decides.
default engine_verified_envelope := false

default engine_subject_binding := ""

default engine_expected_candidate_digest := ""

# ---------------------------------------------------------------------------
# Input form
# ---------------------------------------------------------------------------

# OPA does not evaluate a negated call whose argument is an undefined reference
# to true, so every absent-field test below reads through object.get or a helper
# rule. Written as a bare `not is_object(input.envelope)`, the test is never true
# and the rule it guards never fires, with no error to say so.
wrapped if is_object(object.get(input, "envelope", null))

typed if is_string(object.get(input, "payloadType", null))

form := "wrapper" if wrapped

form := "envelope" if {
	not wrapped
	typed
}

form := "statement" if {
	not wrapped
	not typed
}

envelope := input.envelope if form == "wrapper"

envelope := input if form == "envelope"

enveloped if form in {"wrapper", "envelope"}

payload_bytes := base64.decode(envelope.payload) if is_string(envelope.payload)

decoded := json.unmarshal(payload_bytes) if json.is_valid(payload_bytes)

decoded_object if is_object(decoded)

payload_type_known if envelope.payloadType in {bare_payload_type, intoto_payload_type}

statement := input if form == "statement"

statement := decoded if {
	envelope.payloadType == intoto_payload_type
	is_object(decoded)
}

decision := statement.predicate if is_object(statement.predicate)

decision := decoded if {
	envelope.payloadType == bare_payload_type
	is_object(decoded)
}

declared_predicate := statement.predicateType if is_object(statement)

declared_predicate := decoded.predicateType if {
	envelope.payloadType == bare_payload_type
	is_object(decoded)
}

has_statement if is_object(statement)

has_decision if is_object(decision)

predicate_matches if declared_predicate == predicate_uri

statement_reachable if has_statement

statement_reachable if {
	envelope.payloadType == bare_payload_type
	is_object(decoded)
}

predicate_ok if {
	statement_ok
	predicate_matches
	has_decision
}

statement_ok if not has_statement

statement_ok if statement._type == statement_type

# ---------------------------------------------------------------------------
# Envelope and signer
# ---------------------------------------------------------------------------

errors contains "unsupported_payload_type" if {
	enveloped
	not payload_type_known
}

errors contains "payload_not_json_object" if {
	enveloped
	payload_type_known
	not decoded_object
}

pinned_keyids := {k | some k in object.get(consumer, "trusted_keyids", []); is_string(k); regex.match(hex64, k)}

errors contains "trusted_keys_unpinned" if {
	enveloped
	count(pinned_keyids) == 0
}

named_pinned_key if {
	some sig in envelope.signatures
	sig.keyid in pinned_keyids
}

errors contains "untrusted_key" if {
	enveloped
	count(pinned_keyids) > 0
	not named_pinned_key
}

upstream_verified if consumer.signature_verified_upstream == true

upstream_verified if engine_verified_envelope == true

errors contains "signature_verification_undeclared" if not upstream_verified

# ---------------------------------------------------------------------------
# Statement and predicate
# ---------------------------------------------------------------------------

errors contains "unsupported_statement_type" if {
	has_statement
	object.get(statement, "_type", null) != statement_type
}

errors contains "unsupported_predicate" if {
	statement_reachable
	statement_ok
	not predicate_matches
}

errors contains "unsupported_predicate" if {
	statement_ok
	predicate_matches
	not has_decision
}

# ---------------------------------------------------------------------------
# Payload schema: the fields the reference verifier requires, in its order.
# ---------------------------------------------------------------------------

nonempty_string(x) if {
	is_string(x)
	x != ""
}

digest_map(m) if {
	is_object(m)
	every k, v in m {
		regex.match(map_key, k)
		is_string(v)
		regex.match(hex64, v)
	}
}

got(path) := object.get(decision, path, null)

field_invalid contains "parent" if not nonempty_string(got("parent"))

field_invalid contains "candidate" if not nonempty_string(got("candidate"))

field_invalid contains "candidate_digest" if not candidate_digest_ok

candidate_digest_ok if {
	is_string(decision.candidate_digest)
	regex.match(hex64, decision.candidate_digest)
}

evaluator_ok if {
	is_object(decision.evaluator)
	nonempty_string(decision.evaluator.version)
}

field_invalid contains "evaluator" if not evaluator_ok

field_invalid contains "evaluator.components.suite_file" if {
	evaluator_ok
	not suite_file_ok
}

suite_file_ok if {
	is_string(decision.evaluator.components.suite_file)
	regex.match(hex64, decision.evaluator.components.suite_file)
}

field_invalid contains "exceptions" if not exceptions_ok

exceptions_ok if {
	is_array(decision.exceptions)
	every e in decision.exceptions {
		is_string(e)
	}
}

field_invalid contains "admitted" if not is_boolean(got("admitted"))

field_invalid contains "checks" if not checks_ok

checks_ok if {
	is_array(decision.checks)
	every c in decision.checks {
		is_object(c)
		is_string(c.name)
		is_boolean(c.passed)
	}
}

field_invalid contains "corpus_digests" if not digest_map(got("corpus_digests"))

field_invalid contains "report_digests" if not report_digests_ok

report_digests_ok if {
	digest_map(decision.report_digests)
	count(decision.report_digests) > 0
}

errors contains sprintf("payload_field_invalid:%s", [f]) if {
	predicate_ok
	some f in field_invalid
}

schema_ok if {
	predicate_ok
	count(field_invalid) == 0
}

# ---------------------------------------------------------------------------
# Which harness: the statement subject, the deploy gate's digest, the pin.
# ---------------------------------------------------------------------------

pin(name) := object.get(consumer, name, null)

binding := pin("subject_binding") if is_string(pin("subject_binding"))

binding := engine_subject_binding if {
	not is_string(pin("subject_binding"))
	engine_subject_binding != ""
}

binding := "candidate" if {
	not is_string(pin("subject_binding"))
	engine_subject_binding == ""
}

errors contains "subject_binding_unknown" if not binding in {"candidate", "image"}

errors contains "subject_digest_mismatch" if {
	schema_ok
	binding == "candidate"
	is_object(statement)
	not subject_matches
}

subject_matches if statement.subject[0].digest.sha256 == decision.candidate_digest

expected_digest := pin("expected_candidate_digest") if is_string(pin("expected_candidate_digest"))

expected_digest := engine_expected_candidate_digest if {
	not is_string(pin("expected_candidate_digest"))
	engine_expected_candidate_digest != ""
}

has_expected_digest if is_string(expected_digest)

expected_digest_ok if regex.match(hex64, expected_digest)

errors contains "expected_candidate_digest_invalid" if {
	has_expected_digest
	not expected_digest_ok
}

errors contains "candidate_digest_unpinned" if {
	binding == "image"
	not has_expected_digest
}

errors contains "candidate_digest_mismatch" if {
	schema_ok
	regex.match(hex64, expected_digest)
	expected_digest != decision.candidate_digest
}

errors contains "harness_digest_invalid" if {
	form == "wrapper"
	not wrapper_digest_ok
}

wrapper_digest_ok if {
	is_string(input.harness_digest)
	regex.match(hex64, input.harness_digest)
}

errors contains "candidate_digest_mismatch" if {
	schema_ok
	wrapper_digest_ok
	input.harness_digest != decision.candidate_digest
}

# ---------------------------------------------------------------------------
# Gates and the consistency of the admitted flag
# ---------------------------------------------------------------------------

required_gates := {g | some g in pin("required_gates")} if is_array(pin("required_gates"))

required_gates := admission_gates if not is_array(pin("required_gates"))

errors contains sprintf("required_gate_unknown:%v", [g]) if {
	some g in required_gates
	not g in admission_gates
}

gates_pinned_ok if {
	count(required_gates) > 0
	every g in required_gates {
		g in admission_gates
	}
}

errors contains "required_gates_empty" if count(required_gates) == 0

recorded(g) := [c | some c in decision.checks; c.name == g]

errors contains sprintf("gate_duplicated:%s", [g]) if {
	schema_ok
	some g in required_gates
	count(recorded(g)) > 1
}

missing contains g if {
	schema_ok
	some g in required_gates
	count(recorded(g)) == 0
}

errors contains sprintf("gate_missing:%s", [g]) if {
	gates_pinned_ok
	some g in missing
}

failed contains g if {
	schema_ok
	some g in required_gates
	some c in recorded(g)
	c.passed == false
}

gates_readable if {
	schema_ok
	gates_pinned_ok
	count(missing) == 0
	every g in required_gates {
		count(recorded(g)) == 1
	}
}

errors contains sprintf("admitted_with_failed_gate:%s", [g]) if {
	gates_readable
	decision.admitted == true
	some g in failed
}

errors contains "rejected_with_all_gates_passed" if {
	gates_readable
	decision.admitted == false
	count(failed) == 0
}

# A rejection the issuer signed consistently is a valid record and still admits
# nothing.
errors contains "not_admitted" if {
	gates_readable
	decision.admitted == false
	count(failed) > 0
}

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

default isCompliant := false

isCompliant if count(errors) == 0

reasons := sort([e | some e in errors])
