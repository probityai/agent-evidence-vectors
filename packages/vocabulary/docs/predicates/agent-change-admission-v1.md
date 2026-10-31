# Predicate: agent change admission, version 1

Predicate type URI:
`https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md`

Status: proposed. The terms it carries are in the `change_admission` section of
[vocabulary.yaml](https://github.com/probityai/agent-evidence/blob/main/packages/vocabulary/vocabulary.yaml),
and every one of them starts proposed under the registry's promotion rule.

## Purpose

An AI agent runs inside a harness: a system prompt, procedures, guards that can
block a tool call, and a tool allowlist. When an agent fails, the usual fix is
an untested edit to that harness. This predicate records one decision about one
proposed harness change: whether it was admitted, which gates it was checked
against, and the digest of every piece of evidence the decision rests on. A
rejection is recorded with the same weight as an admission.

A relying party uses it to answer one question before it runs a harness
version: did the evaluator I trust sign an admission of exactly this candidate,
against this parent, with every gate I require passed?

## Envelope

The decision is signed as a DSSE v1 envelope with Ed25519. The signature covers the DSSE pre-authentication
encoding of the payload type and the payload bytes, never the raw payload:

```text
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

A signature's `keyid` is the lowercase hex SHA-256 of the raw 32-byte Ed25519
public key. A consumer pins its trusted keys out of band; a key carried inside
the envelope is never trusted. A signature naming a key the consumer did not
pin is ignored, so an envelope may carry a co-signature the consumer does not
know.

Two carriages are defined, and the consumer's policy pins which one it reads.

| Carriage | `payloadType` | Payload |
| --- | --- | --- |
| bare | `application/vnd.ratchet.decision+json` | the decision object itself, carrying `predicateType` |
| in-toto | `application/vnd.in-toto+json` | an in-toto Statement v1 whose `predicate` is the decision object and whose subject is the candidate harness |

In the in-toto carriage the statement's `_type` is
`https://in-toto.io/Statement/v1`, its `predicateType` is the URI above, the
decision object omits `predicateType`, and at least one entry of `subject`
carries `digest.sha256` equal to the decision's `candidate_digest`.

A statement attached to a container image names the image as its subject, so it
cannot carry the harness digest there. A consumer that admits images binds
`candidate_digest` to the digest of the harness it deploys, pinned in its own
policy, and reads the subject check as satisfied only through that binding.

## Fields

Every field below is required. A verifier checks them in this order and names
the first one that is absent or malformed.

| Field | Type | Meaning |
| --- | --- | --- |
| `predicateType` | string | the URI above (bare carriage only) |
| `parent` | non-empty string | the version identifier of the harness the change is proposed against |
| `candidate` | non-empty string | the version identifier of the proposed harness |
| `candidate_digest` | 64 lowercase hex | SHA-256 of the candidate harness's canonical form |
| `evaluator` | object | the frozen evaluator: `version`, a non-empty string, and `components`, a map of component name to digest |
| `evaluator.components.suite_file` | 64 lowercase hex | SHA-256 of the frozen case suite the evaluations ran |
| `exceptions` | array of strings | every exception met on the way to the decision; an empty array states that none was met |
| `admitted` | boolean | `true` admits the candidate, `false` rejects it |
| `checks` | array of objects | one entry per check: `name` (string), `passed` (boolean), and `evidence` (object) |
| `corpus_digests` | object, name to 64 lowercase hex | for each new guard, the digest of the recorded-trace snapshot it was replayed over; empty when the change adds no guard |
| `report_digests` | non-empty object, name to 64 lowercase hex | SHA-256 of the exact stored bytes of each report the decision rests on |

A name in `corpus_digests` or `report_digests` is 1 to 200 characters with no
control character. A decision may carry further fields, such as `decided_at`
(an RFC 3339 timestamp), `type`, rates and the case identifiers the proposer
could see; a verifier ignores fields it does not check.

The evaluator version changes whenever its cases, graders, fault schedules or
model configuration change. Changing any of them after held-out outcomes were
seen starts a new evaluator version.

## Gates

Gate names form a closed set. The consumer's policy pins which of them it
requires; a check whose name the policy does not require, such as `cost`, is
informational and never a gate.

| Gate | It passes when |
| --- | --- |
| `replay` | every new guard, run over the declared and digest-frozen trace snapshot with each call's recorded pre-call state, fires on every target failure at or before the step that caused it and on no passing trace and no benign twin. Clearance needs an exhaustive pass, every trace checked; a replay may stop at its first counterexample only to reject |
| `heldout` | on fresh held-out runs, the candidate's pass count beats the better of two fresh parent runs by at least the larger of 2 and one more than the number of cases whose outcome differed between the parent runs, and a second fresh candidate run confirms it |
| `no_regression` | no must-succeed case that passed in either parent run fails in a candidate run |
| `benign_twins` | the candidate intervenes on no benign twin, a case built to look like a failure and to need no intervention |
| `overfit_lint` | the candidate's new text carries no identifier, amount or name copied from the training traces |
| `authority` | the tool allowlist is a subset of the parent's, every parent guard and procedure is kept byte for byte, and the parent's system prompt is a prefix of the candidate's, unless a human-signed approval names this exact candidate digest |

Only results produced by runs made for this decision count toward a gate. A
stored result shown again, or a byte-identical replay of a recorded model
request, is labelled as such in the reports and excluded.

## Verification

A verifier takes the envelope, a policy (payload type, predicate type, trusted
keys, required gates, and whether every named report must be supplied) and any
stored reports it holds. It returns `supported`, `contradicted` or
`not_established` with the reason code of the first check that fails, or no
verdict when the envelope cannot be read.

| Step | Check | Decision and reason |
| --- | --- | --- |
| 1 | the bytes parse as a DSSE envelope with a payload type, a base64 payload and at least one signature | no verdict, `malformed_envelope` |
| 2 | the payload type is the pinned one | `not_established`, `unsupported_payload_type` |
| 3 | a signature naming a pinned keyid verifies | `contradicted`, `untrusted_key` when none names a pinned key, `signature_invalid` when one does and fails |
| 4 | the payload is a JSON object; in the in-toto carriage, a Statement v1 | `not_established`, `payload_not_json_object` or `unsupported_statement_type` |
| 5 | the predicate type is the URI above | `not_established`, `unsupported_predicate` |
| 6 | each field in the table above is well formed, in table order | `not_established`, `payload_field_invalid:<field>` |
| 7 | in the in-toto carriage, a subject carries `candidate_digest` | `contradicted`, `subject_digest_mismatch` |
| 8 | every required gate appears in `checks` | `not_established`, `gate_missing:<gate>` |
| 9 | an admitted decision passed every required gate | `contradicted`, `admitted_with_failed_gate:<gate>` |
| 10 | a rejected decision failed at least one required gate | `contradicted`, `rejected_with_all_gates_passed` |
| 11 | every supplied report is named, in name order | `contradicted`, `report_not_named:<name>` |
| 12 | every supplied report's SHA-256 equals its named digest, in name order | `contradicted`, `report_digest_mismatch:<name>` |
| 13 | under a policy that requires reports, every named report is supplied | `not_established`, `report_not_supplied:<name>` |

A decision that passes every step is `supported`, with the reason
`admitted_receipt_verified` or `rejection_receipt_verified`. A supported
rejection is a verified record that the change was refused, and a consumer that
admits only admitted candidates checks `admitted` as well as the verdict.

A verifier that also holds the evaluation reports, the parent and candidate
harnesses and the recorded replay inputs may recompute a gate and compare it
with the signed claim. Such a recomputation adds to these steps and never
replaces one.

The conformance corpus for these steps is
[vectors-agent-change-admission](https://github.com/probityai/agent-evidence-vectors/tree/main/vectors-agent-change-admission):
one supported and one or more refused members per step, each refused member one
scripted mutation away from a supported twin.

## What a valid decision does not establish

A supported verdict means the pinned key signed exactly this decision and every
supplied report matches the digest the decision names. It does not establish
that the evaluations ran, that the reports are true, that a replayed guard's
counterfactual continuation would have succeeded, or that the key holder is
honest. What the verifier recomputed from bytes and what it accepted on the
evaluator's signature are separate statements, and a verifier reports them
separately.

## Carrying the decision in other attestation formats

The in-toto carriage above is normative. A consumer whose admission controller
expects one of the formats below can derive one from a verified decision with
this mapping; the derived statement is the consumer's own and carries its own
signature.

| Decision field | in-toto Statement v1 | Verification summary (`https://slsa.dev/verification_summary/v1`) | Test result (`https://in-toto.io/attestation/test-result/v0.1`) |
| --- | --- | --- | --- |
| `candidate_digest` | `subject[].digest.sha256`, exact | `subject[].digest.sha256`, exact | `subject[].digest.sha256`, exact |
| `admitted` | none | `verificationResult`, `PASSED` or `FAILED` | `result`, `PASSED` or `FAILED`; `WARNED` has no source |
| `checks[].name`, `checks[].passed` | none | none: `verifiedLevels` names levels, not gates | `passedTests` and `failedTests`, by gate name |
| `evaluator.version`, `evaluator.components` | none | `policy`, as a resource descriptor whose digest is the evaluator's component digests | `configuration`, as resource descriptors |
| `report_digests` | none | `inputAttestations`, one resource descriptor per report | none |
| `corpus_digests` | none | `inputAttestations`, one resource descriptor per snapshot | `configuration` |
| `parent` | none | none | none |
| `exceptions` | none | none | none |
| `decided_at` | none | `timeVerified` | none |

The last three rows are why this predicate exists: neither summary format
carries the harness a change was proposed against, the exceptions met, or
which gate refused it.

## Example

The envelope below is the `admitted` member of the conformance corpus. It is
signed with the corpus's published test key, whose seed is the SHA-256 of the
ASCII string `agent-change-admission/v1 test issuer key`; never trust that key
for anything else. Its keyid is
`f8558acc0210bbba12182fa571b5e2621754c5cad2175228685b51e426822d3a` and its
raw public key in base64 is `sobuBQ3ssrnXa666oiq7znpaQdkZM7/87FAY/PfPQ2o=`.

The decoded payload:

```json
{
  "admitted": true,
  "candidate": "8b1e5d72c4a9",
  "candidate_digest": "5da28ed1225d79b7fcacec50557494d62aae8c16996b0870896dc011ae4d57df",
  "checks": [
    {"evidence": {"coverage": "41/41 traces checked", "snapshot_digest": "d960f73a95bca5ebb445601fc649b74f72d9174035d51894c2d261050cf27592", "verdict": "CLEARED"}, "name": "replay", "passed": true},
    {"evidence": {}, "name": "heldout", "passed": true},
    {"evidence": {}, "name": "no_regression", "passed": true},
    {"evidence": {}, "name": "authority", "passed": true},
    {"evidence": {}, "name": "benign_twins", "passed": true},
    {"evidence": {}, "name": "overfit_lint", "passed": true},
    {"evidence": {"gate": false, "model_calls": 212}, "name": "cost", "passed": true}
  ],
  "corpus_digests": {"guard-refund-over-limit": "d960f73a95bca5ebb445601fc649b74f72d9174035d51894c2d261050cf27592"},
  "decided_at": "2026-10-11T12:00:00+00:00",
  "evaluator": {
    "components": {
      "cases": "da5f39ac7c1991f861119ba8a814fa9e965d03b08058526f6eda1f3e7bb7c47b",
      "faults": "4ef4c093f3a82b760ded0d2666f21b1e0b46a127ce90006bd9ab9e026003f3fa",
      "graders": "ff2cfe5b040e56378841c89e9a123fbd46e24a1d991d11ad955066e98cccfda3",
      "model_config": "50df5593b2f6a4456f7585e9aa31d1da856aa7d70b868885da3d71534bf5e9da",
      "suite_file": "65ee1c30edca560cf47aeba5f047d15679d3ec9a04ecb2294d7efd2fe767a738"
    },
    "version": "c41f0a9e2b77"
  },
  "exceptions": [],
  "parent": "3f2a9c41d07e",
  "predicateType": "https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md",
  "report_digests": {
    "heldout-summary": "f7a09632b19538955df6f7b4b7e6d8897a9a9b77f050bbb8ccda202bec61e3d0",
    "replay:guard-refund-over-limit": "d2f103ae67e3553f74308fbff61d1e91c4fec24d82a7af5d445d4bdaef6c1be9"
  },
  "type": "decision"
}
```

The signed payload bytes are this object as canonical JSON: keys sorted, no
whitespace, UTF-8. The envelope, 2445 bytes, has SHA-256
`e143a38b1867267dbb30f857d0cf212add47a7eb91ae18ee793722f61d265056` and is
committed byte for byte as
[cases/admitted/envelope.json](https://github.com/probityai/agent-evidence-vectors/blob/main/vectors-agent-change-admission/cases/admitted/envelope.json).
Its one signature is:

```json
{
  "keyid": "f8558acc0210bbba12182fa571b5e2621754c5cad2175228685b51e426822d3a",
  "sig": "wx9GhRKTk1dEhsO9ZG0UMlDdqSUyY0SIPcGJ3aT+14F3AVrl2H7hJ3rV0o8YSiZznnaBusLLI+baDmcS0oV9BA=="
}
```

## Versioning

This document is version 1 and its URI is fixed. A change that adds an
optional field or a reason code that refuses nothing previously supported
edits this page. A change that adds a required field, renames a field, changes
a field's type or a gate's meaning, or supports a decision version 1 refuses is
breaking: it is published as `agent-change-admission-v2.md` at a new path, and
this page stays.
