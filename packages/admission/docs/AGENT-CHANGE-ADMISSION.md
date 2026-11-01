# Agent change admission

Admit an agent harness version, or the image that carries it, only when a signed decision says that exact version was admitted and every gate your deployment requires passed. The [README](../README.md) is the short version of the repository; this page covers the second rule set it carries.

An agent harness changes by proposal: a new guard that blocks a tool call, a procedure, a prompt edit, a narrower tool allowlist. An evaluator decides whether to admit each proposal and signs that decision as an agent change admission v1 receipt. The predicate type is:

```text
https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md
```

The rules here run on the deploy side. They refuse a harness that has no admitted receipt, a receipt for a different harness, a receipt whose admitted flag disagrees with its own gates, and a receipt signed by a key you did not pin.

## Files

| path | what it is |
|---|---|
| `rego/agent_change_admission.rego` | The reference rule set, package `agent_change_admission`. Every other rail is compared against it. |
| `rego/agent_change_admission_test.rego` | One test per vector, plus tests for the defaults and the deployment overrides. |
| `rego/agent_change_admission_vectors.json` | The vectors: input, consumer pins and the exact refusal set for each case. Written by `rego/gen_agent_change_admission_vectors.py` from fixed test keys; never edit it by hand. |
| `kyverno/imagevalidatingpolicy-agent-change-admission.yaml` | The same rule on Kyverno's CEL rail. |
| `policy-controller/clusterimagepolicy-agent-change-admission.yaml` | The module embedded in a sigstore policy-controller manifest, written by `policy-controller/gen_change_admission_cip.py`. |
| `conformance/run_change_admission_conformance.py` | Runs every vector through every rail and deletes each refusal rule in turn to prove a test exercises it. |

## Inputs the rego module reads

1. An in-toto Statement v1 `{_type, subject, predicateType, predicate}`, which is what Kyverno and policy-controller pass a policy after their key authority verifies the envelope. The decision is `predicate`.
2. A DSSE envelope `{payloadType, payload, signatures}`. Two payload types are read: `application/vnd.in-toto+json`, whose payload is form 1, and `application/vnd.ratchet.decision+json`, whose payload is the decision itself with `predicateType` at its top level.
3. A deploy-gate wrapper `{envelope, harness_digest}`: form 2 plus the SHA-256 of the harness the caller is about to deploy, which must equal the decision's `candidate_digest`.

## Consumer pins

The module reads `data.change_admission_consumer`.

| pin | meaning | absent |
|---|---|---|
| `signature_verified_upstream` | `true` when a verifier checked the envelope signature under the pinned key before this rule ran. | Every input is refused with `signature_verification_undeclared`. |
| `trusted_keyids` | Lowercase hex SHA-256 of each pinned raw Ed25519 public key. A statement carries no keyid, so for form 1 the engine's authority key is the pin. | Forms 2 and 3 are refused with `trusted_keys_unpinned`. |
| `required_gates` | The gates this deployment requires, from `replay`, `heldout`, `no_regression`, `benign_twins`, `overfit_lint`, `authority`. | All six. An empty list is refused. |
| `subject_binding` | `candidate`: the statement's first subject is the harness. `image`: the statement is attached to a container image, the engine binds it to that image, and the harness digest is pinned instead. | `candidate`. |
| `expected_candidate_digest` | The harness digest this deployment admits. | Required under `image` binding; compared whenever present. |

## Refusal reasons

Every refusal is a string in `data.agent_change_admission.errors`; `isCompliant` holds when there is none. Reasons the reference verifier of the receipt also emits carry its spelling.

| reason | when |
|---|---|
| `unsupported_payload_type` | The envelope carries neither payload type. |
| `payload_not_json_object` | The payload does not decode to a JSON object. |
| `trusted_keys_unpinned` | An envelope reached a consumer that pinned no key. |
| `untrusted_key` | No signature names a pinned key. |
| `signature_verification_undeclared` | Nothing declared that the signature was verified. |
| `unsupported_statement_type` | The statement is not an in-toto Statement v1. |
| `unsupported_predicate` | Another predicate type, or no decision object. |
| `payload_field_invalid:<field>` | A required field is absent or of the wrong type: `parent`, `candidate`, `candidate_digest`, `evaluator`, `evaluator.components.suite_file`, `exceptions`, `admitted`, `checks`, `corpus_digests`, `report_digests`. |
| `subject_digest_mismatch` | Under `candidate` binding, the statement's subject is not the candidate. |
| `subject_binding_unknown` | The binding pin is neither value. |
| `expected_candidate_digest_invalid` | The pinned harness digest is not 64 lowercase hex, which includes the `PIN-ME-` placeholder. |
| `candidate_digest_unpinned` | `image` binding with no pinned harness digest. |
| `candidate_digest_mismatch` | The decision admitted a different harness from the pinned or deployed one. |
| `harness_digest_invalid` | The wrapper's harness digest is not 64 lowercase hex. |
| `required_gate_unknown:<gate>`, `required_gates_empty` | The gate pin names a check outside the closed set, or no gate. |
| `gate_missing:<gate>`, `gate_duplicated:<gate>` | A required gate is not recorded, or recorded more than once. |
| `admitted_with_failed_gate:<gate>` | The decision says admitted while a required gate failed. |
| `rejected_with_all_gates_passed` | The decision says rejected while every required gate passed. |
| `not_admitted` | A consistent rejection: a valid record that admits nothing. |

## What this does not establish

Rego has no Ed25519. On an envelope the module checks that a signature names a pinned keyid, which carries weight only after a verifier checked the signature bytes under that key. The vector `limit-tampered-payload-passes-this-rule` is an envelope whose payload was edited after signing, and it passes this rule; the upstream verifier is what refuses it. Kyverno and policy-controller verify the envelope with their own authority key before the policy runs.

No rule here, and no verifier, establishes that the evaluations a decision names ran or that the reports it names are true. A valid receipt means the pinned key signed exactly this decision.

## Deploy it

Kyverno: replace the three `PIN-ME-` values in the ImageValidatingPolicy (the image glob, the issuer's public key, and `pinnedHarness`). policy-controller: put the issuer's public key in the manifest, set `engine_expected_candidate_digest` in the generator's `OVERRIDES` block, and run `python3 policy-controller/gen_change_admission_cip.py`. Either way the manifest refuses every Pod until both are pinned.

A cosign attestation attached to an image names the image as its subject, never the harness inside it, so both engine rails run under `image` binding and compare the pinned harness digest.

## Check it

```bash
python3 rego/gen_agent_change_admission_vectors.py --check
python3 policy-controller/gen_change_admission_cip.py --check
opa test --timeout 300s rego/
python3 conformance/run_change_admission_conformance.py
```

The last command needs `opa` and `kyverno` on the path. It prints how many vectors each rail answered, names the two vectors whose envelope never opens (an engine refuses those before any policy runs), runs a positive control on the harness pin for both engine rails, and ends with the mutation sweep. The `change-admission` job in `.github/workflows/ci.yml` runs all four on every push.
