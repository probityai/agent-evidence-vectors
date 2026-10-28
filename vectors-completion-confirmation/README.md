# Completion-confirmation vectors

Cases for `completion-confirmation/v1`: a task reported complete, the authorization decision for it, and the confirmation record the claim rests on. An operation the enforcement point allowed is not thereby a completed one. A verifier that accepts the claim on the authorization decision and the agent's own report accepts every denied case here.

The cases follow the wording proposed for OWASP AIT Pillar 2, section 5.1, level L3 (Tymofii Pidlisnyi, OWASP Slack, 2026-10-22), and the gap Mayur Agnihotri named on 2026-10-23, that "an allowed operation whose completion cannot be verified does not satisfy the positive control":

> The record links the decision to the enforcement outcome and, if execution occurs, to the protected-resource result. Unresolved outcomes are recorded as such and do not establish success or absence of effect.

> Check all required fields and verify each completed operation against its linked resource-side result. An allowed operation whose completion cannot be verified does not satisfy the positive control.

| Test in the proposal | Case |
| --- | --- |
| A completed operation with no linked resource-side result | `completion-claimed-without-confirmation` (`completion_unconfirmed`) |
| A result for a different task, authorization, resource, operation or arguments | the five `confirmation-for-` cases (`confirmation_not_bound`) |
| A result the acting agent wrote about itself | `confirmation-written-by-the-acting-agent`, `confirmation-observer-unknown`, `confirmation-key-not-observers` (`confirmation_self_reported`) |
| An unresolved outcome that must not establish success | `outcome-unresolved-claimed-complete` (`outcome_unresolved`) |
| A result saying the effect did not happen | `outcome-absent-claimed-complete` (`outcome_contradicts_claim`) |
| The positive control: a verified completion | `allow-confirmed` (`confirmed`) |

An unresolved or failed outcome reported as such asserts nothing to confirm, and is allowed (`allow-unresolved-reported-as-unresolved`, `allow-failed-without-confirmation`, reason `no_completion_claimed`).

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason |
| --- | --- |
| the record carries `contractId` | `contract_id_missing` |
| `contractId` is the completion-confirmation contract | `contract_id_unknown` |
| the record has the fields and types the contract names, and every time parses | `malformed_record` |
| the claim's status is not `complete` | allow, `no_completion_claimed` |
| a confirmation is present | `completion_unconfirmed` |
| the confirmation names the task, the authorization, and the task's operation, resource and argument digest | `confirmation_not_bound` |
| the confirmation was written by an observer that is not the claiming agent, under that observer's trusted key | `confirmation_self_reported` |
| the confirmation's identifier is not among the consumed ones | `confirmation_reused` |
| the confirmation was observed at or after the authorization decision and at or before the decision time | `confirmation_outside_window` |
| the confirmed outcome is not `unresolved` | `outcome_unresolved` |
| the confirmed outcome is not `absent` | `outcome_contradicts_claim` |

A record that passes every check is `allow` with reason `confirmed`.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-completion-confirmation
```

To judge your own verifier, run it as `<verifier> <case-dir>/record.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`.

## Controls

Every denied case departs from a conformant record in one place, and each check is forced by at least one case: switching it off changes a verdict. A verifier that trusts the agent's own claim, running only the chain checks, fails every confirmation case. A verifier that denies everything fails the controls that must be allowed, and one that allows everything fails every denied case. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
