# Principal-action vectors

Cases for `principal-action/v1`, predicate type
`https://w3id.org/agent-evidence/predicate/v1/principal-action`, specified in
[spec/predicates/principal-action.md](../../spec/predicates/principal-action.md).

A record says an action ran under principals an identity provider authenticated: the
invoking `user`, the executing `agent`, the accountable `sponsor` and the `approver`, each
bound to its credential by digest and to its issuer key by RFC 7638 thumbprint, with the
user credential's RFC 8693 `act` chain. The producer signs an in-toto Statement v1 in RFC
8785 bytes in a DSSE envelope; the subject is the digest of the action.

The baseline, `strict-four-principals`, names all four roles with one key type each (OKP,
EC P-256, RSA 2048), an `act` chain that names the agent and an approval the approver
signed. Every rejected case changes one thing in it, so exactly one check refuses it, and
the corpus tests remove each check in turn and require its case to change answer.

| Case | Expected | Change from the baseline |
| --- | --- | --- |
| strict-four-principals | verified, `strict`, `act-chain` | the baseline: four principals, an act chain naming the agent, the approval counted |
| basic-user-agent-act-absent | verified, `basic`, `act-absent` | only user and agent, and no act chain |
| basic-user-agent-act-chain | verified, `basic`, `act-chain` | only user and agent, the act chain names the agent |
| basic-four-principals-act-absent | verified, `basic`, `act-absent` | four principals but no act chain: strict needs both |
| strict-nested-act-chain | verified, `strict`, `act-chain` | the act chain has a prior actor behind the agent |
| strict-act-names-client-id | verified, `strict`, `act-chain` | the act chain names the agent by its client identifier |
| strict-id-jag-source | verified, `strict`, `act-chain` | the user principal was established from an identity assertion grant |
| strict-custom-domain-declared | verified, `strict`, `act-chain` | a custom-domain issuer whose declared provider is accepted as declared |
| strict-no-optional-members | verified, `strict`, `act-chain` | no provider declared and no pin recorded |
| principals-malformed | rejected, `principals_malformed` | a role outside user, agent, sponsor and approver |
| user-member-missing | rejected, `principal_user:principal_member_missing` | the user principal does not name its credential |
| agent-member-unknown | rejected, `principal_agent:principal_member_unknown` | the agent principal carries a member the type does not define |
| user-issuer-invalid | rejected, `principal_user:principal_issuer_invalid` | an issuer that is not an https URL |
| user-audience-duplicate | rejected, `principal_user:principal_malformed` | an audience naming one value twice |
| sponsor-private-key | rejected, `principal_sponsor:principal_key_invalid` | the sponsor key carries a private member |
| agent-thumbprint-mismatch | rejected, `principal_agent:principal_thumbprint_mismatch` | a thumbprint that does not recompute from the key |
| user-kid-mismatch | rejected, `principal_user:principal_kid_mismatch` | the header kid differs from the key's kid |
| user-provider-mismatch | rejected, `principal_user:principal_provider_mismatch` | an Okta issuer declared as Auth0 |
| agent-pin-mismatch | rejected, `principal_agent:principal_pin_mismatch` | the key the client pinned is not the key the record names |
| user-not-yet-valid | rejected, `principal_user:principal_not_yet_valid` | the credential was issued after the action |
| user-expired | rejected, `principal_user:principal_expired` | the credential expired at the moment of the action |
| approver-issuer-untrusted | rejected, `principal_approver:principal_issuer_untrusted` | an approver from an issuer the verifier does not trust |
| agent-key-not-pinned | rejected, `principal_agent:principal_key_not_pinned` | a consistent key the verifier did not pin for that issuer |
| user-act-malformed | rejected, `principal_user:principal_act_malformed` | an act claim without a sub |
| user-idjag-undefined | rejected, `principal_user:principal_idjag_undefined` | an idJag block before its definition is published |
| agent-missing | rejected, `principals_need_user_and_agent` | no agent principal |
| act-names-another-agent | rejected, `principal_act_names_another_agent` | the user credential delegated to a different agent |
| approver-not-an-approval-signer | rejected, `principal_approver_not_an_approval_signer` | an approver principal with no approval counted |
| statement-malformed | rejected, `statement_malformed` | a predicate type one character from this one |
| recorder-signature-invalid | rejected, `recorder_signature_invalid` | the action edited after the producer signed |
| statement-not-canonical | rejected, `statement_not_canonical` | a signed payload that is not RFC 8785 bytes |
| action-malformed | rejected, `action_malformed` | an action carrying a member the type does not define |
| action-digest-mismatch | rejected, `action_digest_mismatch` | the subject digest names another action |

## What a case holds

- `case.json`: the producer's Ed25519 public key (`producerKey`, base64), the verifier's
  pin set (`pins`: issuer to the RFC 7638 thumbprints it accepts) and the envelope name.
  The pins are the verifier's policy, never part of the record.
- `envelope.json`: the DSSE envelope.

## Running it

```sh
python3 corpora/vectors-principal-action/check_vectors.py
python3 corpora/vectors-principal-action/check_vectors.py --verifier "<your verifier>"
```

A verifier receives `<case-dir>/case.json --json`, prints one JSON object with `decision`
and `reason` (and `delegation` when verified), and exits 0 for `verified` and 1 for
`rejected`. The Go reader is `corpusreaders/principalaction.go`. Rebuild the cases with
`python3 corpora/vectors-principal-action/gen_vectors.py`; every key is derived from a
published label and protects nothing.
