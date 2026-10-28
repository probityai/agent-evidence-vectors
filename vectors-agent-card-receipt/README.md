# Agent-card-receipt vectors

Cases for `agent-card-receipt/v1`: a receipt that binds the result of an evaluation to
the exact A2A Agent Card an agent serves, checked against the signed revocation list of
its issuer and the time of the check. The expected decision and reason for every case
are in `MANIFEST.json`, and the predicate is specified in
[spec/predicates/agent-card-receipt.md](../spec/predicates/agent-card-receipt.md).

A card is self-declared. The receipt is a second statement from someone who ran the
agent: it names the card by the digest of its RFC 8785 form without its top-level
`signatures` (A2A section 8.4.1 rules 2 and 3), says how it graded, and says until when.
A caller that holds the card can check all of it without asking the agent.

| Case | Expected |
| --- | --- |
| accept-card-without-signatures | accept, `receipt_current` |
| accept-signatures-excluded | accept, `receipt_current` |
| accept-default-members-kept | accept, `receipt_current` |
| accept-rfc8785-edges | accept, `receipt_current` |
| accept-receipt-extension-declared | accept, `receipt_current` |
| accept-unknown-member-kept | accept, `receipt_current` |
| accept-agent-key-thumbprints | accept, `receipt_current` |
| accept-result-degraded | accept, `receipt_current` |
| accept-other-receipt-revoked | accept, `receipt_current` |
| accept-at-issued-at | accept, `receipt_current` |
| accept-list-at-issued-at | accept, `receipt_current` |
| statement-duplicate-member | reject, `statement_malformed` |
| statement-member-unexpected | reject, `statement_malformed` |
| statement-type-wrong | reject, `statement_type_wrong` |
| predicate-type-wrong | reject, `predicate_type_wrong` |
| subject-two-members | reject, `subject_malformed` |
| subject-digest-uppercase | reject, `subject_malformed` |
| predicate-result-unregistered | reject, `predicate_malformed` |
| predicate-member-unexpected | reject, `predicate_malformed` |
| predicate-registry-missing | reject, `predicate_malformed` |
| predicate-time-fraction | reject, `predicate_malformed` |
| predicate-time-offset | reject, `predicate_malformed` |
| predicate-revocation-list-http | reject, `predicate_malformed` |
| predicate-thumbprints-unsorted | reject, `predicate_malformed` |
| predicate-run-digest-short | reject, `predicate_malformed` |
| validity-window-inverted | reject, `validity_window_inverted` |
| card-duplicate-member | reject, `card_malformed` |
| card-not-an-object | reject, `card_malformed` |
| card-integer-outside-i-json | reject, `card_malformed` |
| digest-defaults-pruned | reject, `card_digest_mismatch` |
| digest-signatures-included | reject, `card_digest_mismatch` |
| digest-not-rfc8785 | reject, `card_digest_mismatch` |
| card-changed-after-receipt | reject, `card_digest_mismatch` |
| receipt-not-yet-valid | reject, `receipt_not_yet_valid` |
| receipt-expired | reject, `receipt_expired` |
| receipt-expired-at-valid-until | reject, `receipt_expired` |
| revocation-list-absent | reject, `revocation_list_absent` |
| revocation-list-payload-type-wrong | reject, `revocation_list_malformed` |
| revocation-list-unsorted | reject, `revocation_list_malformed` |
| revocation-list-other-signer | reject, `revocation_list_signature` |
| revocation-list-edited-after-signing | reject, `revocation_list_signature` |
| revocation-list-stale | reject, `revocation_list_stale` |
| revocation-list-not-yet-issued | reject, `revocation_list_stale` |
| receipt-revoked | reject, `receipt_revoked` |

Each rejected case is built so the check it names is the first that fails and every
earlier check passes. The accepted cases are controls: a verifier that rejects everything
fails them, and so does one that rejects a card for carrying signatures, default-valued
members or a member A2A does not define.

## What a case holds

`card.json` is the Agent Card as served. `statement.json` is an unsigned in-toto
Statement carrying the receipt. `revocations.json` is the issuer's revocation list, a DSSE
envelope signed with Ed25519, and is absent from the case that tests an absent list.
`context.json` names the time of the check, `now`, and the base64 public key of the
receipt signer, `issuerKey`. The keys are test keys derived from public labels.

## The checks, in order

A verifier names the first check that fails.

1. The statement is strict JSON with exactly its four members (`statement_malformed`).
2. `_type` is in-toto Statement v1 (`statement_type_wrong`).
3. `predicateType` is the agent-card-receipt type (`predicate_type_wrong`).
4. `subject` is one member whose digest holds only a lowercase SHA-256
   (`subject_malformed`).
5. The predicate has exactly its members, each well formed (`predicate_malformed`).
6. `issuedAt` is before `validUntil` (`validity_window_inverted`).
7. The card is an I-JSON object with an RFC 8785 form (`card_malformed`).
8. The subject digest is the SHA-256 of that form without `signatures`
   (`card_digest_mismatch`).
9. The check time is not before `issuedAt` (`receipt_not_yet_valid`) and is before
   `validUntil` (`receipt_expired`).
10. A revocation list is present (`revocation_list_absent`), well formed
    (`revocation_list_malformed`), signed by the receipt signer's key
    (`revocation_list_signature`) and current at the check time
    (`revocation_list_stale`).
11. The list does not name the receipt (`receipt_revoked`).

A statement that passes every check is `accept` with reason `receipt_current`.

## What a pass establishes

The card as served is the card the receipt was issued for, the receipt is inside its
window, and a current list signed by the receipt signer's key does not revoke it.

## What a pass does not establish

- That the evaluation named in `run` was a good one, or that the signer is who it claims.
- That the card describes what the agent does at runtime.
- Whether `degraded` or `pass_indirect` is enough: that is the relying party's policy.
- Anything after `validUntil` or after the list names the receipt.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-agent-card-receipt
```

A verifier under test takes `agent-card-receipt/v1 <case-dir> --json`, prints one JSON
object carrying `decision` and `reason`, and exits 0 for `accept` and 1 for `reject`:

```sh
agent-evidence-vectors --corpus vectors-agent-card-receipt --verifier './verifier'
python3 vectors-agent-card-receipt/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-agent-card-receipt` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-agent-card-receipt/gen_vectors.py`.
