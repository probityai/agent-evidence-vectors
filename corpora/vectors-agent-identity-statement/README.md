# Agent identity statement vectors

Cases for `agent-identity-statement/v1`: an issuer's signed, versioned history of an
agent's identity document, and one past decision to re-verify against it. The expected
decision and reason for every case are in `MANIFEST.json`, and the predicate is specified
in [spec/predicates/agent-identity-statement.md](../../spec/predicates/agent-identity-statement.md).

Each version of the document is one DSSE-signed in-toto Statement naming the agent, the
version, the keys in force, the status (`active`, `suspended` or `revoked`) and the instant
it takes effect, chained to the previous version by the SHA-256 of its signed payload. The
question every case asks is the one a relying party, an auditor or a court asks after the
fact: when this decision was made, was the key that signed it in force, and was the agent
active? A live lookup at decision time cannot answer it later, and a key directory that
shows only the current keys cannot answer it at all.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

| Case | Expected |
| --- | --- |
| accept-single-version | accept, `key_in_force` |
| accept-at-effective-instant | accept, `key_in_force` |
| accept-old-key-before-rotation | accept, `key_in_force` |
| accept-new-key-after-rotation | accept, `key_in_force` |
| accept-overlapping-keys | accept, `key_in_force` |
| accept-reactivated-after-suspension | accept, `key_in_force` |
| accept-decision-before-revocation | accept, `key_in_force` |
| accept-history-out-of-order | accept, `key_in_force` |
| accept-second-signature-pinned | accept, `key_in_force` |
| history-not-json | reject, `history_malformed` |
| history-empty | reject, `history_malformed` |
| history-payload-type-other | reject, `history_malformed` |
| statement-signed-by-other-key | reject, `statement_signature` |
| statement-extra-member | reject, `statement_malformed` |
| statement-type-v01 | reject, `statement_type_wrong` |
| predicate-type-other | reject, `predicate_type_wrong` |
| subject-two-members | reject, `subject_malformed` |
| predicate-status-unknown | reject, `predicate_malformed` |
| predicate-keys-unsorted | reject, `predicate_malformed` |
| predicate-key-type-other | reject, `predicate_malformed` |
| predicate-version-one-with-previous | reject, `predicate_malformed` |
| predicate-version-zero | reject, `predicate_malformed` |
| predicate-time-offset | reject, `predicate_malformed` |
| active-without-keys | reject, `active_without_keys` |
| effective-after-issued | reject, `effective_after_issued` |
| agent-other-subject | reject, `agent_mismatch` |
| history-no-genesis | reject, `history_no_genesis` |
| history-forked | reject, `history_forked` |
| history-two-genesis | reject, `history_forked` |
| history-previous-missing | reject, `history_previous_missing` |
| version-not-incremented | reject, `version_not_incremented` |
| version-gap | reject, `version_gap` |
| history-time-reversed | reject, `history_time_reversed` |
| revoked-is-final | reject, `revoked_is_final` |
| history-stops-before-head | reject, `history_head_mismatch` |
| decision-not-json | reject, `decision_malformed` |
| decision-two-signatures | reject, `decision_malformed` |
| key-unknown | reject, `key_unknown` |
| decision-signature-wrong | reject, `decision_signature` |
| decision-before-history | reject, `decision_before_history` |
| agent-suspended | reject, `agent_suspended` |
| agent-revoked | reject, `agent_revoked` |
| agent-revoked-at-effective-instant | reject, `agent_revoked` |
| agent-revoked-backdated | reject, `agent_revoked` |
| key-used-before-rotation | reject, `key_not_in_force` |
| key-retired | reject, `key_not_in_force` |

Each rejected case is built so the check it names is the first that fails and every
earlier check passes. The accepted cases are controls.

## What a case holds

- `context.json`: the consumer's pins. `issuerKeys` lists the issuer's raw Ed25519 public
  keys in lowercase hex, `agent` is the agent the consumer expects (`issuer`, `subject`),
  and `head` is the SHA-256 of the signed payload of the newest version the consumer holds.
- `history.json`: the versions, as a list of DSSE envelopes in any order. A version's
  `previous` is the SHA-256 of the previous version's payload bytes.
- `decision.json`: `at`, the instant the relying party acted, and `envelope`, the DSSE
  envelope the agent signed for it, with one signature whose `keyid` is the SHA-256 of the
  agent's raw public key.

A key's identifier is the SHA-256 of its raw bytes, the identifier a `key` entry of a
signed revocation list carries, so a consumer holding both can join them. The keys are test
keys derived from public labels.

## The checks, in order

The reader in `packaging/agent_evidence_vectors/agentidentity.py` names the first check
that fails, in the order of its `CHECKS` tuple: the history's shape, the issuer's
signature on every version, each Statement's shape, the version's own consistency (no
active version without keys, nothing effective after it was issued), the pinned agent,
the chain (one version 1, no fork, no missing link, versions rising by one, no time
running backwards, nothing after a revocation), the pinned head, and then the decision:
its shape, its key, its signature, and the version in force at `at`.

The version in force at an instant is the highest version whose `effectiveAt` is not
after it. A revocation may be issued after the fact and backdated, and a decision made
between its `effectiveAt` and its `issuedAt` is refused: that is the case a live check
could not catch and a re-verification must.

## Run it

```sh
python3 corpora/vectors-agent-identity-statement/check_vectors.py
python3 corpora/vectors-agent-identity-statement/check_vectors.py --verifier "<your verifier>"
```

The external-verifier contract is `<verifier> agent-identity-statement/v1 <case-dir> --json`:
print one JSON object with `decision` and `reason`, exit 0 for accept and 1 for reject.

Regenerate with `uv run --extra generators python corpora/vectors-agent-identity-statement/gen_vectors.py`.
