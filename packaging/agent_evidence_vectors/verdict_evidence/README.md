# ACS verdict evidence controls

Executable controls for the draft ACS conformance verdict evidence predicate
(GenAI-Security-Project/agent-control-standard pull request 297,
`docs/predicates/acs-verdict-evidence-v1.md` at `v1.0.1-draft`). The draft states in prose
that a scope lift must come from an artifact the peer authored, and that a quarantine
record must be bound and must have an outcome when `review_by` passes. These cases make
a consumer's verifier prove both.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors-verdict-evidence --output out/
agent-evidence-vectors-verdict-evidence --output out/ --verifier "my-verifier"
```

The first command judges every case with the package's reference reader. The second
hands each case to the verifier under test as `<verifier> <case-dir>/case.json --json`.
The verifier prints one JSON object with `decision` and `reason`. It exits 0 for
`supported`, 1 for `contradicted` or `not_established`, and 2 when it reaches no verdict.
The run exits 0 only when every case was answered and every answer matched.
`MANIFEST.json` lists every case with its expected answer and the SHA-256 of every file.

## What each case holds

`case.json` names the signed record (`record.json`), the vector input (`vector.json`),
the files the consumer retained (`peer-statement.json`, `transcript.json`) and the
policy: the pinned runner keys, the pinned peer keys with each holder's relationship
(`peer` or `external`), and the evaluation time `as_of`. Every key is a test key whose
seed is the SHA-256 of the label in `MANIFEST.json`.

## The controls

Each refused case changes one thing about a supported twin.

| Control | Accepted | Refused |
| --- | --- | --- |
| Peer statement | client run and retained transcript, peer and external keys | wrong peer key, statement signed by the runner, wrong vector, wrong requirement, statement absent, digest mismatch, tampered signature, wrong statement type, no evidence kind, client run on another deployment, transcript absent or different, peer observed something else |
| Scope | `SELF` with no peer statement, with an unpinned co-signature, with a timestamp anchor | `PEER` claimed with no statement, `EXTERNAL` claimed through a peer key, operators unequal with no statement, a runner-written `lift_state` |
| Integrity | | edited `observed`, digest field list without `witness_scope`, other subject, unpinned runner key, wrong payload type, not a Statement, other predicate type, each malformed field |
| Quarantine | bound record inside `review_by` | `review_by` edited, `owner` edited and digest recomputed under the old signature, `expiry_disposition` absent, outside the digest or undefined, no issue or gap named, `review_by` passed |

## Reason codes

The reader checks a verdict record in this order and names the first check that fails.
The reference implementation is [reader.py](reader.py); the peer statement and its own
refusals (`peer_artifact_unverified:<step>`, `peer_disagrees`) are defined in
[peer verification](../../../spec/predicates/peer-verification.md).

| Step | Check | Decision and reason |
| --- | --- | --- |
| 1 | The record is a DSSE v1 envelope | no verdict, `malformed_envelope` |
| 2 | Its payload type is `application/vnd.in-toto+json` | `not_established`, `unsupported_payload_type` |
| 3 | A signature naming a pinned runner keyid verifies over the DSSE PAE; a signature naming any other key is ignored | `contradicted`, `untrusted_key` or `signature_invalid` |
| 4 | The payload is an in-toto Statement v1 | `payload_not_statement` |
| 5 | Its predicate type is the pinned one | `unsupported_predicate` |
| 6 | Every field is well formed, in the draft's table order, and no field by which the runner asserts its own scope is present | `field_invalid:<field>` |
| 7 | The subject digest is the SHA-256 of the canonical vector input and `vector_id` is its first 16 hex characters | `subject_digest_mismatch` |
| 8 | `payload_digest` recomputes over `payload_digest_fields`, and that list covers every field the draft names | `payload_digest_mismatch`, `payload_digest_fields_incomplete` |
| 9 | `witness_scope` equals the scope derived from operator identifier equality and the verified peer statement | `witness_scope_misderived`, `peer_artifact_unverified:<step>`, `peer_disagrees` |

A record that passes all nine is `supported`, with the reason naming the derived scope:
`verdict_verified_self`, `verdict_verified_peer` or `verdict_verified_external`.

A quarantine record (a predicate whose `status` is `quarantined`) passes steps 1 to 5 and
7, then: every quarantine field is present, with an issue or a named gap
(`quarantine_field_missing:<field>`); `expiry_disposition` is one of the defined outcomes
(`field_invalid:expiry_disposition`); its digest field list covers every quarantine field
(`payload_digest_fields_incomplete`); the digest recomputes (`quarantine_digest_mismatch`);
and `review_by` has not passed at the policy's `as_of` time (`not_established`,
`quarantine_overdue`: the vector reads `unmeasurable` and stays excluded). One that passes
is `supported`, `quarantine_in_force`.

## Rules these controls add to the draft

Four rules are proposed here and are not yet in the draft text:

- `payload_digest_fields` must cover every field the draft names, so a record cannot
  leave `witness_scope` outside its own digest (`payload_digest_fields_incomplete`);
- the quarantine digest must cover `expiry_disposition`, and its value is
  `revert_to_unmeasurable`, so the expiry outcome cannot be edited in silence;
- after `review_by` a quarantine record is `not_established` with `quarantine_overdue`,
  and the vector reads `unmeasurable`;
- a peer statement carries what the peer observed and the verdict it reached, and a record
  whose peer saw something else, or that reuses one statement for another verdict, is
  refused with `peer_disagrees`.

## What a supported case does not establish

A supported verdict means a pinned runner key signed these bytes, the digest recomputes,
and the scope follows from the operator identifiers and a peer statement that a pinned
peer key signed. It does not establish that the runner observed what it reports, that the
pinned relationship of a peer key is true, or that the deployment is conformant. A digest
is integrity. An anchor is persistence. Neither is provenance.
