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

The reader's checks and reason codes are listed in [reader.py](reader.py). The peer
statement is defined in [peer verification](../../../spec/predicates/peer-verification.md).

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
