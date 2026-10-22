# Predicate type: Peer verification

Type URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/peer-verification`

Status: v1. The field set below is fixed for v1. A change that adds a required field,
renames one or changes a type is published as v2 at a new URI, and this page stays.

## Purpose

A conformance runner can sign a verdict about a deployment it operates. That record is
self-attested whatever it is digested with. A peer verification statement is the artifact
a second party writes when it checked the same requirement itself. It names the vector,
the requirement and the evidence it used, and the peer signs it with its own key. A
verdict record points at the statement by digest. The runner can point at it; it cannot
produce it.

The statement is the lift artifact that the draft ACS conformance verdict evidence
predicate (GenAI-Security-Project/agent-control-standard pull request 297,
`docs/predicates/acs-verdict-evidence-v1.md`) requires for a `witness_scope` above
`SELF`. It does not depend on that predicate. Any record that names a peer check by
digest can use it.

## Envelope

The statement is an in-toto Statement v1 in a DSSE v1 envelope, `payloadType`
`application/vnd.in-toto+json`. The signature covers the DSSE pre-authentication encoding
of the payload type and payload. A signature `keyid` is the lowercase hex SHA-256 of the
raw Ed25519 public key. The consumer pins each peer key out of band, with the
relationship of its holder to the deployment under test: `peer` or `external`. The
statement never carries that relationship. A key carried in the statement is never
trusted.

The digest a verdict record names is the SHA-256 of the statement's canonical JSON
(keys sorted, no whitespace, UTF-8), not of the envelope.

## Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `subject[].digest.sha256` | 64 lowercase hex | SHA-256 of the canonical vector input the peer checked |
| `predicate.requirement` | non-empty string | The repository-relative anchor of the normative clause the peer checked |
| `predicate.evidence_artifact.kind` | `client_run` or `wire_transcript` | How the peer checked it |
| `predicate.evidence_artifact.deployment` | non-empty string | For `client_run`: the operator identifier of the deployment the peer's own client drove |
| `predicate.evidence_artifact.transcript_digest` | 64 lowercase hex | For `wire_transcript`: SHA-256 of the retained transcript bytes |
| `predicate.evidence_artifact.vector` | string | For `wire_transcript`: `acs-conformance-vector:` and the first 16 hex characters of the vector digest |
| `predicate.observed` | object | The disposition and reason codes the peer itself observed |
| `predicate.verdict` | `pass`, `rejected`, `unmeasurable` or `quarantined` | The verdict the peer reached for this vector and requirement |
| `predicate.checked_at` | RFC 3339 | When the peer checked |

## Verification

A consumer that holds a record naming a statement by digest, the statement, any transcript
it names, and its pinned peer keys checks in this order. The first check that fails names
the refusal. Each refusal leaves the record at `SELF` or refuses it.

| Step | Check | Refusal |
| --- | --- | --- |
| 1 | The consumer holds the statement the record names | `peer_artifact_unverified:not_supplied` |
| 2 | A signature naming a pinned peer key verifies; a runner key is never a peer key | `peer_artifact_unverified:untrusted_key`, `:signature_invalid` |
| 3 | The payload is a Statement v1 of this type | `peer_artifact_unverified:payload_not_statement`, `:unsupported_predicate` |
| 4 | Its canonical digest is the one the record names | `peer_artifact_unverified:digest_mismatch` |
| 5 | Its subject is the record's vector | `peer_artifact_unverified:wrong_vector` |
| 6 | Its `requirement` is the record's clause anchor | `peer_artifact_unverified:wrong_requirement` |
| 7 | It names one of the two evidence kinds | `peer_artifact_unverified:no_evidence_artifact` |
| 8 | A `client_run` names the record's deployment operator | `peer_artifact_unverified:wrong_deployment` |
| 9 | A `wire_transcript` is held and its digest and vector match | `peer_artifact_unverified:transcript_not_supplied`, `:transcript_digest_mismatch` |
| 10 | The peer observed what the record says was observed and reached the record's verdict | `peer_disagrees` |

Step 10 binds the outcome. A statement names a vector, a requirement and evidence, and the
same three hold for a second record about that vector. Without the verdict, one genuine
statement would lift a record that reports a different result.

A statement that passes every step lifts the record to the scope of the signing key's
pinned relationship: `PEER` or `EXTERNAL`. A record that claims another scope is refused
with `witness_scope_misderived`.

## What a valid statement does not establish

A valid statement shows that a pinned peer key signed exactly these bytes. It does not
show that the peer's relationship is the one the consumer pinned, that the peer's client
was honest, or that the deployment is conformant. The relationship is the consumer's own
record about a key. A co-signature over the runner's envelope is not a peer statement and
lifts nothing. A timestamp or transparency-log entry proves persistence, not verification.

## Conformance controls

The executable controls are in
[`packaging/agent_evidence_vectors/verdict_evidence/`](../../packaging/agent_evidence_vectors/verdict_evidence/README.md),
shipped in the `agent-evidence-vectors` package as `agent-evidence-vectors-verdict-evidence`.
