# Predicate type: Agent Card Receipt

Type URI: https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt

Version: 0.1.0

Predicate Name: Agent Card Receipt

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> `probityai/agent-evidence`, at
> `https://probityai.github.io/agent-evidence/predicate/v1/agent-card-receipt/`. The URI
> will not move once a signed statement carries it, and no signed statement carries it
> before that page is live. The conformance corpus in this repository,
> `vectors-agent-card-receipt/`, carries it in unsigned statements.

## Purpose

Binds the result of an evaluation of an agent to the exact A2A Agent Card the agent
serves, and says how long the result may be relied on. An Agent Card is the document a
caller reads to decide whether to talk to an agent, and the card is self-declared. A
receipt is the missing second statement: someone other than the agent ran it, graded it,
and signed the grade over the card's bytes. A caller, a gateway or a credential broker
that holds the card can check the receipt without asking the agent anything.

## Use cases

- A caller fetches an Agent Card, looks up the receipt for it, and refuses to delegate
  to an agent whose card has changed since the evaluation, whose receipt has lapsed, or
  whose receipt the issuer has revoked.
- A credential broker releases a scoped credential to an agent only against a current,
  passing receipt for the card the agent presented. [credential-release](credential-release.md)
  records that decision.
- A registry that lists agents shows the receipt state beside each card, and the state
  is recomputed by the registry's reader and not copied from the agent.

## Prerequisites

The in-toto Attestation Framework, strict JSON (a duplicate member at any depth makes a
file malformed), RFC 8785 (JSON Canonicalization Scheme), the A2A Agent Card
specification, and DSSE for the revocation list.

## Model

The producer is the party that evaluated the agent: a harness operator, an auditor or a
registry. The same party issues the signed revocation list.

The **subject** is the Agent Card, by digest. `subject` MUST carry exactly one member,
whose `digest` MUST carry exactly one entry, `sha256`, in lowercase hexadecimal. The
digest is the SHA-256 of the RFC 8785 form of the card as served, without its top-level
`signatures` member. These are A2A specification section 8.4.1 rules 2 and 3, the bytes a
card's own JWS signatures cover, so the receipt binds the bytes the card owner signs and a
card carrying signatures and the same card without them have one digest. Rule 1 of that
section, which decides whether a member the card omits is treated as present at its
default, is open in a2aproject/A2A issue 2122 and is not applied here: the digest is over
the card as it is served. A card that is not an I-JSON object, carries a duplicate member
or an integer of magnitude 2^53 or more, or has no RFC 8785 form, has no digest, and a
receipt for it is refused.

The **predicate** is the evaluation result:

- `run`: `predicateType` (an https URL) and `digest` (`sha256`) of the statement of the
  evaluation run the result was taken from, for example a done-receipt.
- `result`: one of `fail`, `degraded`, `pass_indirect`, `pass`, the lattice of the
  agent-evidence vocabulary, ordered in that sequence.
- `registryDigest`: the `sha256` of the vocabulary registry the result is expressed in.
- `issuedAt` and `validUntil`: RFC 3339 UTC times to whole seconds
  (`YYYY-MM-DDTHH:MM:SSZ`), with `issuedAt` before `validUntil`. The receipt is current
  from `issuedAt` inclusive to `validUntil` exclusive.
- `revocationList`: the https URL of the issuer's signed revocation list.
- `agentKeyThumbprints` (optional): a non-empty, sorted, duplicate-free list of RFC 7638
  JWK SHA-256 thumbprints, base64url without padding, of the keys the agent acts with.

`predicateType` MUST equal the Type URI above.

### The revocation list

The list is a DSSE envelope with `payloadType`
`application/vnd.agent-evidence.agent-card-receipt-revocations.v1+json`, at least one
signature, and a payload that is a JSON object with exactly `issuedAt`, `nextUpdate` and
`revoked`. `revoked` is a sorted, duplicate-free list of lowercase SHA-256 digests of the
bytes of revoked receipt statements. The envelope MUST be signed with the key that signs
the receipts (the verifier is given that key out of band), and the check time MUST be
inside the list's own window, `issuedAt` inclusive to `nextUpdate` exclusive. A missing
list, an unparseable one, one signed by another key, or a stale one is a refusal, never a
clean pass: a verifier that cannot read the revocation state does not know the receipt is
good.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "https://travel-agent.example.com/.well-known/agent-card.json",
      "digest": { "sha256": "<64-hex of RFC 8785 of the card without signatures>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt",
  "predicate": {
    "run": { "predicateType": "https://w3id.org/agent-evidence/predicate/v1/done-receipt",
             "digest": { "sha256": "<64-hex of the run statement>" } },
    "result": "pass",
    "registryDigest": { "sha256": "<64-hex of the vocabulary registry>" },
    "issuedAt": "2026-10-20T00:00:00Z",
    "validUntil": "2026-11-19T00:00:00Z",
    "revocationList": "https://receipts.example.org/agent-card-receipt/revocations.dsse.json",
    "agentKeyThumbprints": ["<43-character base64url thumbprint>"]
  }
}
```

## Rules

A verifier is given the card as served, the receipt statement, the revocation list, the
public key of the receipt signer and the time of the check. It applies these in order and
reports the first that fails.

| # | Rule | Code |
| --- | --- | --- |
| 1 | The statement is strict JSON with exactly `_type`, `subject`, `predicateType` and `predicate` | `statement_malformed` |
| 2 | `_type` is `https://in-toto.io/Statement/v1` | `statement_type_wrong` |
| 3 | `predicateType` is this document's Type URI | `predicate_type_wrong` |
| 4 | `subject` has one member with `name` and a `digest` holding only a lowercase `sha256` | `subject_malformed` |
| 5 | The predicate has exactly its members, each well formed | `predicate_malformed` |
| 6 | `issuedAt` is before `validUntil` | `validity_window_inverted` |
| 7 | The card is an I-JSON object with an RFC 8785 form | `card_malformed` |
| 8 | The subject digest is the SHA-256 of that form without `signatures` | `card_digest_mismatch` |
| 9 | The check time is not before `issuedAt` | `receipt_not_yet_valid` |
| 10 | The check time is before `validUntil` | `receipt_expired` |
| 11 | A revocation list is present | `revocation_list_absent` |
| 12 | The list is a well formed envelope and payload | `revocation_list_malformed` |
| 13 | The envelope verifies under the receipt signer's key over the DSSE PAE of the payload | `revocation_list_signature` |
| 14 | The check time is inside the list's window | `revocation_list_stale` |
| 15 | The list does not name the SHA-256 of the receipt statement's bytes | `receipt_revoked` |

A member that passes every rule is accepted with the reason `receipt_current`.

## Carrying the receipt on an A2A card

A2A section 4.6 lets a card declare extensions in `capabilities.extensions[]`, each
`{uri, description, required, params}`. A card declares this predicate by listing an
extension whose `uri` is the Type URI above and whose `params` carry the https URL of an
index of receipts for the agent. The extension MUST NOT carry a receipt digest: the receipt
is over the card's bytes, and a digest inside the card would make the card and the
receipt depend on each other. Setting `required` to false keeps a caller that does not
know the extension working, which is what A2A section 4.6 asks of an unknown optional
extension.

## Carrying the result in an AP2 mandate

AP2's extension points let a deployment add a mandate constraint with a unique `type`, a
schema and an evaluation algorithm, and AP2 requires that an unknown constraint evaluates
as failing. A constraint of `type` equal to this document's Type URI therefore carries a
minimum `result`, and its evaluation is the rules above applied to the card of the agent
that holds the mandate, followed by a check that the receipt's `result` is at least the
constraint's. An AP2 open mandate names the agent's key as `cnf`; when the receipt carries
`agentKeyThumbprints`, the evaluation also requires the RFC 7638 thumbprint of that key
to be listed. A processor that does not implement the constraint fails the mandate, as AP2
already requires.

## Web Bot Auth

A request signed under the IETF Web Bot Auth drafts names its key in `keyid` as an
RFC 7638 JWK SHA-256 thumbprint, and the `Signature-Agent` header names where the key
directory lives. The thumbprints in `agentKeyThumbprints` are the same value. A site or
gateway that verifies the request signature can look up the receipt for the thumbprint
and evaluate the rules above, so one 43-character string joins the request signature, the
AP2 mandate key and the card's receipt.

## What a receipt does not establish

A receipt is a signed statement that one party evaluated an agent and found the result
stated. It does not show that the evaluation was well designed: `run` names the run and the
registry names the vocabulary, and a reader who does not trust either has to read them. It
does not show that the card describes what the agent does at runtime, only that the card
as served is the card that was evaluated. It does not show who the signer is: the verifier
is handed the signer's key, and a key nobody vouches for proves nothing about origin. And
it says nothing after `validUntil` or after the revocation list names it.

## Conformance

`vectors-agent-card-receipt/` (suite `agent-card-receipt/v1`) holds the members: a card, an
unsigned statement, a signed revocation list and a context naming the check time and the
signer's key. Every rule above is the first failure of at least one member, and the
accepting members are the controls: a card with and without signatures, a check at
`issuedAt`, a list at its own `issuedAt`, a list that names a different receipt, and the
receipt extension declared on the card. A reader conforms when it reaches the declared
decision and reason for every member. `aee-verify vectors-agent-card-receipt` and the
packaged Python reader both replay it.
