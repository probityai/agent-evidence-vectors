# Predicate type: Credential Release

Type URI: https://w3id.org/agent-evidence/predicate/v1/credential-release

Version: 0.1.0

Predicate Name: Credential Release

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> `probityai/agent-evidence`, at
> `https://probityai.github.io/agent-evidence/predicate/v1/credential-release/`. The URI
> will not move once a signed statement carries it, and no signed statement carries it
> before that page is live. The conformance corpus in this repository,
> `vectors-credential-release/`, carries it in unsigned statements.

## Purpose

Records that a broker released a credential to an agent against a named
[agent-card-receipt](agent-card-receipt.md), and holds the broker to what it said it
checked. The record names the receipt by digest, repeats the two receipt fields the
decision turned on, names the revocation list the broker consulted by digest, and states
the credential's audience, scope and lifetime. It has no field that can hold the
credential, a hash of it or a fingerprint of it, so the record can be shared with an
auditor without sharing anything that works as a secret.

## Use cases

- An auditor reading a broker's log can tell, for each credential released, which receipt
  it was released against, whether that receipt was passing and current at that moment,
  and that the credential expired no later than the receipt did.
- A resource server that receives a request from an agent can ask the broker for the
  release record for the presented audience and scope, and check it without learning the
  credential.
- A reviewer comparing two brokers sees the same record shape and the same refusal codes.

## Prerequisites

[agent-card-receipt](agent-card-receipt.md), the in-toto Attestation Framework, strict
JSON, and DSSE for the revocation list.

## Model

The producer is the broker that released the credential.

The **subject** is the Agent Card the credential went to, by the same digest the receipt
carries: one member whose `digest` holds only `sha256`. The subject of the release MUST
equal the subject of the receipt it names, so a receipt for one card cannot release a
credential to another.

The **predicate** carries:

- `releaseId`: a non-empty text.
- `releasedAt`: an RFC 3339 UTC time to whole seconds. Every time check is made at this
  moment, never at the time the record is read.
- `ttlSeconds`: a positive integer below 2^31. The credential expires `ttlSeconds` after
  `releasedAt`.
- `receipt`: `predicateType` (the agent-card-receipt Type URI), `digest` (`sha256` of the
  receipt statement's bytes), and the receipt's `result` and `validUntil` as the broker
  read them.
- `minResult`: `pass_indirect` or `pass`, the lowest receipt result the broker accepts.
- `revocationList`: `digest`, the `sha256` of the bytes of the revocation list consulted.
- `credential`: exactly `kind`, `audience` (an https URL) and `scope` (a non-empty,
  sorted, duplicate-free list of non-empty texts). The object is closed. A member outside
  these three, such as a token, a secret, a hash or a fingerprint, is refused under its own
  code, because a record that can hold one will eventually be handed one.
- `broker`: `id`, an https URL.
- `registryDigest`: the `sha256` of the vocabulary registry the results are expressed in.

`predicateType` MUST equal the Type URI above.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "https://travel-agent.example.com/.well-known/agent-card.json",
      "digest": { "sha256": "<the receipt's subject digest>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/credential-release",
  "predicate": {
    "releaseId": "release-0001",
    "releasedAt": "2026-10-27T12:00:00Z",
    "ttlSeconds": 900,
    "receipt": { "predicateType": "https://w3id.org/agent-evidence/predicate/v1/agent-card-receipt",
                 "digest": { "sha256": "<64-hex of the receipt statement>" },
                 "result": "pass", "validUntil": "2026-11-19T00:00:00Z" },
    "minResult": "pass",
    "revocationList": { "digest": { "sha256": "<64-hex of the list consulted>" } },
    "credential": { "kind": "oauth2-access-token",
                    "audience": "https://api.travel-bookings.example.com",
                    "scope": ["bookings:hold", "bookings:read"] },
    "broker": { "id": "https://broker.example.org/credential-broker" },
    "registryDigest": { "sha256": "<64-hex of the vocabulary registry>" }
  }
}
```

## Rules

A verifier is given the release statement, the receipt statement it names, the revocation
list it says it consulted, and the public key of the receipt signer. It applies these in
order and reports the first that fails.

| # | Rule | Code |
| --- | --- | --- |
| 1 | The release statement is strict JSON with exactly `_type`, `subject`, `predicateType` and `predicate` | `statement_malformed` |
| 2 | `_type` is `https://in-toto.io/Statement/v1` | `statement_type_wrong` |
| 3 | `predicateType` is this document's Type URI | `predicate_type_wrong` |
| 4 | `subject` has one member with `name` and a `digest` holding only a lowercase `sha256` | `subject_malformed` |
| 5 | `credential` has no member outside `kind`, `audience` and `scope` | `credential_fields` |
| 6 | The predicate has exactly its members, each well formed | `predicate_malformed` |
| 7 | The receipt's bytes hash to the digest the release names | `receipt_digest_mismatch` |
| 8 | The receipt is a well formed agent-card receipt statement | `receipt_malformed` |
| 9 | The receipt's `result` and `validUntil` are the ones the release copied | `receipt_fields_differ` |
| 10 | The release's subject is the receipt's subject | `subject_not_receipted` |
| 11 | The receipt's result is at least `minResult` | `receipt_not_passing` |
| 12 | `releasedAt` is inside the receipt's window | `receipt_not_current` |
| 13 | `releasedAt` plus `ttlSeconds` is not after the receipt's `validUntil` | `credential_outlives_receipt` |
| 14 | The revocation list's bytes hash to the digest the release names | `revocation_list_digest_mismatch` |
| 15 | The list is well formed, signed by the receipt signer's key, current at `releasedAt`, and does not name the receipt | `revocation_list_malformed`, `revocation_list_signature`, `revocation_list_stale`, `receipt_revoked` |

A member that passes every rule is accepted with the reason `release_bound`.

## What a release does not establish

A release is a statement by the broker about what it checked. It does not show that the
broker checked it: a broker can write a record for a release it never gated, and a record
is evidence only to a reader who trusts the broker's key. It does not show that the
credential was used as scoped, that it was not copied after release, or that the receipt
was a good evaluation: the receipt's own limits are in
[agent-card-receipt](agent-card-receipt.md). It does not hold the credential.

## Conformance

`vectors-credential-release/` (suite `credential-release/v1`) holds the members: a release
statement, the receipt statement it names, the revocation list it consulted and a context
naming the signer's key. Every rule above is the first failure of at least one member, and
the accepting members are the controls: a minimum of `pass_indirect`, a release at the
receipt's `issuedAt`, a credential that ends exactly when the receipt does, and a plain
release against a passing receipt. A reader conforms when it reaches the declared decision
and reason for every member. `aee-verify vectors-credential-release` and the packaged
Python reader both replay it.
