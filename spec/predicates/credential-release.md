# Predicate type: Credential Release

Type URI: https://w3id.org/agent-evidence/predicate/v1/credential-release

Version: 0.2.0

Predicate Name: Credential Release

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> the organisation (`probityai/probityai.github.io`), at
> `https://probityai.github.io/agent-evidence/predicate/v1/credential-release/`. The URI
> will not move once a signed statement carries it, and no signed statement carries it
> before that page is live. The conformance corpus in this repository,
> `vectors-credential-release/`, carries it in unsigned statements.

## Purpose

Records that a broker released a credential to a named agent, acting for a named user or
on its own authority, and holds the broker to what it said it checked. The release rests
on one of two bases. Under a **receipt** basis the broker released against an
[agent-card-receipt](agent-card-receipt.md): the record names the receipt by digest,
repeats the two receipt fields the decision turned on, and names the revocation list it
consulted by digest. Under a **grant** basis there is no Agent Card to evaluate, which is
the case for an agent driving a browser in a user's login session: the record names the
user's recorded grant by digest and repeats the grant's end. In both, the record states
the credential's kind, audience and lifetime. It has no field that can hold the
credential, a hash of it or a fingerprint of it, so the record can be shared with an
auditor without sharing anything that works as a secret.

## Use cases

- An auditor reading a broker's records can tell, for each credential released, which
  agent received it, which user it acted for, what it was released against, and that the
  credential's release ended no later than that basis did.
- A user can ask for every release made under their grant and check each against the
  grant's own bytes: the agent, the hosts and the end the grant names.
- A resource server that receives a request from an agent can ask the broker for the
  release record for the presented audience, and check it without learning the
  credential.
- A reviewer comparing two brokers sees the same record shape and the same refusal codes.

## Prerequisites

[agent-card-receipt](agent-card-receipt.md) for the receipt basis, the in-toto Attestation
Framework, strict JSON, and DSSE for the revocation list.

## Model

The producer is the broker that released the credential.

The **predicate** carries, on either basis:

- `releaseId`: a non-empty text.
- `releasedAt`: an RFC 3339 UTC time to whole seconds. Every time check is made at this
  moment, never at the time the record is read.
- `ttlSeconds`: a positive integer below 2^31. The release ends `ttlSeconds` after
  `releasedAt`. For a token the broker hands over, that is when the token expires. For a
  session cookie the broker keeps and attaches to the agent's requests itself, it is the
  moment after which the broker attaches it no more under this release; it says nothing
  about how long the site keeps the session.
- `agent`: the principal that received the credential, exactly `issuer` (an https URL)
  and `subject` (a non-empty text): the identity provider and the subject it issued to the
  agent.
- `onBehalfOf`: the user the agent acted for, in the same closed principal shape. It is
  absent when the agent acted on its own authority, and required on a grant basis, because
  a grant is a user's consent. `subject` is the identity provider's subject identifier; a
  broker that shares records outside the user's own organisation should use a pairwise
  subject (OpenID Connect Core 1.0, section 8).
- `credential`: the credential's description, closed by kind:
  - `kind` `session-cookie`: exactly `kind`, `audience` and `cookie`. `audience` is the
    origin the cookie went to, `https://` or `http://` followed by a lowercase host and the
    port only when it is not the scheme's default, with no path. The `http` scheme is
    allowed here and nowhere else, because a cookie without the `Secure` attribute is sent
    over plain HTTP by every browser, and the record must say where the value went.
    `cookie` is the cookie's name, an RFC 9110 token. A session cookie has no scope: it
    carries the user's whole session at that origin, and a record listing one would claim
    a narrowing that does not exist.
  - any other `kind` (a non-empty text such as `oauth2-access-token`): exactly `kind`,
    `audience` (an https URL) and `scope` (a non-empty, sorted, duplicate-free list of
    non-empty texts).

  A member outside `kind`, `audience`, `scope` and `cookie`, such as a token, a cookie's
  value, a secret, a hash or a fingerprint, is refused under its own code, because a
  record that can hold one will eventually be handed one.
- `broker`: `id`, an https URL.

and exactly one basis.

**Receipt basis.** The predicate also carries:

- `receipt`: `predicateType` (the agent-card-receipt Type URI), `digest` (`sha256` of the
  receipt statement's bytes), and the receipt's `result` and `validUntil` as the broker
  read them.
- `minResult`: `pass_indirect` or `pass`, the lowest receipt result the broker accepts.
- `revocationList`: `digest`, the `sha256` of the bytes of the revocation list consulted.
- `registryDigest`: the `sha256` of the vocabulary registry the results are expressed in.

The **subject** is the Agent Card the credential went to, by the same digest the receipt
carries: one member whose `digest` holds only `sha256`. The subject of the release MUST
equal the subject of the receipt it names, so a receipt for one card cannot release a
credential to another.

**Grant basis.** The predicate also carries `grant`: `digest` (`sha256` of the grant
document's bytes) and the grant's `notAfter` as the broker read it. It carries none of the
receipt basis members.

The **subject** is the grant document: one member whose `name` is the grant's `grantId`
and whose `digest` holds only the `sha256` of the grant document's bytes. In both bases the
subject is the thing the release names as the agent's authority to receive the
credential.

The **grant document** is the user's recorded consent, a strict JSON object with exactly:

- `grantId`: a non-empty text.
- `user`: the principal who granted, in the closed principal shape.
- `agent`: the principal the grant lets use the user's credentials.
- `hosts`: a non-empty, sorted, duplicate-free list of lowercase hosts, each with the port
  only when it is not the default (`mail.example.com`, `127.0.0.1:8443`), with no scheme,
  path or wildcard.
- `notAfter`: an RFC 3339 UTC time to whole seconds, when the grant ends.

The digest is over the grant document's bytes as the broker publishes them. A broker
should publish the RFC 8785 form, so two brokers holding one grant name it by one digest.

`predicateType` MUST equal the Type URI above.

## Schema

A browser session release, on a grant basis:

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "grant-0001",
      "digest": { "sha256": "<64-hex of the grant document>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/credential-release",
  "predicate": {
    "releaseId": "release-0001",
    "releasedAt": "2026-10-27T12:00:00Z",
    "ttlSeconds": 900,
    "agent": { "issuer": "https://idp.example.com/realms/agents", "subject": "mail-agent" },
    "onBehalfOf": { "issuer": "https://idp.example.com/realms/users", "subject": "user-0001" },
    "grant": { "digest": { "sha256": "<64-hex of the grant document>" },
               "notAfter": "2026-10-27T18:00:00Z" },
    "credential": { "kind": "session-cookie", "audience": "https://mail.example.com",
                    "cookie": "sid" },
    "broker": { "id": "https://broker.example.org/credential-broker" }
  }
}
```

A token release, on a receipt basis:

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
    "agent": { "issuer": "https://idp.example.com/realms/agents", "subject": "travel-agent" },
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

A verifier is given the release statement and, for a receipt basis, the receipt statement
it names, the revocation list it says it consulted and the public key of the receipt
signer, or, for a grant basis, the grant document it names. It applies these in order and
reports the first that fails. Rules 7 to 15 apply only to a receipt basis and rules 16 to
23 only to a grant basis.

| # | Rule | Code |
| --- | --- | --- |
| 1 | The release statement is strict JSON with exactly `_type`, `subject`, `predicateType` and `predicate` | `statement_malformed` |
| 2 | `_type` is `https://in-toto.io/Statement/v1` | `statement_type_wrong` |
| 3 | `predicateType` is this document's Type URI | `predicate_type_wrong` |
| 4 | `subject` has one member with `name` and a `digest` holding only a lowercase `sha256` | `subject_malformed` |
| 5 | `credential` has no member outside `kind`, `audience`, `scope` and `cookie` | `credential_fields` |
| 6 | The predicate has exactly the members of one basis, each well formed, with `credential` closed for its kind and `onBehalfOf` present on a grant basis | `predicate_malformed` |
| 7 | The receipt's bytes hash to the digest the release names | `receipt_digest_mismatch` |
| 8 | The receipt is a well formed agent-card receipt statement | `receipt_malformed` |
| 9 | The receipt's `result` and `validUntil` are the ones the release copied | `receipt_fields_differ` |
| 10 | The release's subject is the receipt's subject | `subject_not_receipted` |
| 11 | The receipt's result is at least `minResult` | `receipt_not_passing` |
| 12 | `releasedAt` is inside the receipt's window | `receipt_not_current` |
| 13 | `releasedAt` plus `ttlSeconds` is not after the receipt's `validUntil` | `credential_outlives_receipt` |
| 14 | The revocation list's bytes hash to the digest the release names | `revocation_list_digest_mismatch` |
| 15 | The list is well formed, signed by the receipt signer's key, current at `releasedAt`, and does not name the receipt | `revocation_list_malformed`, `revocation_list_signature`, `revocation_list_stale`, `receipt_revoked` |
| 16 | The grant document's bytes hash to the digest the release names | `grant_digest_mismatch` |
| 17 | The grant document is well formed | `grant_malformed` |
| 18 | The grant's `notAfter` is the one the release copied | `grant_fields_differ` |
| 19 | The release's subject digest is the grant's digest | `subject_not_granted` |
| 20 | The release's `agent` is the grant's `agent` and its `onBehalfOf` is the grant's `user` | `principals_not_granted` |
| 21 | The host and port of `credential.audience` are one of the grant's `hosts` | `audience_not_granted` |
| 22 | `releasedAt` is before the grant's `notAfter` | `grant_not_current` |
| 23 | `releasedAt` plus `ttlSeconds` is not after the grant's `notAfter` | `credential_outlives_grant` |

A member that passes every rule is accepted with the reason `release_bound`.

## What a release does not establish

A release is a statement by the broker about what it checked. It does not show that the
broker checked it: a broker can write a record for a release it never gated, and a record
is evidence only to a reader who trusts the broker's key. It does not show that the
credential was used as described, that it was not copied after release, or that the
receipt was a good evaluation: the receipt's own limits are in
[agent-card-receipt](agent-card-receipt.md). On a grant basis it does not show that the
user made the grant, only that the broker holds a document naming them, and it does not
show that the grant was still unrevoked at `releasedAt`: this version defines no grant
revocation list. It does not show that the `agent` principal and the Agent Card of a
receipt basis are the same agent. It does not hold the credential.

## Changes

- 0.2.0: `agent` and `onBehalfOf` name the principals; the grant basis releases against
  a user's grant document when no Agent Card exists; the `session-cookie` credential kind
  names an origin and a cookie, with no scope. Codes added: `grant_digest_mismatch`,
  `grant_malformed`, `grant_fields_differ`, `subject_not_granted`,
  `principals_not_granted`, `audience_not_granted`, `grant_not_current`,
  `credential_outlives_grant`.
- 0.1.0: a receipt basis only, with no member for the agent or the user.

**What a 0.1.0 record means.** It records a credential released to the Agent Card its
subject names, against the receipt it names, and says nothing about who received it or
whom they acted for. A 0.2.0 reader refuses it with `predicate_malformed`, because it has
no `agent`. No signed 0.1.0 statement was published under this URI. A producer that holds
0.1.0 records reissues them as 0.2.0 records naming the principals it knows; a record whose
principals it does not know stays a 0.1.0 record and is not reissued with invented ones.

## Conformance

`vectors-credential-release/` (suite `credential-release/v1`) holds the members. A receipt
basis member is a release statement, the receipt statement it names, the revocation list
it consulted and a context naming the signer's key; a grant basis member is a release
statement and the grant document it names. Every rule above is the first failure of at
least one member, and the accepting members are the controls on each basis, including a
session cookie sent to a plain HTTP origin and a release that ends exactly when its basis
does. A reader conforms when it reaches the declared decision and reason for every member.
`aee-verify vectors-credential-release` and the packaged Python reader both replay it.
