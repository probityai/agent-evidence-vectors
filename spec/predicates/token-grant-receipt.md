# Predicate type: Token Grant Receipt

Type URI: https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt

Version: 0.1.0

Predicate Name: Token Grant Receipt

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> the organisation (`probityai/probityai.github.io`), at
> `https://probityai.github.io/agent-evidence/predicate/v1/token-grant-receipt/`. The URI
> will not move once a signed statement carries it, and no signed statement carries it
> before that page is live.

## Purpose

Records that an identity provider issued an access token to a client, and holds the
provider to what it recorded: which client asked, for which user, under which grant,
with what audience and scope, and from which presented token. The record names the issued
token by the digest of its token identifier and every presented token by the digest of the
token as presented, so it can be shared with an auditor without sharing anything that works
as a credential.

## Use cases

- After an incident, an auditor asks which client obtained which token for which user. The
  provider's own event store answers only for a reader who trusts the provider's database,
  and it can be edited or expire. A receipt signed by a dedicated recorder key, and chained to
  the one before it, answers it for a reader who holds only the key's public half.
- A relying party that received a token computes the digest of the token's identifier and
  checks the receipt against the issuer, client, audience and scope it expected.
- A reviewer comparing two identity providers sees the same record shape for token exchange,
  client credentials and CIBA grants.

## Prerequisites

The in-toto Attestation Framework, DSSE, strict JSON, and an identity provider that exposes
a completed-grant event with the values below (OAuth 2.0 token exchange, RFC 8693; client
credentials, RFC 6749; CIBA, OpenID Connect CIBA Core).

## Model

The producer is the recorder: a component of the identity provider that holds its own Ed25519
key, distinct from the provider's token-signing key. The recorder writes one DSSE envelope per
completed grant, with payload type `application/vnd.in-toto+json`, one envelope per line of an
append-only log.

The **subject** is the issued access token: one member named `access-token-id` whose `digest`
holds only `sha256`, the SHA-256 of the token's `jti` claim. The token itself never reaches the
record. A holder of the token computes the same digest from the `jti` it carries.

The **predicate** carries exactly these members:

- `issuer`: the issuer URL of the realm or tenant that issued the token.
- `grantType`: one of `urn:ietf:params:oauth:grant-type:token-exchange`, `client_credentials`
  and `urn:openid:params:grant-type:ciba`.
- `eventId`: a non-empty text naming the provider's own event.
- `issuedAt`: an RFC 3339 UTC time to whole seconds.
- `actor`: `clientId` (the client that asked) and `authMethod` (how it authenticated, or null).
- `subject`: `userId`, the user the token names; for client credentials, the client's service
  account user.
- `subjectToken`: for a token exchange, `sha256` (the SHA-256 of the presented `subject_token`,
  taken when the recorder read the request) and `issuedTo` (the client the presented token was
  issued to, or null); null for other grants.
- `actorTokenSha256`: the SHA-256 of the presented `actor_token`, or null.
- `requestedTokenType`: the requested token type, or null.
- `audience`: the issued token's audience, a sorted, duplicate-free list of non-empty texts.
- `scope`: the issued token's scope, a sorted, duplicate-free list of non-empty texts.
- `refreshTokenIdSha256`: the SHA-256 of the refresh token's identifier, or null.
- `recorder`: `id`, `version` and `keyId`, where `keyId` is the SHA-256 of the raw 32-byte
  public key that signs the envelope.
- `chain`: `stream` (one per recorder node), `index` (a non-negative integer) and `previous`
  (the SHA-256 of the previous line's bytes, null only at index 0).

No member can hold a token value, a secret or a raw token identifier. A recorder that sees a
presented token hashes it the moment it reads it.

`predicateType` MUST equal the Type URI above.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "access-token-id",
      "digest": { "sha256": "<64-hex SHA-256 of the issued token's jti>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt",
  "predicate": {
    "issuer": "https://idp.example.org/realms/agents",
    "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
    "eventId": "evt-0001",
    "issuedAt": "2026-11-10T06:40:00Z",
    "actor": { "clientId": "agent-gateway", "authMethod": "client-secret" },
    "subject": { "userId": "5b1c0a62-0000-0000-0000-000000000001" },
    "subjectToken": { "sha256": "<64-hex SHA-256 of the presented token>",
                      "issuedTo": "agent-ui" },
    "actorTokenSha256": null,
    "requestedTokenType": null,
    "audience": ["tools-api"],
    "scope": ["tools:execute", "tools:read"],
    "refreshTokenIdSha256": null,
    "recorder": { "id": "token-grant-recorder", "version": "0.1.0",
                  "keyId": "<64-hex SHA-256 of the raw public key>" },
    "chain": { "stream": "node-1", "index": 0, "previous": null }
  }
}
```

## Rules

A verifier is given one envelope, the recorder's public key as the consumer pinned it, and the
values the consumer expects. It may also be given the recorder's whole log. It applies these in
order. A failure in rules 1, 3 and 4 is invalid input and yields no decision about the grant; a
failure in rules 2 and 5 to 7 yields `not_established`; a failure in rule 8 yields
`contradicted`.

| # | Rule | Outcome |
| --- | --- | --- |
| 1 | The envelope is strict UTF-8 JSON with exactly `payload`, `payloadType` and `signatures`; every base64 text is canonical and padded | invalid input |
| 2 | One signature verifies, under the pinned key, over the DSSE pre-authentication encoding of the payload type and payload | `receipt_signature_unverified` when none does |
| 3 | `payloadType` is `application/vnd.in-toto+json` and the payload is strict JSON with no repeated member and no floating-point number | invalid input |
| 4 | The statement has exactly `_type`, `subject`, `predicateType` and `predicate`; `predicateType` is this document's Type URI; `subject` has one member named `access-token-id` with a `digest` holding only a lowercase `sha256`; the predicate has exactly the members above, each well formed; `recorder.keyId` is the pinned key's identifier | invalid input |
| 5 | When a log is supplied, every line of it satisfies rules 1 to 4 under the same key | `receipt_log_unestablished` |
| 6 | When a log is supplied, the stream is one name, the indexes rise by one, and each `previous` is the SHA-256 of the line before | `receipt_log_unestablished` |
| 7 | When a log is supplied, the envelope is one of its lines | `receipt_log_unestablished`, or `receipt_log_unavailable` when no log can be read |
| 8 | Each value the consumer pinned equals the record's: `issuer`, `grantType`, `actor.clientId` and the subject digest, and when pinned `subject.userId`, `subjectToken.sha256` and `audience`; the record's `scope` is a subset of the scope the consumer allows | `grant_issuer_mismatch`, `grant_type_mismatch`, `grant_actor_mismatch`, `grant_token_mismatch`, `grant_subject_mismatch`, `grant_subject_token_mismatch`, `grant_audience_mismatch`, `grant_scope_exceeds_expected` |

A receipt that passes every rule is accepted with the reason `grant_recorded_as_expected`.

## What a receipt does not establish

A receipt is a statement by the holder of the recorder key that this grant was recorded with
these values. It does not show that the provider's policy allowed the grant, that the recorder
saw every grant, or who holds the key. A hash chain shows that the lines between the first and
the last the verifier was given are intact; it cannot show a removed head or a truncated tail.
A consumer that needs to detect either retains the head digest it last saw, or has an
independent party co-sign checkpoints. A recorder that runs as an event listener cannot refuse
a grant it fails to record; a deployment that must refuse writes the same record from a hook
that runs before the response. The record does not hold the token.

## Conformance

The reference check is the `token_grant_receipt/v1` claim type of `agent-evidence-verify`,
with its decisions and reasons listed above. A recorder conforms when a receipt it writes is
accepted by that check under its own pinned key for the values it recorded, and refused with
the reason of the first rule it breaks when any value differs. A conformance corpus for this
type, so that other identity providers can emit the record and be checked by one suite, is
planned for this repository and is not yet in it.
