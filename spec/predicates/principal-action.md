# Predicate type: Principal Action

Type URI: https://w3id.org/agent-evidence/predicate/v1/principal-action

Version: 0.1.0

Predicate Name: Principal Action

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> the organisation (`probityai/probityai.github.io`), at
> `https://probityai.github.io/agent-evidence/predicate/v1/principal-action/`. The URI
> will not move once a signed statement carries it. The conformance corpus in this
> repository, `vectors-principal-action/`, carries it in signed statements made with
> published test keys.

## Purpose

Records that an action an agent took ran under principals an identity provider
authenticated, and binds each principal to the credential that proved it. A gateway, a
tool server or a decision point that validated a signed token before it let the agent act
knows who the token named, which client it was issued to, which key the issuer signed it
with and whether the token carried a delegation chain. Logs keep that answer as text a
reader cannot check. This predicate keeps it as signed bytes: up to four principals, each
named by issuer, subject, client, audience, the digest of the credential, the issuer key
and its RFC 7638 thumbprint, and the digest of the issuer's key set, together with the
RFC 8693 `act` chain the credential carried. A third party rechecks every binding offline,
against the issuers and keys it trusts, without the token.

## Use cases

- An auditor reading a tool server's records can tell, for each call, which user invoked
  it, which agent executed it, who is accountable for that agent and who approved the
  call, and that each of them was established from a credential of an issuer the auditor
  trusts, under a key the auditor pinned for that issuer.
- A relying party that requires delegated authority can refuse a record whose user
  credential names a different agent in its `act` chain, and can require `strict`
  conformance: all four principals and a delegation chain.
- A gateway operator that accepts Cross App Access grants records the identity assertion
  grant as the principal's source, so the grant and the action are joined by digest.

## Prerequisites

The in-toto Attestation Framework (Statement v1 in a DSSE envelope), RFC 8785 (JSON
Canonicalization Scheme), RFC 7638 (JWK thumbprint), RFC 7517 (JWK), RFC 8693 (`act`
claim), and the `principal` member of the agent audit record
([proposed text](../../docs/proposals/audit-record-04-principal.md)), whose members each
principal here carries unchanged.

## Model

The producer is the party that validated the credentials before the action ran: a
gateway, a tool server or a decision point. It signs the statement with its own key in a
DSSE envelope whose `payloadType` is `application/vnd.in-toto+json`. The payload is the
RFC 8785 serialization of the statement, and no other serialization is accepted.

The **subject** is the action: exactly one member, named `action`, whose `digest` holds
only `sha256`, the SHA-256 of the RFC 8785 bytes of the predicate's `action` object.

The **predicate** carries:

- `action`: what was done, an object of exactly these members:
  - `tool`: the name of the tool, operation or endpoint, a non-empty text.
  - `argumentsDigest`: the SHA-256 of the RFC 8785 bytes of the arguments, 64 lower-case
    hexadecimal characters. The arguments are never carried.
  - `at`: the time the action was taken, an RFC 3339 UTC time ending in `Z`. Every time
    check is made at this moment, never when the record is read.
- `principals`: an object whose keys are drawn from `user` (who invoked the action),
  `agent` (what executed it), `sponsor` (the accountable owner of the agent) and
  `approver` (who approved the action, when someone did). `user` and `agent` are
  required. Each value is a principal, defined below.
- `approvals`: OPTIONAL, an array of approvals the record counts, each an object of
  exactly `subject` (the approver's subject, a non-empty text) and `approvalDigest` (the
  SHA-256 of the approval record's bytes, 64 lower-case hexadecimal characters).

A **principal** is an object carrying exactly the required members of the audit-record
`principal` member, and MAY carry its optional members and `act` and `idJag`:

- Required: `issuer` (an `https` URL), `subject`, `clientId`, `audience` (a non-empty
  array of distinct texts), `authMethod` (a value of the IANA registry "OAuth Token
  Endpoint Authentication Methods"), `source`, `tokenDigest`, `issuedAt`, `expiresAt`,
  `kid`, `key`, `keyThumbprint` and `jwksDigest`, each as the audit-record member defines
  it.
- `source` is one of `jwt-access-token` (RFC 9068), `id-token` (OpenID Connect Core 1.0),
  `jwt-assertion` (RFC 7523) and `id-jag` (an Identity Assertion JWT Authorization Grant,
  JWS `typ` `oauth-id-jag+jwt`).
- `tokenDigest` is the assertion digest: the SHA-256 of the exact credential bytes the
  principal presented, 64 lower-case hexadecimal characters. The credential is never
  carried.
- Optional: `tenant`, `identityProvider` and `pinnedThumbprint`, as the audit-record
  member defines them.
- `act`: OPTIONAL, the credential's RFC 8693 `act` claim as the credential carried it: an
  object with a text `sub`, and optionally a nested `act` of the same shape, outermost
  (the current actor) first.
- `idJag`: OPTIONAL, reserved for the identity assertion grant block of the audit-record
  `principal` member. Its members and checks are those that definition gives. Until it
  is published, a verifier refuses a principal carrying `idJag`
  (`principal_idjag_undefined`), because it cannot check what it was given.

## Schema

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "action", "digest": {"sha256": "<sha256 of RFC 8785 action>"}}],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/principal-action",
  "predicate": {
    "action": {"tool": "<text>", "argumentsDigest": "<hex64>", "at": "<RFC 3339 Z>"},
    "principals": {
      "user": {"issuer": "https://...", "subject": "<text>", "clientId": "<text>",
               "audience": ["<text>"], "authMethod": "<IANA value>", "source": "<source>",
               "tokenDigest": "<hex64>", "issuedAt": "<RFC 3339 Z>",
               "expiresAt": "<RFC 3339 Z>", "kid": "<text>", "key": {"kty": "...", "kid": "..."},
               "keyThumbprint": "<base64url>", "jwksDigest": "<hex64>",
               "act": {"sub": "<agent subject or client>"}},
      "agent": {"...": "a principal"},
      "sponsor": {"...": "a principal, optional"},
      "approver": {"...": "a principal, optional"}
    },
    "approvals": [{"subject": "<text>", "approvalDigest": "<hex64>"}]
  }
}
```

## Rules

A verifier holds the producer's public key and a pin set: for each issuer it trusts, the
RFC 7638 thumbprints of the issuer keys it accepts. The pin set is the verifier's policy
and is never read from the record. The verifier applies these checks in this order and
reports the first that fails; the codes are the reference reader's.

1. The envelope parses, its payload is an in-toto Statement v1 of this type with one
   `action` subject, and the predicate has `action` and `principals` objects and, when
   present, an `approvals` array of well-formed approvals (`statement_malformed`).
2. The DSSE signature verifies under the producer key (`recorder_signature_invalid`).
3. The payload is byte-for-byte the RFC 8785 serialization of the statement
   (`statement_not_canonical`).
4. `action` carries exactly `tool`, `argumentsDigest` and `at`, well formed
   (`action_malformed`).
5. The subject digest is the SHA-256 of the RFC 8785 bytes of `action`
   (`action_digest_mismatch`).
6. `principals` is a non-empty object whose keys are roles (`principals_malformed`).
7. For each role present, in the order `user`, `agent`, `sponsor`, `approver`, the
   principal passes the checks below; a failure is reported as
   `principal_<role>:<code>`.
   1. It is an object (`principal_malformed`), carries every required member
      (`principal_member_missing`) and no member outside the required and optional
      sets (`principal_member_unknown`).
   2. `issuer` is an `https` URL (`principal_issuer_invalid`); `subject`, `clientId`,
      `kid` and `keyThumbprint` are non-empty texts, `audience` a non-empty array of
      distinct texts, `source` and `authMethod` registered values, `tokenDigest` and
      `jwksDigest` 64 lower-case hexadecimal characters, `identityProvider` a value of
      the `identity_provider` term and `pinnedThumbprint` unpadded base64url, where
      present (`principal_malformed`).
   3. `key` is a public JWK with no private member (`principal_key_invalid`), of key
      type `RSA`, `EC` or `OKP` with every member its thumbprint needs
      (`principal_key_invalid`).
   4. `keyThumbprint` is the RFC 7638 SHA-256 thumbprint of `key`
      (`principal_thumbprint_mismatch`), and `key.kid` equals `kid`
      (`principal_kid_mismatch`).
   5. A declared `identityProvider` agrees with the provider the `issuer` names, by the
      derivation of the audit-record member (`principal_provider_mismatch`), and a
      `pinnedThumbprint` equals `keyThumbprint` (`principal_pin_mismatch`).
   6. `issuedAt` and `expiresAt` are RFC 3339 UTC times with `expiresAt` later
      (`principal_malformed`); at `action.at` the credential had been issued
      (`principal_not_yet_valid`) and had not expired (`principal_expired`).
   7. The pin set names `issuer` (`principal_issuer_untrusted`) and holds
      `keyThumbprint` for it (`principal_key_not_pinned`).
   8. `act`, when present, is a chain of objects each with a text `sub`
      (`principal_act_malformed`).
   9. `idJag`, when present, is refused until its definition is published
      (`principal_idjag_undefined`).
8. `user` and `agent` are both present (`principals_need_user_and_agent`).
9. When the user principal carries `act`, the outermost actor's `sub` is the agent
   principal's `subject` or `clientId` (`principal_act_names_another_agent`).
10. When `approver` is present, its `subject` is the `subject` of one of `approvals`
    (`principal_approver_not_an_approval_signer`). A record with no `approvals` counts
    none.

A record that passes every check is verified, and graded on two axes. Never refused on
either:

- **Delegation:** `act-chain` when the user principal carries `act`, `act-absent` when it
  does not.
- **Conformance:** `strict` when all four roles are present and the delegation is
  `act-chain`; `basic` otherwise. A relying party MAY require `strict`.

## What a record does not establish

That the credential's signature verified (the producer checked it; the record names the
key it used and the digest of the credential, so a party holding the credential and the
retained key set rechecks it), that the issuer's key set at that time held `key` (the
retained key set and `jwksDigest` answer that), that a custom-domain issuer is run by the
provider it declares, or that a subject is who the issuer says it is. A signature shows
who wrote the record, not that it is true.

## Relation to other types

- The agent audit record's `principal` member carries one principal of a decision. This
  type carries up to four for one action, with the delegation chain, and each principal
  is that member's object unchanged, so one reader checks both.
- A `token-grant-receipt` records the issuance of a credential at the identity provider.
  A principal here names that credential by `tokenDigest`; joining the two by that digest
  ties the action to the grant without either record holding the token.

## Conformance

`corpora/vectors-principal-action/` (suite `principal-action/v1`) holds signed accept
and reject cases with a published producer test key. Each case is `case.json` (the
producer key and the verifier's pin set) and one envelope. A verifier conforms when it
gives every case its declared decision and reason. The reference readers are
`packaging/agent_evidence_vectors/principalaction.py` and
`corpusreaders/principalaction.go`, written independently of each other.
