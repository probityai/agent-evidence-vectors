# Predicate type: Agent Identity Statement

Type URI: https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement

Version: 0.1.0

Predicate Name: Agent Identity Statement

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The URI redirects to a page built from this file and served by the Pages site of
> the organisation (`probityai/probityai.github.io`), at
> `https://probityai.github.io/agent-evidence/predicate/v1/agent-identity-statement/`. The
> URI will not move once a signed statement carries it, and no signed statement carries it
> before that page is live. The conformance corpus in this repository,
> `vectors-agent-identity-statement/`, carries it in statements signed with test keys.

## Purpose

Records, for each version of an agent's identity document, which keys were in force and
whether the agent was active, suspended or revoked, from which instant, signed by the
party that issues the agent's identity and chained to the version before it. A relying
party that accepted a signed request from an agent can then answer, after the fact and
offline, the question a key directory cannot: when the decision was made, was the key that
signed it in force, and was the agent allowed to act? A directory shows the keys as they are
now. A live status lookup answers for the moment it is made and leaves no record. Neither
lets an auditor re-check a decision made last month, after a rotation or a revocation.

## Use cases

- A relying party that keeps the agent's signed requests and the issuer's history can show
  an auditor that every request it accepted was signed by a key in force, by an agent that
  was active at that instant.
- An issuer that learns a key was compromised revokes the agent with an `effectiveAt` before
  the statement's own `issuedAt`. Every decision made in that window is refused on re-check,
  which no check made at the time could have done.
- A consumer that holds the newest version an issuer published can tell a history that
  stops early (a withheld revocation) from a complete one, because it pins the head.
- Two issuers' histories read the same way, with the same refusal codes.

## Prerequisites

The in-toto Attestation Framework, DSSE, strict JSON and Ed25519.

## Model

The producer is the issuer of the agent's identity: the identity provider, registry or
platform that names the agent and stands behind its keys. Each version is an in-toto
Statement in a DSSE envelope (`payloadType` `application/vnd.in-toto+json`) signed with an
issuer key. A consumer pins the issuer's keys; it never takes a key from the history it is
checking.

The **subject** is the identity document this version describes: one member whose `name`
identifies the document (its URL, for a served document) and whose `digest` holds only the
`sha256` of that version's bytes. The statement binds the version to those bytes; the
verifier does not need the document itself.

The **predicate** carries:

- `agent`: the agent, exactly `issuer` (an https URL) and `subject` (a non-empty text), the
  principal shape [credential-release](credential-release.md) uses. Every version of one
  history names the same agent.
- `version`: a positive integer below 2^53. Version 1 begins the history.
- `previous`: `sha256`, the SHA-256 of the previous version's DSSE payload bytes. Present
  exactly when `version` is above 1.
- `issuedAt`: when the issuer signed this version, an RFC 3339 UTC time to whole seconds.
- `effectiveAt`: when this version takes effect, in the same form, never after `issuedAt`.
  It may be earlier: an issuer that learns of a compromise late revokes from the moment it
  began.
- `status`: `active`, `suspended` or `revoked`. `revoked` is final: no version follows it.
  A suspended agent may be made active again by a later version.
- `keys`: the agent's keys in force, a list of `{ "type": "Ed25519", "publicKey": <the raw
  32-byte key in lowercase hex> }`, sorted by `publicKey`, without duplicates. An `active`
  version lists at least one key. A key's identifier is the SHA-256 of its raw bytes, which
  is the identifier a `key` entry of a signed revocation list carries.
- `reason`: an optional non-empty text, for a person reading why the status changed.

Each member is exactly as listed; any other member makes the predicate malformed.

**The version in force** at an instant is the version with the highest `version` whose
`effectiveAt` is not after that instant. An instant before version 1's `effectiveAt` has no
version in force.

`predicateType` MUST equal the Type URI above.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "https://agents.example.com/travel-agent/identity.json",
      "digest": { "sha256": "<64-hex of this version of the document>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement",
  "predicate": {
    "agent": { "issuer": "https://idp.example.com/realms/agents", "subject": "travel-agent" },
    "version": 2,
    "previous": { "sha256": "<64-hex of version 1's signed payload>" },
    "issuedAt": "2026-11-10T00:00:00Z",
    "effectiveAt": "2026-11-10T00:00:00Z",
    "status": "active",
    "keys": [ { "type": "Ed25519", "publicKey": "<64-hex raw key>" } ]
  }
}
```

## Verifying a past decision

A consumer holds the issuer's keys, the agent it expects, and the SHA-256 of the newest
version it has (the head). It is given the history and a decision: the instant it acted and
the DSSE envelope the agent signed, with one signature whose `keyid` is the SHA-256 of the
agent's raw key. It refuses with the first rule that fails:

| Order | Rule | Code |
| --- | --- | --- |
| 1 | The history is a non-empty list of DSSE envelopes with in-toto payloads | `history_malformed` |
| 2 | Every version is signed by a pinned issuer key | `statement_signature` |
| 3 | Each payload is exactly the four Statement members | `statement_malformed` |
| 4 | `_type` is in-toto Statement v1 | `statement_type_wrong` |
| 5 | `predicateType` is this Type URI | `predicate_type_wrong` |
| 6 | The subject is one member with a lowercase SHA-256 | `subject_malformed` |
| 7 | The predicate has exactly its members, each well formed | `predicate_malformed` |
| 8 | No `active` version has an empty key set | `active_without_keys` |
| 9 | No version takes effect after it was issued | `effective_after_issued` |
| 10 | Every version names the pinned agent | `agent_mismatch` |
| 11 | There is a version 1 | `history_no_genesis` |
| 12 | No two versions name the same previous version (or both begin the history) | `history_forked` |
| 13 | Every previous version is in the history | `history_previous_missing` |
| 14 | A version is above its previous one | `version_not_incremented` |
| 15 | A version is its previous one plus one | `version_gap` |
| 16 | Neither `effectiveAt` nor `issuedAt` runs backwards | `history_time_reversed` |
| 17 | Nothing follows a revoked version | `revoked_is_final` |
| 18 | The chain ends at the pinned head | `history_head_mismatch` |
| 19 | The decision is an instant and an envelope with one signature naming its key | `decision_malformed` |
| 20 | Some version lists the decision's key | `key_unknown` |
| 21 | That key signed the decision | `decision_signature` |
| 22 | A version is in force at the decision's instant | `decision_before_history` |
| 23 | The agent is not suspended in it | `agent_suspended` |
| 24 | The agent is not revoked in it | `agent_revoked` |
| 25 | Its key set holds the decision's key | `key_not_in_force` |

A decision that passes every rule is accepted with reason `key_in_force`. Identical
envelopes count once.

The head is the consumer's own pin. A history whose newest version is not the head, such as
one that stops before a revocation the consumer already saw, is refused rather than read as
complete. What the head cannot show is a version the consumer never received; a consumer
that must know it holds the newest version fetches the head from the issuer, or from a log
the issuer writes each version into, at the time it re-checks.

## What it does not establish

That the issuer is entitled to speak for the agent (the consumer decides that by pinning its
keys), that the identity document's contents are true, or that a decision whose instant the
relying party recorded wrongly was made when it says. It establishes, for the decision as
recorded, that the history the issuer signed placed the key in force and the agent active at
that instant.

## Changes

- 0.1.0: first version.
