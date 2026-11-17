# Record binding terms

Name which bytes a digest or signature covers, the rule that produced them, the order of a record stream and whose key may sign, so a party that does not trust the producer can recompute every binding. The [README](../README.md) is the short version of the repository; this page covers the `record_binding` section, added in 0.10.0. Every term is `proposed`, lists no issuer, carries `criticality: critical`, a `review_by` date and a `check`, and none is canonical.

## The terms

| term | what it names | check |
|---|---|---|
| `canonicalization` | the rule that turns a record or a referenced object into the bytes that are hashed or signed | recompute under exactly the declared rule; undeclared is cannot tell; a refusal by a declared subset profile is counted as outside the profile, never as a mismatch |
| `hash_alg` | the hash function of a digest | named next to the digest, never inferred from its length; length and alphabet must match |
| `sequence_number` | a record's position in its producer's stream for one trajectory | from 0, rising by exactly 1, in 0 to 2^53-1, consistent with the digest chain |
| `trajectory_head` | what fixes the end of a named record stream | witnessed only under a pinned witness key, over the stream identity the consumer asked for, the last digest and the count walked; the signed bytes are `agent-evidence/record-binding/v1/trajectory-head`, then the identity, the digest and the decimal count, each after one 0x0A |
| `coverage_boundary` | what a stream or digest is meant to cover, including which copy of an object | an omission is reported only inside a declared boundary; a digest over a copy the consumer does not read is refused |
| `signature_coverage` | how much of a record a verifying signature covers | full only when every member the consumer acts on is signed; an unreachable key is cannot tell |
| `key_authority` | what proves the signing key may speak for the record | agreement only under a checked pin, DNSSEC chain or key-transparency inclusion; a self-carried key tops out at cannot tell |
| `signing_construction` | which bytes a signature over an agent catalog object is computed on | an input, never searched for; every verdict names the construction it applied |
| `key_history` | the standing of a signing key as of the record's issuance time | evaluated at the signed issuance time against a held key history |

The link from a record to the one before it is `receipt_chain_link`, in the `decision_receipt` section. Its rule applies to any stream of records, so this section adds the sequence number, the head and the coverage boundary and does not register a second link term.

## The values

| term | values |
|---|---|
| `canonicalization` | `rfc8785`, `jcs_safe_integer_v1`, `jcs_integer_only_v1`, `cbor_deterministic`, `raw` |
| `hash_alg` | `sha_256`, `sha_384`, `sha_512` |
| `trajectory_head` | `witnessed`, `producer_signed`, `absent` |
| `coverage_boundary` | `declared`, `undeclared` |
| `signature_coverage` | `full`, `endpoint_only`, `none` |
| `key_authority` | `pin`, `dnssec_chain`, `kt_inclusion`, `none` |
| `signing_construction` | `ard_draft_bu_00`, `ai_catalog_2026_11`, `ai_catalog_snapshot`, `field_whole_entry` |
| `key_history` | `key_current`, `key_rotated_out`, `key_not_authorized_at_issue`, `key_revoked`, `key_unknown` |

## Two safe-integer profiles, not one

`jcs_safe_integer_v1` and `jcs_integer_only_v1` both refuse integers a double cannot hold exactly, and they differ on everything else:

| number token | `rfc8785` | `jcs_safe_integer_v1` | `jcs_integer_only_v1` |
|---|---|---|---|
| `9007199254740991` | in | in | in |
| `9007199254740992` | in | outside | outside |
| `9007199254740991.5` | in | outside (its nearest double is 2^53) | outside |
| `1.5` | in | in | outside |
| `1e2` | in | in | outside |
| `1.00000000000000001e16` | in | outside | outside |
| `-0` | in (written `0`) | in (written `0`) | outside (the profile refuses the rewrite to `0`) |

`registry.number_in_profile(token, profile)` in the Python package applies the rule to one token:

```python
from agent_evidence_vocabulary import registry

registry.number_in_profile("9007199254740991.5", "jcs_safe_integer_v1").reason   # 'outside-profile-unsafe-integer'
registry.number_in_profile("1.5", "jcs_integer_only_v1").reason                   # 'outside-profile-not-an-integer'
registry.number_in_profile("1.5", "jcs_safe_integer_v1").value                     # 'jcs_safe_integer_v1'
```

RFC 7493 section 2.2 says only that a sender cannot expect exactness past 2^53-1, so neither profile is called I-JSON. A verifier that holds a record under one profile never judges it under the other.

## Key history as of issuance

`registry.key_history(history, key_id, issued_at)` reads a history of `{key, authorized_from, retired_at, revoked_at}` entries at the signed issuance time. Every entry that names the key is read, never only the first, so a later entry that revokes it is not hidden behind an earlier one. A key whose every window holding the issuance time has since ended, by rotation or by a revocation effective after issuance, is `key_rotated_out` and the record stays valid; `key_current` needs a window that is still open and no recorded revocation; a key whose authorization had not begun, or had ended, at issuance is `key_not_authorized_at_issue` and the record is refused; a revocation for compromise applies from its effective time; a key the history does not name is `key_unknown`, an indeterminate result. A history entry that is not an object, or a window whose `retired_at` precedes its `authorized_from`, makes the history malformed and is refused, never read as an empty window.

## Crosswalks

`crosswalk/dns-aid-core.yaml` maps the dns-aid-core `SignatureStatus` values onto `signature_coverage` and `key_authority`. `crosswalk/ai-catalog.yaml` maps the AI Catalog signing procedures onto `signing_construction` and `canonicalization`. `crosswalk/draft-pei-opsawg-agentops-observability.yaml` maps the event model of that IETF draft onto `sequence_number` and records the integrity members it does not carry. All three are third-party filings that record provenance and promote nothing.

OBS-5 of draft-mcw-opsawg-icon-requirements-02 asks that telemetry be tamper-evident against both alteration and omission of execution trajectories. A per-event hash meets the first half only. A log meets both when each record carries a `sequence_number` and the `receipt_chain_link` digest of the record before it, the stream ends in a `witnessed` `trajectory_head`, its `coverage_boundary` is `declared`, and every digest names its `canonicalization` and `hash_alg`.
