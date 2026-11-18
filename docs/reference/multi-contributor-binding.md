# Several contributors about one artifact

A publisher, an assessor and a catalog operator can each have something to say about the same artifact release, on their own schedule. Some catalog formats now carry those claims as an array of independent contributions, one per contributor, each with its own signature. This page maps that shape onto the records and corpora here, and states the two rules a verifier of either must keep.

## The shape

Each contribution names its contributor by an absolute identity URI, names the artifact release it is about (identifier, type, version when the release has one, and the digest of the artifact bytes), carries the contributor's claims, and carries at most one signature. A contribution can be updated or withdrawn without touching the others, and one contributor can hold several contributions.

| Contribution member | Here |
| --- | --- |
| contributor | the record's subject DID in `agent-did-identity-binding/v1` ([vectors-identity-binding](../../corpora/vectors-identity-binding/)) |
| signature signer | the DID the DSSE signature's `keyid` names |
| subject: identifier, type, version, digest | the in-toto Statement subject, by digest; a retrieval URL is not part of it, so a mirror serving the same bytes still matches |
| the contributor's claims | the predicate, one statement per contributor |
| the contributor's role | the vocabulary terms `party_role`, `independence_basis` and `observation_vantage` |

## Rule 1: the signer is the contributor, byte for byte

A signature counts for a contribution only when the identity that signed is exactly the contributor it names. The comparison is equality of the two identifiers code point for code point, after the record's own syntax is undone and before anything else is: a JSON escape (`did:web:ex\u0061mple.com`) is decoded, because it is how the string is written and not part of it, and then nothing more happens. There is no case folding of the host, no percent-decoding of a port, no Unicode normalization (an NFC and an NFD spelling of one name are two identifiers), no dropped or added path segment and no resolution to a canonical form. Two identifiers that a resolver would treat as the same DID are still two identifiers here; a verifier that normalizes before comparing accepts a contribution signed by one name and claimed under another, and a verifier that compares the raw text refuses a contribution whose identifiers differ only in how they were escaped.

The identity-binding reader applies this rule as its second check: the DID the signing key belongs to must equal the record's subject, and a record that fails is refused with `signer_not_subject`. The corpus's `subject-swap` case forces the rule for two unrelated DIDs; cases that differ only by case, encoding or a trailing segment are the next addition.

## Rule 2: each contribution is judged on its own

A verifier reports a verdict per contribution. A contribution whose signature does not verify, whose signer is not its contributor, or whose subject names another release is refused, and the others keep their verdicts: an assessor's broken or withdrawn manifest says nothing about the publisher's. What a consumer requires (the publisher alone, the publisher and one independent assessor, a quorum of observers) is the consumer's policy over those per-contribution verdicts, never a property of the record. A policy that counts counts contributors, not contributions: several accepted contributions from one contributor (Rule 1's comparison decides who is one contributor) count once, and so do contributions signed with one key under different contributor names, since one key is one party however many identities it signs as. Without both rules, one assessor who files twice, or who signs under two DIDs, meets a quorum of two.

A contribution's subject must match the release it is attached to, including whether the release has a version. A contribution that names another version, or no version for a versioned release, is about a different release and is refused, which is the anti-transplantation rule: a valid signed claim moved onto a release it was not made for.

## What a signature covers

When a contribution signs itself (a JSON object signed over its own canonical form), the exclusion set must be closed and not recursive. The signature member being computed is left out, and so is any member the format reserves for later signatures; nothing else is, and a member with one of those names inside a nested value is signed as it stands. The agent card receipt here states its own exclusion the same way: the card's top-level `signatures` member and nothing else ([agent card receipt](../../spec/predicates/agent-card-receipt.md)).
