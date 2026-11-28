# Credential-release suite changelog

The suite id `credential-release/v1` never changes. A normative change to the predicate
bumps the predicate version in `spec/predicates/credential-release.md`, and the generator
rewrites the cases byte-identically.

## Predicate 0.2.0: the principals, the grant basis and the session cookie

- Every release names the `agent` that received the credential, and `onBehalfOf` names the
  user it acted for; a release with no `agent`, which is every 0.1.0 record, is refused with
  `predicate_malformed`.
- A release may rest on the user's grant document in place of an agent-card receipt, so a
  browser session release, where no Agent Card exists, is a statement of this predicate.
- The `session-cookie` credential kind names the origin and the cookie, with no scope.
- Codes added: `grant_digest_mismatch`, `grant_malformed`, `grant_fields_differ`,
  `subject_not_granted`, `principals_not_granted`, `audience_not_granted`,
  `grant_not_current`, `credential_outlives_grant`.
- Cases changed: every receipt basis case, because its release now names the agent. Each
  keeps its verdict.
