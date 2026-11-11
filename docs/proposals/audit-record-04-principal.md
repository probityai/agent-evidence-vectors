# Proposed text for draft-gilda-audit-agent-audit-record-04: the authenticated principal

Change text for the next revision of the members section. Each paragraph names the members of
`vectors-agent-audit-record` that test it. The predicate URI does not change: `principal` is an
optional member, so a record without it is judged exactly as under revision 03.

## 1. Why the member exists

A decision point that authenticated a call through an identity provider knows which principal the
call ran under: the issuer, the subject, the client, the audience and the key the issuer signed
with. Revision 03 records the agent (`agent`) and the delegation (`delegation`), but a reader
cannot tell from the signed bytes which authenticated principal the decision point accepted, or
check that the credential it names is the one that principal was established from. `principal`
carries that answer inside the bytes the observer signs, bound by digest to the agent's credential
and by RFC 7638 thumbprint to the issuer's key. The token itself is never carried.

## 2. The member

Add to Section 5, after `delegation`:

> `principal`, OPTIONAL. The principal the decision point established from a signed token it
> validated. When present it is an object carrying exactly these members, and MAY carry `tenant`,
> `identityProvider` and `pinnedThumbprint`; a record missing one of them or carrying any other
> member in it is malformed (vectors `PR7`, `PR11`):
>
> * `issuer`, the `iss` of the token, an `https` URL.
> * `subject`, the `sub` of the token. When `delegation.subjectKind` is `user`, it MUST equal
>   `delegation.subject` (vector `PR8`). Under `system`, it names the client itself (vector `PR2`).
> * `clientId`, the OAuth `client_id` of the client the token was issued to.
> * `audience`, the `aud` of the token: a non-empty array of distinct strings.
> * `authMethod`, how the client authenticated to the issuer: a value of the IANA registry
>   "OAuth Token Endpoint Authentication Methods" (`none`, `client_secret_post`,
>   `client_secret_basic`, `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`,
>   `self_signed_tls_client_auth`).
> * `source`, what the decision point validated: `jwt-access-token` (RFC 9068), `id-token`
>   (OpenID Connect Core 1.0) or `jwt-assertion` (RFC 7523) (vectors `PR1`, `PR3`).
> * `tokenDigest`, the SHA-256 digest of the token bytes the agent presented. It MUST equal
>   `agent.credentialDigest`: the principal is bound by hash to the credential the agent
>   presented (vector `PR6`).
> * `issuedAt` and `expiresAt`, the token's `iat` and `exp` as RFC 3339 times, `expiresAt` later
>   than `issuedAt`. At `decision.reportedAt` the token MUST have been issued and MUST NOT have
>   expired, each within the skew tolerance of the draft (vectors `PR10`, `PR5`).
> * `kid`, the `kid` of the token's JWS header.
> * `key`, the public JWK of the issuer's JWKS that `kid` selects, of key type `RSA`, `EC` or
>   `OKP`, carrying no private member. Its `kid` MUST equal `kid` (vector `PR9`).
> * `keyThumbprint`, the RFC 7638 SHA-256 thumbprint of `key`, base64url without padding, which a
>   verifier recomputes from `key` (vector `PR4`).
> * `jwksDigest`, the SHA-256 digest of the RFC 8785 bytes of the issuer's JWKS as the decision
>   point held it. A party that retained that snapshot checks that `key` is in it.
> * `tenant`, OPTIONAL, the issuer's tenant or organization identifier.
> * `identityProvider`, OPTIONAL, who operates the issuer: one of `okta`, `entra`, `auth0`,
>   `keycloak`, `self_issued` and `other`, the values of the `identity_provider` term of the
>   agent-evidence vocabulary (vector `PR20` refuses any other value). A verifier derives the
>   provider from `issuer`: `self_issued` for `https://self-issued.me` and
>   `https://self-issued.me/v2`; `okta` for a host ending in `.okta.com`, `.oktapreview.com`,
>   `.okta-emea.com` or `.okta-gov.com`; `entra` for `login.microsoftonline.com`,
>   `login.microsoftonline.us`, `login.chinacloudapi.cn`, `sts.windows.net` or a host ending in
>   `.ciamlogin.com`; `auth0` for a host ending in `.auth0.com`; `keycloak` for a path of
>   `/realms/<realm>` or `/auth/realms/<realm>`; otherwise `other`. Where the derivation names a
>   provider, `identityProvider` MUST equal it (vectors `PR12`, `PR13`, `PR16`), and `other` does
>   not replace a named provider (vector `PR22`). Where it gives `other`, the issuer is a custom
>   domain and the declared value is accepted as declared, not derived (vectors `PR14`, `PR15`).
>   A principal whose provider is `self_issued` is vouched for by nobody but the party that runs
>   the issuer; a verifier MUST NOT report it as vouched for by a third party.
> * `pinnedThumbprint`, OPTIONAL, the RFC 7638 SHA-256 thumbprint of the issuer key the client
>   held in its configuration before its first call to the issuer, base64url without padding
>   (vector `PR19` refuses another shape). Present, it records `pinned_before_first_call` of the
>   vocabulary's `issuer_key_pinning` term and MUST equal `keyThumbprint` (vectors `PR17`,
>   `PR18`, `PR21`); absent, the record says the client did not pin. A client whose pin did not
>   hold refused the key and did not fall back to an unpinned fetch, so a record never carries a
>   pin that differs from the key it names.

## 3. Verifying a record

Add after the delegation check, in this order:

> When `principal` is present, a verifier checks its members (`PR7`, `PR11`), that its subject
> agrees with the delegation (`PR8`), that `tokenDigest` equals `agent.credentialDigest` (`PR6`),
> that the token was valid at `decision.reportedAt` (`PR10`, `PR5`), that `key.kid` equals `kid`
> (`PR9`), that `keyThumbprint` recomputes from `key` (`PR4`), that a declared `identityProvider`
> agrees with the provider `issuer` names (`PR13`, `PR16`, `PR22`), and that a `pinnedThumbprint`
> equals `keyThumbprint` (`PR18`). A record failing any of these is malformed.

The reference reader's codes for these refusals are `principal-member-missing`,
`principal-member-unknown`, `principal-malformed`, `principal-subject-mismatch`,
`principal-credential-unbound`, `principal-not-yet-valid`, `principal-expired`,
`principal-kid-mismatch`, `principal-thumbprint-mismatch`, `principal-provider-mismatch` and
`principal-pin-mismatch`.

## 4. What the member does not establish

That a custom-domain issuer is run by the provider it declares (the record says the value was
declared, and a verifier reports it so), that the issuer's JWKS at the time held `key` (the
retained snapshot and `jwksDigest` answer
that), that the token's signature verified (the decision point checked it; the record names the
key it used), or that the subject is who the issuer says it is.

## 5. Appendix B rows

Add rows `PR1` to `PR22` as `MANIFEST.json` of `vectors-agent-audit-record` states them (`row`
and `expected`).
