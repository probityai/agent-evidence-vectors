# Principal identity terms

Name who stands behind the issuer of a token an agent's call ran under, and whether the client pinned that issuer's key, so a party that does not trust the gateway can check both. The [README](../README.md) is the short version of the repository; this page covers the `principal_identity` section, added in 0.10.0.

The agent-audit-record predicate records the principal a decision point established from a token it validated: the issuer, subject, client, audience, key and its RFC 7638 thumbprint. Its `principal.source` names the kind of token (`jwt-access-token`, `id-token`, `jwt-assertion`) and keeps meaning that. The issuer URL already says which identity provider runs the issuer, so these terms name the provider from that URL instead of adding providers to `source`. Both terms are `proposed`, list no issuer, carry `criticality: critical`, a `review_by` date and a `check`, and neither is canonical.

## The terms

| term | what it names | check |
|---|---|---|
| `identity_provider` | the identity provider that operates the issuer of a validated principal | derived from `principal.issuer` by host and path; a declared value that contradicts a derived provider is refused; a custom domain accepts a declared value, reported as declared; a non-https issuer is malformed; `self_issued` is never read as third-party vouching |
| `issuer_key_pinning` | whether the client pinned the issuer key by RFC 7638 thumbprint before its first call | pinned only when the configured thumbprint equals the thumbprint recomputed from `principal.key`; a mixed or conflicting configuration is refused; a mismatch or failed fetch never falls back to unpinned |

## The values

| term | values |
|---|---|
| `identity_provider` | `okta`, `entra`, `auth0`, `keycloak`, `self_issued`, `other` |
| `issuer_key_pinning` | `pinned_before_first_call`, `unpinned` |

## Deriving the provider

`registry.identity_provider(issuer, declared=None, self_issuers=frozenset())` in the Python package applies the rule:

```python
from agent_evidence_vocabulary import registry

registry.identity_provider("https://example.okta.com/oauth2/default").value          # 'okta'
registry.identity_provider("https://login.microsoftonline.com/TENANT/v2.0").value    # 'entra'
registry.identity_provider("https://example.us.auth0.com/").value                     # 'auth0'
registry.identity_provider("https://sso.example.com/realms/agents").value             # 'keycloak'
registry.identity_provider("https://id.example.com", declared="okta").reason          # 'declared for a custom-domain issuer, not derived'
registry.identity_provider("https://example.okta.com", declared="auth0").outcome      # 'malformed'
```

## Pinning the issuer key

The admission package's `agent_evidence_admission.issuer_pin` module is a client that enforces `pinned_before_first_call`: it takes the pins before any call, refuses a mixed or conflicting configuration when it is built, refuses a key whose thumbprint differs, and refuses on a failed fetch without falling back.
