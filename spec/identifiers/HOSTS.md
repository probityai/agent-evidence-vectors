# Identifier hosts: one name, two spellings

Every identifier this repository defines (predicate types, contracts, observer
contracts, schema `$id` values, evaluators, vocabulary terms, verifier ids) is
an `https` URI under a host of the probityai organisation. Two hosts are
recognised, and an identifier means the same thing under either:

| Host | Role |
|---|---|
| `probityai.github.io` | The host every identifier already issued carries, and the host identifiers are written under today. |
| `probityai.org` | The host identifiers are written under from the release that switches to it. |

## The rule

- `canonical_identifier(s)`: when `s` is a string that starts with exactly
  `https://<h>/` for a recognised host `h`, return `https://` followed by the
  host identifiers are written under, `/`, and the rest of `s` unchanged.
  Otherwise return `s` unchanged.
- `same_identifier(a, b)` is `canonical_identifier(a) == canonical_identifier(b)`.
- A reader compares the canonical form of an identifier taken from a record with
  its own identifier. What it reports back stays the record's own bytes, and it
  never rewrites the record it judges. Signed bytes are never touched.

The match is byte-exact and case-sensitive on the scheme and the host. These
spellings are not recognised and keep failing exactly as any unknown identifier
fails: `http://`, `www.`, a port (`:443` included), a trailing dot, upper case
anywhere in the scheme or the host, userinfo, a longer host such as
`probityai.org.example` or `probityai.organisation`, and leading white space.
The path is never changed and is compared byte for byte.

## Why two spellings are one name

A signed record cannot be edited without breaking its signature, so every
record already issued keeps the identifiers it was signed with, under
`https://probityai.github.io/`, forever. From the release that switches hosts,
new records carry `https://probityai.org/`. Both hosts are ours: GitHub serves
the old one for the probityai organisation and forwards every path on it to the
same path on the new one, which is verified for that organisation. So the two
spellings name one type, and a verifier that accepted only one would reject
either every record already issued or every record issued from then on.
Accepting both widens nothing an attacker controls: an identifier is a label,
not a credential, and trust comes from the signature and the key, which this
rule does not change. The match is byte-exact on the scheme and the host; no
other spelling is recognised.

## Conformance vectors

[`host-equivalence.json`](host-equivalence.json) lists pairs `{a, b, same, why}`
that every implementation must reproduce: `same_identifier(a, b)` is `same`. It
holds one pair for each family of identifier this repository publishes
(predicate v1 and v2, the organisation predicate namespace, contract, observer
contract, schema, evaluator, vocabulary term, verifier), identity and path
pairs, and one pair for each refused spelling above. The Python test is
`tests/test_identifier_hosts.py`; it also proves that every reader in the
package returns the same verdict and reason for each corpus member rewritten
under `probityai.org`.
