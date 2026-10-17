# Delegation lifecycle cases

Cases for `delegation-lifecycle/v1`. Each case asks one question a relying party
asks about an AI agent: does this presenter hold this delegated authority at the
time the relying party observed the presentation? A case is a set of signed
records (identifier registrations, grants, revocations, disputes, resolutions,
identifier links, retirements), one signed presentation, and the policy that
judges them. The cases come in three sets:

- `tree-`: revocation across a delegation tree, including a revocation that is
  disputed, as in the case "revocation issued in error, or disputed" proposed to
  the AAIF Identity and Trust working group;
- `rereg-`: re-registration, where an old identifier is linked to a new one;
- `recovery-`: recovery after the old key is lost or compromised, the question
  asked on AAIF Identity and Trust issue 18 about use case B (redeployment
  under a new identifier).

Judge the corpus with the Go verifier, from the repository root:

```sh
GOWORK=off go build -o aee-verify ./cmd/aee-verify
./aee-verify vectors-delegation-lifecycle
```

`aee-verify` derives the outcome of every case from its records and exits 0 only
when each one matches the outcome `MANIFEST.json` declares. [INDEX.md](INDEX.md)
lists every case with its situation, its expected outcome and the rule it applies.

## Records

Every record is a DSSE v1 envelope, signed with Ed25519, whose payload type is
`application/vnd.agent-evidence.delegation-lifecycle.v1+json` and whose payload
is a JSON object with a `type`. Times are RFC 3339.

| `type` | Fields | Signed by |
| --- | --- | --- |
| `registration` | `identifier`, `keyid`, `public_key`, `registered_at`, optional `responsible` and `software` | the registry |
| `retirement` | `identifier`, `retired_at` | the registry |
| `identifier-revocation` | `identifier`, `revoked_at`, `grounds` | the registry |
| `grant` | `grant_id`, `parent` (null for a top-level grant), `issuer`, `delegate`, `issued_at` | the issuer |
| `revocation` | `revocation_id`, `grant_id`, `initiator`, `grounds`, `effective_at`, `issued_at` | the initiator |
| `dispute` | `dispute_id`, `revocation_id`, `filed_by`, `grounds`, `filed_at` | the filer |
| `resolution` | `dispute_id`, `revocation_id`, `decided_by`, `outcome` (`restored` or `confirmed`), `decided_at`, optional `replacement_grant` | the decider |
| `link` | `link_id`, `old`, `new`, `linked_at` | the old identifier, the new identifier and the registry |
| `recovery` | `recovery_id`, `old`, `new`, `responsible`, `recovered_at` | the registry and the Responsible entity |
| `presentation` | `presenter`, `chain` (grant ids, top first), `observed_at` | the presenter and the relying party |

A signature counts when its `keyid` names a key the registry bound to the signer
and it verifies over the DSSE pre-authentication encoding. `case.json` pins the
payload type, the registry's key, the relying party's key and the trusted roots,
and lists the record files and the presentation.

## The rules, in the order the verifier applies them

The verifier names the first check that fails.

| Check | Refusal | Source |
| --- | --- | --- |
| every record is a DSSE envelope over a JSON object of a known type, with its fields | no verdict, `malformed_record` | |
| the presentation carries the presenter's and the relying party's signatures | `signature_invalid:presentation` | the relying party's signature fixes `observed_at` |
| each grant on the chain verifies under its issuer's key | `signature_invalid:grant` | |
| each grant names the one before it as `parent`, its issuer is that grant's delegate, and the top grant comes from a trusted root | `chain_broken` | UCAN delegation chains |
| the registry had not retired or revoked the presenter at `observed_at` | `presenter_inactive` | |
| the presenter is the last delegate, or reaches it through links | `presenter_not_delegate` | |
| every link on that path is signed by the old identifier, the new identifier and the registry | `signature_invalid:link` | |
| every link on that path is one to one | `link_conflict` | proposed |
| the registry had not retired or revoked the old identifier at `linked_at` | `link_old_inactive` | |
| no grant on the chain carries a revocation, signed by a principal with standing, with `effective_at` at or before `observed_at` | `grant_revoked` | UCAN revocation; the time rule of case GT-R8 in [interop/govops-trace-profile](../interop/govops-trace-profile/INDEX.md) |
| that revocation states its grounds | `revocation_incomplete` | proposed |
| no dispute of that revocation by an affected principal is still open | `grant_revoked_dispute_open` | proposed |
| every recovery record that names the presenter as `new` is signed by the registry and the Responsible entity | `signature_invalid:recovery` | proposed |
| the registry registered both identifiers of that recovery to its Responsible entity with one `software` digest | `recovery_mismatch` | proposed |

A case that passes every check is accepted with `authority_valid`, with
`authority_valid_via_link` when the presenter holds the grant through a link, or
with `authority_valid_with_history` when a recovered predecessor left an adverse
record.

Standing, cascade and irreversibility follow the
[UCAN revocation specification](https://github.com/ucan-wg/revocation): the issuer
of a grant, or any issuer above it in the presented chain, may revoke it; a
revoked grant breaks every chain that passes through it and no other; and a
revocation is never undone. A grant issued in error is replaced by a new grant.

A record whose signature does not verify counts as absent. A forged revocation
therefore stops nothing, while a forged grant or link carries no authority and is
named in the refusal when the decision depends on it.

## Disputed revocation

The working-group case asks that a revocation leave a record (initiator, grounds,
scope, effective time), that an affected principal, including one cut off by the
cascade, have a defined way to contest it, and that a design state whether it
favours containment or recoverability. These cases state the choice: containment.

- A dispute does not suspend a revocation. While no resolution signed by a
  principal with standing closes it, the refusal is `grant_revoked_dispute_open`,
  so the relying party sees that the revocation is contested.
- A resolution counts only when its signer has standing to revoke the grant. A
  disputing principal cannot resolve its own dispute.
- A resolution in the principal's favour does not revive the revoked grant. The
  restoration is a replacement grant, and every principal cut off by the cascade
  needs its own grant re-issued under the replacement, because its old grant
  still names the revoked parent.
- When several revocations with standing name one grant, the earliest
  `effective_at` applies.
- A revocation applies from its stated `effective_at` even when it was issued
  later, as an X.509 invalidity date does (RFC 5280, section 5.3.2).
- A revocation from a principal with standing that states no grounds still stops
  the authority, and the refusal names the missing field.

## Re-registration

A grant made to an old identifier is held by its successor when a link names
both and carries three signatures: the old identifier's key, which shows the old
holder agreed; the new identifier's key; and the registry's, which makes
`linked_at` trustworthy. Links are followed one hop at a time, and every hop is
checked on its own. A link carries a grant as it stands, so a revocation of the
grant reaches the successor too. An old identifier stays usable until the
registry retires it.

Two rules here are proposals with no precedent we know of, and the cases mark
them as such: a link is one to one, so two old identifiers linked to one new one
(a merge of two principals' authority, which needs a new grant) and one old
identifier linked to two new ones (an ambiguous successor) are both refused with
`link_conflict`.

## Recovery

A link needs the old key's signature. When that key is lost or compromised at
redeployment, no link can be made. Use case B in AAIF Identity and Trust pull
request 20 links the old and the new identifier by the Responsible entity and the
software attestation instead. These cases state that path as a separate record,
the recovery record, and keep it apart from authority:

- A recovery record is signed by the registry and by the Responsible entity the
  registry bound to both identifiers, and the two registrations carry one
  software attestation digest. The registry alone cannot move an agent's history.
- A recovery record carries history and no grant. The successor holds a grant
  only when an issuer grants it again, so a recovery never revives authority,
  including authority the registry removed by revoking the old identifier for
  compromise.
- History follows the agent forward. An identifier revocation of the old
  identifier, a revocation of a grant made to it, and its disputes resolve from
  the successor, and the acceptance names them with
  `authority_valid_with_history`.
- A presenter named by a recovery record that fails is refused, because its
  history cannot be resolved.

Every rule in this section is a proposal with no precedent we know of.

## What these cases do not test

Scope narrowing between hops, grant expiry, and whether a grant's issuer was
still active when it signed are out of scope here. Scope and expiry are
covered by [vectors-authority-at-dispatch](../vectors-authority-at-dispatch/README.md),
the authority-at-dispatch cases of AAIF Identity and Trust issue 13, which
judge one dispatch against its delegation chain and share this corpus's
revocation time rule and its `grant_revoked` refusal. Whether an issuer was
still active when it signed is tested in neither corpus.

## Keys

Every record is signed with test keys whose seeds are the SHA-256 of public
labels in `gen_vectors.py`. Anyone can re-derive them. They are test keys only.

## Tools

- `gen_vectors.py` writes every case, `MANIFEST.json` and `INDEX.md`
  deterministically, with each expected outcome written by hand.
- `corpora/delegationlifecycle.go` is the verifier `aee-verify` runs. Its tests
  swap each refused case with its accepted twin and require the derived outcome
  to move, and switch off each rule in turn and require some case to change.
- `tests/test_corpus.py` regenerates the corpus byte for byte and recomputes its
  digest from the files.
