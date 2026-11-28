# Revocation fence vectors

Type URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-fence`

Signing domains: `<type URI>#effect-permit`, `<type URI>#epoch-update` and
`<type URI>#target-outcome`.

Cases for `revocation-fence/v1`: a revocation that a target enforces at its own commit, so
that a permit from a revoked epoch cannot commit. A revocation that only a gateway or a
registry knows about does not stop a permit already on its way to a target. The fence moves
the decision to the target. An authority signs an effect permit that names the subject's
revocation epoch. The target commits the effect only when the epoch it holds for the subject
equals the permit's epoch, and it signs what it did. Revoking a subject is installing its
next epoch.

The predicate [`revocation-boundary`](../../spec/predicates/revocation-boundary.md) reports
the outcome of a revocation. This corpus specifies one mechanism that produces such outcomes
and the checks a reader applies to its records. The expected object of every case is in
`MANIFEST.json`, and its `counts` and `kinds` members give the cases per decision and per kind.

## Run it

```
python3 corpora/vectors-revocation-fence/check_vectors.py
python3 corpora/vectors-revocation-fence/check_vectors.py --verifier "<your verifier>"
python3 packaging/run_vectors.py --corpus vectors-revocation-fence
```

The external contract: `<verifier> <case-dir>/case.json --json` prints one JSON object equal
to the case's `expected` object and exits 0 for an accepting decision, 1 for `refused`, 2 for
`pending`, 3 for `no_outcome` and 4 for `outcome_mismatch`.

## Wire family

- A signed record is `{"claims": {...}, "sig": "<base64>"}` with exactly those members.
- `claims` has exactly the members of its record type, and `v` is the JSON integer `1`.
- The signature is Ed25519 over `DOMAIN || 0x00 || JCS(claims)` (RFC 8785, JSON
  Canonicalization Scheme). `sig` is standard base64 with padding of the signature bytes, in
  its one canonical spelling.
- A key is a raw Ed25519 public key in standard base64. `kid` is the lowercase hex SHA-256 of
  the raw key. A reader takes keys only from the lists `case.json` pins; `kid` only selects
  among them.
- A time is nanoseconds as a canonical decimal string (`^(0|[1-9][0-9]*)$`), because RFC 8785
  numbers stop at 2^53. Epochs and counters are JSON integers, never booleans or `1.0`.
- Every window is half-open: an instant `t` is inside when `not_before <= t < not_after`.

## The three records

| Record | Domain fragment | Claims, exactly |
| --- | --- | --- |
| Effect permit | `#effect-permit` | `v`, `permit_id`, `subject`, `epoch`, `idempotency_key`, `audience`, `operation_digest`, `not_before_ns`, `not_after_ns`, `kid` |
| Epoch update | `#epoch-update` | `v`, `subject`, `epoch`, `audience`, `kid` |
| Target outcome | `#target-outcome` | `v`, `target_id`, `permit_id`, `subject`, `epoch`, `idempotency_key`, `stage` (`accept`, `execute`, `settle` or `final`), `outcome` (`committed` or `refused`), `reason` (the code, `""` when committed), `shape`, `signed_at_ns`, `kid` |

## The commit rule and its three shapes

A target commits only when the authoritative epoch for the subject equals the permit's
epoch. A target that holds no epoch refuses, and a target that cannot read its epoch refuses.
Each shape puts the revocation and the commit in one order:

- Shape a: the epoch row and the effect live in one transactional store, and the effect
  holds a lock on the row to its end.
- Shape b: the epoch source grants commit leases. A revocation waits until every live lease
  is released or expired, and no new lease is granted while it waits.
- Shape c: one coordinator orders prepare, commit and revocation. A revocation voids every
  prepared hold of the subject.

## Check order per kind

The first failing check wins. `case.json` carries `v` and `kind`; the permit, epoch-update,
outcome and commit kinds also carry `audience` (the target id) and `keys`
(`authority`, `epoch_source`, `target`).

**permit** (`now_ns`, `permit`): decision `valid` (`permit_valid`) or `refused`.

| Order | Check | Code |
| --- | --- | --- |
| 1 | strict JSON, exact members, `v` is 1 | `malformed` |
| 2 | text members non-empty strings, `epoch` an integer, both times canonical | `malformed` |
| 3 | `epoch >= 0` and `not_after_ns > not_before_ns` | `malformed` |
| 4 | `kid` pinned as an authority key | `unknown_authority` |
| 5 | signature under the effect-permit domain | `bad_signature` |
| 6 | `audience` is this target | `wrong_audience` |
| 7 | `now >= not_before_ns` | `not_yet_valid` |
| 8 | `now < not_after_ns` | `expired` |

**epoch-update** (`held`: subject to epoch, `updates`: files in order). Each update is read
with checks 1 to 3 of the permit (no window), then `kid` pinned as an epoch source
(`unknown_epoch_source`), the signature (`bad_signature`) and the audience
(`wrong_audience`). It then installs: no epoch held, or a higher one, is `installed`
(`epoch_installed`); an equal one is `unchanged` (`epoch_unchanged`); a lower one is refused
(`epoch_rollback`). A refused update does not stop later ones. The case's decision is that of
its last update, beside `results` and `held_after`.

**outcome** (`outcome`): decision `valid` (`outcome_valid`) or `refused`.

| Order | Check | Code |
| --- | --- | --- |
| 1 | strict JSON, exact members, `v` is 1 | `malformed` |
| 2 | `stage` and `outcome` are known values | `malformed` |
| 3 | `kid` pinned as a target key | `unknown_target_key` |
| 4 | signature under the target-outcome domain | `bad_signature` |
| 5 | text members non-empty, `reason` a string, `signed_at_ns` canonical, `epoch` an integer | `malformed` |

**commit** (`shape`, `stage`, `now_ns`, `permit`, `state`, `outcome`). The permit is read as
above; a refusal there is decision `no_outcome`, because no outcome can be attributed to an
unverifiable permit. `state` holds `epoch` (an integer, `null` when none is held, or
`"unavailable"` in shape a), `effects` (idempotency key to `permit_id` and
`operation_digest`), and for shape b `revocation_pending` and `lease_expired`, for shape c
`hold` (`prepared`, `void_pending` or `voided`).

| Order | Shape a | Shape b | Shape c |
| --- | --- | --- | --- |
| 1 | same effect recorded: `replayed`; another effect under the key: `key_reused` | as shape a | as shape a |
| 2 | epoch unavailable: `epoch_unavailable` | no epoch: `epoch_unknown` | no epoch: `epoch_unknown` |
| 3 | no epoch: `epoch_unknown` | revocation waiting: `revocation_pending` | epoch differs: `epoch_mismatch` |
| 4 | epoch differs: `epoch_mismatch` | epoch differs: `epoch_mismatch` | hold not prepared: `revoked_before_commit` |
| 5 | `committed` | lease ended: `lease_expired` | `committed` |
| 6 |  | `committed` |  |

The reader then requires `outcome.json` to be the target's honest answer: it verifies under a
pinned target key and its claims equal the target id, the permit's `permit_id`, `subject`,
`epoch` and `idempotency_key`, the case's `stage` and `shape`, `outcome` `committed` (for a
commit or a replay) or `refused`, and `reason` `""` or the code. Otherwise the decision is
`outcome_mismatch`, with the fence's reason kept. Reasons: `commit_done`, `replay_done` or the
code.

**propagation** (`commit_ns`, `leases`: gateway to `granted_ns`, `length_ns`, `skew_ns`,
`acks`, `now_ns`). A lease is live at the commit when `granted <= commit < granted + length`.
An acknowledgement from a gateway with no live lease is refused (`malformed`). A gateway is
waited on while live, not acknowledged, and `now < granted + length + skew`. The label is
`pending` while any gateway is waited on, with `waiting_on` and `worst_case_ends_ns` (the
largest end waited on), and `revoked for new admissions` otherwise, with the commit time.

**ledger** (`steps`: `submit`, `mark_unknown`, `revoke`, `retry`, `resolve`). States are
`in flight`, `unknown`, `unresolved, revoked`, `committed` and `not committed`. A submit for a
revoked subject is refused (`retry_after_revoke`). An outcome marked unknown after its subject
is revoked, or unknown when the subject is revoked, is `unresolved, revoked`. A retry that is
not read-only of a revoked subject's open request is refused (`retry_after_revoke`); a
read-only retry returns the state. Every request not `committed` or `not committed` keeps its
reservation in `reserved`.

**feed** (`receiver_audience`, `issuer_keys`, `session_binding`, `journal`, `set`): a
Security Event Token (RFC 8417) as a compact JWS with `alg` `EdDSA` (RFC 8037).

| Order | Check | Code |
| --- | --- | --- |
| 1 | ASCII, three parts, base64url without padding, header exactly `alg` `EdDSA`, `kid`, `typ` `secevent+jwt` | `set_malformed` |
| 2 | payload a JSON object with a string `iss` | `set_malformed` |
| 3 | `kid` pinned for that `iss` | `unknown_issuer_key` |
| 4 | signature | `bad_signature` |
| 5 | `aud` (a string or a list) names the receiver | `wrong_audience` |
| 6 | no `sub` or `exp`, a non-empty `jti`, a numeric `iat`, `events` with one object member, a `sub_id` of format `iss_sub` or `complex` | `set_shape` |
| 7 | the `sub_id` issuer is the token's `iss` | `subject_issuer_mismatch` |
| 8 | `jti` journalled with the same SHA-256 of the token bytes: `delivered`; with another | `jti_reused` |

Then the event, with the type URIs of [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
and [RISC 1.0](https://openid.net/specs/openid-risc-1_0-final.html):

| Event | Result |
| --- | --- |
| CAEP `session-revoked` | `session_ended` with the session id when the receiver binds sessions for this issuer and the subject carries one; else `rotated` |
| CAEP `credential-change` | `create`: `journalled`; `revoke`, `delete`, `update`: `rotated`; any other `change_type`: `set_shape` |
| RISC `account-disabled`, `account-purged` | `revoked`, with the entry `<iss>#<sub>` |
| CAEP `risk-level-change`, RISC `account-enabled` | `journalled`; account-enabled never lifts a revocation |
| any other type | refused, `event_unknown` |

A `rotated` result carries `not_before_s`: the floor of `event_timestamp` when it is a number
no later than `iat`, else the floor of `iat`.

## Revocation status

Every case about a revocation states `revocation_status`, one of `live`, `partial`, `closed`
or `unknown`. An open, unresolved or unreadable revocation never reads `closed`.

- commit: an epoch the target cannot read, has not heard, or holds below the permit's is
  `unknown`; a later epoch is `closed`; at the permit's epoch a waiting revocation or a void
  pending hold is `partial`, a voided hold `closed`, and otherwise `live`.
- epoch-update: `closed` when the target now holds a later epoch, or refused a rollback.
- propagation: `partial` while pending, `closed` when revoked for new admissions, `unknown`
  for a refused acknowledgement.
- ledger: per revoked subject in `subjects`, `unknown` while any of its requests is open and
  `closed` otherwise; the case reads `unknown` when any subject does, `live` with none revoked.
- feed: a refused token is `unknown`; `rotated` and `session_ended` are `partial`; `revoked`
  is `closed`.
