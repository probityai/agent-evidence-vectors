# Input contract — exact-call envelope matrix v1

Contract **version 1.0.1** (2026-10-12). This file is the published interface for
the matrix. Anything a third party needs in order to reproduce the comparison
without reading PriorSeal source is written here.

## 0. Changelog

- **1.0.0** — initial published text, pinned at
  `imokokok/PriorSeal@d84055319325e6eef5a0a275e0f2f78f5919bdb4`.
- **1.0.1** — this version, revised after an independent third-party review of
  the 1.0.0 delivery:
  1. **`bound` is pinned to the §4 mismatch set only.** 1.0.0 left it
     unspecified whether §5 availability codes sit in the set that decides
     `bound`; the 1.0.0 fixture encoded them in, while the 1.0.0 case note
     argued they should not. v1.0.1 adopts the availability reading: §5 codes
     are reported alongside in `availabilityCodes` and never enter the deciding
     set. **This flips case-04's `bound` from `false` to `true`** — the
     envelope itself matches; only the evidence is missing. The downstream rule
     in §7 (`UNDETERMINED` overrides any boolean conjunction of `bound`) is
     what keeps "unknown" from being silently consumed as "no".
  2. **The second time path is named.** The field map now includes the
     authorization-window row (`notBefore` / `expiresAt` →
     `OUTSIDE_AUTHORIZATION_WINDOW`) alongside the `validUntil` row. The
     fixture sets the two windows equal, so a new sixth case (`case-05`, late
     `executedAt`) exercises both paths at once.
  3. **§2.1 type wording corrected** to match the frozen fixture: the instants
     are JSON numbers, `maxUses` is the decimal string. The bytes were always
     right; the 1.0.0 text was not.
  4. **§2.3 publishes the struct-field → JSON-path map** instead of leaving
     every reader to re-derive it.
  5. **§4 states the actual comparison semantics** (decimal-string forms,
     case-insensitive, `String()` coercion). Whether producer-side parsing
     should tighten is flagged as open and deliberately not settled here.

  Note on the shipped profile: the PriorSeal implementation as of the 1.0.0 pin
  reads `EXECUTION_UNAVAILABLE` into its internal binding set, so its raw
  `bound` for case-04 is `false` where this contract now says `true`. The
  matrix runner applies the published v1.0.1 partition to both implementations
  and records the raw profile binding beside it. Tightening the producer is a
  PriorSeal-side question, out of scope for this contract revision.

## 1. Signed profile

`priorseal.execution-profile.exact-call.v1`, carried by a `priorseal.intent.v2`
intent inside a `priorseal.authorization.v2` authorization.

The profile binds the transaction envelope and nothing else. It deliberately
does not infer recipient, asset, amount or transfer uniqueness from emitted
`Transfer` logs, so the comparison below does not look at those fields either.
Section 4 defines the mismatch set that alone decides `bound`.

## 2. Source record

`fixture/signed-authorization.json` — schema `oel.source-record.v1`.

| Field | Meaning |
| --- | --- |
| `authorization` | The principal-signed authorization. `authorization.intent` carries the signed `callTarget`, `calldataHash` and `transactionValue`; `authorization.signature` is the EIP-712 signature over it. |
| `acceptance` | The issuer's `priorseal.authorization-receipt.v1` acceptance, Ed25519-signed. |

### 2.1 EIP-712 authorization digest and recovery rule

Domain: `{ name: "PriorSeal", version: "2", chainId: intent.chainId }`
Primary type: `PriorSealAuthorization`

| Field | Solidity type |
| --- | --- |
| `intentHash` | `bytes32` |
| `principalType` | `string` |
| `principalId` | `string` |
| `principalAccount` | `address` |
| `authorizerType` | `string` |
| `authorizer` | `address` |
| `agentId` | `string` |
| `executor` | `address` |
| `issuedAt` | `uint256` |
| `notBefore` | `uint256` |
| `expiresAt` | `uint256` |
| `authorizationNonce` | `bytes32` |
| `maxUses` | `uint256` |
| `audience` | `string` |
| `policyHash` | `bytes32` |

Notes that matter for byte agreement:

- `authorization.intent.intentHash` is stored as **bare lowercase hex** (no
  `0x`). The struct field is the `0x`-prefixed 32-byte form. The other three
  `bytes32` fields are already `0x`-prefixed in the signed authorization.
- `issuedAt`, `notBefore` and `expiresAt` are **JSON numbers** (Unix seconds)
  and `maxUses` is a **decimal string** (`"1"`); all four become `uint256` in
  the digest input through unsigned-integer coercion (`BigInt(value)`). The
  1.0.0 text called all of them decimal strings; the fixture bytes were always
  as stated here (corrected in 1.0.1, item 3 of the changelog).
- Recovery rule: `digest = hashTypedData(domain, types, message)`, then recover
  the signer from `(digest, authorization.signature)` and require equality with
  `authorization.authorizer.address`.

A reader that reproduces the digest and recovers
`0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A` has the same signing bytes as the
producer. `report.json` records the digest this fixture yields.

### 2.2 Acceptance signature rule

`signature = base64url(Ed25519.sign(seed, utf8(canonicalJson(acceptance without "signature"))))`

The verification key is published in `fixture/public-test-keys.json`. The
canonical JSON is the producer's RFC 8785-style canonical form; it is the
producer's rule and is named here so the check is reproducible, not because the
reader has to re-derive it.

### 2.3 Struct field → JSON path map (added in 1.0.1)

| EIP-712 struct field | JSON path in the source record |
| --- | --- |
| `intentHash` | `authorization.intentHash` (bare lowercase hex, 64 chars) |
| `principalType` | `authorization.principal.type` |
| `principalId` | `authorization.principal.id` |
| `principalAccount` | `authorization.principal.account` |
| `authorizerType` | `authorization.authorizer.type` |
| `authorizer` | `authorization.authorizer.address` |
| `agentId` | `authorization.delegate.agentId` |
| `executor` | `authorization.delegate.executor` |
| `issuedAt` | `authorization.issuedAt` (JSON number) |
| `notBefore` | `authorization.notBefore` (JSON number) |
| `expiresAt` | `authorization.expiresAt` (JSON number) |
| `authorizationNonce` | `authorization.authorizationNonce` |
| `maxUses` | `authorization.maxUses` (decimal string) |
| `audience` | `authorization.audience` |
| `policyHash` | `authorization.policyHash` |

## 3. Observed envelopes

`fixture/observed/<case-id>.json` — each file is one `priorseal.execution-observation.v1`
envelope in the producer's normalized form. Only these fields take part in the
comparison.

## 4. Field map

| Signed | Observed | Rule | Reason code |
| --- | --- | --- | --- |
| `intent.chainId` | `chainId` | strict equality of the integer values | `CHAIN_MISMATCH` |
| `intent.action` | `action` | case-insensitive equality | `ACTION_MISMATCH` |
| `intent.sender` | `sender` | case-insensitive equality | `SENDER_MISMATCH` |
| `intent.nonce` | `nonce` | equality of decimal-string forms, default `"0"` | `NONCE_MISMATCH` |
| `intent.callTarget` | `target` | case-insensitive equality, only when present in the signed intent | `CALL_TARGET_MISMATCH` |
| `intent.calldataHash` | `calldataHash` | case-insensitive equality, only when present in the signed intent | `CALLDATA_MISMATCH` |
| `intent.transactionValue` | `nativeValue` | equality of decimal-string forms, only when present in the signed intent | `TRANSACTION_VALUE_MISMATCH` |
| `intent.validUntil` | `executedAt` (fallback `observedAt`) | observed time greater than `validUntil` | `OUTSIDE_TIME_WINDOW` |
| `authorization.notBefore` / `authorization.expiresAt` | `executedAt` (fallback `observedAt`) | observed time earlier than `notBefore` or greater than `expiresAt` | `OUTSIDE_AUTHORIZATION_WINDOW` |

**Comparison semantics (made explicit in 1.0.1).** The shipped implementations
compare values after JavaScript `String()` coercion: a JSON integer
participates through its canonical decimal string (`8453` → `"8453"`), a
missing or null value through the empty string, and string comparison is
ASCII-case-insensitive. Under these rules a numeric nonce `7` and the string
`"7"` are the same value. The contract states this coercion rather than
tightening it; whether the producer should reject non-canonical forms is an
open question, deliberately not settled in 1.0.1.

**What decides `bound` (pinned in 1.0.1).** `bound` is decided by the mismatch
set of this section only: `bound = (mismatch codes is empty)`. Reason codes are
compared as a **sorted set**, so implementation order does not matter. Section 5
codes are reported beside the result, never inside the deciding set.

## 5. Evidence availability

| Observed | Rule | Code |
| --- | --- | --- |
| `executionDataAvailable` | `false` yields `EXECUTION_UNAVAILABLE` | `EXECUTION_UNAVAILABLE` |

This is a separate class. It says the evidence is missing, not that the
authorization was breached, and it is never scored as a mismatch. Pinned in
1.0.1: these codes are reported in `availabilityCodes`, a set beside — not
inside — the §4 mismatch set that decides `bound`. (1.0.0 was silent on the set
membership; see the changelog.)

## 6. Deliberately not compared

| Field | Why |
| --- | --- |
| `intent.recipient` | exact-call binds the transaction envelope; it does not infer transfer semantics |
| `intent.asset` | same |
| `intent.amount` | same |
| `execution.transfers` | transfer uniqueness is not a property of an exact-call envelope |

## 7. What the result means

| Case | Reader / profile | Meaning |
| --- | --- | --- |
| `case-00` | `bound: true`, no mismatch codes | The observed envelope is the authorized envelope |
| `case-01` | `CALL_TARGET_MISMATCH` | The observed call went to a different target |
| `case-02` | `CALLDATA_MISMATCH` | The observed calldata hash differs from the signed one |
| `case-03` | `TRANSACTION_VALUE_MISMATCH` | The observed native value differs from the signed one |
| `case-04` | `EXECUTION_UNAVAILABLE` beside `bound: true` | The envelope matches; the evidence is missing, so no agreement claim is made |
| `case-05` | `OUTSIDE_TIME_WINDOW` and `OUTSIDE_AUTHORIZATION_WINDOW` | The observed execution falls outside both time windows (added in 1.0.1) |

A mismatch result is a statement about the envelope relation only. It does not
establish that the calldata was malicious, that an economic loss occurred, or
that anything happened on a real chain.

**Downstream rule (added in 1.0.1):** an `UNDETERMINED` outcome overrides any
boolean conjunction of `bound`. Aggregating cases by AND-ing their `bound`
flags would silently consume "unknown" as "no"; that is forbidden here.

## 8. Attribution

The binding rules, reason codes and the `COMPLIANT` / `NON_COMPLIANT` /
`NOT_ASSESSABLE` vocabulary belong to the PriorSeal exact-call profile.
`reader.mjs` is the submission reader: a separate implementation of sections
4 and 5 that imports nothing from PriorSeal and was authored by the fixture
contributor. It is not the external reviewer's Python reader. The independent
cold run preserved in the linked v1.0.0 record was written and run by another
developer; v1.0.1 has not yet had an independent rerun. These results do not
imply adoption, endorsement, integration or a pilot by either project.
