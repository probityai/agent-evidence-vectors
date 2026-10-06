# GovOps TRACE profile conformance vectors

Conformance cases for the GovOps TRACE profile (`eat_profile: tag:govops,2026:trace-v1`), as published at
[GovOpsWG/GovOps `govops-trace-profile.md`](https://github.com/GovOpsWG/GovOps/blob/131cb66bc87cd266e224d7df6f7b9401c00f3ef7/govops-trace-profile.md)
(commit `131cb66`). They cover one governed execution end to end: an agent moves funds, and three producers each sign their own record with their own key, on their own hash chain.

| producer | event kind | edge |
|---|---|---|
| `cedarling-fleet-1` (PDP) | `AUTHORIZATION_DECISION` | none |
| `payments-gateway` (enforcement point) | `CAPABILITY_INVOKED` | `authorized` to the decision |
| `payments-ledger` (system of record) | `RUNTIME_EFFECT` | `produced_effect` to the invocation |

Each producer also carries the record before it in its chain, so `prev_record_hash` is checked against a real predecessor. Every other member is this chain with one defect. [`INDEX.md`](INDEX.md) lists all 27 members. [`MANIFEST.json`](MANIFEST.json) holds each member's expected verdict, refusal code or flags, and the `capability_resolution` a TRACE consumer must derive.

## Run it

```sh
uv run --extra generators python vectors-govops-trace/gen_vectors.py    # rebuild, byte-identical
uv run --extra generators python vectors-govops-trace/check_vectors.py  # judge and sweep
```

`check_vectors.py` exits 0 only when every member file matches its recorded digest and the reference reader ([`verifier.py`](verifier.py)) reaches every expected verdict. The capability resolutions the funds transfer depends on must also equal values written by hand, and turning off any one of the 23 rules must change the result of every member that names it. That last check is the mutation sweep: a rule no member depends on, or a member that passes with its rule removed, fails CI.

To score your own TRACE consumer, run it over each `members/<id>.json` with [`registry.json`](registry.json) as the Producer Key Registry and [`mapping.json`](mapping.json) as the policy-store capability mapping, then compare against `MANIFEST.json`. The keys are published test keys derived from fixed seeds.

## The envelope

A record is the profile's envelope exactly as section 1 writes it: `producer`, `record_id`, `kid`, the `trace` claim, `producer_chain`, `parent_record_ids`, and `signature`. The signature is Ed25519 over the RFC 8785 bytes of every member except `signature`, verified only with the key the registry holds for `(producer, kid)`. The same record can also travel as the predicate of an in-toto Statement inside a DSSE envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the RFC 8785 bytes of the Statement>",
  "signatures": [{ "keyid": "<kid>", "sig": "<Ed25519 over DSSE PAE>" }]
}
```

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "govops:<producer>/<record_id>", "digest": { "sha256": "<content digest>" } }],
  "predicateType": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/govops-trace-record",
  "predicate": { "<the GovOps record, without signature>": "..." }
}
```

Both forms reach the same record checks, and `GT-A1` and `GT-A2` are the same six records in the two forms. DSSE adds three things the inline form lacks: the payload type is signed, so a GovOps record signature cannot be replayed as a different JSON document under the same key; existing in-toto and DSSE verifiers can carry records unchanged; and the signature is checked over the received bytes before anything is canonicalized. That third point matters because the inline form makes a verifier canonicalize unverified JSON. `GT-R6` is the case: `outcome` appears twice, a last-wins parser reads `ALLOW`, and the signature covers `DENY`.

## Conformance section (proposed text for the profile)

The following is written as the profile's conformance section. Each requirement names the members that test it.

**C1. Admission before canonicalization.** A TRACE consumer MUST refuse a record whose JSON contains a duplicate member name (`GT-R6`) or a number outside the I-JSON integer range (`GT-R12`) before computing RFC 8785 bytes or verifying a signature.

**C2. Key resolution.** A consumer MUST resolve the verification key from the Producer Key Registry by `(producer, kid)` and MUST refuse a record whose key does not resolve (`GT-R2`). It MUST NOT use a key carried in the record body: a `cnf` member is ignored and flagged (`GT-F7`), and a record signed by its own `cnf` key fails (`GT-R5`).

**C3. Signature.** A consumer MUST verify Ed25519 over the RFC 8785 bytes of every member except `signature` and MUST refuse on failure (`GT-R1`). For DSSE carriage, it MUST check `payloadType` (`GT-D1`), the PAE signature under the registry key named by `keyid` (`GT-D4`), the `predicateType` (`GT-D2`), and that a subject digest equals the record's content digest (`GT-D3`).

**C4. Key authority.** A consumer MUST refuse a record when `signed_at` falls outside the key's `valid_from`/`valid_until` (`GT-R9`), when the key was revoked at or before `signed_at` (`GT-R8`), or when the record's `event_kind` is not in the key's `authorized_event_kinds` (`GT-R3`).

**C5. Record shape.** A consumer MUST refuse a record whose `eat_profile` is not `tag:govops,2026:trace-v1` (`GT-R10`), or whose `event_kind` is outside the catalog it declares (`GT-R13`). It MUST also refuse when `producer` differs from `producer_chain.producer_id` (`GT-R4`), when a decision or invocation carries both the singular and the batch form (`GT-R7`), or when a field the kind requires is absent (`GT-R11`).

**C6. Consumer-derived fields.** A consumer MUST ignore and flag any section 12 field found anywhere in the signed body, including a producer-signed `capability_id`, and MUST derive `capability_resolution` from the mapping regardless (`GT-F1`).

**C7. Capability resolution.** A consumer MUST resolve `capability_id` per decision or invocation from `(policy_store_id, policy_store_version, action, resource_type)` (`GT-A1`, `GT-A3`). An invocation resolves against the policy store of the decision its `authorized` edge names. A miss MUST be recorded as `resolution_status: unmapped` and kept (`GT-F2`, `GT-F6`).

**C8. Chain integrity.** A consumer MUST flag `prev_record_hash` that does not equal the predecessor's content digest (`GT-F3`), a gap in `sequence_number` (`GT-F4`), two different records at one position of one chain (`GT-F5`), and a `parent_record_ids` edge to a record it does not hold (`GT-F6`).

**C9. Recipes.** The content digest is `sha256:` followed by the lowercase hex SHA-256 of the RFC 8785 bytes of every member except `signature`, so it is identical in both carriage forms. The genesis sentinel is `sha256:` followed by 64 zeros.

**C10. Conformance claim.** An implementation is conformant to this profile at a given corpus release when it reaches every verdict, refusal code and flag set in that release's `MANIFEST.json`, and every listed `capability_resolution`.

C7's invocation rule and both recipes in C9 fill gaps the profile text leaves open: it names `content_digest` and a genesis sentinel without fixing either, and its invocation example carries no `policy` block to resolve against. The vectors fix one answer for each so two consumers can be compared. If the profile picks different answers, the members are regenerated to match.

## Limits

These are synthetic records over published test keys. They check what a consumer does with records it receives. They do not check that a producer observed what it signed, and they do not cover the receipt ledger, token enrichment, or the full-design event kinds the profile defers past the MVP.
