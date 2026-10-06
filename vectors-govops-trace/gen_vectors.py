"""Build the GovOps TRACE profile corpus, byte-identically on every machine.

One governed execution: Alice's agent asks to move funds. Three producers each
sign their own record on their own key and their own hash chain:

    cedarling-fleet-1  AUTHORIZATION_DECISION  (the PDP allows Pay on Payment)
    payments-gateway   CAPABILITY_INVOKED      (authorized edge -> the decision)
    payments-ledger    RUNTIME_EFFECT          (produced_effect edge -> the invocation)

Each producer also carries the record before it in its chain, so the
prev_record_hash links are checked, not assumed. Every other member is this
chain with one defect. PUBLISHED TEST KEYS: the seeds below are public.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from canonical import canonical_bytes  # noqa: E402
from verifier import (  # noqa: E402
    GENESIS,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    PROFILE,
    STATEMENT_TYPE,
    content_digest,
    pae,
)  # noqa: E402

EXEC = "exec-01JGOVOPSFUNDSXFER0000001"
STORE = {
    "policy_store_id": "https://bank.example/policy-stores/payments",
    "policy_store_version": "1.2.3",
}
PAY = {"action": 'Bank::Action::"Pay"', "resource_type": "Bank::Payment"}
T0 = 1791300000
YEAR = 31536000


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"govops-trace-vectors/" + name.encode()).digest()
    )


def _pub(k: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


KEYS = {n: _key(n) for n in ("pdp", "gateway", "ledger", "attacker", "revoked")}


def registry() -> dict[str, Any]:
    def entry(producer: str, kid: str, key: str, kinds: list[str], **extra: Any) -> dict[str, Any]:
        return {
            "producer_id": producer,
            "kid": kid,
            "public_key_hex": _pub(KEYS[key]),
            "key_type": "Ed25519",
            "authorized_event_kinds": kinds,
            "valid_from": T0 - YEAR,
            "valid_until": T0 + YEAR,
            "revoked_at": None,
            **extra,
        }

    return {
        "evidence_domain_id": "bank.example/payments",
        "keys": [
            entry("cedarling-fleet-1", "pdp-2026-01", "pdp", ["AUTHORIZATION_DECISION"]),
            entry("payments-gateway", "gw-2026-01", "gateway", ["CAPABILITY_INVOKED"]),
            entry("payments-ledger", "ledger-2026-01", "ledger", ["RUNTIME_EFFECT"]),
            entry(
                "cedarling-fleet-1",
                "pdp-2025-09",
                "revoked",
                ["AUTHORIZATION_DECISION"],
                revoked_at=T0 - 3600,
                revocation_reason="key_compromise",
            ),
        ],
    }


def mapping() -> dict[str, Any]:
    return {
        "mapping_version": "3",
        "entries": [
            {**STORE, **PAY, "capability_id": "invoke:funds-transfer"},
            {
                **STORE,
                "action": 'Bank::Action::"ViewBalance"',
                "resource_type": "Bank::Account",
                "capability_id": "read:account-balance",
            },
        ],
    }


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign_inline(rec: dict[str, Any], key: str) -> dict[str, Any]:
    body = {k: v for k, v in rec.items() if k != "signature"}
    return {**body, "signature": _b64url(KEYS[key].sign(canonical_bytes(body)))}


def dsse(
    rec: dict[str, Any],
    key: str,
    kid: str,
    *,
    payload_type: str = PAYLOAD_TYPE,
    predicate_type: str = PREDICATE_TYPE,
    subject_digest: str | None = None,
) -> str:
    body = {k: v for k, v in rec.items() if k != "signature"}
    digest = subject_digest or content_digest(body)[len("sha256:") :]
    statement: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": f"govops:{body['producer']}/{body['record_id']}", "digest": {"sha256": digest}}
        ],
        "predicateType": predicate_type,
        "predicate": body,
    }
    payload = canonical_bytes(statement)
    sig = KEYS[key].sign(pae(payload_type, payload))
    env = {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}],
    }
    return json.dumps(env, indent=1, sort_keys=True)


def _base(
    producer: str,
    kid: str,
    rid: str,
    kind: str,
    seq: int,
    prev: str,
    chain_id: str,
    instance: str,
    event: dict[str, Any],
    at: int,
    execution: str = EXEC,
    **trace_extra: Any,
) -> dict[str, Any]:
    trace = {
        "eat_profile": PROFILE,
        "event_kind": kind,
        "signed_at": at,
        "trace_execution_id": execution,
        "execution_authority": "spiffe://bank.example/agent/treasury-assistant",
        "subject": {"workload_id": "spiffe://bank.example/agent/treasury-assistant"},
        "evidence_origin": "directly_observed",
        "event": event,
        **trace_extra,
    }
    return {
        "producer": producer,
        "record_id": rid,
        "kid": kid,
        "trace": trace,
        "producer_chain": {
            "producer_id": producer,
            "producer_instance_id": instance,
            "producer_chain_id": chain_id,
            "sequence_number": seq,
            "prev_record_hash": prev,
        },
        "parent_record_ids": [],
    }


def decision(
    seq: int, prev: str, rid: str, outcome: str = "ALLOW", execution: str = EXEC
) -> dict[str, Any]:
    return _base(
        "cedarling-fleet-1",
        "pdp-2026-01",
        rid,
        "AUTHORIZATION_DECISION",
        seq,
        prev,
        "chain-pdp-A",
        "cedarling-001",
        {
            "decision": {**PAY, "outcome": outcome},
            "tokens": [
                {
                    "issuer": "https://login.bank.example",
                    "token_type": "transaction_token",
                    "jti": "tt-7e5f0a21",
                }
            ],
        },
        T0 + seq,
        execution,
        policy={
            "bundle_hash": "sha256:" + "ab" * 32,
            **STORE,
            "policy_language": "cedar",
            "policy_language_version": "4.4.0",
        },
        runtime={"pdp_id": "cedarling-001"},
    )


def invocation(seq: int, prev: str, rid: str, parent: str) -> dict[str, Any]:
    r = _base(
        "payments-gateway",
        "gw-2026-01",
        rid,
        "CAPABILITY_INVOKED",
        seq,
        prev,
        "chain-gw-A",
        "gw-01",
        {
            "invocation": {**PAY, "outcome": "SUCCESS"},
            "enforcement_point_id": "payments-gateway-01",
        },
        T0 + seq + 1,
    )
    r["parent_record_ids"] = [
        {"producer_id": "cedarling-fleet-1", "record_id": parent, "relationship_type": "authorized"}
    ]
    return r


def effect(seq: int, prev: str, rid: str, parent: str) -> dict[str, Any]:
    r = _base(
        "payments-ledger",
        "ledger-2026-01",
        rid,
        "RUNTIME_EFFECT",
        seq,
        prev,
        "chain-ledger-A",
        "ledger-01",
        {"outcome": "SETTLED", "result_digest": "sha256:" + "cd" * 32},
        T0 + seq + 2,
    )
    r["parent_record_ids"] = [
        {
            "producer_id": "payments-gateway",
            "record_id": parent,
            "relationship_type": "produced_effect",
        }
    ]
    return r


def chain() -> list[tuple[dict[str, Any], str]]:
    """The six signed records of the valid funds transfer, with their signer."""
    d0 = sign_inline(
        decision(40, GENESIS.replace("0", "1"), "dec-0040", execution="exec-prior-01"), "pdp"
    )
    d1 = sign_inline(decision(41, content_digest(d0), "dec-0041"), "pdp")
    i0 = sign_inline(invocation(90, "sha256:" + "11" * 32, "inv-0090", "dec-0040"), "gateway")
    i1 = sign_inline(invocation(91, content_digest(i0), "inv-0091", "dec-0041"), "gateway")
    e0 = sign_inline(effect(0, GENESIS, "eff-0000", "inv-0090"), "ledger")
    e1 = sign_inline(effect(1, content_digest(e0), "eff-0001", "inv-0091"), "ledger")
    return [
        (d0, "pdp"),
        (d1, "pdp"),
        (i0, "gateway"),
        (i1, "gateway"),
        (e0, "ledger"),
        (e1, "ledger"),
    ]


KID = {"pdp": "pdp-2026-01", "gateway": "gw-2026-01", "ledger": "ledger-2026-01"}


def inline(recs: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{"form": "inline", "text": json.dumps(r, indent=1, sort_keys=True)} for r in recs]


def resign(rec: dict[str, Any], signer: str, edit: Any) -> dict[str, Any]:
    r = copy.deepcopy(rec)
    edit(r)
    return sign_inline(r, signer)


def members() -> list[dict[str, Any]]:  # noqa: PLR0915 -- one flat table of cases reads best
    c = chain()
    recs = [r for r, _ in c]
    d0, d1, i0, i1, e0, e1 = recs
    out: list[dict[str, Any]] = []

    def add(
        mid: str,
        verdict: str,
        why: str,
        records: list[dict[str, str]],
        code: str | None = None,
        flags: list[str] | None = None,
        basis: str = "",
    ) -> None:
        out.append(
            {
                "id": mid,
                "verdict": verdict,
                "code": code,
                "flags": sorted(flags or []),
                "why": why,
                "basis": basis,
                "records": records,
            }
        )

    add(
        "GT-A1",
        "accept",
        "The funds transfer: decision, invocation and effect from three producers, "
        "each with its predecessor.",
        inline(recs),
        basis="profile sections 1, 5, 6, 8, 9",
    )
    add(
        "GT-A2",
        "accept",
        "The same six records, each the predicate of an in-toto Statement in a DSSE envelope.",
        [{"form": "dsse", "text": dsse(r, s, KID[s])} for r, s in c],
        basis="carriage proposal",
    )
    batch = resign(
        d1,
        "pdp",
        lambda r: (
            r["trace"]["event"].pop("decision")
            and r["trace"]["event"].update(
                decisions=[
                    {"decision_id": "d1", **PAY, "outcome": "ALLOW"},
                    {
                        "decision_id": "d2",
                        "action": 'Bank::Action::"ViewBalance"',
                        "resource_type": "Bank::Account",
                        "outcome": "DENY",
                    },
                ]
            )
        ),
    )
    add(
        "GT-A3",
        "accept",
        "A batched decisions[] with mixed outcomes resolves one capability per decision_id.",
        inline([d0, batch]),
        basis="profile sections 8 and 9",
    )

    signed_cap = resign(
        d1,
        "pdp",
        lambda r: r["trace"]["event"]["decision"].update(capability_id="read:account-balance"),
    )
    add(
        "GT-F1",
        "flag",
        "The PDP signed a capability_id that disagrees with the mapping. "
        "It is ignored; resolution still gives invoke:funds-transfer.",
        inline([d0, signed_cap]),
        flags=["consumer-derived-field-ignored"],
        basis="profile sections 9 and 12",
    )
    unmapped = resign(
        d1, "pdp", lambda r: r["trace"]["event"]["decision"].update(action='Bank::Action::"Refund"')
    )
    add(
        "GT-F2",
        "flag",
        "No mapping entry for the signed facts: resolution_status unmapped, recorded, not dropped.",
        inline([d0, unmapped]),
        flags=["capability-unmapped"],
        basis="profile section 9",
    )
    badlink = resign(
        d1, "pdp", lambda r: r["producer_chain"].update(prev_record_hash="sha256:" + "ee" * 32)
    )
    add(
        "GT-F3",
        "flag",
        "prev_record_hash does not equal the content digest of the predecessor.",
        inline([d0, badlink]),
        flags=["chain-link-failure"],
        basis="profile sections 5 and 12",
    )
    gap = resign(d1, "pdp", lambda r: r["producer_chain"].update(sequence_number=43))
    add(
        "GT-F4",
        "flag",
        "Sequence 41 is missing between 40 and 43.",
        inline([d0, gap]),
        flags=["coverage-gap"],
        basis="profile section 12",
    )
    twin = resign(d1, "pdp", lambda r: r["trace"]["event"]["decision"].update(outcome="DENY"))
    add(
        "GT-F5",
        "flag",
        "Two different records claim sequence 41 of one chain.",
        inline([d0, d1, twin]),
        flags=["equivocation"],
        basis="profile section 12",
    )
    add(
        "GT-F6",
        "flag",
        "The invocation's authorized edge names a decision that never arrived.",
        inline([i0, i1]),
        flags=["unresolved-parent", "capability-unmapped"],
        basis="profile sections 6 and 9",
    )

    with_cnf = resign(
        d1,
        "pdp",
        lambda r: r.update(
            cnf={
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(bytes.fromhex(_pub(KEYS["pdp"]))),
                }
            }
        ),
    )
    add(
        "GT-F7",
        "flag",
        "The body carries cnf. The key comes from the registry by kid; cnf is ignored and flagged.",
        inline([d0, with_cnf]),
        flags=["cnf-ignored"],
        basis="profile section 1 (cnf not carried)",
    )

    tampered = copy.deepcopy(d1)
    tampered["trace"]["event"]["decision"]["outcome"] = (
        "ALLOW" if d1["trace"]["event"]["decision"]["outcome"] != "ALLOW" else "DENY"
    )
    add(
        "GT-R1",
        "reject",
        "The outcome was changed after signing.",
        inline([d0, tampered]),
        code="bad-signature",
        basis="profile section 1",
    )
    add(
        "GT-R2",
        "reject",
        "kid names no registered key.",
        inline([resign(d1, "pdp", lambda r: r.update(kid="pdp-2027-99"))]),
        code="key-unresolved",
        basis="profile section 10",
    )
    wrong_role = resign(
        d1,
        "gateway",
        lambda r: (
            r.update(producer="payments-gateway", kid="gw-2026-01")
            or r["producer_chain"].update(producer_id="payments-gateway")
        ),
    )
    add(
        "GT-R3",
        "reject",
        "The gateway's key signed an authorization decision.",
        inline([wrong_role]),
        code="producer-not-authorized-for-claim",
        basis="profile sections 8 and 10",
    )
    add(
        "GT-R4",
        "reject",
        "producer and producer_chain.producer_id differ.",
        inline(
            [
                resign(
                    d1, "pdp", lambda r: r["producer_chain"].update(producer_id="cedarling-fleet-2")
                )
            ]
        ),
        code="producer-mismatch",
        basis="profile section 1",
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    ax = _b64url(KEYS["attacker"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    cnf = copy.deepcopy(d1)
    cnf["cnf"] = {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": ax}}
    cnf["trace"]["event"]["decision"]["outcome"] = "ALLOW"
    cnf = sign_inline(cnf, "attacker")
    add(
        "GT-R5",
        "reject",
        "The body carries cnf with the signer's own key. "
        "The registry key is the only key, so the signature fails.",
        inline([cnf]),
        code="bad-signature",
        basis="profile section 1 (cnf not carried)",
    )
    deny = resign(d1, "pdp", lambda r: r["trace"]["event"]["decision"].update(outcome="DENY"))
    text = json.dumps(deny, indent=1, sort_keys=True).replace(
        '"outcome": "DENY"', '"outcome": "DENY",\n   "outcome": "ALLOW"', 1
    )
    add(
        "GT-R6",
        "reject",
        "outcome appears twice. A last-wins parser reads ALLOW, while the signature covers DENY.",
        [{"form": "inline", "text": text}],
        code="duplicate-member",
        basis="RFC 8785 section 3.1, I-JSON",
    )
    both = resign(
        d1,
        "pdp",
        lambda r: r["trace"]["event"].update(
            decisions=[{"decision_id": "d1", **PAY, "outcome": "ALLOW"}]
        ),
    )
    add(
        "GT-R7",
        "reject",
        "Both decision and decisions[] are present.",
        inline([both]),
        code="decision-form-ambiguous",
        basis="profile section 8",
    )
    revoked = resign(d1, "revoked", lambda r: r.update(kid="pdp-2025-09"))
    add(
        "GT-R8",
        "reject",
        "Signed by a key revoked an hour before signed_at.",
        inline([revoked]),
        code="key-revoked",
        basis="profile section 10",
    )
    late = resign(d1, "pdp", lambda r: r["trace"].update(signed_at=T0 + 2 * YEAR))
    add(
        "GT-R9",
        "reject",
        "signed_at falls after the key's valid_until.",
        inline([late]),
        code="key-temporally-invalid",
        basis="profile section 10",
    )
    base = resign(
        d1, "pdp", lambda r: r["trace"].update(eat_profile="tag:agentrust-io.com,2026:trace-v0.2")
    )
    add(
        "GT-R10",
        "reject",
        "A base TRACE v0.2 profile tag on a GovOps-shaped record.",
        inline([base]),
        code="profile-mismatch",
        basis="profile section 2",
    )
    nopdp = resign(d1, "pdp", lambda r: r["trace"].pop("runtime"))
    add(
        "GT-R11",
        "reject",
        "An authorization decision without runtime.pdp_id.",
        inline([nopdp]),
        code="missing-required-field",
        basis="profile section 8",
    )
    big = resign(d1, "pdp", lambda r: r["producer_chain"].update(sequence_number=2**53 - 1))
    add(
        "GT-R12",
        "reject",
        "sequence_number of 2^53, beyond the integers every JSON reader agrees on.",
        [
            {
                "form": "inline",
                "text": json.dumps(big, indent=1, sort_keys=True).replace(
                    str(2**53 - 1), str(2**53)
                ),
            }
        ],
        code="number-not-ijson",
        basis="RFC 8785 section 3.2.2.3, RFC 7493",
    )
    unknown = resign(d1, "pdp", lambda r: r["trace"].update(event_kind="POLICY_CHANGED"))
    add(
        "GT-R13",
        "reject",
        "A full-design event kind in an MVP-conformant stream.",
        inline([unknown]),
        code="unknown-event-kind",
        basis="profile section 7",
    )

    add(
        "GT-D1",
        "reject",
        "The envelope's payloadType is not in-toto.",
        [{"form": "dsse", "text": dsse(d1, "pdp", KID["pdp"], payload_type="application/json")}],
        code="dsse-payload-type",
        basis="carriage proposal",
    )
    add(
        "GT-D2",
        "reject",
        "The Statement names another predicate type.",
        [
            {
                "form": "dsse",
                "text": dsse(d1, "pdp", KID["pdp"], predicate_type="https://example.org/other/v1"),
            }
        ],
        code="predicate-type-mismatch",
        basis="carriage proposal",
    )
    add(
        "GT-D3",
        "reject",
        "The subject digest is not the record's content digest.",
        [{"form": "dsse", "text": dsse(d1, "pdp", KID["pdp"], subject_digest="00" * 32)}],
        code="subject-digest-mismatch",
        basis="carriage proposal",
    )
    add(
        "GT-D4",
        "reject",
        "Signed by the gateway's key under the PDP's keyid.",
        [{"form": "dsse", "text": dsse(d1, "gateway", KID["pdp"])}],
        code="dsse-bad-signature",
        basis="carriage proposal",
    )
    return out


def main() -> None:
    from verifier import judge

    reg, mp = registry(), mapping()
    (HERE / "members").mkdir(exist_ok=True)
    manifest = []
    for m in members():
        path = HERE / "members" / f"{m['id']}.json"
        path.write_text(json.dumps({"records": m["records"]}, indent=1, sort_keys=True) + "\n")
        got = judge({"records": m["records"]}, reg, mp)
        entry = {k: m[k] for k in ("id", "verdict", "code", "flags", "why", "basis")}
        if m["verdict"] != "reject":
            entry["capability_resolution"] = got.get("capability_resolution")
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.append(entry)
    (HERE / "registry.json").write_text(json.dumps(reg, indent=1, sort_keys=True) + "\n")
    (HERE / "mapping.json").write_text(json.dumps(mp, indent=1, sort_keys=True) + "\n")
    doc = {
        "profile": PROFILE,
        "profileSource": "https://github.com/GovOpsWG/GovOps/blob/131cb66bc87cd266e224d7df6f7b9401c00f3ef7/govops-trace-profile.md",
        "predicateType": PREDICATE_TYPE,
        "keyNote": "PUBLISHED TEST KEYS derived from fixed seeds in gen_vectors.py.",
        "members": manifest,
    }
    (HERE / "MANIFEST.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    rows = [
        "# Members",
        "",
        "Generated by gen_vectors.py from MANIFEST.json. Do not edit by hand.",
        "",
        "| id | verdict | code or flags | case | basis |",
        "|---|---|---|---|---|",
    ]
    for e in manifest:
        mark = e["code"] or ", ".join(e["flags"]) or "-"
        rows.append(
            f"| [{e['id']}](members/{e['id']}.json) | {e['verdict']} | `{mark}` "
            f"| {e['why']} | {e['basis']} |"
        )
    (HERE / "INDEX.md").write_text("\n".join(rows) + "\n")
    print(f"wrote {len(manifest)} members")


if __name__ == "__main__":
    main()
