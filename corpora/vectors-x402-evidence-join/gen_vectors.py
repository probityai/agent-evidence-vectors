"""Build the deterministic x402 evidence join cases.

    uv run python corpora/vectors-x402-evidence-join/gen_vectors.py

Three accepted members and fourteen twins, one per rule, each one mutation away
from the accepted member it names. A twin is rejected when the evidence
contradicts the offer-to-settlement join and indeterminate when the evidence
needed to establish the join is absent. Every case, the manifest, the index and
the profile map are functions of this file alone. The fixtures are synthetic:
no real seller, payer, address, asset contract or transaction appears in them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "x402-evidence-join/v1"
SCHEMA = "x402-evidence-join-record/v1"
ACCEPT_REASON = "join_holds"
ACCEPTED, REJECTED, INDETERMINATE = "accepted", "rejected", "indeterminate"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _digest(value: object) -> str:
    return _sha(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )


SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "fieldNames": (
        "PaymentRequirements (scheme, network, amount, asset, payTo, maxTimeoutSeconds), "
        "ResourceInfo (url) and SettlementResponse (success, payer, transaction, network) "
        "follow the x402 v2 specification"
    ),
    "upstream": {
        "repository": "https://github.com/x402-foundation/x402",
        "path": "specs/x402-specification-v2.md",
        "commit": "911709c32e62641f7bd4df345b2029ebe84968c8",
    },
    "scope": (
        "The offer-to-settlement join a third party recomputes from one evidence package: "
        "seller key to resource domain, signed offer, payment construction, facilitator "
        "settlement against the ledger, delivered body and the fulfilment evaluation. "
        "Digests are recomputed; signature values are modelled, not verified."
    ),
}

PROFILE = {
    "suite": SUITE,
    "note": (
        "Maps each stage of an x402 transaction to the record fields this suite checks. "
        "Stage labels follow the Evidence Chain RFP (S2 offer to S7 fulfilment); x402 "
        "field names follow the v2 specification."
    ),
    "map": {
        "seller identity anchor (base domain of the resource URL)": (
            "seller.domain, offer.resource.url"
        ),
        "keys the seller domain vouches for": "seller.key_ids",
        "S2 offer (PaymentRequirements accepted by the buyer)": "offer.accepted",
        "S2 offer digest and signature": "offer.digest, offer.signature",
        "S3 payment construction (exact scheme authorization)": "payment.authorization",
        "S3 payment bound to the offer": "payment.offer_digest",
        "buyer identity anchor (payer address)": (
            "payment.authorization.from, settlement.facilitator.payer"
        ),
        "S5 facilitator SettlementResponse": "settlement.facilitator",
        "S5 ledger transfer read by a party other than the payer": "settlement.ledger",
        "S6 delivered result": "delivery.body, delivery.body_sha256",
        "receipt binding offer, transaction and delivery": "receipt",
        "S7 fulfilment evaluation against declared criteria": "fulfilment",
    },
    "verdicts": {
        "accepted": "verified: every join in the record recomputes",
        "rejected": (
            "contradicted: the evidence present fails the join, and the reason names the clause"
        ),
        "indeterminate": (
            "the evidence needed to establish the join is absent, "
            "and the reason names what is missing"
        ),
        "fulfilment.evaluated false": (
            "not evaluated: visible in the record and does not block acceptance"
        ),
    },
}

_RAILS: dict[str, dict[str, str]] = {
    "evm": {
        "network": "eip155:8453",
        "asset": "0x" + "a5" * 20,
        "payTo": "0x" + "b0" * 20,
        "payer": "0x" + "c1" * 20,
        "transaction": "0x" + "d2" * 32,
        "nonce": "0x" + "e3" * 32,
    },
    "solana": {
        "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "asset": "SynthAsset1111111111111111111111111111111111",
        "payTo": "SynthPayee1111111111111111111111111111111111",
        "payer": "SynthPayer1111111111111111111111111111111111",
        "transaction": "SynthTx" + "1" * 81,
        "nonce": "synth-nonce-0001",
    },
}

OTHER_ADDRESS = {"evm": "0x" + "f4" * 20, "solana": "SynthOther1111111111111111111111111111111111"}
SELLER_DOMAIN = "seller.example"
BODY = '{"forecast":"clear","city":"Example City","unit":"C","high":21}'


def _seal_offer(r: dict[str, Any]) -> None:
    offer = r["offer"]
    offer["digest"] = _digest({"accepted": offer["accepted"], "resource": offer["resource"]})
    offer["signature"] = {
        "key_id": offer["signature"]["key_id"],
        "value_sha256": _sha(offer["digest"].encode()),
    }


def _seal_receipt(r: dict[str, Any]) -> None:
    receipt = r["receipt"]
    body = {k: v for k, v in receipt.items() if k != "signature"}
    receipt["signature"] = _sha(_digest(body).encode())


def _base(rail: str, fulfilment_evaluated: bool = False) -> dict[str, Any]:
    v = _RAILS[rail]
    r: dict[str, Any] = {
        "schema": SCHEMA,
        "seller": {"domain": SELLER_DOMAIN, "key_ids": ["seller-key-1"]},
        "offer": {
            "resource": {"url": f"https://{SELLER_DOMAIN}/v1/forecast"},
            "accepted": {
                "scheme": "exact",
                "network": v["network"],
                "amount": "10000",
                "asset": v["asset"],
                "payTo": v["payTo"],
                "maxTimeoutSeconds": 60,
            },
            "signature": {"key_id": "seller-key-1"},
        },
    }
    _seal_offer(r)
    r["payment"] = {
        "offer_digest": r["offer"]["digest"],
        "authorization": {
            "from": v["payer"],
            "to": v["payTo"],
            "value": "10000",
            "nonce": v["nonce"],
            "validBefore": "1795000000",
        },
        "signature": {"signer": v["payer"]},
    }
    r["settlement"] = {
        "facilitator": {
            "success": True,
            "payer": v["payer"],
            "network": v["network"],
            "transaction": v["transaction"],
        },
        "ledger": {
            "transaction": v["transaction"],
            "network": v["network"],
            "status": "success",
            "from": v["payer"],
            "to": v["payTo"],
            "value": "10000",
            "asset": v["asset"],
        },
    }
    r["delivery"] = {"body": BODY, "body_sha256": _sha(BODY.encode())}
    r["receipt"] = {
        "offer_digest": r["offer"]["digest"],
        "transaction": v["transaction"],
        "delivery_digest": r["delivery"]["body_sha256"],
        "key_id": "seller-key-1",
    }
    _seal_receipt(r)
    if fulfilment_evaluated:
        r["fulfilment"] = {
            "evaluated": True,
            "criteria_digest": _digest({"field": "forecast", "present": True}),
            "outcome": "met",
        }
    else:
        r["fulfilment"] = {"evaluated": False}
    return r


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "evm-exact-join": lambda: _base("evm"),
    "solana-exact-join": lambda: _base("solana"),
    "evm-exact-join-fulfilment-met": lambda: _base("evm", fulfilment_evaluated=True),
}


def _receipt_key_outside(r: dict[str, Any]) -> None:
    r["receipt"]["key_id"] = "seller-key-9"
    _seal_receipt(r)


def _offer_edited(r: dict[str, Any]) -> None:
    r["offer"]["accepted"]["amount"] = "1"


def _payment_other_offer(r: dict[str, Any]) -> None:
    r["payment"]["offer_digest"] = _sha(b"another offer")


def _payer_not_signer(r: dict[str, Any]) -> None:
    r["payment"]["signature"]["signer"] = OTHER_ADDRESS["evm"]


def _payee_swapped(r: dict[str, Any]) -> None:
    r["payment"]["authorization"]["to"] = OTHER_ADDRESS["solana"]


def _amount_short(r: dict[str, Any]) -> None:
    r["payment"]["authorization"]["value"] = "9999"


def _receipt_other_offer(r: dict[str, Any]) -> None:
    r["receipt"]["offer_digest"] = _sha(b"another offer")
    _seal_receipt(r)


def _receipt_no_offer(r: dict[str, Any]) -> None:
    del r["receipt"]["offer_digest"]
    _seal_receipt(r)


def _no_reference(r: dict[str, Any]) -> None:
    del r["receipt"]["transaction"]
    r["settlement"]["ledger"] = None
    _seal_receipt(r)


def _ledger_reverted(r: dict[str, Any]) -> None:
    r["settlement"]["ledger"]["status"] = "reverted"


def _ledger_other_payee(r: dict[str, Any]) -> None:
    r["settlement"]["ledger"]["to"] = OTHER_ADDRESS["evm"]


def _facilitator_only(r: dict[str, Any]) -> None:
    r["settlement"]["ledger"] = None


def _body_differs(r: dict[str, Any]) -> None:
    r["delivery"]["body"] = BODY.replace("clear", "rain")


def _not_met(r: dict[str, Any]) -> None:
    r["fulfilment"]["outcome"] = "not_met"


Member = tuple[str, str, Callable[[dict[str, Any]], None] | None, str, str, str]

# (id, base, mutation or None for an accepted member, decision, reason, description)
MEMBERS: tuple[Member, ...] = (
    ("evm-exact-join", "", None, ACCEPTED, ACCEPT_REASON,
     "EVM exact payment, ledger agrees, fulfilment not evaluated"),
    ("solana-exact-join", "", None, ACCEPTED, ACCEPT_REASON,
     "Solana exact payment, ledger agrees, fulfilment not evaluated"),
    ("evm-exact-join-fulfilment-met", "", None, ACCEPTED, ACCEPT_REASON,
     "declared fulfilment criteria evaluated and met"),
    ("seller-key-outside-domain", "evm-exact-join", _receipt_key_outside, REJECTED,
     "seller_key_not_domain_bound", "receipt key not listed by the seller domain"),
    ("offer-terms-edited", "evm-exact-join", _offer_edited, REJECTED,
     "offer_digest_mismatch", "amount changed after the offer digest"),
    ("payment-for-other-offer", "solana-exact-join", _payment_other_offer, REJECTED,
     "payment_not_for_offer", "payment names another offer"),
    ("payer-not-signer", "evm-exact-join", _payer_not_signer, REJECTED,
     "payer_not_authorization_signer", "payment signed by an address other than the payer"),
    ("payee-swapped", "solana-exact-join", _payee_swapped, REJECTED,
     "payee_not_offer_payee", "authorization pays another address than payTo"),
    ("amount-short", "evm-exact-join", _amount_short, REJECTED,
     "amount_not_offer_amount", "one atomic unit short of the offer amount"),
    ("receipt-names-other-offer", "evm-exact-join", _receipt_other_offer, REJECTED,
     "receipt_names_other_offer", "receipt names another offer"),
    ("receipt-omits-offer-digest", "evm-exact-join", _receipt_no_offer, INDETERMINATE,
     "receipt_offer_unbound", "receipt carries no offer digest"),
    ("no-transaction-reference", "evm-exact-join", _no_reference, INDETERMINATE,
     "settlement_reference_missing", "no transaction in the receipt or a ledger read"),
    ("facilitator-success-ledger-reverted", "solana-exact-join", _ledger_reverted, REJECTED,
     "settlement_conflict", "facilitator says success, ledger says reverted"),
    ("ledger-pays-other-address", "evm-exact-join", _ledger_other_payee, REJECTED,
     "ledger_transfer_not_offer_terms", "ledger credits another address than payTo"),
    ("facilitator-only-settlement", "evm-exact-join", _facilitator_only, INDETERMINATE,
     "settlement_asserted_by_facilitator_only", "facilitator assertion, no ledger read"),
    ("delivered-body-differs", "evm-exact-join", _body_differs, REJECTED,
     "delivery_digest_mismatch", "delivered body differs from the bound digest"),
    ("fulfilment-not-met", "evm-exact-join-fulfilment-met", _not_met, REJECTED,
     "fulfilment_not_met", "declared criteria evaluated, not met"),
)  # fmt: skip

_ACCEPT_IDS = {m[0] for m in MEMBERS if m[2] is None}


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# x402 evidence join vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Suite: `{SUITE}`. Record schema: `{SCHEMA}`.",
        "",
        f"Corpus digest: `{digest}`",
        "",
        "| id | decision | reason | twin | case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(
            f"| `{e['id']}` | {x['decision']} | `{x['reason']}` | "
            f"{e.get('twin', '')} | {e['description']} |"
        )
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest, the index and the profile map."""
    entries = []
    for name, base, mutate, decision, reason, description in MEMBERS:
        record = copy.deepcopy(BASES[name if mutate is None else base]())
        if mutate is not None:
            mutate(record)
        record["case_id"] = f"vectors-x402-evidence-join-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "id": name,
            "path": f"cases/{name}",
            "files": {"case.json": _sha(data)},
            "description": description,
            "expected": {"decision": decision, "reason": reason},
        }
        if mutate is not None:
            assert base in _ACCEPT_IDS, (name, base)
            entry["twin"] = base
        entries.append(entry)
    digest = _sha(_json(entries))
    manifest = {
        "suite": SUITE,
        "schema": SCHEMA,
        "vectors": entries,
        "specification": SPECIFICATION,
        "verifierContract": "verifier case.json --json",
        "corpusDigest": digest,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    return manifest


if __name__ == "__main__":
    generate()
