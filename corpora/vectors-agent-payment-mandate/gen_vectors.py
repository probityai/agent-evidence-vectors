"""Build the deterministic Agent payment mandate cases.

    uv run python vectors-agent-payment-mandate/gen_vectors.py

Five accepted members (one per scheme, the exact-limit boundary, and a pack of
two mandates on two rails) and twenty-nine rejected twins, at least one per rule, each
one mutation away from an accepted member. The rejected twins include every forgery the
16 Nov 2026 attack run found the reader accepting: a mandate used by another agent, a
sub-delegation the user never signed, a charge on a rail the mandate does not name, a
single-use mandate settled twice (on one rail, or once on each of two rails), expiry
dodged by a zone offset or by Unix seconds, a missing expiry, a charge before the
mandate was issued, fractional and negative minor units, a duplicate JSON member, and a
post-checkout requirement deleted from the unsigned record. Every case, the
manifest, the index, the profile map and the relying party's policy are functions
of this file alone. The fixtures are synthetic, and so are the signing keys: their
seeds are public on purpose.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
SUITE = "agent-payment-mandate/v1"
SCHEMA = "agent-payment-mandate-record/v1"
ACCEPT_REASON = "mandate_chain_holds"
MANDATE_DOMAIN = b"agent-payment-mandate/v1:mandate:"
RECEIPT_DOMAIN = b"agent-payment-mandate/v1:receipt:"
AGENT_DOMAIN = b"agent-payment-mandate/v1:agent:"
PACK_SCHEMA = "agent-payment-mandate-pack/v1"
# Deterministic synthetic keys; the seeds are public on purpose (fixtures, not secrets).
_SEEDS = {
    "issuer-key-1": "11" * 32,
    "witness-key-1": "22" * 32,
    "agent-key-1": "33" * 32,
    "agent-key-2": "44" * 32,
}
_SK = {k: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v)) for k, v in _SEEDS.items()}
_PK = {
    k: s.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    for k, s in _SK.items()
}
POLICY = {
    "note": (
        "The relying party's trust root for this corpus: the issuer keys that may sign a "
        "mandate and the settlement-witness keys that may sign a receipt. In deployment it "
        "comes from the relying party, never from the evidence pack."
    ),
    "issuer_keys": {"issuer-key-1": _PK["issuer-key-1"]},
    "witness_keys": {"witness-key-1": _PK["witness-key-1"]},
}


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
    "scope": (
        "Receipt-side fields only. Each source scheme is named by concept; no upstream "
        "field name is asserted, and none of the three schemes' texts is vendored."
    ),
    "schemes": [
        "ap2-cart-mandate",
        "mastercard-verifiable-intent-credential",
        "stripe-shared-payment-token",
    ],
}

_SCHEME_TERMS = {
    "ap2-cart-mandate": ("cart", "merchant-a.example", "USD", 12900, ["card"]),
    "mastercard-verifiable-intent-credential": (
        "intent",
        "merchant-b.example",
        "EUR",
        4500,
        ["card"],
    ),
    "stripe-shared-payment-token": (
        "seller-bound-token",
        "merchant-c.example",
        "USD",
        2500,
        ["stripe"],
    ),
}

PROFILE = {
    "suite": SUITE,
    "note": (
        "Maps what each scheme binds to the receipt-side record fields this suite "
        "checks. Source side is a concept, not an upstream field name."
    ),
    "map": {
        "ap2-cart-mandate": {
            "what the user authorised": "mandate.terms",
            "the authorised ceiling": "mandate.terms.max_amount_minor",
            "who signed it": "mandate.signature",
            "what the agent presented": "credential",
            "the agent the mandate delegates to": "mandate.terms.agent",
            "what ran": "execution",
            "the agent's proof over what ran": "execution.agent_signature",
        },
        "mastercard-verifiable-intent-credential": {
            "the delegated intent": "mandate.terms",
            "credential bound to the intent": "credential.mandate_digest",
            "single use": "mandate.terms.single_use",
            "the agent key the intent binds": "mandate.terms.agent",
            "what ran": "execution",
        },
        "stripe-shared-payment-token": {
            "seller the token is scoped to": "mandate.terms.merchant",
            "amount and time bound": "mandate.terms.max_amount_minor, mandate.terms.expires_at",
            "token identifier": "credential.token_id",
            "what ran": "execution",
        },
        "receipt": {
            "what the agent did after checkout": "post_checkout.recorded",
            "binding of mandate and execution": "receipt",
            "which settlement of the token this is": "receipt.token_use_seq",
            "rails the mandate may be spent on": "mandate.terms.rails",
            "actions the mandate requires after checkout": "mandate.terms.post_checkout_required",
        },
    },
}


def _canon(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sign_agent(r: dict[str, Any], key_id: str = "agent-key-1") -> None:
    """The agent signs the charge it ran, bound to the mandate digest."""
    body = {k: v for k, v in r["execution"].items() if k != "agent_signature"}
    message = AGENT_DOMAIN + r["mandate"]["digest"].encode() + b":" + _canon(body)
    r["execution"]["agent_signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "value": _SK[key_id].sign(message).hex(),
    }


def _sign_receipt(
    r: dict[str, Any], key_id: str = "witness-key-1", agent: str = "agent-key-1"
) -> None:
    """The agent signs the charge, then the settlement witness (or ``key_id``) signs the receipt."""
    _sign_agent(r, agent)
    r["receipt"]["execution_digest"] = _digest(r["execution"])
    body = {k: v for k, v in r["receipt"].items() if k != "signature"}
    r["receipt"]["signature"] = {
        "alg": "ed25519",
        "key_id": key_id,
        "value": _SK[key_id].sign(RECEIPT_DOMAIN + _canon(body)).hex(),
    }


def _seal(r: dict[str, Any]) -> dict[str, Any]:
    """Recompute every digest a conformant record carries and sign it as issuer and witness."""
    r["mandate"]["digest"] = _digest(r["mandate"]["terms"])
    r["mandate"]["signature"] = {
        "alg": "ed25519",
        "key_id": "issuer-key-1",
        "value": _SK["issuer-key-1"].sign(MANDATE_DOMAIN + r["mandate"]["digest"].encode()).hex(),
    }
    r["credential"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["mandate_digest"] = r["mandate"]["digest"]
    _sign_receipt(r)
    return r


def _base(
    scheme: str,
    amount: int | None = None,
    rail: str | None = None,
    rails: list[str] | None = None,
) -> dict[str, Any]:
    kind, merchant, currency, limit, scheme_rails = _SCHEME_TERMS[scheme]
    mandated = rails or scheme_rails
    spend = limit - 400 if amount is None else amount
    r: dict[str, Any] = {
        "schema": SCHEMA,
        "scheme": scheme,
        "mandate": {
            "terms": {
                "kind": kind,
                "issuer": "did:example:issuer-1",
                "max_amount_minor": limit,
                "currency": currency,
                "merchant": merchant,
                "issued_at": "2026-11-01T09:00:00Z",
                "expires_at": "2026-11-30T00:00:00Z",
                "agent": {"key_id": "agent-key-1", "public_key": _PK["agent-key-1"]},
                "rails": mandated,
                "single_use": True,
                "post_checkout_required": ["capture", "fulfilment"],
            }
        },
        "credential": {"token_id": "tok-0001", "single_use": True, "consumed_token_ids": []},
        "execution": {
            "executed_at": "2026-11-02T10:15:00Z",
            "amount_minor": spend,
            "currency": currency,
            "merchant": merchant,
            "token_id": "tok-0001",
            "agent_key_id": "agent-key-1",
            "rail": rail or mandated[0],
        },
        "receipt": {"receipt_id": "rcpt-0001", "token_use_seq": 1},
        "post_checkout": {
            "required": ["capture", "fulfilment"],
            "recorded": ["capture", "fulfilment"],
        },
    }
    return _seal(r)


def _pack(spent_twice: bool) -> dict[str, Any]:
    """Two records on two rails: two mandates (accepted) or one single-use mandate (refused)."""
    rails = ["card", "x402"]
    first = _base("ap2-cart-mandate", rail="card", rails=rails)
    second = _base("ap2-cart-mandate", rail="x402", rails=rails)
    if not spent_twice:
        second["mandate"]["terms"]["merchant"] = "merchant-d.example"
        second["execution"]["merchant"] = "merchant-d.example"
        second["credential"]["token_id"] = second["execution"]["token_id"] = "tok-0002"
        _seal(second)
    second["receipt"]["receipt_id"] = "rcpt-0002"
    second["execution"]["executed_at"] = "2026-11-02T10:16:00Z"
    _sign_receipt(second)
    return {"schema": PACK_SCHEMA, "scheme": "ap2-cart-mandate", "records": [first, second]}


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "ap2": lambda: _base("ap2-cart-mandate"),
    "vi": lambda: _base("mastercard-verifiable-intent-credential"),
    "spt": lambda: _base("stripe-shared-payment-token"),
    "limit": lambda: _base("ap2-cart-mandate", amount=12900),
    "pack": lambda: _pack(spent_twice=False),
}


def _unsigned(r: dict[str, Any]) -> None:
    r["mandate"]["signature"] = None


def _edited_terms(r: dict[str, Any]) -> None:
    r["mandate"]["terms"]["max_amount_minor"] = 999999


def _unbound(r: dict[str, Any]) -> None:
    r["credential"]["mandate_digest"] = _sha(b"another mandate")


def _expired(r: dict[str, Any]) -> None:
    r["execution"]["executed_at"] = "2026-12-01T00:00:01Z"
    _sign_receipt(r)


def _over_limit(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] = r["mandate"]["terms"]["max_amount_minor"] + 1
    _sign_receipt(r)


def _currency(r: dict[str, Any]) -> None:
    r["execution"]["currency"] = "GBP"
    _sign_receipt(r)


def _merchant(r: dict[str, Any]) -> None:
    r["execution"]["merchant"] = "other-merchant.example"
    _sign_receipt(r)


def _other_token(r: dict[str, Any]) -> None:
    r["execution"]["token_id"] = "tok-9999"
    _sign_receipt(r)


def _replayed(r: dict[str, Any]) -> None:
    r["credential"]["consumed_token_ids"] = ["tok-0001"]


def _receipt_stale(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] -= 100
    _sign_agent(r)


def _no_fulfilment(r: dict[str, Any]) -> None:
    r["post_checkout"]["recorded"] = ["capture"]


def _ceiling_raised_without_key(r: dict[str, Any]) -> None:
    """The pack's holder raises the ceiling and recomputes every digest; it holds no issuer key."""
    r["mandate"]["terms"]["max_amount_minor"] = 10**9
    r["mandate"]["digest"] = _digest(r["mandate"]["terms"])
    r["credential"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["mandate_digest"] = r["mandate"]["digest"]
    r["mandate"]["signature"]["value"] = "ab" * 64


def _charge_rewritten_after_witness(r: dict[str, Any]) -> None:
    """The holder rewrites the charge and its digest after the witness signed; no witness key."""
    r["execution"]["amount_minor"] -= 100
    _sign_agent(r)
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _duplicate_member(r: dict[str, Any]) -> None:
    """The bytes carry amount_minor twice; generate() writes the first, unsigned copy."""


def _amount_fraction(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] = r["mandate"]["terms"]["max_amount_minor"] + 0.9
    _sign_receipt(r)


def _amount_negative(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] = -50000
    _sign_receipt(r)


def _executed_epoch(r: dict[str, Any]) -> None:
    r["execution"]["executed_at"] = 1796083200
    _sign_receipt(r)


def _expiry_missing(r: dict[str, Any]) -> None:
    del r["mandate"]["terms"]["expires_at"]
    r["execution"]["executed_at"] = "2027-11-02T10:15:00Z"
    _seal(r)


def _credential_multi_use(r: dict[str, Any]) -> None:
    r["credential"]["single_use"] = False


def _other_agent(r: dict[str, Any]) -> None:
    r["execution"]["agent_key_id"] = "agent-key-2"
    _sign_receipt(r, agent="agent-key-2")


def _sub_delegation(r: dict[str, Any]) -> None:
    r["credential"]["delegation"] = [{"from": "agent-key-1", "to": "agent-key-2"}]
    r["execution"]["agent_key_id"] = "agent-key-2"
    _sign_receipt(r, agent="agent-key-2")


def _agent_proof_other_key(r: dict[str, Any]) -> None:
    _sign_agent(r, "agent-key-2")
    r["execution"]["agent_signature"]["key_id"] = "agent-key-1"
    r["receipt"]["execution_digest"] = _digest(r["execution"])
    body = {k: v for k, v in r["receipt"].items() if k != "signature"}
    r["receipt"]["signature"]["value"] = (
        _SK["witness-key-1"].sign(RECEIPT_DOMAIN + _canon(body)).hex()
    )


def _before_issue(r: dict[str, Any]) -> None:
    r["execution"]["executed_at"] = "2026-10-20T10:15:00Z"
    _sign_receipt(r)


def _expired_offset(r: dict[str, Any]) -> None:
    r["execution"]["executed_at"] = "2026-11-29T23:30:00-05:00"
    _sign_receipt(r)


def _unmandated_rail(r: dict[str, Any]) -> None:
    r["execution"]["rail"] = "x402"
    _sign_receipt(r)


def _second_settlement(r: dict[str, Any]) -> None:
    r["receipt"]["receipt_id"] = "rcpt-0002"
    r["receipt"]["token_use_seq"] = 2
    _sign_receipt(r)


def _requirement_dropped(r: dict[str, Any]) -> None:
    r["post_checkout"] = {"required": ["capture"], "recorded": ["capture"]}


def _spent_on_two_rails(_r: dict[str, Any]) -> dict[str, Any]:
    return _pack(spent_twice=True)


def _receipt_signed_by_agent(r: dict[str, Any]) -> None:
    """The agent signs its own receipt: a valid signature from a party that is no witness."""
    _sign_receipt(r, "agent-key-1")


# (id, base, mutation or None for an accepted member, refusal code, description, twin)
MEMBERS: tuple[tuple[str, str, Callable[[dict[str, Any]], Any] | None, str, str, str], ...] = (
    (
        "authorized-ap2-cart",
        "ap2",
        None,
        "",
        "cart mandate, bound credential, in-limit charge, fulfilment recorded",
        "",
    ),
    (
        "authorized-vi-credential",
        "vi",
        None,
        "",
        "verifiable-intent credential bound to its intent, charge inside the ceiling",
        "",
    ),
    (
        "authorized-spt-seller-bound",
        "spt",
        None,
        "",
        "seller-bound shared token used once at its seller inside its bounds",
        "",
    ),
    (
        "authorized-at-exact-limit",
        "limit",
        None,
        "",
        "charge equal to the ceiling is inside the mandate",
        "",
    ),
    (
        "mandate-unsigned",
        "ap2",
        _unsigned,
        "mandate_unsigned",
        "the mandate carries no issuer signature",
        "authorized-ap2-cart",
    ),
    (
        "mandate-terms-edited",
        "ap2",
        _edited_terms,
        "mandate_digest_mismatch",
        "terms raised after the digest was taken",
        "authorized-ap2-cart",
    ),
    (
        "credential-bound-to-another-mandate",
        "vi",
        _unbound,
        "credential_not_bound_to_mandate",
        "the credential names a different mandate digest",
        "authorized-vi-credential",
    ),
    (
        "charge-after-expiry",
        "ap2",
        _expired,
        "mandate_expired",
        "executed after the mandate expired",
        "authorized-ap2-cart",
    ),
    (
        "charge-over-limit",
        "ap2",
        _over_limit,
        "amount_over_limit",
        "one minor unit over the authorised ceiling",
        "authorized-ap2-cart",
    ),
    (
        "charge-in-other-currency",
        "vi",
        _currency,
        "currency_mismatch",
        "authorised in EUR, charged in GBP",
        "authorized-vi-credential",
    ),
    (
        "charge-at-other-merchant",
        "spt",
        _merchant,
        "merchant_mismatch",
        "token scoped to one seller, used at another",
        "authorized-spt-seller-bound",
    ),
    (
        "executed-token-differs",
        "spt",
        _other_token,
        "token_not_the_executed_token",
        "the charge ran under a token the credential does not hold",
        "authorized-spt-seller-bound",
    ),
    (
        "single-use-token-replayed",
        "ap2",
        _replayed,
        "single_use_token_replayed",
        "a single-use token already consumed is used again",
        "authorized-ap2-cart",
    ),
    (
        "receipt-not-over-execution",
        "vi",
        _receipt_stale,
        "receipt_not_bound_to_execution",
        "execution changed after the receipt digest was taken",
        "authorized-vi-credential",
    ),
    (
        "mandate-ceiling-raised-without-key",
        "ap2",
        _ceiling_raised_without_key,
        "mandate_signature_invalid",
        "holder raised the ceiling and recomputed every digest without the issuer key",
        "authorized-ap2-cart",
    ),
    (
        "charge-rewritten-after-witness",
        "vi",
        _charge_rewritten_after_witness,
        "receipt_signature_invalid",
        "charge and its digest rewritten after the settlement witness signed the receipt",
        "authorized-vi-credential",
    ),
    (
        "receipt-signed-by-agent",
        "spt",
        _receipt_signed_by_agent,
        "receipt_signer_not_witness",
        "the agent signed its own receipt; no pinned settlement witness did",
        "authorized-spt-seller-bound",
    ),
    (
        "post-checkout-fulfilment-missing",
        "ap2",
        _no_fulfilment,
        "post_checkout_action_missing",
        "capture recorded, the fulfilment action is missing",
        "authorized-ap2-cart",
    ),
    (
        "authorized-two-mandates-two-rails",
        "pack",
        None,
        "",
        "a pack of two single-use mandates, one settled on each of two mandated rails",
        "",
    ),
    (
        "duplicate-member-in-record",
        "ap2",
        _duplicate_member,
        "record_malformed",
        "the case bytes carry the charge amount twice; a first-wins parser reads another amount",
        "authorized-ap2-cart",
    ),
    (
        "amount-fractional-minor-units",
        "ap2",
        _amount_fraction,
        "record_malformed",
        "0.9 of a minor unit over the ceiling, which an integer cast truncates away",
        "authorized-ap2-cart",
    ),
    (
        "amount-negative",
        "ap2",
        _amount_negative,
        "record_malformed",
        "a negative charge passes any ceiling test",
        "authorized-ap2-cart",
    ),
    (
        "executed-at-unix-seconds",
        "spt",
        _executed_epoch,
        "record_malformed",
        "executed_at in Unix seconds, after expiry, which a string comparison reads as before it",
        "authorized-spt-seller-bound",
    ),
    (
        "mandate-expiry-missing",
        "ap2",
        _expiry_missing,
        "record_malformed",
        "the terms carry no expiry and the charge runs a year later",
        "authorized-ap2-cart",
    ),
    (
        "credential-claims-multi-use",
        "spt",
        _credential_multi_use,
        "credential_widens_mandate",
        "the unsigned credential says multi-use; the signed terms say single-use",
        "authorized-spt-seller-bound",
    ),
    (
        "mandate-used-by-other-agent",
        "ap2",
        _other_agent,
        "agent_not_the_mandated_agent",
        "the mandate names one agent; another agent ran and signed the charge",
        "authorized-ap2-cart",
    ),
    (
        "sub-delegation-without-user-link",
        "vi",
        _sub_delegation,
        "agent_not_the_mandated_agent",
        "the mandated agent claims a hand-off to a second agent that the user never signed",
        "authorized-vi-credential",
    ),
    (
        "agent-proof-by-other-key",
        "ap2",
        _agent_proof_other_key,
        "agent_proof_invalid",
        "the charge names the mandated agent but is signed by another key",
        "authorized-ap2-cart",
    ),
    (
        "charge-before-mandate-issued",
        "ap2",
        _before_issue,
        "charge_before_mandate",
        "the charge ran before the user signed the mandate",
        "authorized-ap2-cart",
    ),
    (
        "charge-after-expiry-via-offset",
        "ap2",
        _expired_offset,
        "mandate_expired",
        "23:30 at -05:00 is 04:30Z, after a 00:00Z expiry a string comparison misses",
        "authorized-ap2-cart",
    ),
    (
        "charge-on-unmandated-rail",
        "ap2",
        _unmandated_rail,
        "rail_not_mandated",
        "a card-only mandate settled on another rail",
        "authorized-ap2-cart",
    ),
    (
        "single-use-token-second-settlement",
        "spt",
        _second_settlement,
        "single_use_token_replayed",
        "the witness counts the second settlement of a single-use token",
        "authorized-spt-seller-bound",
    ),
    (
        "post-checkout-requirement-dropped",
        "ap2",
        _requirement_dropped,
        "post_checkout_action_missing",
        "fulfilment deleted from the unsigned required list; the signed terms still require it",
        "authorized-ap2-cart",
    ),
    (
        "single-use-mandate-spent-on-two-rails",
        "pack",
        _spent_on_two_rails,
        "mandate_spent_twice",
        "one single-use mandate settled once on each of two rails; each witness counted use 1",
        "authorized-two-mandates-two-rails",
    ),
)

_ACCEPT_IDS = {name for name, _b, mutate, *_ in MEMBERS if mutate is None}


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
        "# Agent payment mandate vectors",
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


def _with_duplicate_amount(data: bytes, signed: int) -> bytes:
    """Write the charge amount twice: an unsigned amount first, the signed one last."""
    line = f'"amount_minor": {signed},'.encode()
    assert data.count(line) == 1
    return data.replace(line, b'"amount_minor": 999999,\n    ' + line, 1)


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest, the index and the profile map."""
    entries = []
    for name, base, mutate, reason, description, twin in MEMBERS:
        record = BASES[base]()
        if mutate is not None:
            record = mutate(record) or record
        record["case_id"] = f"vectors-agent-payment-mandate-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        if mutate is _duplicate_member:
            data = _with_duplicate_amount(data, record["execution"]["amount_minor"])
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "id": name,
            "path": f"cases/{name}",
            "files": {"case.json": _sha(data)},
            "description": description,
            "expected": {
                "decision": "accepted" if mutate is None else "rejected",
                "reason": reason if mutate is not None else ACCEPT_REASON,
            },
        }
        if mutate is not None:
            assert twin in _ACCEPT_IDS, (name, twin)
            entry["twin"] = twin
        entries.append(entry)
    digest = _sha(_json(entries))
    manifest = {
        "suite": SUITE,
        "schema": SCHEMA,
        "vectors": entries,
        "specification": SPECIFICATION,
        "verifierContract": "verifier case.json --json --policy policy.json",
        "corpusDigest": digest,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    (root / "policy.json").write_bytes(_json(POLICY))
    return manifest


if __name__ == "__main__":
    generate()
