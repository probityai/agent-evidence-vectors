"""Build the deterministic Agent payment mandate cases.

    uv run python vectors-agent-payment-mandate/gen_vectors.py

Four accepted members (one per scheme plus the exact-limit boundary) and eleven
rejected twins, one per rule, each one mutation away from an accepted member.
Every case, the manifest, the index and the profile map are functions of this
file alone. The fixtures are synthetic.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "agent-payment-mandate/v1"
SCHEMA = "agent-payment-mandate-record/v1"
ACCEPT_REASON = "mandate_chain_holds"


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
    "ap2-cart-mandate": ("cart", "merchant-a.example", "USD", 12900),
    "mastercard-verifiable-intent-credential": ("intent", "merchant-b.example", "EUR", 4500),
    "stripe-shared-payment-token": ("seller-bound-token", "merchant-c.example", "USD", 2500),
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
            "what ran": "execution",
        },
        "mastercard-verifiable-intent-credential": {
            "the delegated intent": "mandate.terms",
            "credential bound to the intent": "credential.mandate_digest",
            "single use": "credential.single_use",
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
        },
    },
}


def _seal(r: dict[str, Any]) -> dict[str, Any]:
    """Recompute every digest a conformant record carries from its own terms."""
    r["mandate"]["digest"] = _digest(r["mandate"]["terms"])
    r["mandate"]["signature"] = {
        "alg": "ed25519",
        "key_id": "issuer-key-1",
        "value_sha256": _sha(r["mandate"]["digest"].encode()),
    }
    r["credential"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["execution_digest"] = _digest(r["execution"])
    return r


def _base(scheme: str, amount: int | None = None) -> dict[str, Any]:
    kind, merchant, currency, limit = _SCHEME_TERMS[scheme]
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
                "expires_at": "2026-11-30T00:00:00Z",
            }
        },
        "credential": {"token_id": "tok-0001", "single_use": True, "consumed_token_ids": []},
        "execution": {
            "executed_at": "2026-11-02T10:15:00Z",
            "amount_minor": spend,
            "currency": currency,
            "merchant": merchant,
            "token_id": "tok-0001",
        },
        "receipt": {"receipt_id": "rcpt-0001"},
        "post_checkout": {
            "required": ["capture", "fulfilment"],
            "recorded": ["capture", "fulfilment"],
        },
    }
    return _seal(r)


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "ap2": lambda: _base("ap2-cart-mandate"),
    "vi": lambda: _base("mastercard-verifiable-intent-credential"),
    "spt": lambda: _base("stripe-shared-payment-token"),
    "limit": lambda: _base("ap2-cart-mandate", amount=12900),
}


def _unsigned(r: dict[str, Any]) -> None:
    r["mandate"]["signature"] = None


def _edited_terms(r: dict[str, Any]) -> None:
    r["mandate"]["terms"]["max_amount_minor"] = 999999


def _unbound(r: dict[str, Any]) -> None:
    r["credential"]["mandate_digest"] = _sha(b"another mandate")


def _expired(r: dict[str, Any]) -> None:
    r["execution"]["executed_at"] = "2026-12-01T00:00:01Z"
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _over_limit(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] = r["mandate"]["terms"]["max_amount_minor"] + 1
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _currency(r: dict[str, Any]) -> None:
    r["execution"]["currency"] = "GBP"
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _merchant(r: dict[str, Any]) -> None:
    r["execution"]["merchant"] = "other-merchant.example"
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _other_token(r: dict[str, Any]) -> None:
    r["execution"]["token_id"] = "tok-9999"
    r["receipt"]["execution_digest"] = _digest(r["execution"])


def _replayed(r: dict[str, Any]) -> None:
    r["credential"]["consumed_token_ids"] = ["tok-0001"]


def _receipt_stale(r: dict[str, Any]) -> None:
    r["execution"]["amount_minor"] -= 100


def _no_fulfilment(r: dict[str, Any]) -> None:
    r["post_checkout"]["recorded"] = ["capture"]


# (id, base, mutation or None for an accepted member, refusal code, description, twin)
MEMBERS: tuple[tuple[str, str, Callable[[dict[str, Any]], None] | None, str, str, str], ...] = (
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
        "post-checkout-fulfilment-missing",
        "ap2",
        _no_fulfilment,
        "post_checkout_action_missing",
        "capture recorded, the fulfilment action is missing",
        "authorized-ap2-cart",
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


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest, the index and the profile map."""
    entries = []
    for name, base, mutate, reason, description, twin in MEMBERS:
        record = BASES[base]()
        if mutate is not None:
            mutate(record)
        record["case_id"] = f"vectors-agent-payment-mandate-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
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
        "verifierContract": "verifier case.json --json",
        "corpusDigest": digest,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    return manifest


if __name__ == "__main__":
    generate()
