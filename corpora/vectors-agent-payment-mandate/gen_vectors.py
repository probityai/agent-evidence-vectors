"""Build the deterministic Agent payment mandate cases.

    uv run python vectors-agent-payment-mandate/gen_vectors.py

Accepted members for each card-side scheme and for x402 exact payments on EVM, and
rejected twins, each one mutation away from an accepted member. Every case, the
manifest, the index and the profile map are functions of this file alone. The
fixtures are synthetic. The x402 members carry real secp256k1 signatures made with
deterministic test-only keys derived below; no key here holds or ever held value.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import evmsig  # noqa: E402
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
        "Receipt-side fields only. The three card-side schemes are named by concept; no "
        "upstream field name is asserted for them, and none of their texts is vendored. "
        "The x402 members carry the facilitator request (paymentPayload and "
        "paymentRequirements) in x402 v2 field names and verify its EIP-712 signature."
    ),
    "schemes": [
        "ap2-cart-mandate",
        "mastercard-verifiable-intent-credential",
        "stripe-shared-payment-token",
        "x402-exact-evm-eip3009",
    ],
    "x402": {
        "source": "https://github.com/x402-foundation/x402",
        "commit": "e35bf8846f3e40f584f7235ea96c0841cb597b27",
        "read": [
            "specs/x402-specification-v2.md",
            "specs/schemes/exact/scheme_exact_evm.md",
        ],
        "transfer": "EIP-3009 transferWithAuthorization, settled when validAfter < t < validBefore",
    },
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
        "x402-exact-evm-eip3009": {
            "what the resource server required": (
                "credential.facilitator_request.paymentRequirements"
            ),
            "what the agent's wallet signed": (
                "credential.facilitator_request.paymentPayload.payload.authorization"
            ),
            "who signed it": "recovered from paymentPayload.payload.signature, never read",
            "which wallet the user let the agent pay from": "mandate.terms.agent_payer",
            "the network, token and payee the user allowed": (
                "mandate.terms.network, mandate.terms.currency, mandate.terms.merchant"
            ),
            "what moved on the ledger": "execution.transfer, execution.authorization_used",
            "nonces the token contract had consumed before": "execution.nonces_used_before",
            "what the facilitator reported": "receipt.settlement_response",
        },
        "receipt": {
            "what the agent did after checkout": "post_checkout.recorded",
            "binding of mandate and execution": "receipt",
        },
    },
}

X402_SCHEME = "x402-exact-evm-eip3009"
X402_NETWORK = "eip155:84532"
X402_OTHER_NETWORK = "eip155:8453"
# The USDC address on Base Sepolia that the x402 v2 specification's own examples use.
X402_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
X402_OTHER_TOKEN = evmsig.checksum(
    evmsig.keccak256(b"agent-evidence-vectors synthetic token")[12:].hex()
)
X402_SIGNED_AT = 1793614500  # 2026-11-02T10:15:00Z
X402_AFTER_MANDATE = 1796000400  # 2026-11-30T01:00:00Z, an hour after the mandate expires


def _test_key(label: str) -> int:
    """A deterministic secp256k1 key for these fixtures only."""
    seed = hashlib.sha256(b"agent-evidence-vectors x402 test-only key: " + label.encode())
    return int.from_bytes(seed.digest(), "big") % (evmsig.N - 1) + 1


X402_KEYS = {label: _test_key(label) for label in ("agent", "payee", "attacker", "other-wallet")}
X402_ADDRESS = {label: evmsig.address_of_key(key) for label, key in X402_KEYS.items()}


def _nonce(label: str) -> str:
    return "0x" + evmsig.keccak256(b"agent-evidence-vectors x402 nonce: " + label.encode()).hex()


def _request(r: dict[str, Any]) -> dict[str, Any]:
    request: dict[str, Any] = r["credential"]["facilitator_request"]
    return request


def _x402_sign(
    r: dict[str, Any], key: str = "agent", network: str | None = None, asset: str | None = None
) -> None:
    """Sign the authorization under the token domain the client chose (its `accepted`)."""
    payload = _request(r)["paymentPayload"]
    accepted = payload["accepted"]
    digest = evmsig.eip3009_digest(
        payload["payload"]["authorization"],
        network or accepted["network"],
        asset or accepted["asset"],
        accepted["extra"]["name"],
        accepted["extra"]["version"],
    )
    payload["payload"]["signature"] = "0x" + evmsig.sign(X402_KEYS[key], digest).hex()


def _x402_settle(r: dict[str, Any]) -> None:
    """The ledger read: the transfer and the nonce the token contract consumed."""
    payload = _request(r)["paymentPayload"]
    auth = payload["payload"]["authorization"]
    signature = bytes.fromhex(payload["payload"]["signature"][2:])
    r["execution"].update(
        {
            "network": payload["accepted"]["network"],
            "asset": payload["accepted"]["asset"],
            "transaction": "0x" + evmsig.keccak256(b"synthetic transaction: " + signature).hex(),
            "transfer": {"from": auth["from"], "to": auth["to"], "value": auth["value"]},
            "authorization_used": {"authorizer": auth["from"], "nonce": auth["nonce"]},
        }
    )


def _x402_respond(r: dict[str, Any]) -> None:
    """The facilitator's SettlementResponse for the settled transfer."""
    e = r["execution"]
    r["receipt"]["settlement_response"] = {
        "success": True,
        "transaction": e["transaction"],
        "network": e["network"],
        "payer": e["transfer"]["from"],
        "amount": e["transfer"]["value"],
    }


def _x402_reissue(r: dict[str, Any], key: str = "agent", **domain: str) -> dict[str, Any]:
    """Re-sign, re-settle, re-report and re-seal after a mutation upstream of the signature."""
    _x402_sign(r, key, **domain)
    _x402_settle(r)
    _x402_respond(r)
    return _seal(r)


def _x402_base(
    amount: str = "10000", signed_at: int = X402_SIGNED_AT, settle_after: int = 5
) -> dict[str, Any]:
    requirement = {
        "scheme": "exact",
        "network": X402_NETWORK,
        "amount": amount,
        "asset": X402_USDC,
        "payTo": X402_ADDRESS["payee"],
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USDC", "version": "2"},
    }
    r: dict[str, Any] = {
        "schema": SCHEMA,
        "scheme": X402_SCHEME,
        "mandate": {
            "terms": {
                "kind": "x402-exact",
                "issuer": "did:example:issuer-1",
                "agent_payer": X402_ADDRESS["agent"],
                "max_amount_minor": 50000,
                "currency": X402_USDC,
                "merchant": X402_ADDRESS["payee"],
                "network": X402_NETWORK,
                "expires_at": "2026-11-30T00:00:00Z",
            }
        },
        "credential": {
            "facilitator_request": {
                "x402Version": 2,
                "paymentPayload": {
                    "x402Version": 2,
                    "resource": {"url": "https://api.example.com/premium-data"},
                    "accepted": copy.deepcopy(requirement),
                    "payload": {
                        "signature": "",
                        "authorization": {
                            "from": X402_ADDRESS["agent"],
                            "to": X402_ADDRESS["payee"],
                            "value": amount,
                            "validAfter": str(signed_at - 600),
                            "validBefore": str(signed_at + 60),
                            "nonce": _nonce("first"),
                        },
                    },
                },
                "paymentRequirements": requirement,
            }
        },
        "execution": {"block_timestamp": signed_at + settle_after, "nonces_used_before": []},
        "receipt": {"receipt_id": "rcpt-x402-0001"},
    }
    return _x402_reissue(r)


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
    "x402": _x402_base,
    "x402-ceiling": lambda: _x402_base(amount="50000"),
    "x402-last-second": lambda: _x402_base(settle_after=59),
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


def _authorization(r: dict[str, Any]) -> dict[str, Any]:
    auth: dict[str, Any] = _request(r)["paymentPayload"]["payload"]["authorization"]
    return auth


def _x_over_ceiling(r: dict[str, Any]) -> None:
    request = _request(r)
    for terms in (request["paymentRequirements"], request["paymentPayload"]["accepted"]):
        terms["amount"] = "50001"
    _authorization(r)["value"] = "50001"
    _x402_reissue(r)


def _x_other_asset(r: dict[str, Any]) -> None:
    _request(r)["paymentPayload"]["accepted"]["asset"] = X402_OTHER_TOKEN
    _x402_reissue(r)


def _x_unmandated_payee(r: dict[str, Any]) -> None:
    request = _request(r)
    for terms in (request["paymentRequirements"], request["paymentPayload"]["accepted"]):
        terms["payTo"] = X402_ADDRESS["attacker"]
    _authorization(r)["to"] = X402_ADDRESS["attacker"]
    _x402_reissue(r)


def _x_pays_other(r: dict[str, Any]) -> None:
    _authorization(r)["to"] = X402_ADDRESS["attacker"]
    _x402_reissue(r)


def _x_other_network(r: dict[str, Any]) -> None:
    _request(r)["paymentPayload"]["accepted"]["network"] = X402_OTHER_NETWORK
    _x402_reissue(r)


def _x_value_over_required(r: dict[str, Any]) -> None:
    _authorization(r)["value"] = "10001"
    _x402_reissue(r)


def _x_settled_at(field: str) -> Callable[[dict[str, Any]], None]:
    def mutate(r: dict[str, Any]) -> None:
        r["execution"]["block_timestamp"] = int(_authorization(r)[field])
        _seal(r)

    return mutate


def _x_after_mandate(r: dict[str, Any]) -> None:
    auth = _authorization(r)
    auth["validAfter"] = str(X402_AFTER_MANDATE - 600)
    auth["validBefore"] = str(X402_AFTER_MANDATE + 60)
    r["execution"]["block_timestamp"] = X402_AFTER_MANDATE + 5
    _x402_reissue(r)


def _x_high_s(r: dict[str, Any]) -> None:
    payload = _request(r)["paymentPayload"]["payload"]
    raw = bytes.fromhex(payload["signature"][2:])
    s_value = evmsig.N - int.from_bytes(raw[32:64], "big")
    flipped = raw[:32] + s_value.to_bytes(32, "big") + bytes([55 - raw[64]])
    payload["signature"] = "0x" + flipped.hex()
    _x402_settle(r)
    _x402_respond(r)
    _seal(r)


def _x_other_key(r: dict[str, Any]) -> None:
    _x402_reissue(r, key="attacker")


def _x_selector(r: dict[str, Any]) -> None:
    _request(r)["paymentPayload"]["payload"]["signer"] = X402_ADDRESS["attacker"]
    _x402_reissue(r, key="attacker")


def _x_other_chain(r: dict[str, Any]) -> None:
    _x402_reissue(r, network=X402_OTHER_NETWORK)


def _x_other_wallet(r: dict[str, Any]) -> None:
    _authorization(r)["from"] = X402_ADDRESS["other-wallet"]
    _x402_reissue(r, key="other-wallet")


def _x_other_nonce(r: dict[str, Any]) -> None:
    r["execution"]["authorization_used"]["nonce"] = _nonce("second")
    _x402_respond(r)
    _seal(r)


def _x_transfer_differs(r: dict[str, Any]) -> None:
    r["execution"]["transfer"]["value"] = "1000000"
    _x402_respond(r)
    _seal(r)


def _x_nonce_used(r: dict[str, Any]) -> None:
    r["execution"]["nonces_used_before"] = [_authorization(r)["nonce"]]
    _seal(r)


def _x_response_other_payer(r: dict[str, Any]) -> None:
    r["receipt"]["settlement_response"]["payer"] = X402_ADDRESS["attacker"]
    _seal(r)


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
    ("x402-exact-evm-settled-once", "x402", None, "",
     "x402 exact on EVM: wallet the mandate names signs the required payment, settled once", ""),
    ("x402-exact-evm-at-mandate-ceiling", "x402-ceiling", None, "",
     "x402 required amount equal to the mandate ceiling is inside the mandate", ""),
    ("x402-settled-last-valid-second", "x402-last-second", None, "",
     "settled one second before validBefore, inside the EIP-3009 window", ""),
    ("x402-requirement-over-mandate-ceiling", "x402-ceiling", _x_over_ceiling,
     "amount_over_limit", "server requires one unit over the mandate ceiling and the agent pays it",
     "x402-exact-evm-at-mandate-ceiling"),
    ("x402-paid-in-other-asset", "x402", _x_other_asset, "currency_mismatch",
     "payment signed for a token other than the required asset", "x402-exact-evm-settled-once"),
    ("x402-requirement-pays-unmandated-payee", "x402", _x_unmandated_payee, "merchant_mismatch",
     "server requires payment to an address the mandate does not name",
     "x402-exact-evm-settled-once"),
    ("x402-authorization-pays-other-address", "x402", _x_pays_other, "merchant_mismatch",
     "signed authorization pays an address other than payTo", "x402-exact-evm-settled-once"),
    ("x402-accepted-other-network", "x402", _x_other_network, "network_mismatch",
     "payment built and signed for a network other than the required one",
     "x402-exact-evm-settled-once"),
    ("x402-value-over-required-amount", "x402", _x_value_over_required, "amount_not_offer_amount",
     "authorization one unit over the exact required amount, under the mandate ceiling",
     "x402-exact-evm-settled-once"),
    ("x402-settled-at-valid-before", "x402-last-second", _x_settled_at("validBefore"),
     "authorization_outside_validity_window", "settled at validBefore, which EIP-3009 excludes",
     "x402-settled-last-valid-second"),
    ("x402-settled-at-valid-after", "x402", _x_settled_at("validAfter"),
     "authorization_outside_validity_window", "settled at validAfter, which EIP-3009 excludes",
     "x402-exact-evm-settled-once"),
    ("x402-settled-after-mandate-expiry", "x402", _x_after_mandate, "mandate_expired",
     "authorization valid on its own but settled after the mandate expired",
     "x402-exact-evm-settled-once"),
    ("x402-signature-high-s", "x402", _x_high_s, "signature_not_canonical",
     "the same signature with s above n/2, which recovers to the payer", "x402-exact-evm-settled-once"),
    ("x402-signed-by-other-key", "x402", _x_other_key, "payer_not_authorization_signer",
     "authorization from the agent wallet, signed by another key", "x402-exact-evm-settled-once"),
    ("x402-verifying-key-from-unsigned-selector", "x402", _x_selector,
     "payer_not_authorization_signer",
     "another key signs and an unsigned payload member names that key as the signer",
     "x402-exact-evm-settled-once"),
    ("x402-signature-from-other-chain", "x402", _x_other_chain, "payer_not_authorization_signer",
     "authorization signed under another chain's token domain, presented on this one",
     "x402-exact-evm-settled-once"),
    ("x402-payer-not-the-mandated-agent", "x402", _x_other_wallet, "payer_not_mandated_agent",
     "a validly signed payment from a wallet the mandate does not name",
     "x402-exact-evm-settled-once"),
    ("x402-settlement-consumed-other-nonce", "x402", _x_other_nonce,
     "token_not_the_executed_token", "the ledger consumed another nonce than the one signed",
     "x402-exact-evm-settled-once"),
    ("x402-settled-transfer-differs", "x402", _x_transfer_differs,
     "settlement_not_the_authorization", "the ledger transfer moved another value than was signed",
     "x402-exact-evm-settled-once"),
    ("x402-nonce-already-used", "x402", _x_nonce_used, "single_use_token_replayed",
     "the authorization's nonce was consumed before this settlement", "x402-exact-evm-settled-once"),
    ("x402-settlement-response-other-payer", "x402", _x_response_other_payer,
     "receipt_not_bound_to_execution", "the facilitator's response names a payer other than the signer",
     "x402-exact-evm-settled-once"),
)  # fmt: skip

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
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    return manifest


if __name__ == "__main__":
    generate()
