"""Build the deterministic x402 payment binding cases.

    uv run python corpora/vectors-x402-payment-binding/gen_vectors.py

Each case is one x402 evidence record and, where one was made, a chain read of
the EIP-3009 token contract on the stated network. Each case expects TWO
verdicts: whether the record identifies one authorization, and whether the
chain read identifies the transfer that settled it. A single-verdict answer
cannot pass: case C identifies the authorization while its settlement stays
indeterminate, and case A identifies neither.

Three accepted members and eighteen twins, each one mutation away from the
accepted member it names. Every case, the manifest, the index and the profile
map are functions of this file alone. The fixtures are synthetic: no real
payer, payee, asset contract, nonce or transaction appears in them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "x402-payment-binding/v1"
SCHEMA = "x402-payment-binding-record/v1"
VERIFIED, CONTRADICTED = "verified", "contradicted"
INDETERMINATE, NOT_EVALUATED = "indeterminate", "not_evaluated"
AUTH_OK, SETTLE_OK = "authorization_identified", "transfer_identified"

WG37 = "https://github.com/x402-foundation/wg-identity/issues/37"
TSC21 = "https://github.com/x402-foundation/tsc/issues/21"
SOURCES = {
    "binding-values": f"{WG37}#issuecomment-7044162063",
    "test-pair-a-b": f"{WG37}#issuecomment-7045346617",
    "network-alias": f"{WG37}#issuecomment-7059013079",
    "case-c": f"{WG37}#issuecomment-7107019973",
    "a-and-c-distinct": f"{WG37}#issuecomment-7123441470",
    "chain-read-reasons": f"{TSC21}#issuecomment-7107032958",
    "two-verdicts": f"{TSC21}#issuecomment-7130535657",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "scope": (
        "Whether an x402 evidence record identifies one EIP-3009 authorization (network, "
        "asset contract, payer and nonce together), and whether a chain read of that "
        "contract identifies the Transfer log that settled it. The two answers are "
        "separate verdicts. Chain reads are modelled fields, never fetched."
    ),
    "upstream": {
        "eip3009": {
            "repository": "https://github.com/ethereum/ERCs",
            "path": "ERCS/erc-3009.md",
            "commit": "542e05025b63a542606124a55f86aaf85add23a7",
            "used": (
                "AuthorizationUsed(authorizer, nonce) and the optional "
                "AuthorizationCanceled(authorizer, nonce) events, authorizationState(authorizer, "
                "nonce), nonces unique to the authorizer on one contract, and "
                "transferWithAuthorization requiring block time before validBefore"
            ),
        },
        "x402": {
            "repository": "https://github.com/x402-foundation/x402",
            "commit": "211b6bd3b589af8b2fc01d2b5a41ab32fad1c0a6",
            "paths": [
                "specs/schemes/exact/scheme_exact_evm.md",
                "specs/x402-specification-v2.md",
                "python/x402/mechanisms/evm/v1/constants.py",
            ],
            "used": (
                "the exact scheme's EIP-3009 authorization fields, settlement_pending with a "
                "broadcast transaction hash, CAIP-2 network identifiers and the v1 network "
                "names mapped to chain ids"
            ),
        },
    },
    "discussion": SOURCES,
}

#: v1 network names, as x402 maps them to EVM chain ids at the pinned commit
#: (python/x402/mechanisms/evm/v1/constants.py, V1_NETWORK_CHAIN_IDS). A CAIP-2
#: identifier names its own chain; any other identifier is unknown.
V1_NETWORKS: dict[str, str] = {
    name: f"eip155:{chain}"
    for name, chain in {
        "base": 8453,
        "base-sepolia": 84532,
        "ethereum": 1,
        "polygon": 137,
        "polygon-amoy": 80002,
        "avalanche": 43114,
        "avalanche-fuji": 43113,
        "abstract": 2741,
        "abstract-testnet": 11124,
        "iotex": 4689,
        "sei": 1329,
        "sei-testnet": 1328,
        "peaq": 3338,
        "story": 1514,
        "educhain": 41923,
        "skale-base-sepolia": 324705682,
        "megaeth": 4326,
        "monad": 143,
        "monad-testnet": 10143,
        "stable": 988,
        "stable-testnet": 2201,
        "celo": 42220,
        "flare": 14,
        "hemi": 43111,
        "hemi-testnet": 743111,
    }.items()
}

PROFILE = {
    "suite": SUITE,
    "note": (
        "Maps what binds an x402 evidence record to one payment, and what a chain read "
        "must show, to the record fields this suite checks. Two verdicts per case, each "
        "in the four states of the Evidence Chain RFP: verified, contradicted, "
        "indeterminate, not_evaluated."
    ),
    "map": {
        "accepted option the buyer acted on (served form kept)": "offer.accepted",
        "authorization the buyer signed (exact scheme, EIP-3009)": "payment.authorization",
        "what binds the record: authorization one-time value or accepted option only": (
            "binding.kind"
        ),
        "authorization scope: network, asset contract, payer, nonce": "binding.authorization",
        "settlement reference: network, transaction, log index": "binding.settlement",
        "chain read of the bound network": "chain_read.network, chain_read.status",
        "the head the read was taken at, and whether it is final": "chain_read.head",
        "authorizationState(payer, nonce) at that head": "chain_read.authorization_state",
        "AuthorizationUsed, AuthorizationCanceled and Transfer logs read": "chain_read.logs",
    },
    "networkIdentifiers": {
        "rule": (
            "Kept in the record exactly as the origin served it. Compared after mapping: a "
            "CAIP-2 identifier names itself, a v1 name maps through the table below, any "
            "other identifier is unknown and leaves the comparison unresolved."
        ),
        "v1": V1_NETWORKS,
    },
    "verdicts": {
        "authorization": {
            VERIFIED: "the record identifies one authorization by its full scope",
            CONTRADICTED: "the record's binding disagrees with the authorization it carries",
            INDETERMINATE: "the record does not identify one authorization; the reason says why",
        },
        "settlement": {
            VERIFIED: "the chain read identifies the Transfer log that settled the authorization",
            CONTRADICTED: (
                "the chain read shows the authorization did not or cannot settle as the "
                "record binds it"
            ),
            INDETERMINATE: (
                "settlement cannot be decided from this read; the reason separates a read "
                "that failed from a read that found nothing yet"
            ),
            NOT_EVALUATED: "no chain read was made; an offline run records this, not a failure",
        },
    },
}

ASSET = "0x" + "a5" * 20
PAY_TO = "0x" + "b0" * 20
PAYER = "0x" + "c1" * 20
OTHER = "0x" + "f4" * 20
NONCE_1 = "0x" + "e3" * 32
NONCE_2 = "0x" + "e4" * 32
BATCH_TX = "0x" + "d2" * 32
SINGLE_TX = "0x" + "d3" * 32
OTHER_TX = "0x" + "d9" * 32
VALID_AFTER, VALID_BEFORE = "1794999000", "1795000000"
HEAD_BEFORE, HEAD_AFTER = 1794999500, 1795000100
AMOUNT = "10000"


def _offer(network: str) -> dict[str, Any]:
    return {
        "accepted": {
            "scheme": "exact",
            "network": network,
            "amount": AMOUNT,
            "asset": ASSET,
            "payTo": PAY_TO,
            "maxTimeoutSeconds": 60,
        }
    }


def _authorization(nonce: str) -> dict[str, str]:
    return {
        "from": PAYER,
        "to": PAY_TO,
        "value": AMOUNT,
        "validAfter": VALID_AFTER,
        "validBefore": VALID_BEFORE,
        "nonce": nonce,
    }


def _used(tx: str, index: int, nonce: str) -> dict[str, Any]:
    return {
        "transaction": tx,
        "log_index": index,
        "address": ASSET,
        "event": "AuthorizationUsed",
        "authorizer": PAYER,
        "nonce": nonce,
    }


def _transfer(tx: str, index: int, value: str = AMOUNT, to: str = PAY_TO) -> dict[str, Any]:
    return {
        "transaction": tx,
        "log_index": index,
        "address": ASSET,
        "event": "Transfer",
        "from": PAYER,
        "to": to,
        "value": value,
    }


def _read(nonce: str, logs: list[dict[str, Any]], used: bool = True) -> dict[str, Any]:
    return {
        "network": "eip155:8453",
        "status": "ok",
        "head": {"number": 30000000, "timestamp": HEAD_AFTER, "finalized": True},
        "authorization_state": {"authorizer": PAYER, "nonce": nonce, "used": used},
        "logs": logs,
    }


def _bound(network: str, nonce: str) -> dict[str, Any]:
    return {
        "kind": "authorization",
        "authorization": {"network": network, "asset": ASSET, "payer": PAYER, "nonce": nonce},
    }


def _batch() -> dict[str, Any]:
    """Case B: two payments, same payer, option and payTo, settled in one transaction.

    The record binds the second payment by payer and nonce and names its Transfer
    by log index.
    """
    binding = _bound("eip155:8453", NONCE_2)
    binding["settlement"] = {"network": "eip155:8453", "transaction": BATCH_TX, "log_index": 3}
    return {
        "schema": SCHEMA,
        "offer": _offer("eip155:8453"),
        "payment": {"authorization": _authorization(NONCE_2)},
        "binding": binding,
        "chain_read": _read(
            NONCE_2,
            [
                _used(BATCH_TX, 0, NONCE_1),
                _transfer(BATCH_TX, 1),
                _used(BATCH_TX, 2, NONCE_2),
                _transfer(BATCH_TX, 3),
            ],
        ),
    }


def _single(network: str) -> dict[str, Any]:
    """One payment bound by payer and nonce, settled alone in its transaction."""
    return {
        "schema": SCHEMA,
        "offer": _offer(network),
        "payment": {"authorization": _authorization(NONCE_1)},
        "binding": _bound(network, NONCE_1),
        "chain_read": _read(NONCE_1, [_used(SINGLE_TX, 5, NONCE_1), _transfer(SINGLE_TX, 6)]),
    }


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "b-batch-log-index-names-transfer": _batch,
    "c-confirmed-single-transfer": lambda: _single("eip155:8453"),
    "c-confirmed-network-served-as-base": lambda: _single("base"),
}


def _option_only(r: dict[str, Any]) -> None:
    r["payment"] = None
    r["binding"] = {"kind": "accepted_option", "time": "2026-11-20T16:00:00Z"}
    r["chain_read"]["authorization_state"] = None


def _not_used(r: dict[str, Any], timestamp: int = HEAD_BEFORE, finalized: bool = True) -> None:
    r["chain_read"]["logs"] = []
    r["chain_read"]["authorization_state"]["used"] = False
    r["chain_read"]["head"] = {"number": 29999000, "timestamp": timestamp, "finalized": finalized}


def _broadcast_hash_pending(r: dict[str, Any]) -> None:
    _not_used(r)
    r["binding"]["settlement"] = {"network": "eip155:8453", "transaction": SINGLE_TX}


def _expired(r: dict[str, Any]) -> None:
    _not_used(r, HEAD_AFTER)


def _expired_head_not_final(r: dict[str, Any]) -> None:
    _not_used(r, HEAD_AFTER, finalized=False)


def _canceled(r: dict[str, Any]) -> None:
    r["chain_read"]["logs"] = [
        {
            "transaction": OTHER_TX,
            "log_index": 0,
            "address": ASSET,
            "event": "AuthorizationCanceled",
            "authorizer": PAYER,
            "nonce": NONCE_1,
        }
    ]


def _used_event_not_read(r: dict[str, Any]) -> None:
    r["chain_read"]["logs"] = []


def _read_failed(r: dict[str, Any]) -> None:
    r["chain_read"] = {
        "network": "eip155:8453",
        "status": "failed",
        "error": "source unavailable: the RPC endpoint timed out before answering",
    }


def _no_read(r: dict[str, Any]) -> None:
    r["chain_read"] = None


def _read_other_network(r: dict[str, Any]) -> None:
    r["chain_read"]["network"] = "eip155:84532"


def _named_other_tx(r: dict[str, Any]) -> None:
    r["binding"]["settlement"]["transaction"] = OTHER_TX


def _log_index_other_payment(r: dict[str, Any]) -> None:
    r["chain_read"]["logs"][1]["value"] = "25000"
    r["binding"]["settlement"]["log_index"] = 1


def _no_log_index(r: dict[str, Any]) -> None:
    del r["binding"]["settlement"]["log_index"]


def _transfer_pays_other(r: dict[str, Any]) -> None:
    r["chain_read"]["logs"][1]["to"] = OTHER


def _unknown_network(r: dict[str, Any]) -> None:
    r["offer"]["accepted"]["network"] = "base-mainnet"
    r["binding"]["authorization"]["network"] = "base-mainnet"


def _binding_other_nonce(r: dict[str, Any]) -> None:
    r["binding"]["authorization"]["nonce"] = NONCE_2


def _binding_without_asset(r: dict[str, Any]) -> None:
    del r["binding"]["authorization"]["asset"]


def _v(state: str, reason: str) -> dict[str, str]:
    return {"state": state, "reason": reason}


OK_AUTH = _v(VERIFIED, AUTH_OK)
UNIDENTIFIED = _v(INDETERMINATE, "authorization_not_identified")

Member = tuple[
    str, str, Callable[[dict[str, Any]], None] | None, dict[str, str], dict[str, str], str, str
]

# (id, twin, mutation or None for an accepted member, authorization verdict,
#  settlement verdict, description, rationale)
MEMBERS: tuple[Member, ...] = (
    ("b-batch-log-index-names-transfer", "", None, OK_AUTH, _v(VERIFIED, SETTLE_OK),
     "case B: two payments in one transaction; payer and nonce identify the authorization, "
     "the log index names its Transfer",
     "TKCollective's record B: payer and nonce identify which authorization was used once "
     "matched to AuthorizationUsed on the stated network, and the log index beside the "
     "transaction hash names the Transfer in the batch."),
    ("c-confirmed-single-transfer", "", None, OK_AUTH, _v(VERIFIED, SETTLE_OK),
     "case C after confirmation: AuthorizationUsed read, one Transfer in the transaction, "
     "no log index needed",
     "The log index is needed only where the transaction carries more than one transfer, "
     "as XFuel-Lab's revised wording says; with one Transfer the hash and the event suffice."),
    ("c-confirmed-network-served-as-base", "", None, OK_AUTH, _v(VERIFIED, SETTLE_OK),
     "network alias pair: the same record with the network served as base",
     "TKCollective's alias test: the record keeps base as served; mapped through x402's v1 "
     "table it names eip155:8453, so the answer equals the eip155:8453 twin's."),
    ("a-option-only-two-payments-fit", "b-batch-log-index-names-transfer", _option_only,
     _v(INDETERMINATE, "option_fits_more_than_one_payment"), UNIDENTIFIED,
     "case A: bound by the accepted option and time only; two payments in the batch fit",
     "TKCollective's record A: the option and time fit both payments, so the record "
     "identifies neither authorization nor transfer. Both payments settled, and that does "
     "not make settlement verified: the record names no transfer."),
    ("a-option-only-one-payment-fits", "c-confirmed-single-transfer", _option_only,
     _v(INDETERMINATE, "bound_by_accepted_option_only"), UNIDENTIFIED,
     "accepted option only; exactly one payment in the read fits",
     "Decided here: the revised wording says unresolved where more than one payment fits "
     "and is silent where one does. A read covers some transactions, not every payment "
     "the option could match, so one fit in the read does not identify the authorization."),
    ("b-batch-without-log-index", "b-batch-log-index-names-transfer", _no_log_index,
     OK_AUTH, _v(INDETERMINATE, "transaction_carries_more_than_one_transfer"),
     "case B without its log index: the authorization is identified, its Transfer is not",
     "The transaction carries two Transfer logs of the asset. EIP-3009 fixes no order between "
     "AuthorizationUsed and Transfer (the order is in its reference implementation only), so "
     "a verifier does not pair them by position; without the log index the transfer stays "
     "open."),
    ("b-log-index-names-other-payment", "b-batch-log-index-names-transfer",
     _log_index_other_payment, OK_AUTH,
     _v(CONTRADICTED, "transfer_not_authorization_terms"),
     "the log index names the batch's other Transfer, which pays a different amount",
     "The named log is a Transfer of the asset, but not of this authorization's value."),
    ("b-named-transaction-did-not-use-authorization", "b-batch-log-index-names-transfer",
     _named_other_tx, OK_AUTH, _v(CONTRADICTED, "transaction_did_not_use_authorization"),
     "the record names a transaction; AuthorizationUsed for its nonce is in another one",
     "The chain read places this authorization's use in another transaction."),
    ("c-authorization-not-yet-used", "c-confirmed-single-transfer", _not_used, OK_AUTH,
     _v(INDETERMINATE, "authorization_not_yet_used"),
     "case C: authorization identified; no AuthorizationUsed yet and validBefore not reached",
     "XFuel-Lab's record C: bound to one authorization with settlement unconfirmed, not "
     "contradicted. A verifier that answers unresolved for both A and C loses the "
     "authorization C identifies."),
    ("c-settlement-pending-broadcast-hash", "c-confirmed-single-transfer",
     _broadcast_hash_pending, OK_AUTH, _v(INDETERMINATE, "authorization_not_yet_used"),
     "case C holding the facilitator's broadcast hash (settlement_pending)",
     "x402 v2 lets a facilitator return settlement_pending with the broadcast hash. A hash "
     "is not a settlement: the read shows the authorization unused before validBefore."),
    ("c-valid-before-passed", "c-confirmed-single-transfer", _expired, OK_AUTH,
     _v(CONTRADICTED, "authorization_expired_unused"),
     "twin of C: unused at a finalized head whose time is past validBefore",
     "Decided here, from EIP-3009: transferWithAuthorization requires block time before "
     "validBefore, so once a finalized head is past it with the authorization unused, the "
     "authorization can never settle. Never settled, not pending. The head's time is the "
     "clock, not the verifier's."),
    ("c-valid-before-passed-head-not-finalized", "c-confirmed-single-transfer",
     _expired_head_not_final, OK_AUTH, _v(INDETERMINATE, "authorization_not_yet_used"),
     "twin of C: past validBefore at the head, but the head is not finalized",
     "A head that is not final can be replaced by blocks timed before validBefore that "
     "carry the authorization, so the answer stays pending."),
    ("c-authorization-canceled", "c-confirmed-single-transfer", _canceled, OK_AUTH,
     _v(CONTRADICTED, "authorization_canceled"),
     "the read shows AuthorizationCanceled for the payer and nonce",
     "EIP-3009's optional cancelAuthorization marks the nonce used without a transfer."),
    ("c-authorization-used-event-not-read", "c-confirmed-single-transfer",
     _used_event_not_read, OK_AUTH, _v(INDETERMINATE, "authorization_use_not_read"),
     "authorizationState is true, but the read carries no AuthorizationUsed log",
     "The nonce is spent somewhere; without the event the transaction and its Transfer are "
     "unknown."),
    ("c-chain-read-failed", "c-confirmed-single-transfer", _read_failed, OK_AUTH,
     _v(INDETERMINATE, "chain_read_failed"),
     "read-failed half of the pair: the source was unavailable",
     "XFuel-Lab asked to keep the reason: source unavailable here, not found in "
     "c-authorization-not-yet-used. Both are indeterminate and neither counts against the "
     "record."),
    ("c-no-chain-read", "c-confirmed-single-transfer", _no_read, OK_AUTH,
     _v(NOT_EVALUATED, "no_chain_read"),
     "an offline run: no chain read was made",
     "The authorization is identified from the record alone; settlement was not evaluated, "
     "which is visible and is not a failure."),
    ("c-chain-read-other-network", "c-confirmed-single-transfer", _read_other_network,
     OK_AUTH, _v(INDETERMINATE, "chain_read_not_bound_network"),
     "the read is of eip155:84532; the record is bound to eip155:8453",
     "A read of another chain says nothing about this authorization."),
    ("c-transfer-pays-other-address", "c-confirmed-single-transfer", _transfer_pays_other,
     OK_AUTH, _v(CONTRADICTED, "transfer_not_authorization_terms"),
     "the single Transfer after AuthorizationUsed credits another address than payTo",
     "The transfer the read identifies is not this authorization's terms."),
    ("network-identifier-unknown", "c-confirmed-single-transfer", _unknown_network,
     _v(INDETERMINATE, "binding_network_unknown"), UNIDENTIFIED,
     "the network is served as base-mainnet, which no mapping names",
     "TKCollective's rule: with an unknown identifier the network comparison stays "
     "unresolved, so the authorization's scope is not established."),
    ("binding-nonce-not-payment-nonce", "c-confirmed-single-transfer", _binding_other_nonce,
     _v(CONTRADICTED, "binding_not_record_authorization"), UNIDENTIFIED,
     "the binding names another nonce than the authorization the record carries",
     "The record contradicts itself about which authorization binds it."),
    ("binding-without-asset", "c-confirmed-single-transfer", _binding_without_asset,
     _v(INDETERMINATE, "authorization_scope_incomplete"), UNIDENTIFIED,
     "the binding names payer and nonce but no asset contract",
     "An EIP-3009 nonce is unique to its authorizer on one contract, so payer and nonce "
     "without the asset and network do not identify one authorization."),
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
        "# x402 payment binding vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Suite: `{SUITE}`. Record schema: `{SCHEMA}`.",
        "",
        f"Corpus digest: `{digest}`",
        "",
        "| id | authorization | settlement | twin | case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        a, s = e["expected"]["authorization"], e["expected"]["settlement"]
        lines.append(
            f"| `{e['id']}` | {a['state']} `{a['reason']}` | {s['state']} `{s['reason']}` | "
            f"{e.get('twin', '')} | {e['description']} |"
        )
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest, the index and the profile map."""
    entries = []
    for name, twin, mutate, auth, settle, description, rationale in MEMBERS:
        record = copy.deepcopy(BASES[name if mutate is None else twin]())
        if mutate is not None:
            mutate(record)
        record["case_id"] = f"vectors-x402-payment-binding-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "id": name,
            "path": f"cases/{name}",
            "files": {"case.json": _sha(data)},
            "description": description,
            "rationale": rationale,
            "expected": {"authorization": auth, "settlement": settle},
        }
        if mutate is not None:
            assert twin in _ACCEPT_IDS, (name, twin)
            entry["twin"] = twin
        entries.append(entry)
    digest = _sha(_json(entries))
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "schema": SCHEMA,
        "vectors": entries,
        "specification": SPECIFICATION,
        "verifierContract": "verifier case.json --json",
        "corpusDigest": digest,
    }
    counts: dict[str, dict[str, int]] = {}
    for verdict in ("authorization", "settlement"):
        states = [entry["expected"][verdict]["state"] for entry in entries]
        counts[verdict] = {state: states.count(state) for state in sorted(set(states))}
    manifest["counts"] = counts
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    (root / "profile.json").write_bytes(_json(PROFILE))
    return manifest


if __name__ == "__main__":
    generate()
