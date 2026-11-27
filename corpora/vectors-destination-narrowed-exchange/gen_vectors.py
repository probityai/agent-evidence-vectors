"""Build the destination-narrowed-exchange cases byte-identically.

Every case is one chain of signed statements: the issuer's delegated token, an optional
revocation, then one exchange and one presentation per destination. Each refusal is an
accepted chain with one edit, re-sealed so that every check before the one it names
still passes. Keys are derived from public seeds below: every member is synthetic, and
the keys sign nothing outside this corpus.

The rules come from public standards text only: RFC 8693 (token exchange: ``audience``,
``resource``, ``actor_token`` and the ``act`` claim), RFC 9449 (``cnf.jkt`` holder
binding), RFC 7638 (the key thumbprint), RFC 7519 (``exp``), RFC 6749 section 3.3
(``scope``), RFC 6750 section 2 and RFC 9700 section 4.3.2 (tokens in request
parameters).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent


def _load_digest() -> Any:
    """The preimage lives in digest.py beside this file, loaded by path (see the
    actor-marker-survival generator for why by path)."""
    spec = importlib.util.spec_from_file_location("dest_exchange_digest", ROOT / "digest.py")
    if spec is None or spec.loader is None:
        raise SystemExit("FAIL: digest.py beside this generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_DIGEST = _load_digest()
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import actormarker  # noqa: E402
from agent_evidence_vectors import destexchange as reader  # noqa: E402

SUITE = reader.SUITE
U = "user:alice@example.com"
T0 = 1795359600  # 2026-11-21T15:00:00Z
LIFETIME = 300
ISSUER = "idp.example"
HOLDER = "agent:researcher"
PLANNER = "agent:planner"
EXCHANGER = "exchange:internal"
WRITERS = {
    ISSUER: "issuer",
    EXCHANGER: "exchanger",
    "exchange:other": "exchanger",
    "verifier:payroll": "destination",
    "verifier:calendar": "destination",
    "verifier:billing": "destination",
    "agent:intruder": "exchanger",
}
DESTINATIONS = {
    "calendar": {"verifier": "verifier:calendar"},
    "payroll": {"verifier": "verifier:payroll"},
}
ENTITLEMENTS = {
    "billing": "billing:read billing:pay",
    "calendar": "calendar:read calendar:write",
    "payroll": "payroll:read payroll:write payroll:approve",
}
DELEGATED_SCOPE = "payroll:read payroll:write calendar:read billing:read"
SOURCES = {
    "rfc6750": {"title": "RFC 6750", "url": "https://www.rfc-editor.org/rfc/rfc6750"},
    "rfc7519": {"title": "RFC 7519", "url": "https://www.rfc-editor.org/rfc/rfc7519"},
    "rfc7638": {"title": "RFC 7638", "url": "https://www.rfc-editor.org/rfc/rfc7638"},
    "rfc8693": {"title": "RFC 8693", "url": "https://www.rfc-editor.org/rfc/rfc8693"},
    "rfc9449": {"title": "RFC 9449", "url": "https://www.rfc-editor.org/rfc/rfc9449"},
}
#: One sentence per rule, quoted from the source (whitespace normalised).
ANCHORS = {
    "audience": (
        "rfc8693",
        "2.1",
        "The logical name of the target service where the client intends to use the "
        "requested security token.",
    ),
    "nesting": (
        "rfc8693",
        "4.1",
        'The outermost "act" claim represents the current actor while nested "act" '
        "claims represent prior actors. The least recent actor is the most deeply nested.",
    ),
    "aud": (
        "rfc7519",
        "4.1.3",
        "If the principal processing the claim does not identify itself with a value in "
        'the "aud" claim when this claim is present, then the JWT MUST be rejected.',
    ),
    "exp": (
        "rfc7519",
        "4.1.4",
        'The "exp" (expiration time) claim identifies the expiration time on or after '
        "which the JWT MUST NOT be accepted for processing.",
    ),
    "jkt": (
        "rfc9449",
        "6.1",
        "the value of the jkt member MUST be the base64url encoding (as defined in "
        "[RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP "
        "public key (in JWK format) to which the access token is bound.",
    ),
    "uri": (
        "rfc6750",
        "2.3",
        "Because of the security weaknesses associated with the URI method (see Section "
        "5), including the high likelihood that the URL containing the access token will "
        "be logged, it SHOULD NOT be used unless it is impossible to transport the access "
        'token in the "Authorization" request header field or the HTTP request '
        "entity-body.",
    ),
    "scope-narrow": (
        "rfc8693",
        "2.1",
        "A list of space-delimited, case-sensitive strings, as defined in Section 3.3 of "
        "[RFC6749], that allow the client to specify the desired scope of the requested "
        "security token in the context of the service or resource where the token will "
        "be used.",
    ),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(offset: int) -> str:
    return actormarker.datetime.fromtimestamp(T0 + offset, actormarker.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def key(name: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"destination-narrowed-exchange/v1 test key " + name.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public(name: str) -> str:
    raw = key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return reader.b64url(raw)


def jwk(name: str) -> dict[str, str]:
    return {"crv": "Ed25519", "kty": "OKP", "x": public(name)}


def trust() -> dict[str, Any]:
    return {
        "contractId": reader.CONTRACT_ID,
        "destinations": DESTINATIONS,
        "maxDelegatedLifetimeSeconds": LIFETIME,
        "writers": {n: {"key": public(n), "role": r} for n, r in sorted(WRITERS.items())},
    }


def rfc8693(subject: str, actors: tuple[str, ...], **extra: Any) -> dict[str, Any]:
    token = actormarker.encode("rfc8693", (subject, actors))
    token["claims"].update(extra)
    return token


# Chain building ----------------------------------------------------------------------------

Spec = dict[str, Any]


def exchange(destination: str, **kw: Any) -> Spec:
    """One exchange-and-presentation spec. Keyword edits replace what a correct
    exchanger and verifier would do."""
    return {"destination": destination, **kw}


def build(
    exchanges: list[Spec],
    *,
    chain: tuple[str, ...] = (PLANNER, HOLDER),
    lifetime: int = LIFETIME,
    bound: bool = True,
    revoke_at: int | None = None,
    revoke_jti: str = "dt-1",
) -> list[dict[str, Any]]:
    """Unsealed statement entries: origin, an optional revocation, then each exchange
    followed by its presentation."""
    delegated_claims: dict[str, Any] = {
        "aud": [EXCHANGER],
        "exp": T0 + lifetime,
        "iat": T0,
        "jti": "dt-1",
        "scope": DELEGATED_SCOPE,
    }
    if bound:
        delegated_claims["cnf"] = {"jkt": reader.thumbprint(jwk(HOLDER))}
    origin = {
        "entitlements": ENTITLEMENTS,
        "kind": "origin",
        "sent": {
            "at": at(0),
            "protocol": "rfc8693",
            "to": HOLDER,
            "token": rfc8693(U, chain, **delegated_claims),
        },
        "writer": ISSUER,
    }
    entries: list[dict[str, Any]] = [{"statement": origin}]
    clock = 60
    for spec in exchanges:
        entries.extend(_pair(origin, spec, clock, chain))
        clock += 30
    if revoke_at is not None:
        # The revocation goes where its time puts it, so the statements stay in time order.
        revocation = {
            "at": at(revoke_at),
            "jti": revoke_jti,
            "kind": "revocation",
            "writer": ISSUER,
        }
        place = next(
            (
                i
                for i, e in enumerate(entries)
                if i and reader._time(e["statement"]) >= T0 + revoke_at
            ),
            len(entries),
        )
        entries.insert(place, {"statement": revocation})
    return entries


def _pair(
    origin: dict[str, Any], spec: Spec, clock: int, chain: tuple[str, ...]
) -> list[dict[str, Any]]:
    destination = spec["destination"]
    writer = spec.get("writer", EXCHANGER)
    clock = spec.get("at", clock)
    verifier = DESTINATIONS.get(destination, {"verifier": f"verifier:{destination}"})["verifier"]
    aimed = spec.get("aimed", verifier)
    received: dict[str, Any] = {
        "at": at(clock),
        "carriedIn": spec.get("carried", reader.HEADER),
        "from": HOLDER,
        "protocol": "rfc8693",
        "token": copy.deepcopy(origin["sent"]["token"]),
    }
    if "received_token" in spec:
        spec["received_token"](received["token"])
    if spec.get("proof", True):
        received["proof"] = proof(received, writer, clock, spec.get("proof_edit"))
    here = sorted(s for s in DELEGATED_SCOPE.split(" ") if s.startswith(destination + ":"))
    rights = spec.get("rights", here[:1])
    actors = spec.get("actors", (*chain, writer))
    sent_token = rfc8693(
        spec.get("subject", U),
        tuple(actors),
        aud=aimed,
        exp=T0 + clock + 1 + 120,
        iat=T0 + clock + 1,
        scope=" ".join(rights),
    )
    statement: dict[str, Any] = {
        "kind": "exchange",
        "received": received,
        "sent": {"at": at(clock + 1), "protocol": "rfc8693", "to": aimed, "token": sent_token},
        "writer": writer,
    }
    if spec.get("checked", True):
        digest = spec.get("allowlist", reader.allowlist_digest(trust()))
        statement["destinationCheck"] = {"allowlistSha256": digest, "destination": destination}
    presented = {
        "at": at(spec.get("presented_at", clock + 5)),
        "carriedIn": spec.get("presented_in", reader.HEADER),
        "protocol": "rfc8693",
        "token": copy.deepcopy(sent_token),
    }
    presentation = {
        "kind": "presentation",
        "received": presented,
        "writer": spec.get("presented_to", aimed),
    }
    out = [{"statement": statement}, {"statement": presentation}]
    return out if spec.get("recorded", True) else out[1:]


def proof(
    received: dict[str, Any],
    exchanger: str,
    clock: int,
    edit: Callable[[dict[str, Any]], str | None] | None = None,
) -> dict[str, Any]:
    """The holder's proof: an Ed25519 signature over the RFC 8785 bytes of the token
    hash, the exchanger it is for and the second it was made. ``edit`` may change the
    payload or the key and return the name of the key that signs instead."""
    ath = reader.b64url(bytes.fromhex(_sha(reader.token_bytes(received))))
    body: dict[str, Any] = {
        "jwk": jwk(HOLDER),
        "payload": {"ath": ath, "aud": exchanger, "iat": T0 + clock},
    }
    signer = (edit(body) if edit else None) or HOLDER
    body["signature"] = reader.b64url(key(signer).sign(reader.a2ajcs.canonicalize(body["payload"])))
    return body


def seal(
    entries: list[dict[str, Any]], signers: dict[int, str] | None = None
) -> list[dict[str, Any]]:
    """Link each statement to the one before it and sign every statement."""
    chosen = signers or {}
    out: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        entry = copy.deepcopy(entry)
        statement = entry["statement"]
        if index:
            statement["prev"] = _sha(reader.signing_input(out[index - 1]["statement"]))
        signer = chosen.get(index) or str(statement["writer"])
        entry["signature"] = reader.b64url(key(signer).sign(reader.signing_input(statement)))
        out.append(entry)
    return out


def record(
    statements: list[dict[str, Any]], contract: str | None = reader.CONTRACT_ID
) -> dict[str, Any]:
    body: dict[str, Any] = {"statements": statements}
    if contract is not None:
        body["contractId"] = contract
    return body


def one(**kw: Any) -> dict[str, Any]:
    """A sealed record of one payroll exchange with the given edits."""
    chain_kw = {
        k: kw.pop(k) for k in ("chain", "lifetime", "bound", "revoke_at", "revoke_jti") if k in kw
    }
    return record(seal(build([exchange(kw.pop("destination", "payroll"), **kw)], **chain_kw)))


def _forge() -> dict[str, Any]:
    sealed = seal(build([exchange("payroll")]))
    sealed[1]["statement"]["sent"]["token"]["claims"]["scope"] = "payroll:read payroll:write"
    return record(sealed)


def _drop(index: int) -> dict[str, Any]:
    sealed = seal(build([exchange("payroll"), exchange("calendar")]))
    return record([s for i, s in enumerate(sealed) if i != index])


def _carried(where: str) -> dict[str, Any]:
    entries = build([exchange("payroll")])
    entries[1]["statement"]["received"]["carriedIn"] = where
    return record(seal(entries))


def _other_key(body: dict[str, Any]) -> str | None:
    body["jwk"] = jwk("agent:intruder")
    return "agent:intruder"


def _signed_by_other(body: dict[str, Any]) -> str | None:
    return "agent:intruder"


def _other_token(body: dict[str, Any]) -> str | None:
    body["payload"]["ath"] = reader.b64url(hashlib.sha256(b"another token").digest())
    return None


def _other_exchanger(body: dict[str, Any]) -> str | None:
    body["payload"]["aud"] = "exchange:other"
    return None


def _widen_received(token: dict[str, Any]) -> None:
    token["claims"]["scope"] = DELEGATED_SCOPE + " payroll:approve"


Case = tuple[str, dict[str, Any], str, str, str, list[str]]


def cases() -> list[Case]:
    """id, record, expected decision, reason, the edit, and the anchors it rests on."""
    a, r, ok = reader.ACCEPT, reader.REJECT, reader.ACCEPT_REASON
    other_list = _sha(
        reader.a2ajcs.canonicalize({**DESTINATIONS, "billing": {"verifier": "verifier:billing"}})
    )
    return [
        (
            "accept-single-destination",
            one(),
            a,
            ok,
            "control: the holder proves its key, the exchanger checks the reviewed list and sends "
            "one narrowed token for payroll carrying the whole chain and itself",
            ["audience", "nesting", "jkt", "scope-narrow"],
        ),
        (
            "accept-two-destinations",
            record(seal(build([exchange("payroll"), exchange("calendar")]))),
            a,
            ok,
            "control: one delegated token, one exchange and one token per destination",
            ["audience"],
        ),
        (
            "accept-one-actor-chain",
            one(chain=(HOLDER,)),
            a,
            ok,
            "control: the delegated token names one agent; "
            "the exchanged token carries it and the exchanger",
            ["nesting"],
        ),
        (
            "accept-rights-equal-to-delegation",
            one(rights=["payroll:read", "payroll:write"]),
            a,
            ok,
            "control: the exchanged token carries every right the delegation names "
            "for payroll and no more",
            ["scope-narrow"],
        ),
        (
            "accept-revoked-after-exchange",
            one(revoke_at=200),
            a,
            ok,
            "control: the delegated token is revoked after the exchange; the exchange stands",
            [],
        ),
        (
            "accept-exchange-a-second-before-expiry",
            one(at=LIFETIME - 1),
            a,
            ok,
            "control: the exchange happens one second before the delegated token's exp",
            ["exp"],
        ),
        (
            "accept-revocation-of-another-token",
            one(revoke_at=30, revoke_jti="dt-other"),
            a,
            ok,
            "control: a revocation of another token's jti before the exchange changes nothing",
            [],
        ),
        (
            "contract-id-missing",
            record(seal(build([exchange("payroll")])), contract=None),
            r,
            "contract_id_missing",
            "the record names no contract",
            [],
        ),
        (
            "contract-id-unknown",
            record(
                seal(build([exchange("payroll")])),
                contract=reader.CONTRACT_ID.replace("/predicate/v1/", "/predicate-unknown/v1/"),
            ),
            r,
            "contract_id_unknown",
            "the record names another contract",
            [],
        ),
        (
            "token-carried-in-cookie",
            _carried("cookie"),
            r,
            "record_malformed",
            "the exchange states the token arrived in a place this contract does not name",
            [],
        ),
        (
            "writer-not-in-trust-bundle",
            one(writer="exchange:unlisted"),
            r,
            "statement_writer_unknown",
            "the exchange is written by a component the trust bundle does not list",
            [],
        ),
        (
            "signature-forged",
            _forge(),
            r,
            "statement_signature_invalid",
            "the exchanged token's scope is widened after the exchange statement was signed",
            [],
        ),
        (
            "signature-swapped-key",
            record(seal(build([exchange("payroll")]), signers={1: "agent:intruder"})),
            r,
            "statement_signature_invalid",
            "the exchange statement is signed with another writer's key",
            [],
        ),
        (
            "statement-dropped-from-chain",
            _drop(2),
            r,
            "hop_link_broken",
            "the payroll presentation is removed from a two-destination chain",
            [],
        ),
        (
            "exchange-unrecorded",
            one(recorded=False),
            r,
            "exchange_unrecorded",
            "a verifier states a token naming the exchanger, and no statement records the exchange",
            ["nesting"],
        ),
        (
            "delegated-token-edited-by-holder",
            one(received_token=_widen_received),
            r,
            "received_not_sent",
            "the holder adds a right to its delegated token before it presents it",
            [],
        ),
        (
            "forwarded-token-at-another-destination",
            one(presented_to="verifier:calendar"),
            r,
            "token_presented_off_destination",
            "the token minted for the payroll verifier is forwarded to the calendar verifier",
            ["aud"],
        ),
        (
            "delegated-token-in-query",
            _carried("query"),
            r,
            "token_in_request_parameter",
            "the holder sends its delegated token as a query parameter",
            ["uri"],
        ),
        (
            "exchanged-token-in-form-body",
            one(presented_in="form-body"),
            r,
            "token_in_request_parameter",
            "the exchanged token reaches the verifier as a form parameter",
            ["uri"],
        ),
        (
            "delegated-token-unmarked",
            one(chain=(), actors=(EXCHANGER,)),
            r,
            "delegated_token_unmarked",
            "the issuer mints the delegated token for the user alone, with no agent marker",
            ["nesting"],
        ),
        (
            "exchanged-by-hop-outside-intermediaries",
            one(writer="exchange:other"),
            r,
            "exchanger_not_intermediary",
            "an exchanger the delegated token does not name as an intermediary exchanges it",
            ["aud"],
        ),
        (
            "delegated-token-revoked-before-exchange",
            one(revoke_at=30),
            r,
            "delegated_token_revoked",
            "the issuer revokes the delegated token before the exchange",
            [],
        ),
        (
            "revoked-at-the-second-of-exchange",
            one(revoke_at=60),
            r,
            "delegated_token_revoked",
            "the revocation and the exchange fall in the same second; the revocation wins",
            [],
        ),
        (
            "exchanged-after-expiry",
            one(at=LIFETIME + 30),
            r,
            "delegated_token_expired",
            "the exchange happens after the delegated token's exp",
            ["exp"],
        ),
        (
            "exchanged-at-expiry",
            one(at=LIFETIME),
            r,
            "delegated_token_expired",
            "the exchange happens at the delegated token's exp, which is already expired",
            ["exp"],
        ),
        (
            "delegated-lifetime-over-limit",
            one(lifetime=LIFETIME + 1),
            r,
            "delegated_lifetime_over_limit",
            "the delegated token lives 301 s, over the relying party's 300 s limit",
            [],
        ),
        (
            "delegated-token-bearer",
            one(bound=False, proof=False),
            r,
            "delegated_token_unbound",
            "the delegated token names no key, so anyone holding it can exchange it",
            ["jkt"],
        ),
        (
            "holder-proof-missing",
            one(proof=False),
            r,
            "holder_proof_missing",
            "the delegated token is bound to a key and is presented with no proof of it",
            ["jkt"],
        ),
        (
            "holder-proof-other-key",
            one(proof_edit=_other_key),
            r,
            "holder_proof_invalid",
            "the proof is made with a key whose thumbprint is not the token's jkt",
            ["jkt"],
        ),
        (
            "holder-proof-signature-invalid",
            one(proof_edit=_signed_by_other),
            r,
            "holder_proof_invalid",
            "the proof names the holder's key and is signed with another",
            ["jkt"],
        ),
        (
            "holder-proof-for-another-token",
            one(proof_edit=_other_token),
            r,
            "holder_proof_invalid",
            "the proof's token hash is for another token",
            ["jkt"],
        ),
        (
            "holder-proof-for-another-exchanger",
            one(proof_edit=_other_exchanger),
            r,
            "holder_proof_invalid",
            "the proof was made for another exchanger and replayed here",
            ["jkt"],
        ),
        (
            "exchange-path-skips-destination-list",
            one(checked=False),
            r,
            "destination_check_skipped",
            "an automatic exchange path mints the token without consulting the reviewed list",
            ["audience"],
        ),
        (
            "exchange-checked-another-list",
            one(allowlist=other_list),
            r,
            "destination_check_skipped",
            "the exchanger consulted a list other than the reviewed one the relying party pins",
            ["audience"],
        ),
        (
            "destination-off-allowlist",
            one(destination="billing"),
            r,
            "destination_not_allowlisted",
            "the exchange is for a destination the reviewed list does not name",
            ["audience"],
        ),
        (
            "exchanged-token-aimed-at-another-verifier",
            one(aimed="verifier:calendar"),
            r,
            "destination_verifier_mismatch",
            "the exchange for payroll aims its token at the calendar verifier",
            ["audience", "aud"],
        ),
        (
            "subject-replaced-at-exchange",
            one(subject="user:bob@example.com"),
            r,
            "subject_replaced",
            "the exchanged token names another user",
            [],
        ),
        (
            "actor-lost-at-exchange",
            one(actors=()),
            r,
            "actor_lost_at_exchange",
            "the exchanged token names only the user: the destination's authorization reads no "
            "intermediary and no chain",
            ["nesting"],
        ),
        (
            "agent-marker-dropped",
            one(actors=(EXCHANGER,)),
            r,
            "agent_marker_dropped",
            "the exchanged token names the exchanger and drops the agents it received",
            ["nesting"],
        ),
        (
            "previous-hop-dropped",
            one(actors=(HOLDER, EXCHANGER)),
            r,
            "previous_hop_dropped",
            "the exchanged token keeps the acting agent's marker and drops the agent before it",
            ["nesting"],
        ),
        (
            "exchanger-not-in-chain",
            one(actors=(PLANNER, HOLDER)),
            r,
            "exchanger_not_in_chain",
            "the exchanged token forwards the chain and leaves out the exchanger that minted it",
            ["nesting"],
        ),
        (
            "chain-reordered-at-exchange",
            one(actors=(HOLDER, PLANNER, EXCHANGER)),
            r,
            "chain_altered_at_exchange",
            "the exchanged token reverses the agents it received",
            ["nesting"],
        ),
        (
            "rights-beyond-destination",
            one(rights=["payroll:read", "calendar:read"]),
            r,
            "rights_beyond_destination",
            "the payroll token also carries a calendar right from the delegation",
            ["scope-narrow"],
        ),
        (
            "rights-not-narrowed",
            one(rights=sorted(ENTITLEMENTS["payroll"].split(" "))),
            r,
            "rights_not_narrowed",
            "the destination is narrowed and the token carries the user's full payroll rights, "
            "where the delegation named fewer",
            ["scope-narrow"],
        ),
        (
            "rights-widened-while-destination-narrowed",
            one(rights=["payroll:read", "payroll:approve"]),
            r,
            "rights_widened",
            "the exchange narrows the destination and adds a right the delegation never named",
            ["scope-narrow"],
        ),
        (
            "exchanged-token-used-after-expiry",
            one(presented_at=60 + 1 + 120),
            r,
            "exchanged_token_expired_at_use",
            "the verifier accepts the exchanged token at its exp",
            ["exp"],
        ),
    ]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write TRUST.json, every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    trust_bytes = _json(trust())
    (root / "TRUST.json").write_bytes(trust_bytes)
    entries = []
    for name, body, decision, reason, edit, anchors in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"record.json": _json(body)}
        for index, item in enumerate(body["statements"]):
            files[f"signing-input-{index}.jcs"] = reader.signing_input(item["statement"])
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json", root / "TRUST.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "anchors": [
                    {"quote": ANCHORS[k][2], "section": ANCHORS[k][1], "source": ANCHORS[k][0]}
                    for k in anchors
                ],
                "edit": edit,
                "expected": expected,
                "files": {k: _sha(v) for k, v in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(body),
            }
        )
    words = [e["expected"]["decision"] for e in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _DIGEST.entries_digest(entries),
        "counts": {w: words.count(w) for w in sorted(set(words))},
        "sources": SOURCES,
        "suite": SUITE,
        "synthetic": True,
        "trustSha256": _sha(trust_bytes),
        "verifierContract": (
            "verifier record.json --trust TRUST.json --json; exit 0 accept, 1 reject"
        ),
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
