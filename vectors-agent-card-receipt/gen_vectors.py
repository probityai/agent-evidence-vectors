"""Build the agent-card-receipt cases byte-identically.

Every case is an A2A Agent Card, an unsigned in-toto Statement carrying a
receipt for it (spec/predicates/agent-card-receipt.md), the issuer's revocation
list as a signed DSSE envelope, and a context naming the time of the check and
the receipt signer's public key. Each rejected case is built so the check it
names is the first that fails and every earlier check passes; each accepted
case is a control.

Regenerate byte-identically:

    uv run --extra generators python vectors-agent-card-receipt/gen_vectors.py

TEST KEYS ONLY. Each Ed25519 seed is the SHA-256 of a public label, so anyone
can rebuild the keys and the signatures. The receipts themselves are unsigned:
a signed statement must not carry a predicate URI before its page is served.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import a2ajcs  # noqa: E402
from agent_evidence_vectors import cardreceipt as reader  # noqa: E402

SUITE = reader.RECEIPT_SUITE
ISSUER_LABEL = "agent-evidence-vectors agent-card-receipt test issuer"
OTHER_LABEL = "agent-evidence-vectors agent-card-receipt test other"
AGENT_LABEL = "agent-evidence-vectors agent-card-receipt test agent"
CARD_URL = "https://travel-agent.example.com/.well-known/agent-card.json"
LIST_URL = "https://receipts.example.org/agent-card-receipt/revocations.dsse.json"
DONE_RECEIPT = "https://w3id.org/agent-evidence/predicate/v1/done-receipt"
# The SHA-256 of agent-evidence-vocabulary 0.8.0's vocabulary.yaml.
REGISTRY = "76233ba8924cebdf053f0449ce023186805156aedca4121b9b156bd747a411b4"
RUN = hashlib.sha256(b"graded run statement of travel-agent 1.4.0").hexdigest()
ISSUED, NOW, UNTIL = "2026-10-20T00:00:00Z", "2026-10-27T12:00:00Z", "2026-11-19T00:00:00Z"
LIST_ISSUED, LIST_NEXT = "2026-10-27T00:00:00Z", "2026-10-28T00:00:00Z"


_DIGEST_SPEC = importlib.util.spec_from_file_location(
    "agent_card_receipt_digest", ROOT / "digest.py")
assert _DIGEST_SPEC and _DIGEST_SPEC.loader
_digest = importlib.util.module_from_spec(_DIGEST_SPEC)
_DIGEST_SPEC.loader.exec_module(_digest)
sha, enc, corpus_digest = _digest.sha, _digest.enc, _digest.corpus_digest


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


ISSUER, OTHER, AGENT = key(ISSUER_LABEL), key(OTHER_LABEL), key(AGENT_LABEL)


def thumbprint(k: Ed25519PrivateKey) -> str:
    """The RFC 7638 JWK SHA-256 thumbprint of an Ed25519 key (RFC 8037 OKP)."""
    x = base64.urlsafe_b64encode(public_raw(k)).rstrip(b"=").decode()
    members = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, sort_keys=True,
                         separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(members).digest()).rstrip(b"=").decode()


def context(now: str = NOW, signer: Ed25519PrivateKey = ISSUER) -> dict[str, Any]:
    return {"issuerKey": _b64(public_raw(signer)), "now": now}


def revocation_list(revoked: list[str], *, signer: Ed25519PrivateKey = ISSUER,
                    issued: str = LIST_ISSUED, next_update: str = LIST_NEXT,
                    payload_type: str = reader.REVOCATIONS_PAYLOAD_TYPE,
                    tamper: Callable[[bytes], bytes] | None = None) -> dict[str, Any]:
    """A signed revocation list; ``tamper`` edits the payload after signing."""
    body = reader._manifest_json({"issuedAt": issued, "nextUpdate": next_update,
                                  "revoked": revoked})
    sig = signer.sign(b"DSSEv1 %d %s %d " % (len(payload_type), payload_type.encode(),
                                             len(body)) + body)
    carried = tamper(body) if tamper else body
    return {"payload": _b64(carried), "payloadType": payload_type,
            "signatures": [{"keyid": sha(public_raw(signer)), "sig": _b64(sig)}]}


def base_card() -> dict[str, Any]:
    """A card with no default-valued member: its payload is itself minus nothing."""
    return {
        "capabilities": {"streaming": True},
        "defaultInputModes": ["text/plain"], "defaultOutputModes": ["application/json"],
        "description": "Books flights and hotels within a traveller's approved budget.",
        "name": "Travel Agent",
        "provider": {"organization": "Example Travel", "url": "https://travel.example.com"},
        "skills": [{"description": "Find and hold a flight that fits the itinerary.",
                    "id": "book-flight", "name": "Book flight", "tags": ["travel", "flight"]}],
        "supportedInterfaces": [{"protocolBinding": "JSONRPC", "protocolVersion": "1.0",
                                 "url": "https://travel-agent.example.com/a2a/v1"}],
        "version": "1.4.0",
    }


def card_with(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    card = base_card()
    change(card)
    return card


def _defaults(card: dict[str, Any]) -> None:
    """Members a protobuf JSON encoder would omit, served as written."""
    card["capabilities"]["extensions"] = []
    card["capabilities"]["pushNotifications"] = False
    card["supportedInterfaces"][0]["tenant"] = ""


def _pruned(card: dict[str, Any]) -> dict[str, Any]:
    """The same card with those members removed: one reading of A2A rule 1."""
    out = copy.deepcopy(card)
    del out["capabilities"]["extensions"], out["capabilities"]["pushNotifications"]
    del out["supportedInterfaces"][0]["tenant"]
    return out


def _extension(card: dict[str, Any]) -> None:
    card["capabilities"]["extensions"] = [{
        "description": "Receipts for evaluated runs of this card.",
        "params": {"receipts": "https://receipts.example.org/travel-agent/index.json"},
        "uri": reader.RECEIPT_TYPE}]


def _signatures(card: dict[str, Any]) -> None:
    card["signatures"] = [{"protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0",
                           "signature": "QFdkNLNszlGj3z3u0YQGt_T9LixY3qtdQpZmsTdDHDe3fX"}]


def _rfc8785_edges(card: dict[str, Any]) -> None:
    """A non-ASCII name, a small number and keys whose UTF-16 and code point
    orders differ: the three places A2A issue 2122 found SDKs disagree."""
    card["name"] = "Caf\u00e9 Agent"
    card["capabilities"]["extensions"] = [{
        "params": {"tolerance": 0.000001}, "uri": "https://example.com/ext/tolerance/v1"}]
    card["securitySchemes"] = {
        "\U0001f600": {"mtlsSecurityScheme": {"description": "astral"}},
        "\ue000": {"mtlsSecurityScheme": {"description": "private use"}}}


def _vendor(card: dict[str, Any]) -> None:
    card["x-example-region"] = "eu-west"


def _payload(card: dict[str, Any]) -> bytes:
    return reader.card_payload(enc(card))


def _python_dumps(card: dict[str, Any]) -> bytes:
    """A wrong canonicalizer: sorted keys by code point, ASCII escapes, repr numbers."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def receipt(card: dict[str, Any] | None = None, *, digest: str | None = None,
            **predicate_changes: Any) -> dict[str, Any]:
    card = base_card() if card is None else card
    predicate: dict[str, Any] = {
        "issuedAt": ISSUED, "registryDigest": {"sha256": REGISTRY}, "result": "pass",
        "revocationList": LIST_URL, "run": {"digest": {"sha256": RUN},
                                            "predicateType": DONE_RECEIPT},
        "validUntil": UNTIL,
    }
    predicate.update(predicate_changes)
    return {
        "_type": reader.STATEMENT_TYPE, "predicate": predicate,
        "predicateType": reader.RECEIPT_TYPE,
        "subject": [{"digest": {"sha256": digest or sha(_payload(card))},
                     "name": CARD_URL}],
    }


Case = tuple[str, str, dict[str, bytes], str, str]


def case(name: str, edit: str, *, card: dict[str, Any] | None = None,
         statement: dict[str, Any] | bytes | None = None, revoked: list[str] | None = None,
         listing: dict[str, Any] | None | bool = True, ctx: dict[str, Any] | None = None,
         reason: str = "receipt_current") -> Case:
    """One case. The default revocation list is current and names nothing."""
    card = base_card() if card is None else card
    stmt = receipt(card) if statement is None else statement
    stmt_bytes = stmt if isinstance(stmt, bytes) else enc(stmt)
    files = {"card.json": enc(card), "context.json": enc(ctx or context()),
             "statement.json": stmt_bytes}
    if listing is True:
        listing = revocation_list(revoked if revoked is not None else [])
    if isinstance(listing, dict):
        files["revocations.json"] = enc(listing)
    decision = reader.ACCEPT if reason == "receipt_current" else reader.REJECT
    return name, edit, files, decision, reason


def _receipt_bytes(stmt: dict[str, Any]) -> str:
    return sha(enc(stmt))


def _edited(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    stmt = receipt()
    change(stmt)
    return stmt


def _predicate(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    return _edited(lambda s: change(s["predicate"]))


def accepted() -> list[Case]:
    defaults, extension = card_with(_defaults), card_with(_extension)
    signed, edges, vendor = card_with(_signatures), card_with(_rfc8785_edges), card_with(_vendor)
    other = sha(b"some other receipt statement")
    thumbs = sorted([thumbprint(AGENT), thumbprint(OTHER)])
    return [
        case("accept-card-without-signatures", "control: a card with no signatures, a current "
             "receipt and a current list that names nothing"),
        case("accept-signatures-excluded", "control: the card's JWS signatures are not part "
             "of the bytes a receipt binds", card=signed, statement=receipt(signed)),
        case("accept-default-members-kept", "control: an empty extensions array, an empty "
             "tenant and a false pushNotifications are hashed as served", card=defaults,
             statement=receipt(defaults)),
        case("accept-rfc8785-edges", "control: a non-ASCII name, the number 0.000001 and keys "
             "whose UTF-16 order differs from code point order", card=edges,
             statement=receipt(edges)),
        case("accept-receipt-extension-declared", "control: the card declares the receipt "
             "extension with a receipts index URL and no receipt digest", card=extension,
             statement=receipt(extension)),
        case("accept-unknown-member-kept", "control: a member A2A does not define is hashed "
             "as served", card=vendor, statement=receipt(vendor)),
        case("accept-agent-key-thumbprints", "control: the receipt names the RFC 7638 "
             "thumbprints of the keys the agent signed with during the run",
             statement=receipt(agentKeyThumbprints=thumbs)),
        case("accept-result-degraded", "control: a receipt whose result is degraded is a valid "
             "receipt; whether it is enough is the relying party's policy",
             statement=receipt(result="degraded")),
        case("accept-other-receipt-revoked", "control: the list revokes a different receipt",
             revoked=[other]),
        case("accept-at-issued-at", "control: the check time equals issuedAt, against a "
             "list current at that time", ctx=context(now=ISSUED),
             listing=revocation_list([], issued=ISSUED, next_update="2026-10-21T00:00:00Z")),
        case("accept-list-at-issued-at", "control: the check time equals the list's issuedAt",
             ctx=context(now=LIST_ISSUED)),
    ]


def _statement_cases() -> list[Case]:
    upper = receipt()
    upper["subject"][0]["digest"]["sha256"] = upper["subject"][0]["digest"]["sha256"].upper()
    two = receipt()
    two["subject"].append({"digest": {"sha256": RUN}, "name": "run"})
    extra = receipt()
    extra["signer"] = "issuer-1"
    dup = enc(receipt()).replace(b'"_type"', b'"_type": "x",\n  "_type"', 1)
    return [
        case("statement-duplicate-member", "the statement repeats _type",
             statement=dup, reason="statement_malformed"),
        case("statement-member-unexpected", "the statement carries a fifth member",
             statement=extra, reason="statement_malformed"),
        case("statement-type-wrong", "_type names in-toto Statement v0.1",
             statement=_edited(lambda s: s.update(_type="https://in-toto.io/Statement/v0.1")),
             reason="statement_type_wrong"),
        case("predicate-type-wrong", "predicateType names the done-receipt predicate",
             statement=_edited(lambda s: s.update(predicateType=DONE_RECEIPT)),
             reason="predicate_type_wrong"),
        case("subject-two-members", "the subject names the card and the run",
             statement=two, reason="subject_malformed"),
        case("subject-digest-uppercase", "the subject digest is uppercase hexadecimal",
             statement=upper, reason="subject_malformed"),
    ]


def _predicate_cases() -> list[Case]:
    unsorted = sorted([thumbprint(AGENT), thumbprint(OTHER)], reverse=True)
    return [
        case("predicate-result-unregistered", "result is a word the vocabulary's result term "
             "does not register", statement=receipt(result="passed"),
             reason="predicate_malformed"),
        case("predicate-member-unexpected", "the predicate carries a score",
             statement=_predicate(lambda p: p.update(score=0.93)), reason="predicate_malformed"),
        case("predicate-registry-missing", "the predicate names no vocabulary registry",
             statement=_predicate(lambda p: p.pop("registryDigest")),
             reason="predicate_malformed"),
        case("predicate-time-fraction", "issuedAt carries fractional seconds",
             statement=receipt(issuedAt="2026-10-20T00:00:00.000Z"),
             reason="predicate_malformed"),
        case("predicate-time-offset", "validUntil carries a +00:00 offset instead of Z",
             statement=receipt(validUntil="2026-11-19T00:00:00+00:00"),
             reason="predicate_malformed"),
        case("predicate-revocation-list-http", "the revocation list URL is plain http",
             statement=receipt(revocationList=LIST_URL.replace("https:", "http:")),
             reason="predicate_malformed"),
        case("predicate-thumbprints-unsorted", "the agent key thumbprints are not sorted",
             statement=receipt(agentKeyThumbprints=unsorted), reason="predicate_malformed"),
        case("predicate-run-digest-short", "the run digest is not 64 hexadecimal digits",
             statement=receipt(run={"digest": {"sha256": RUN[:40]},
                                    "predicateType": DONE_RECEIPT}),
             reason="predicate_malformed"),
        case("validity-window-inverted", "validUntil is before issuedAt",
             statement=receipt(validUntil="2026-10-19T00:00:00Z"),
             reason="validity_window_inverted"),
    ]


def _card_cases() -> list[Case]:
    dup = enc(base_card()).replace(b'"name"', b'"name": "Other",\n  "name"', 1)
    big = card_with(lambda c: c["capabilities"].update(extensions=[
        {"params": {"limit": 2**53}, "uri": "https://example.com/ext/limit/v1"}]))
    defaults, signed = card_with(_defaults), card_with(_signatures)
    edges = card_with(_rfc8785_edges)
    added = card_with(lambda c: c["skills"].append(
        {"description": "Pay for a held booking.", "id": "pay", "name": "Pay",
         "tags": ["payment"]}))

    def raw_card(name: str, edit: str, card_bytes: bytes) -> Case:
        return (name, edit, {"card.json": card_bytes, "context.json": enc(context()),
                             "revocations.json": enc(revocation_list([])),
                             "statement.json": enc(receipt())}, reader.REJECT,
                "card_malformed")

    return [
        raw_card("card-duplicate-member", "the card repeats name", dup),
        raw_card("card-not-an-object", "the card is a JSON array", b"[]\n"),
        case("card-integer-outside-i-json", "an extension parameter is 2 to the 53rd, "
             "outside the I-JSON range RFC 8785 requires", card=big,
             statement=receipt(), reason="card_malformed"),
        case("digest-defaults-pruned", "the digest is over the card with its default-valued "
             "members removed, one reading of A2A rule 1, while the card was served with them",
             card=defaults, statement=receipt(defaults, digest=sha(_payload(_pruned(defaults)))),
             reason="card_digest_mismatch"),
        case("digest-signatures-included", "the digest covers the card's signatures member",
             card=signed, statement=receipt(signed, digest=sha(a2ajcs.canonicalize(signed))),
             reason="card_digest_mismatch"),
        case("digest-not-rfc8785", "the digest is over sorted-key JSON with ASCII escapes and "
             "the number written 1e-06, which is not RFC 8785", card=edges,
             statement=receipt(edges, digest=sha(_python_dumps(edges))),
             reason="card_digest_mismatch"),
        case("card-changed-after-receipt", "the card gained a skill after the receipt was "
             "issued", card=added, statement=receipt(), reason="card_digest_mismatch"),
    ]


def _time_cases() -> list[Case]:
    return [
        case("receipt-not-yet-valid", "the check time is a second before issuedAt",
             ctx=context(now="2026-10-19T23:59:59Z"), reason="receipt_not_yet_valid"),
        case("receipt-expired", "the check time is after validUntil",
             ctx=context(now="2026-11-20T00:00:00Z"), reason="receipt_expired"),
        case("receipt-expired-at-valid-until", "the check time equals validUntil; the window "
             "is half open", ctx=context(now=UNTIL), reason="receipt_expired"),
    ]


def _list_cases() -> list[Case]:
    stmt = receipt()
    mine = _receipt_bytes(stmt)
    other = sha(b"some other receipt statement")
    return [
        case("revocation-list-absent", "no revocation list was obtained", listing=False,
             reason="revocation_list_absent"),
        case("revocation-list-payload-type-wrong", "the envelope's payloadType is plain JSON",
             listing=revocation_list([], payload_type="application/json"),
             reason="revocation_list_malformed"),
        case("revocation-list-unsorted", "the revoked digests are not sorted",
             listing=revocation_list(sorted([mine, other], reverse=True)),
             reason="revocation_list_malformed"),
        case("revocation-list-other-signer", "the list is signed by a key that did not sign "
             "the receipt", listing=revocation_list([], signer=OTHER),
             reason="revocation_list_signature"),
        case("revocation-list-edited-after-signing", "the receipt's digest was removed from "
             "the list after it was signed",
             listing=revocation_list([mine], tamper=lambda body: body.replace(
                 f'"{mine}"'.encode(), b"").replace(b"[\n    \n  ]", b"[]")),
             reason="revocation_list_signature"),
        case("revocation-list-stale", "the check time is at the list's nextUpdate",
             ctx=context(now=LIST_NEXT), reason="revocation_list_stale"),
        case("revocation-list-not-yet-issued", "the check time is before the list was issued",
             ctx=context(now="2026-10-26T23:59:59Z"), reason="revocation_list_stale"),
        case("receipt-revoked", "the current list names this receipt's digest",
             revoked=sorted([mine, other]), reason="receipt_revoked"),
    ]


def cases() -> list[Case]:
    """Every case: id, what it shows, files, expected decision and reason."""
    return [*accepted(), *_statement_cases(), *_predicate_cases(), *_card_cases(),
            *_time_cases(), *_list_cases()]


def generate(root: Path = ROOT, build: Callable[[], list[Case]] = cases,
             suite: str = SUITE) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, edit, files, decision, reason in build():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        for stale in directory.iterdir():
            if stale.name not in files:
                stale.unlink()
        for file_name, data in files.items():
            (directory / file_name).write_bytes(data)
        entries.append({"edit": edit, "expected": {"decision": decision, "reason": reason},
                        "files": {n: sha(d) for n, d in sorted(files.items())},
                        "id": name, "path": f"cases/{name}"})
    manifest = {
        "corpusDigest": sha(enc(entries)), "suite": suite,
        "verifierContract": "verifier <suite> <case-dir> --json; exit 0 accept, 1 reject",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(enc(manifest))
    return manifest


if __name__ == "__main__":
    generate()
