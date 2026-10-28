"""Build the credential-release cases byte-identically.

Every case is an unsigned in-toto Statement recording that a broker released a
scoped credential (spec/predicates/credential-release.md), the agent-card
receipt it released against, the revocation list it says it consulted, and a
context naming the receipt signer's public key. Each rejected case is built so
the check it names is the first that fails; each accepted case is a control.

Regenerate byte-identically:

    uv run --extra generators python vectors-credential-release/gen_vectors.py

TEST KEYS ONLY, from the same labels as vectors-agent-card-receipt.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import cardreceipt as reader  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "agent_card_receipt_generator", ROOT.parent / "vectors-agent-card-receipt" / "gen_vectors.py")
assert _SPEC and _SPEC.loader
receipts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(receipts)

SUITE = reader.RELEASE_SUITE
_DIGEST_SPEC = importlib.util.spec_from_file_location(
    "credential_release_digest", ROOT / "digest.py")
assert _DIGEST_SPEC and _DIGEST_SPEC.loader
_digest = importlib.util.module_from_spec(_DIGEST_SPEC)
_DIGEST_SPEC.loader.exec_module(_digest)
enc, sha, corpus_digest = _digest.enc, _digest.sha, _digest.corpus_digest
RELEASED = "2026-10-27T12:00:00Z"
BROKER = "https://broker.example.org/credential-broker"
AUDIENCE = "https://api.travel-bookings.example.com"


def receipt_statement(**changes: Any) -> dict[str, Any]:
    return dict(receipts.receipt(**changes))


def listing(revoked: list[str] | None = None, **changes: Any) -> dict[str, Any]:
    return dict(receipts.revocation_list(revoked or [], **changes))


def release(receipt: dict[str, Any], revocations: dict[str, Any], *,
            subject: str | None = None, **changes: Any) -> dict[str, Any]:
    """A release on ``receipt`` that copies its result and validUntil."""
    held = receipt["predicate"]
    predicate: dict[str, Any] = {
        "broker": {"id": BROKER},
        "credential": {"audience": AUDIENCE, "kind": "oauth2-access-token",
                       "scope": ["bookings:hold", "bookings:read"]},
        "minResult": "pass", "registryDigest": {"sha256": receipts.REGISTRY},
        "receipt": {"digest": {"sha256": sha(enc(receipt))}, "predicateType": reader.RECEIPT_TYPE,
                    "result": held["result"], "validUntil": held["validUntil"]},
        "releaseId": "release-0001", "releasedAt": RELEASED,
        "revocationList": {"digest": {"sha256": sha(enc(revocations))}},
        "ttlSeconds": 900,
    }
    predicate.update(changes)
    digest = subject or receipt["subject"][0]["digest"]["sha256"]
    return {"_type": reader.STATEMENT_TYPE, "predicate": predicate,
            "predicateType": reader.RELEASE_TYPE,
            "subject": [{"digest": {"sha256": digest}, "name": receipts.CARD_URL}]}


Case = tuple[str, str, dict[str, bytes], str, str]


def case(name: str, edit: str, *, receipt: dict[str, Any] | None = None,
         revocations: dict[str, Any] | None = None,
         statement: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any] | bytes]
         | None = None, receipt_file: bytes | None = None,
         revocations_file: bytes | None = None, reason: str = "release_bound") -> Case:
    held = receipt_statement() if receipt is None else receipt
    lst = listing() if revocations is None else revocations
    stmt = (statement or release)(held, lst)
    files = {"context.json": enc(receipts.context()),
             "receipt.json": receipt_file if receipt_file is not None else enc(held),
             "revocations.json": revocations_file if revocations_file is not None else enc(lst),
             "statement.json": stmt if isinstance(stmt, bytes) else enc(stmt)}
    decision = reader.ACCEPT if reason == "release_bound" else reader.REJECT
    return name, edit, files, decision, reason


def _with(**changes: Any) -> Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]:
    return lambda held, lst: release(held, lst, **changes)


def _edited(change: Callable[[dict[str, Any]], None]
            ) -> Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]:
    def build(held: dict[str, Any], lst: dict[str, Any]) -> dict[str, Any]:
        stmt = release(held, lst)
        change(stmt)
        return stmt
    return build


def _credential(**members: Any) -> Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]:
    return _edited(lambda s: s["predicate"]["credential"].update(members))


def accepted() -> list[Case]:
    indirect = receipt_statement(result="pass_indirect")
    return [
        case("accept-release-on-passing-receipt", "control: a fifteen-minute token released "
             "to the card a current passing receipt names, after a current list named "
             "nothing"),
        case("accept-pass-indirect-minimum", "control: the broker's minimum is pass_indirect "
             "and the receipt's result is pass_indirect", receipt=indirect,
             statement=_with(minResult="pass_indirect")),
        case("accept-ttl-ends-at-receipt-expiry", "control: the credential expires exactly when "
             "the receipt does", statement=_with(releasedAt="2026-11-18T23:00:00Z",
                                                  ttlSeconds=3600),
             revocations=listing(issued="2026-11-18T00:00:00Z",
                                 next_update="2026-11-19T00:00:00Z")),
        case("accept-released-at-receipt-issued-at", "control: the credential was released at "
             "the second the receipt was issued", statement=_with(
                 releasedAt=receipts.ISSUED),
             revocations=listing(issued=receipts.ISSUED, next_update="2026-10-21T00:00:00Z")),
    ]


def _shape_cases() -> list[Case]:
    upper = _edited(lambda s: s["subject"][0]["digest"].update(
        sha256=s["subject"][0]["digest"]["sha256"].upper()))
    return [
        case("statement-not-json", "the statement is not JSON",
             statement=lambda held, lst: b"{\"_type\": \n", reason="statement_malformed"),
        case("statement-type-wrong", "_type names in-toto Statement v0.1",
             statement=_edited(lambda s: s.update(_type="https://in-toto.io/Statement/v0.1")),
             reason="statement_type_wrong"),
        case("predicate-type-wrong", "predicateType names the agent-card-receipt predicate",
             statement=_edited(lambda s: s.update(predicateType=reader.RECEIPT_TYPE)),
             reason="predicate_type_wrong"),
        case("subject-digest-uppercase", "the subject digest is uppercase hexadecimal",
             statement=upper, reason="subject_malformed"),
        case("credential-carries-secret", "the credential object carries the token itself",
             statement=_credential(token="eyJhbGciOiJub25lIn0.e30."),
             reason="credential_fields"),
        case("credential-carries-token-hash", "the credential object carries a SHA-256 of "
             "the token, which identifies it and, for a short secret, reveals it",
             statement=_credential(tokenSha256=sha(b"eyJhbGciOiJub25lIn0.e30.")),
             reason="credential_fields"),
        case("predicate-min-result-degraded", "the broker's minimum is degraded, which is not "
             "a passing result", statement=_with(minResult="degraded"),
             reason="predicate_malformed"),
        case("predicate-ttl-zero", "ttlSeconds is zero", statement=_with(ttlSeconds=0),
             reason="predicate_malformed"),
        case("predicate-ttl-boolean", "ttlSeconds is true", statement=_with(ttlSeconds=True),
             reason="predicate_malformed"),
        case("predicate-scope-unsorted", "the credential scope is not sorted",
             statement=_credential(scope=["bookings:read", "bookings:hold"]),
             reason="predicate_malformed"),
        case("predicate-scope-empty", "the credential scope is empty",
             statement=_credential(scope=[]), reason="predicate_malformed"),
        case("predicate-receipt-type-other", "the release names a done-receipt as its basis",
             statement=_edited(lambda s: s["predicate"]["receipt"].update(
                 predicateType=receipts.DONE_RECEIPT)), reason="predicate_malformed"),
        case("predicate-broker-missing", "the release names no broker",
             statement=_edited(lambda s: s["predicate"].pop("broker")),
             reason="predicate_malformed"),
    ]


def _receipt_cases() -> list[Case]:
    degraded = receipt_statement(result="degraded")
    broken = receipt_statement()
    del broken["predicate"]["revocationList"]
    other = sha(b"a different agent card")
    return [
        case("receipt-digest-mismatch", "the receipt file is not the receipt the release names",
             statement=lambda held, lst: release(receipt_statement(result="degraded"), lst),
             reason="receipt_digest_mismatch"),
        case("receipt-malformed", "the named receipt has no revocation list URL",
             receipt=broken, reason="receipt_malformed"),
        case("receipt-fields-differ", "the release copied pass where the receipt says degraded",
             receipt=degraded, statement=_edited(lambda s: s["predicate"]["receipt"].update(
                 result="pass")), reason="receipt_fields_differ"),
        case("subject-not-receipted", "the credential went to a digest the receipt does not "
             "name", statement=lambda held, lst: release(held, lst, subject=other),
             reason="subject_not_receipted"),
        case("receipt-not-passing", "the receipt's result is degraded and the minimum is pass",
             receipt=degraded, reason="receipt_not_passing"),
        case("receipt-not-current", "the credential was released after the receipt expired",
             statement=_with(releasedAt="2026-11-19T00:00:01Z"),
             revocations=listing(issued="2026-11-19T00:00:00Z",
                                 next_update="2026-11-20T00:00:00Z"),
             reason="receipt_not_current"),
        case("receipt-not-current-at-valid-until", "the credential was released at the "
             "receipt's validUntil; the window is half open",
             statement=_with(releasedAt=receipts.UNTIL),
             revocations=listing(issued=receipts.UNTIL, next_update="2026-11-20T00:00:00Z"),
             reason="receipt_not_current"),
        case("credential-outlives-receipt", "the credential expires a second after the receipt",
             statement=_with(releasedAt="2026-11-18T23:00:00Z", ttlSeconds=3601),
             revocations=listing(issued="2026-11-18T00:00:00Z",
                                 next_update="2026-11-19T00:00:00Z"),
             reason="credential_outlives_receipt"),
    ]


def _list_cases() -> list[Case]:
    held = receipt_statement()
    mine = sha(enc(held))
    stale = listing(issued="2026-10-26T00:00:00Z", next_update="2026-10-27T12:00:00Z")
    unsorted = listing(sorted([mine, sha(b"x")], reverse=True))
    return [
        case("revocation-list-digest-mismatch", "the list file is not the list the release "
             "names", statement=lambda h, lst: release(h, listing([sha(b"x")])),
             reason="revocation_list_digest_mismatch"),
        case("revocation-list-malformed", "the consulted list's revoked digests are unsorted",
             revocations=copy.deepcopy(unsorted), reason="revocation_list_malformed"),
        case("revocation-list-other-signer", "the consulted list was signed by another key",
             revocations=listing(signer=receipts.OTHER), reason="revocation_list_signature"),
        case("revocation-list-stale", "the list's nextUpdate is the release time",
             revocations=stale, reason="revocation_list_stale"),
        case("receipt-revoked", "the consulted list names the receipt", receipt=held,
             revocations=listing([mine]), reason="receipt_revoked"),
    ]


def cases() -> list[Case]:
    """Every case: id, what it shows, files, expected decision and reason."""
    return [*accepted(), *_shape_cases(), *_receipt_cases(), *_list_cases()]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    return dict(receipts.generate(root, cases, SUITE))


if __name__ == "__main__":
    generate()
