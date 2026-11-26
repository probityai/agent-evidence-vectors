"""Build the credential-release cases byte-identically.

Every case is an unsigned in-toto Statement recording that a broker released a
credential to a named agent (spec/predicates/credential-release.md, version
0.2.0) and the basis it names. A receipt basis case also holds the agent-card
receipt it released against, the revocation list it says it consulted, and a
context naming the receipt signer's public key; a grant basis case holds the
user's grant document. Each rejected case is built so the check it names is the
first that fails; each accepted case is a control.

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
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

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
AGENT = {"issuer": "https://idp.example.com/realms/agents", "subject": "travel-agent"}
MAIL_AGENT = {"issuer": "https://idp.example.com/realms/agents", "subject": "mail-agent"}
USER = {"issuer": "https://idp.example.com/realms/users", "subject": "user-0001"}
SITE = "mail.example.com"
GRANT_ENDS = "2026-10-27T18:00:00Z"


def receipt_statement(**changes: Any) -> dict[str, Any]:
    return dict(receipts.receipt(**changes))


def listing(revoked: list[str] | None = None, **changes: Any) -> dict[str, Any]:
    return dict(receipts.revocation_list(revoked or [], **changes))


def release(receipt: dict[str, Any], revocations: dict[str, Any], *,
            subject: str | None = None, **changes: Any) -> dict[str, Any]:
    """A release on ``receipt`` that copies its result and validUntil."""
    held = receipt["predicate"]
    predicate: dict[str, Any] = {
        "agent": dict(AGENT), "broker": {"id": BROKER},
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


def grant_document(**changes: Any) -> dict[str, Any]:
    """The user's grant: this agent may use this user's login at these hosts until notAfter."""
    grant: dict[str, Any] = {"agent": dict(MAIL_AGENT), "grantId": "grant-0001",
                             "hosts": [SITE], "notAfter": GRANT_ENDS, "user": dict(USER)}
    grant.update(changes)
    return grant


def grant_release(grant: dict[str, Any], *, grant_bytes: bytes | None = None,
                  **changes: Any) -> dict[str, Any]:
    """A browser session release of the user's cookie under ``grant``, which it names."""
    digest = sha(enc(grant) if grant_bytes is None else grant_bytes)
    predicate: dict[str, Any] = {
        "agent": dict(MAIL_AGENT), "broker": {"id": BROKER},
        "credential": {"audience": f"https://{SITE}", "cookie": "sid", "kind": "session-cookie"},
        "grant": {"digest": {"sha256": digest}, "notAfter": grant["notAfter"]},
        "onBehalfOf": dict(USER), "releaseId": "release-0001", "releasedAt": RELEASED,
        "ttlSeconds": 900,
    }
    predicate.update(changes)
    return {"_type": reader.STATEMENT_TYPE, "predicate": predicate,
            "predicateType": reader.RELEASE_TYPE,
            "subject": [{"digest": {"sha256": digest}, "name": grant["grantId"]}]}


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


def grant_case(name: str, edit: str, *, grant: dict[str, Any] | None = None,
               statement: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
               grant_file: bytes | None = None, reason: str = "release_bound") -> Case:
    held = grant_document() if grant is None else grant
    stmt = (statement or grant_release)(held)
    files = {"statement.json": enc(stmt)}
    if grant_file != b"":
        files["grant.json"] = grant_file if grant_file is not None else enc(held)
    decision = reader.ACCEPT if reason == "release_bound" else reader.REJECT
    return name, edit, files, decision, reason


def _granted(**changes: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda held: grant_release(held, **changes)


def _grant_edited(change: Callable[[dict[str, Any]], None]
                  ) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def build(held: dict[str, Any]) -> dict[str, Any]:
        stmt = grant_release(held)
        change(stmt["predicate"])
        return stmt
    return build


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
        case("accept-receipt-on-behalf-of-user", "control: the release names the user the "
             "agent acted for", statement=_with(onBehalfOf=dict(USER))),
        case("accept-session-cookie-on-receipt", "control: a session cookie released to an "
             "agent a passing receipt names", statement=_with(credential={
                 "audience": "https://bookings.example.com", "cookie": "sid",
                 "kind": "session-cookie"}, onBehalfOf=dict(USER))),
    ]


def accepted_grants() -> list[Case]:
    return [
        grant_case("accept-session-cookie-on-grant", "control: a browser session released "
                   "the user's cookie to the agent and host the user's grant names"),
        grant_case("accept-session-cookie-plain-http-origin", "control: the cookie went to "
                   "a plain HTTP origin, which the record states",
                   statement=_grant_edited(lambda p: p["credential"].update(
                       audience=f"http://{SITE}"))),
        grant_case("accept-session-cookie-non-default-port", "control: the grant names a "
                   "host with its port and the origin carries it",
                   grant=grant_document(hosts=["127.0.0.1:8443", SITE]),
                   statement=_grant_edited(lambda p: p["credential"].update(
                       audience="https://127.0.0.1:8443"))),
        grant_case("accept-release-ends-at-grant-end", "control: the release ends exactly "
                   "when the grant does", statement=_granted(
                       releasedAt="2026-10-27T17:00:00Z", ttlSeconds=3600)),
        grant_case("accept-token-on-grant", "control: a scoped token released under the "
                   "user's grant to an API on a granted host", statement=_granted(
                       credential={"audience": f"https://{SITE}/api",
                                   "kind": "oauth2-access-token", "scope": ["mail:read"]})),
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
        case("predicate-v0-1-without-agent", "a 0.1.0 record: it names no agent",
             statement=_edited(lambda s: s["predicate"].pop("agent")),
             reason="predicate_malformed"),
        case("predicate-agent-issuer-not-https", "the agent's issuer is not an https URL",
             statement=_with(agent={"issuer": "idp.example.com", "subject": "travel-agent"}),
             reason="predicate_malformed"),
        case("predicate-on-behalf-of-extra-member", "the user principal also carries an "
             "email address", statement=_with(onBehalfOf={**USER, "email": "a@example.com"}),
             reason="predicate_malformed"),
        case("predicate-receipt-and-grant", "the release names a receipt and a grant",
             statement=_with(grant={"digest": {"sha256": sha(b"g")}, "notAfter": GRANT_ENDS},
                             onBehalfOf=dict(USER)), reason="predicate_malformed"),
        case("credential-carries-cookie-value", "the credential object carries the cookie's "
             "value", statement=_credential(value="user-session-value"),
             reason="credential_fields"),
        case("credential-session-cookie-with-scope", "a session cookie claims a scope",
             statement=_with(credential={"audience": "https://bookings.example.com",
                                         "cookie": "sid", "kind": "session-cookie",
                                         "scope": ["bookings:read"]}),
             reason="predicate_malformed"),
        case("credential-token-audience-plain-http", "a token names a plain HTTP audience, "
             "which only a session cookie may", statement=_credential(
                 audience="http://api.travel-bookings.example.com"),
             reason="predicate_malformed"),
    ]


def _grant_shape_cases() -> list[Case]:
    return [
        grant_case("predicate-grant-without-on-behalf-of", "a grant basis release names no "
                   "user", statement=_grant_edited(lambda p: p.pop("onBehalfOf")),
                   reason="predicate_malformed"),
        grant_case("predicate-grant-with-min-result", "a grant basis release carries a "
                   "receipt basis member", statement=_granted(minResult="pass"),
                   reason="predicate_malformed"),
        grant_case("predicate-grant-not-after-not-a-time", "the grant's copied notAfter is "
                   "not an RFC 3339 time", statement=_grant_edited(
                       lambda p: p["grant"].update(notAfter="2026-10-27")),
                   reason="predicate_malformed"),
        grant_case("credential-session-cookie-audience-path", "the cookie's origin carries "
                   "a path", statement=_grant_edited(lambda p: p["credential"].update(
                       audience=f"https://{SITE}/inbox")), reason="predicate_malformed"),
        grant_case("credential-session-cookie-default-port", "the cookie's origin writes the "
                   "default port", statement=_grant_edited(lambda p: p["credential"].update(
                       audience=f"https://{SITE}:443")), reason="predicate_malformed"),
        grant_case("credential-session-cookie-uppercase-host", "the cookie's origin host is "
                   "not lowercase", statement=_grant_edited(lambda p: p["credential"].update(
                       audience="https://Mail.example.com")), reason="predicate_malformed"),
        grant_case("credential-cookie-name-not-token", "the cookie name holds a space",
                   statement=_grant_edited(lambda p: p["credential"].update(
                       cookie="session id")), reason="predicate_malformed"),
    ]


def _grant_cases() -> list[Case]:
    other_user = {"issuer": USER["issuer"], "subject": "user-0002"}
    held = grant_document()
    return [
        grant_case("grant-digest-mismatch", "the grant file is not the grant the release names",
                   statement=lambda g: grant_release(grant_document(hosts=["other.example"])),
                   reason="grant_digest_mismatch"),
        grant_case("grant-absent", "the release names a grant and none is given",
                   grant_file=b"", reason="grant_digest_mismatch"),
        grant_case("grant-malformed-hosts-unsorted", "the grant's hosts are not sorted",
                   grant=grant_document(hosts=[SITE, "calendar.example.com"]),
                   reason="grant_malformed"),
        grant_case("grant-malformed-host-has-scheme", "the grant writes a host as a URL",
                   grant=grant_document(hosts=[f"https://{SITE}"]), reason="grant_malformed"),
        grant_case("grant-malformed-not-json", "the grant file is not JSON",
                   grant_file=b"{\"grantId\": \n",
                   statement=lambda g: grant_release(g, grant_bytes=b"{\"grantId\": \n"),
                   reason="grant_malformed"),
        grant_case("grant-fields-differ", "the release copied a later end than the grant's",
                   statement=_grant_edited(lambda p: p["grant"].update(
                       notAfter="2026-10-28T18:00:00Z")), reason="grant_fields_differ"),
        grant_case("subject-not-granted", "the subject names a digest the release's grant "
                   "member does not", statement=lambda g: {
                       **grant_release(g), "subject": [{"digest": {"sha256": sha(b"x")},
                                                        "name": g["grantId"]}]},
                   reason="subject_not_granted"),
        grant_case("principals-agent-not-granted", "another agent received the cookie",
                   statement=_granted(agent=dict(AGENT)), reason="principals_not_granted"),
        grant_case("principals-agent-issuer-differs", "the agent's subject is granted under "
                   "another issuer", statement=_granted(agent={
                       "issuer": "https://other-idp.example.com", "subject": "mail-agent"}),
                   reason="principals_not_granted"),
        grant_case("principals-user-not-granted", "the release names a user who did not "
                   "grant", statement=_granted(onBehalfOf=other_user),
                   reason="principals_not_granted"),
        grant_case("audience-not-granted", "the cookie went to a host the grant does not name",
                   statement=_grant_edited(lambda p: p["credential"].update(
                       audience="https://tracker.example.net")),
                   reason="audience_not_granted"),
        grant_case("audience-port-not-granted", "the cookie went to the granted host on "
                   "another port", statement=_grant_edited(lambda p: p["credential"].update(
                       audience=f"https://{SITE}:8443")), reason="audience_not_granted"),
        grant_case("grant-not-current", "the release was made at the grant's end; the grant "
                   "holds until, not at, notAfter", statement=_granted(releasedAt=GRANT_ENDS),
                   reason="grant_not_current"),
        grant_case("grant-not-current-after-end", "the release was made after the grant "
                   "ended", grant=held, statement=_granted(releasedAt="2026-10-28T00:00:00Z"),
                   reason="grant_not_current"),
        grant_case("credential-outlives-grant", "the release ends a second after the grant",
                   statement=_granted(releasedAt="2026-10-27T17:00:00Z", ttlSeconds=3601),
                   reason="credential_outlives_grant"),
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
    return [*accepted(), *accepted_grants(), *_shape_cases(), *_grant_shape_cases(),
            *_receipt_cases(), *_list_cases(), *_grant_cases()]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    return dict(receipts.generate(root, cases, SUITE))


if __name__ == "__main__":
    generate()
