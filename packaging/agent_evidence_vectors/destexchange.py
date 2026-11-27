"""Judge a delegated token exchanged for one token per destination.

A user's issuer mints one short-lived delegated token for an agent. The token names the
intermediaries that may exchange it (``aud``), the rights delegated (``scope``) and,
when it is holder-bound, the key the holder must prove (``cnf.jkt``, RFC 9449 section 6
and RFC 7638). An intermediary exchanges it (RFC 8693 section 2.1, ``audience`` and
``resource``) for a token aimed at one destination's verifier, after it checks the
destination against a reviewed allowlist that maps a destination name to its verifier.
The destination's verifier then states what it received.

Narrowing the destination is not narrowing the rights. A design protected only by the
token's lifetime and the intermediary's allowlist leaves four properties unshown: holder
binding, rights narrowing, a recorded exchange, and revocation before expiry. These
cases test all four, and the actor chain across the exchange (RFC 8693 section 4.1).

A record is a list of signed statements, each Ed25519 (RFC 8032) over its RFC 8785
bytes, each after the first carrying ``prev``, the SHA-256 of the previous statement's
signed bytes:

* ``origin`` (writer role ``issuer``): the delegated token it ``sent`` to the agent, and
  ``entitlements``, the user's full rights at each destination;
* ``revocation`` (role ``issuer``): the ``jti`` it revoked ``at`` a time;
* ``exchange`` (role ``exchanger``): the token it ``received`` (who presented it, where
  it was carried, and the holder ``proof``), the ``destinationCheck`` it applied (the
  destination and the SHA-256 of the RFC 8785 bytes of the allowlist it read), and the
  token it ``sent``;
* ``presentation`` (role ``destination``): the token it ``received``.

Keys, roles, the reviewed allowlist (``destinations``) and the lifetime limit
(``maxDelegatedLifetimeSeconds``) come from ``TRUST.json``, which the manifest pins by
digest, never from the record. The reader checks in the order of ``CHECKS`` and names
the first that fails; a record that passes every check is ``accept`` /
``exchange_narrowed``.

The verifier contract: ``<verifier> <case-dir>/record.json --trust <corpus>/TRUST.json
--json`` prints one JSON object with ``decision`` and ``reason`` and exits 0 for
``accept`` and 1 for ``reject``.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

from . import a2ajcs
from .actormarker import (
    Malformed,
    _ed25519_verify,
    _external_answer,
    _is_time,
    _load,
    _need,
    _seconds,
    _sha,
    _unb64url,
    b64url,
    decode,
    signing_input,
)

SUITE = "destination-narrowed-exchange/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
    "destination-narrowed-exchange"
)
ACCEPT, REJECT = "accept", "reject"
ACCEPT_REASON = "exchange_narrowed"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
#: Where a token may travel. RFC 6750 section 2 and RFC 9449 section 7.1 carry it in the
#: Authorization header; a query or form parameter leaks into logs and referrers.
CARRIERS = ("authorization-header", "query", "form-body")
HEADER = "authorization-header"
KINDS = ("revocation", "exchange", "presentation")
ROLE_FOR = {
    "origin": "issuer",
    "revocation": "issuer",
    "exchange": "exchanger",
    "presentation": "destination",
}
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "statement_writer_unknown",
    "statement_signature_invalid",
    "hop_link_broken",
    "exchange_unrecorded",
    "received_not_sent",
    "token_presented_off_destination",
    "token_in_request_parameter",
    "delegated_token_unmarked",
    "exchanger_not_intermediary",
    "delegated_token_revoked",
    "delegated_token_expired",
    "delegated_lifetime_over_limit",
    "delegated_token_unbound",
    "holder_proof_missing",
    "holder_proof_invalid",
    "destination_check_skipped",
    "destination_not_allowlisted",
    "destination_verifier_mismatch",
    "subject_replaced",
    "actor_lost_at_exchange",
    "agent_marker_dropped",
    "previous_hop_dropped",
    "exchanger_not_in_chain",
    "chain_altered_at_exchange",
    "rights_beyond_destination",
    "rights_not_narrowed",
    "rights_widened",
    "exchanged_token_expired_at_use",
)
#: The actor-chain classes across one exchange, by the check each one fails.
ACTOR_CLASSES = CHECKS[22:27]
#: The rights classes of one exchanged token, by the check each one fails.
RIGHTS_CLASSES = CHECKS[27:30]
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-destination-narrowed-exchange"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-destination-narrowed-exchange"
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

Record = dict[str, Any]


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def scopes(text: str) -> frozenset[str]:
    """The rights a space-separated ``scope`` names (RFC 6749 section 3.3)."""
    parts = text.split(" ")
    _need(all(parts) and len(parts) == len(set(parts)), "scope is not distinct names")
    return frozenset(parts)


def claims(side: dict[str, Any]) -> dict[str, Any]:
    claims_: dict[str, Any] = side["token"]["claims"]
    return claims_


def token_bytes(side: dict[str, Any]) -> bytes:
    """The RFC 8785 bytes of the token a side carries: what a proof's ``ath`` covers."""
    return a2ajcs.canonicalize({"protocol": side["protocol"], "token": side["token"]})


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638: SHA-256 over the required members in lexicographic order, no spaces,
    which for an OKP key is its RFC 8785 form."""
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    return b64url(bytes.fromhex(_sha(a2ajcs.canonicalize(required))))


def allowlist_digest(trust: dict[str, Any]) -> str:
    return _sha(a2ajcs.canonicalize(trust["destinations"]))


def _shape_token(side: Any, where: str, *, delegated: bool) -> None:
    _need(isinstance(side, dict), f"{where} is not an object")
    _need(_is_time(side.get("at")), f"{where}.at is not an RFC 3339 UTC second")
    _need(side.get("protocol") == "rfc8693", f"{where} is not an RFC 8693 token")
    decode(side)
    body = claims(side)
    _need(isinstance(body.get("scope"), str), f"{where} scope")
    scopes(body["scope"])
    _need(_int(body.get("iat")) and _int(body.get("exp")), f"{where} iat and exp")
    _need(body["iat"] <= body["exp"], f"{where} expires before it is issued")
    if delegated:
        audience = body.get("aud")
        _need(
            isinstance(audience, list) and bool(audience) and all(_text(a) for a in audience),
            "the delegated token's aud is not a list of intermediaries",
        )
        _need(_text(body.get("jti")), "the delegated token has no jti")
        cnf = body.get("cnf")
        _need(cnf is None or (isinstance(cnf, dict) and _text(cnf.get("jkt"))), "cnf")
    else:
        _need(_text(body.get("aud")), f"{where} aud is not one verifier")


def _shape_proof(proof: Any) -> None:
    _need(isinstance(proof, dict), "proof is not an object")
    jwk, payload = proof.get("jwk"), proof.get("payload")
    _need(
        isinstance(jwk, dict)
        and jwk.get("kty") == "OKP"
        and jwk.get("crv") == "Ed25519"
        and isinstance(jwk.get("x"), str),
        "proof.jwk is not an Ed25519 key",
    )
    _need(
        isinstance(payload, dict)
        and set(payload) == {"ath", "aud", "iat"}
        and isinstance(payload["ath"], str)
        and isinstance(payload["aud"], str)
        and _int(payload["iat"]),
        "proof.payload",
    )
    _need(isinstance(proof.get("signature"), str), "proof.signature")


def _shape_received(side: Any, *, exchange: bool) -> None:
    _need(isinstance(side, dict), "received is not an object")
    _need(side.get("carriedIn") in CARRIERS, "received.carriedIn")
    _shape_token(
        {k: v for k, v in side.items() if k in ("at", "protocol", "token")},
        "received",
        delegated=exchange,
    )
    if exchange:
        _need(_text(side.get("from")), "received.from")
        if "proof" in side:
            _shape_proof(side["proof"])


def _time(statement: dict[str, Any]) -> int:
    if statement["kind"] == "origin":
        return _seconds(statement["sent"]["at"])
    if statement["kind"] == "revocation":
        return _seconds(statement["at"])
    return _seconds(statement["received"]["at"])


def _shape_statement(index: int, statement: Any) -> None:
    _need(isinstance(statement, dict), "statement is not an object")
    _need(isinstance(statement.get("writer"), str), "writer is not a string")
    kind = statement.get("kind")
    _need((kind == "origin") == (index == 0), "the origin is not the first statement")
    _need(kind == "origin" or kind in KINDS, f"kind {kind!r}")
    if index:
        _need(isinstance(statement.get("prev"), str) and bool(_HEX64.match(statement["prev"])), "prev")
    if kind == "origin":
        _shape_token(statement.get("sent"), "sent", delegated=True)
        _need(_text(statement["sent"].get("to")), "sent.to")
        rights = statement.get("entitlements")
        _need(
            isinstance(rights, dict)
            and all(isinstance(v, str) for v in rights.values()),
            "entitlements",
        )
        for value in rights.values():
            scopes(value)
    elif kind == "revocation":
        _need(_is_time(statement.get("at")) and _text(statement.get("jti")), "revocation")
    elif kind == "exchange":
        _shape_received(statement.get("received"), exchange=True)
        _shape_token(statement.get("sent"), "sent", delegated=False)
        _need(_text(statement["sent"].get("to")), "sent.to")
        _need(
            _seconds(statement["received"]["at"]) <= _seconds(statement["sent"]["at"]),
            "the exchange sent before it received",
        )
        check = statement.get("destinationCheck")
        _need(
            check is None
            or (
                isinstance(check, dict)
                and set(check) == {"allowlistSha256", "destination"}
                and _text(check["destination"])
                and isinstance(check["allowlistSha256"], str)
                and bool(_HEX64.match(check["allowlistSha256"]))
            ),
            "destinationCheck",
        )
    else:
        _shape_received(statement.get("received"), exchange=False)


def _shape(record: Record) -> None:
    """Raise Malformed unless the record has the shape this contract reads."""
    items: Any = record.get("statements")
    _need(isinstance(items, list) and len(items) >= 2, "statements needs an origin and more")
    previous = None
    for index, item in enumerate(items):
        _need(isinstance(item, dict) and isinstance(item.get("signature"), str), "entry")
        _shape_statement(index, item.get("statement"))
        now = _time(item["statement"])
        _need(previous is None or previous <= now, "statements are not in time order")
        previous = now


class _Chain:
    """One shape-checked record read against one trust bundle."""

    def __init__(self, record: Record, trust: dict[str, Any]) -> None:
        self.items = record["statements"]
        self.statements: list[dict[str, Any]] = [item["statement"] for item in self.items]
        self.trust = trust
        self.writers = trust["writers"]
        self.origin = self.statements[0]
        self.delegated = claims(self.origin["sent"])

    def of(self, kind: str) -> list[tuple[int, dict[str, Any]]]:
        return [(i, s) for i, s in enumerate(self.statements) if s["kind"] == kind]

    def exchanges(self) -> list[dict[str, Any]]:
        return [s for _, s in self.of("exchange")]

    def writer_unknown(self) -> bool:
        for statement in self.statements:
            writer = self.writers.get(statement["writer"])
            if not isinstance(writer, dict) or writer.get("role") != ROLE_FOR[statement["kind"]]:
                return True
        return False

    def signature_invalid(self) -> bool:
        for item in self.items:
            key = _unb64url(self.writers[item["statement"]["writer"]].get("key"), 32)
            signature = _unb64url(item["signature"], 64)
            if key is None or signature is None:
                return True
            if not _ed25519_verify(key, signing_input(item["statement"]), signature):
                return True
        return False

    def link_broken(self) -> bool:
        return any(
            s["prev"] != _sha(signing_input(self.statements[i - 1]))
            for i, s in enumerate(self.statements)
            if i
        )

    def unrecorded(self) -> bool:
        return any(self.statements[i - 1]["kind"] != "exchange" for i, _ in self.of("presentation"))

    def received_not_sent(self) -> bool:
        issued = token_bytes(self.origin["sent"])
        if any(token_bytes(s["received"]) != issued for s in self.exchanges()):
            return True
        return any(
            token_bytes(s["received"]) != token_bytes(self.statements[i - 1]["sent"])
            for i, s in self.of("presentation")
        )

    def off_destination(self) -> bool:
        for i, s in self.of("presentation"):
            minted = self.statements[i - 1]["sent"]
            if s["writer"] != minted["to"] or s["writer"] != claims(minted)["aud"]:
                return True
        return False

    def in_parameter(self) -> bool:
        return any(
            s["received"]["carriedIn"] != HEADER
            for s in self.statements
            if s["kind"] in ("exchange", "presentation")
        )

    def unmarked(self) -> bool:
        return not decode(self.origin["sent"])[1]

    def outside_intermediaries(self) -> bool:
        return any(s["writer"] not in self.delegated["aud"] for s in self.exchanges())

    def revoked(self) -> bool:
        revoked_at: int | None = None
        for statement in self.statements:
            if statement["kind"] == "revocation" and statement["jti"] == self.delegated["jti"]:
                when = _seconds(statement["at"])
                revoked_at = when if revoked_at is None else min(revoked_at, when)
            if statement["kind"] == "exchange" and revoked_at is not None:
                if revoked_at <= _seconds(statement["received"]["at"]):
                    return True
        return False

    def expired(self) -> bool:
        return any(
            _seconds(s["received"]["at"]) >= self.delegated["exp"] for s in self.exchanges()
        )

    def lifetime_over(self) -> bool:
        limit = self.trust["maxDelegatedLifetimeSeconds"]
        return bool(self.delegated["exp"] - self.delegated["iat"] > limit)

    def unbound(self) -> bool:
        return "cnf" not in self.delegated

    def proof_missing(self) -> bool:
        return any("proof" not in s["received"] for s in self.exchanges())

    def proof_invalid(self) -> bool:
        for s in self.exchanges():
            received, proof = s["received"], s["received"]["proof"]
            jwk, payload = proof["jwk"], proof["payload"]
            key = _unb64url(jwk["x"], 32)
            signature = _unb64url(proof["signature"], 64)
            if key is None or signature is None:
                return True
            if thumbprint(jwk) != self.delegated["cnf"]["jkt"]:
                return True
            if not _ed25519_verify(key, a2ajcs.canonicalize(payload), signature):
                return True
            if payload["ath"] != b64url(bytes.fromhex(_sha(token_bytes(received)))):
                return True
            if payload["aud"] != s["writer"] or payload["iat"] != _seconds(received["at"]):
                return True
        return False

    def check_skipped(self) -> bool:
        digest = allowlist_digest(self.trust)
        return any(
            "destinationCheck" not in s or s["destinationCheck"]["allowlistSha256"] != digest
            for s in self.exchanges()
        )

    def off_allowlist(self) -> bool:
        listed = self.trust["destinations"]
        return any(s["destinationCheck"]["destination"] not in listed for s in self.exchanges())

    def verifier_mismatch(self) -> bool:
        listed = self.trust["destinations"]
        for s in self.exchanges():
            verifier = listed[s["destinationCheck"]["destination"]]["verifier"]
            if s["sent"]["to"] != verifier or claims(s["sent"])["aud"] != verifier:
                return True
        return False

    def subject_replaced(self) -> bool:
        return any(decode(s["sent"])[0] != decode(s["received"])[0] for s in self.exchanges())

    def actor_class(self, name: str) -> bool:
        return any(
            classify(decode(s["received"])[1], s["writer"], decode(s["sent"])[1]) == name
            for s in self.exchanges()
        )

    def rights_class(self, name: str) -> bool:
        for s in self.exchanges():
            destination = s["destinationCheck"]["destination"]
            full = self.origin["entitlements"].get(destination, "")
            found = rights(
                destination,
                scopes(self.delegated["scope"]),
                scopes(full) if full else frozenset(),
                scopes(claims(s["sent"])["scope"]),
            )
            if found == name:
                return True
        return False

    def exchanged_expired(self) -> bool:
        return any(
            _seconds(s["received"]["at"]) >= claims(self.statements[i - 1]["sent"])["exp"]
            for i, s in self.of("presentation")
        )


def classify(received: tuple[str, ...], exchanger: str, sent: tuple[str, ...]) -> str | None:
    """The actor-chain check an exchanged token fails, or None.

    The exchanged token owes the received chain with the exchanger appended as the
    current actor (RFC 8693 section 4.1)."""
    owed = (*received, exchanger)
    if sent == owed:
        return None
    if not sent:
        return "actor_lost_at_exchange"
    if received and received[-1] not in sent:
        return "agent_marker_dropped"
    if len(sent) < len(owed) and owed[len(owed) - len(sent) :] == sent:
        return "previous_hop_dropped"
    if sent == received:
        return "exchanger_not_in_chain"
    return "chain_altered_at_exchange"


def rights(
    destination: str, delegated: frozenset[str], full: frozenset[str], sent: frozenset[str]
) -> str | None:
    """The rights check an exchanged token fails, or None.

    The token for one destination may carry only rights the delegation names for that
    destination: a name ``<destination>:<right>`` in the delegated ``scope``."""
    here = frozenset(s for s in delegated if s.startswith(destination + ":"))
    if any(not s.startswith(destination + ":") for s in sent):
        return "rights_beyond_destination"
    if sent <= here:
        return None
    if sent == full and here < full:
        return "rights_not_narrowed"
    return "rights_widened"


def _first_failure(
    record: Record, trust: dict[str, Any], skip: frozenset[str] = frozenset()
) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each check is
    forced by some member; a verifier never sets it."""
    if "contract_id_missing" not in skip and "contractId" not in record:
        return "contract_id_missing"
    if "contract_id_unknown" not in skip and record.get("contractId", CONTRACT_ID) != CONTRACT_ID:
        return "contract_id_unknown"
    try:
        _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return None if "record_malformed" in skip else "record_malformed"
    chain = _Chain(record, trust)
    ordered: list[tuple[str, Callable[[], bool]]] = [
        ("statement_writer_unknown", chain.writer_unknown),
        ("statement_signature_invalid", chain.signature_invalid),
        ("hop_link_broken", chain.link_broken),
        ("exchange_unrecorded", chain.unrecorded),
        ("received_not_sent", chain.received_not_sent),
        ("token_presented_off_destination", chain.off_destination),
        ("token_in_request_parameter", chain.in_parameter),
        ("delegated_token_unmarked", chain.unmarked),
        ("exchanger_not_intermediary", chain.outside_intermediaries),
        ("delegated_token_revoked", chain.revoked),
        ("delegated_token_expired", chain.expired),
        ("delegated_lifetime_over_limit", chain.lifetime_over),
        ("delegated_token_unbound", chain.unbound),
        ("holder_proof_missing", chain.proof_missing),
        ("holder_proof_invalid", chain.proof_invalid),
        ("destination_check_skipped", chain.check_skipped),
        ("destination_not_allowlisted", chain.off_allowlist),
        ("destination_verifier_mismatch", chain.verifier_mismatch),
        ("subject_replaced", chain.subject_replaced),
        *[(n, (lambda n=n: chain.actor_class(n))) for n in ACTOR_CLASSES],
        *[(n, (lambda n=n: chain.rights_class(n))) for n in RIGHTS_CLASSES],
        ("exchanged_token_expired_at_use", chain.exchanged_expired),
    ]
    # A check reads only fields every earlier check has vouched for, so a skipped check
    # stops the run when it would have failed: later checks never see what it guards.
    for name, fails in ordered:
        if fails():
            return None if name in skip else name
    return None


def judge(
    record: Record, trust: dict[str, Any], skip: frozenset[str] = frozenset()
) -> dict[str, str]:
    failure = _first_failure(record, trust, skip)
    if failure is not None:
        return {"decision": REJECT, "reason": failure}
    return {"decision": ACCEPT, "reason": ACCEPT_REASON}


def verify(
    record_path: Path, trust_path: Path | None = None, skip: frozenset[str] = frozenset()
) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    trust = _load(trust_path or (record_path.parents[2] / "TRUST.json"))
    try:
        record = _load(record_path)
    except (ValueError, UnicodeDecodeError):
        return {"decision": REJECT, "reason": "record_malformed"}
    if not isinstance(record, dict):
        return {"decision": REJECT, "reason": "record_malformed"}
    return judge(record, trust, skip)


def retained(record: Record) -> dict[str, Any]:
    """What a verifier keeps: each destination's delivered principals and rights, and
    each statement's digest."""
    try:
        _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return {"delivered": None, "signingInputs": []}
    delivered = []
    for item in record["statements"]:
        statement = item["statement"]
        if statement["kind"] != "presentation":
            continue
        subject, actors = decode(statement["received"])
        delivered.append(
            {
                "actors": list(actors),
                "rights": sorted(scopes(claims(statement["received"])["scope"])),
                "subject": subject,
                "verifier": statement["writer"],
            }
        )
    return {
        "delivered": delivered,
        "signingInputs": [_sha(signing_input(i["statement"])) for i in record["statements"]],
    }


def _load_corpus(root: Path) -> tuple[list[dict[str, Any]], Path, dict[str, Any]]:
    entries, manifest_error = _validated_entries(root, SUITE)
    if manifest_error:
        raise ValueError(manifest_error)
    manifest = _load(root / "MANIFEST.json")
    trust_path = root / "TRUST.json"
    if _sha(trust_path.read_bytes()) != manifest["trustSha256"]:
        raise ValueError("TRUST.json does not match the digest the manifest pins")
    return entries, trust_path, _load(trust_path)


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT, skip: frozenset[str] = frozenset()
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    try:
        entries, trust_path, _ = _load_corpus(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        record_path = directory / "record.json"
        if retained(_load(record_path)) != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, trust_path, skip)
        else:
            ran, observed = _external_answer(command, record_path, trust_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument("--trust", help="the trust bundle (default: TRUST.json of the corpus)")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record), Path(args.trust) if args.trust else None)
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(_load(ROOT / "MANIFEST.json")["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
