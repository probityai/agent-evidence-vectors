"""Judge whether a presenter holds the key its credential confirms.

A record is one credential and the proofs of possession presented with it. The
credential states, as claims its issuer already vouched for, whom it names (``subject``),
when it is valid, the token a proof must bind to, and the key it confirms: ``cnf.jkt``, the
RFC 7638 thumbprint of the holder's public key (RFC 7800 section 3.1, RFC 9449 section 6).
Each presentation is an HTTP request (``htm``, ``htu``), the time the relying party saw it
(``at``) and a DPoP proof JWT (RFC 9449 section 4.2) in flattened JWS JSON form (RFC 7515
section 7.2.2: ``protected``, ``payload``, ``signature``).

This contract tests possession only. Whether the credential's own claims are genuine is the
question a level 1 test answers about the same subject (identity-assurance-levels/v1), so a
record here never carries the issuer's signature and no key is chosen by the data it is
judged on: the verifying key is the one the credential confirms, and a proof whose header
carries any other key is refused before its signature counts.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. it is this contract (``contract_id_unknown``);
3. the record has the shape below (``record_malformed``);
4. the credential confirms a key (``credential_not_holder_bound``: a bearer credential is
   usable by whoever copies it);
5. the credential is valid at every presentation (``credential_not_yet_valid``,
   ``credential_expired``; the window is half-open, ``iat <= at < exp``);
6. every proof is a compact JWS whose header and payload are strict JSON objects
   (``proof_malformed``);
7. every header ``typ`` is ``dpop+jwt`` (``proof_type_wrong``; RFC 9449 section 4.2);
8. no header ``alg`` is ``none`` or a MAC (``proof_alg_forbidden``; RFC 9449 section 4.2);
9. every header ``alg`` is ``EdDSA``, the algorithm this profile reads
   (``proof_alg_unsupported``);
10. every header ``jwk`` is a public Ed25519 key in the prime-order subgroup and carries no
    private member (``proof_key_invalid``; RFC 9449 section 4.2). A key of small order, or one
    with a torsion component, is refused: the identity point verifies the signature
    (identity, 0) over every message, so a credential confirming it is usable by anyone;
11. every signature verifies under the key in its own header (``proof_signature_invalid``);
12. every payload has a string ``jti``, ``htm`` and ``htu`` and an integer ``iat``
    (``proof_claims_malformed``);
13. ``htm`` is the request's method (``proof_method_mismatch``);
14. ``htu`` is the request's target URI without query and fragment (``proof_uri_mismatch``);
15. ``iat`` is no older than 60 seconds before ``at`` (``proof_stale``);
16. ``iat`` is no more than 5 seconds after ``at`` (``proof_from_future``);
17. every payload carries ``ath`` (``proof_ath_missing``);
18. ``ath`` is the base64url SHA-256 of the credential's token (``proof_ath_mismatch``);
19. the RFC 7638 thumbprint of the header key is the credential's ``cnf.jkt``
    (``proof_key_not_bound``);
20. no ``jti`` is presented twice in the record (``proof_replayed``).

A record that passes all twenty is ``accept`` / ``holder_bound``.

The verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object
with ``decision`` and ``reason`` and exits 0 for ``accept`` and 1 for ``reject``.
"""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import importlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

from . import strictjson

SUITE = "holder-bound-credential/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/holder-bound-credential"
)
ACCEPT, REJECT = "accept", "reject"
ACCEPT_REASON = "holder_bound"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
#: Seconds a proof's ``iat`` may precede the time the relying party saw it, and follow it.
MAX_AGE, MAX_AHEAD = 60, 5
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "credential_not_holder_bound",
    "credential_not_yet_valid",
    "credential_expired",
    "proof_malformed",
    "proof_type_wrong",
    "proof_alg_forbidden",
    "proof_alg_unsupported",
    "proof_key_invalid",
    "proof_signature_invalid",
    "proof_claims_malformed",
    "proof_method_mismatch",
    "proof_uri_mismatch",
    "proof_stale",
    "proof_from_future",
    "proof_ath_missing",
    "proof_ath_mismatch",
    "proof_key_not_bound",
    "proof_replayed",
)
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-holder-bound-credential"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-holder-bound-credential"
)
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k", "oth")

Record = dict[str, Any]


class Malformed(ValueError):
    """The record does not have the shape this contract reads."""


@dataclass(frozen=True)
class Proof:
    """One presentation, decoded. ``header`` and ``claims`` are None when the JWS is not."""

    at: int
    method: str
    uri: str
    signing_input: bytes
    header: dict[str, Any] | None
    claims: dict[str, Any] | None
    signature: bytes


def _rail() -> Any:
    """The reference rail's pure-Python Ed25519, resolved at call time (the rail imports
    this module to dispatch the suite, so a module-level import is a cycle)."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "ed25519_verify"):
            return module
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url(data: bytes) -> str:
    """Unpadded base64url, the encoding of every key, signature and digest here."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: Any) -> bytes | None:
    """The bytes of canonical unpadded base64url ``text``, or None when it is not."""
    if not isinstance(text, str) or not _B64URL.match(text) or len(text) % 4 == 1:
        return None
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return data if b64url(data) == text else None


def thumbprint(jwk: dict[str, Any]) -> str:
    """The RFC 7638 SHA-256 thumbprint of a public OKP key."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    text = json.dumps(members, sort_keys=True, separators=(",", ":"))
    return b64url(hashlib.sha256(text.encode("ascii")).digest())


def ath(token: str) -> str:
    """The ``ath`` claim of RFC 9449 section 4.2 for an access token."""
    return b64url(hashlib.sha256(token.encode("ascii")).digest())


def _need(condition: bool, what: str) -> None:
    if not condition:
        raise Malformed(what)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _shape(record: Record) -> None:
    _need(isinstance(record, dict), "record is not an object")
    _need(set(record) == {"contractId", "subject", "credential", "presentations"}, "members")
    _need(_is_text(record["subject"]), "subject")
    credential = record["credential"]
    _need(isinstance(credential, dict), "credential")
    allowed = {"issuer", "iat", "exp", "token"}
    _need(allowed <= set(credential) <= allowed | {"cnf"}, "credential members")
    _need(_is_text(credential["issuer"]), "issuer")
    _need(_is_int(credential["iat"]) and _is_int(credential["exp"]), "validity")
    _need(credential["iat"] < credential["exp"], "validity order")
    token = credential["token"]
    _need(_is_text(token) and token.isascii(), "token")
    if "cnf" in credential:
        cnf = credential["cnf"]
        _need(isinstance(cnf, dict) and set(cnf) == {"jkt"}, "cnf members")
        _need(unb64url(cnf["jkt"]) is not None and len(unb64url(cnf["jkt"]) or b"") == 32, "jkt")
    presentations = record["presentations"]
    _need(isinstance(presentations, list) and bool(presentations), "presentations")
    for item in presentations:
        _need(isinstance(item, dict) and set(item) == {"at", "request", "proof"}, "presentation")
        _need(_is_int(item["at"]), "at")
        request = item["request"]
        _need(isinstance(request, dict) and set(request) == {"htm", "htu"}, "request members")
        _need(_is_text(request["htm"]) and _is_text(request["htu"]), "request values")
        _need(not set("?#") & set(request["htu"]), "htu carries a query or fragment")
        proof = item["proof"]
        _need(
            isinstance(proof, dict)
            and set(proof) == {"protected", "payload", "signature"}
            and all(isinstance(v, str) for v in proof.values()),
            "proof is not a flattened JWS",
        )


def _decode_proof(item: dict[str, Any]) -> Proof:
    """Decode one presentation; a proof that is not a JWS leaves header None.

    The proof is the flattened JWS JSON serialization of RFC 7515 section 7.2.2: its three
    segments are the members ``protected``, ``payload`` and ``signature``, and the bytes that
    were signed are ``protected`` + "." + ``payload``, exactly as in the compact form.
    """
    proof = item["proof"]
    parts = [proof["protected"], proof["payload"], proof["signature"]]
    request = item["request"]
    blank = Proof(item["at"], request["htm"], request["htu"], b"", None, None, b"")
    # An unsecured JWS (alg none) has an empty signature segment; it still decodes, so the
    # algorithm check, not a decoding error, is what refuses it.
    raw = [unb64url(parts[0]), unb64url(parts[1]), b"" if parts[2] == "" else unb64url(parts[2])]
    if any(part is None for part in raw):
        return blank
    try:
        header = strictjson.loads(raw[0].decode("utf-8"))  # type: ignore[union-attr]
        claims = strictjson.loads(raw[1].decode("utf-8"))  # type: ignore[union-attr]
    except (ValueError, UnicodeDecodeError):
        return blank
    if not isinstance(header, dict) or not isinstance(claims, dict) or "crit" in header:
        return blank
    signing = f"{parts[0]}.{parts[1]}".encode("ascii")
    return Proof(item["at"], request["htm"], request["htu"], signing, header, claims, raw[2] or b"")


@functools.lru_cache(maxsize=256)
def _prime_order(raw: bytes) -> bool:
    """Whether ``raw`` encodes a point of the prime-order subgroup other than the identity, as an
    honest key does.

    A point of small order (the identity, the order-2 point, the order-4 and order-8 points)
    verifies a forged signature over a message the forger chooses, and a point with a torsion
    component is read differently by cofactored and cofactorless verifiers, so neither is a
    key whose holder alone can sign.
    """
    rail = _rail()
    point = rail._pt_decompress(raw)
    if point is None:
        return False
    identity = (0, 1, 1, 0)
    return not rail._pt_eq(point, identity) and bool(
        rail._pt_eq(rail._pt_mul(rail._L, point), identity)
    )


def _key_of(proof: Proof) -> dict[str, Any] | None:
    """The header key when it is a public Ed25519 key of prime order with exactly its three members."""
    jwk = (proof.header or {}).get("jwk")
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x"}:
        return None
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
        return None
    raw = unb64url(jwk["x"])
    return jwk if raw is not None and len(raw) == 32 and _prime_order(raw) else None


def _signature_holds(proof: Proof) -> bool:
    jwk = _key_of(proof)
    if jwk is None or len(proof.signature) != 64:
        return False
    key = unb64url(jwk["x"]) or b""
    return bool(_rail().ed25519_verify(key, proof.signing_input, proof.signature))


def _claims_ok(proof: Proof) -> bool:
    c = proof.claims or {}
    return (
        _is_text(c.get("jti"))
        and _is_text(c.get("htm"))
        and _is_text(c.get("htu"))
        and _is_int(c.get("iat"))
    )


def _first_failure(record: Record, skip: frozenset[str] = frozenset()) -> str | None:
    contract = record.get("contractId") if isinstance(record, dict) else None
    shaped = {"ok": True}

    def malformed() -> bool:
        try:
            _shape(record)
        except (Malformed, KeyError, TypeError, ValueError, AttributeError):
            shaped["ok"] = False
        return not shaped["ok"]

    cache: dict[str, list[Proof]] = {}

    def proofs() -> list[Proof]:
        if "p" not in cache:
            cache["p"] = [_decode_proof(item) for item in record["presentations"]]
        return cache["p"]

    def decoded(check: Callable[[Proof], bool]) -> bool:
        return any(check(p) for p in proofs() if p.header is not None and p.claims is not None)

    def credential() -> dict[str, Any]:
        value: dict[str, Any] = record["credential"]
        return value

    def not_bound(p: Proof) -> bool:
        jwk = _key_of(p)
        return jwk is not None and thumbprint(jwk) != credential().get("cnf", {}).get("jkt")

    def replayed() -> bool:
        seen = [p.claims["jti"] for p in proofs() if p.claims and "jti" in p.claims]  # type: ignore[index]
        return len(seen) != len(set(map(str, seen)))

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: not isinstance(record, dict) or "contractId" not in record,
        "contract_id_unknown": lambda: contract != CONTRACT_ID,
        "record_malformed": malformed,
        "credential_not_holder_bound": lambda: "cnf" not in credential(),
        "credential_not_yet_valid": lambda: any(
            i["at"] < credential()["iat"] for i in record["presentations"]
        ),
        "credential_expired": lambda: any(
            i["at"] >= credential()["exp"] for i in record["presentations"]
        ),
        "proof_malformed": lambda: any(p.header is None or p.claims is None for p in proofs()),
        "proof_type_wrong": lambda: decoded(lambda p: (p.header or {}).get("typ") != "dpop+jwt"),
        "proof_alg_forbidden": lambda: decoded(
            lambda p: str((p.header or {}).get("alg")).lower() == "none"
            or str((p.header or {}).get("alg")).upper().startswith("HS")
        ),
        "proof_alg_unsupported": lambda: decoded(lambda p: (p.header or {}).get("alg") != "EdDSA"),
        "proof_key_invalid": lambda: decoded(
            lambda p: _key_of(p) is None
            or any(m in ((p.header or {}).get("jwk") or {}) for m in _PRIVATE_MEMBERS)
        ),
        "proof_signature_invalid": lambda: decoded(lambda p: not _signature_holds(p)),
        "proof_claims_malformed": lambda: decoded(lambda p: not _claims_ok(p)),
        "proof_method_mismatch": lambda: decoded(lambda p: (p.claims or {}).get("htm") != p.method),
        "proof_uri_mismatch": lambda: decoded(lambda p: (p.claims or {}).get("htu") != p.uri),
        "proof_stale": lambda: decoded(lambda p: (p.claims or {}).get("iat", 0) < p.at - MAX_AGE),
        "proof_from_future": lambda: decoded(
            lambda p: (p.claims or {}).get("iat", 0) > p.at + MAX_AHEAD
        ),
        "proof_ath_missing": lambda: decoded(lambda p: "ath" not in (p.claims or {})),
        "proof_ath_mismatch": lambda: decoded(
            lambda p: (p.claims or {}).get("ath") != ath(credential()["token"])
        ),
        "proof_key_not_bound": lambda: decoded(not_bound),
        "proof_replayed": replayed,
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def judge(record: Record, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The decision and reason for one decoded record."""
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": REJECT, "reason": failure}
    return {"decision": ACCEPT, "reason": ACCEPT_REASON}


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    try:
        record = _load(record_path)
    except (ValueError, UnicodeDecodeError):
        return {"decision": REJECT, "reason": "record_malformed"}
    if not isinstance(record, dict):
        return {"decision": REJECT, "reason": "record_malformed"}
    return judge(record, skip)


def retained(record: Record) -> dict[str, Any]:
    """What a verifier keeps: the subject and the key the credential confirms."""
    try:
        _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return {"subject": None, "jkt": None}
    cnf = record["credential"].get("cnf")
    return {"subject": record["subject"], "jkt": cnf["jkt"] if cnf else None}


def _external_answer(command: list[str], record: Path) -> tuple[bool, dict[str, Any] | str]:
    import subprocess

    try:
        result = subprocess.run(
            [*command, str(record), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    import shlex

    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
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
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
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
    import argparse

    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
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
