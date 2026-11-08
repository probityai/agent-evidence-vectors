"""Judge recorded per-request agent proofs as durable evidence.

An agent that signs every HTTP request with a short-lived RS256 proof JWT binds
the request to its key: the proof names the method (``htm``), the path
(``htu``), the SHA-256 of the transmitted body (``body_sha256``), a single-use
``jti`` and a lifetime of at most sixty seconds. The service that receives the
request checks the proof and then discards it, so nobody after the call can
re-check what the agent asked for. The ``agent-request-proof/v1`` predicate
keeps it: an in-toto Statement v1, serialised as RFC 8785 bytes and signed in a
DSSE envelope by the recorder that received the request, whose subject is the
body digest and whose predicate carries the request, the compact proof, the
principal's public JWK with its registered RFC 7638 thumbprint, and the time
the recorder observed the request. A third party re-runs every check the
receiving service ran, offline, after the call.

The principal block is a verified principal, not a reported one: the record
carries the key the proof verifies under and the thumbprint it was registered
by, so a reader recomputes the binding instead of trusting an authentication
method the recorder wrote down.

Each case is ``case.json`` naming the recorder's Ed25519 public key and an
ordered list of envelopes, all from one recorder. Every envelope but the last
is a prior record that verifies; the decision is the last envelope's. The
reader checks in a fixed order and names the first check that fails:

1. the payload is an in-toto Statement v1 of this predicate type with one
   sha256 subject and every predicate member (``statement_malformed``);
2. the DSSE signature verifies under the recorder key
   (``recorder_signature_invalid``);
3. the proof header's ``typ`` is the profile's (``typ_mismatch``);
4. the header's ``alg`` is ``RS256`` and it embeds no ``jwk``, ``jku`` or
   ``x5u`` (``alg_not_allowed``);
5. the RFC 7638 thumbprint of the principal JWK is the registered thumbprint
   (``thumbprint_mismatch``);
6. the proof's RS256 signature verifies under that JWK, a modulus of at least
   2048 bits (``proof_signature_invalid``);
7. the proof's ``iss`` and ``sub`` are the principal's issuer and subject
   (``principal_mismatch``);
8. ``htm`` and ``htu`` are the recorded method and path
   (``htm_htu_mismatch``);
9. ``body_sha256`` and the statement subject are the SHA-256 of the recorded
   body (``body_digest_mismatch``);
10. ``iat`` <= observedAt < ``exp`` and ``exp - iat`` is at most the profile's
    lifetime (``proof_expired``);
11. no earlier record from the recorder carries the same issuer and ``jti``
    (``replayed_jti``).

A record that passes all eleven is ``verified`` with reason ``request_bound``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``verified`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "agent-request-proof/v1"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-request-proof"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
# The proof profiles this suite reads, keyed by the header typ the predicate names.
PROFILES: dict[str, dict[str, Any]] = {
    "openbox-agent-proof+jwt": {"alg": "RS256", "maxLifetime": 60},
}
MIN_MODULUS_BITS = 2048
EMBEDDED_KEY_HEADERS = ("jwk", "jku", "x5u", "x5c")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "statement_malformed",
    "recorder_signature_invalid",
    "typ_mismatch",
    "alg_not_allowed",
    "thumbprint_mismatch",
    "proof_signature_invalid",
    "principal_mismatch",
    "htm_htu_mismatch",
    "body_digest_mismatch",
    "proof_expired",
    "replayed_jti",
)
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-agent-request-proof"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-agent-request-proof"
)
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "pae")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to
    dispatch the suite, so a module-level import would be a cycle."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 and DSSE primitives are unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or "=" in text:
        raise ValueError("not unpadded base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def rsa_thumbprint(jwk: dict[str, Any]) -> str:
    """The RFC 7638 SHA-256 thumbprint of an RSA JWK, base64url without padding."""
    member = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"), sort_keys=True
    )
    return b64url(hashlib.sha256(member.encode()).digest())


def rs256_verify(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 8.2.2)."""
    try:
        n = int.from_bytes(b64url_decode(str(jwk["n"])), "big")
        e = int.from_bytes(b64url_decode(str(jwk["e"])), "big")
    except (KeyError, ValueError):
        return False
    size = (n.bit_length() + 7) // 8
    if n.bit_length() < MIN_MODULUS_BITS or e < 3 or len(signature) != size:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    encoded = pow(s, e, n).to_bytes(size, "big")
    tail = _SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(tail) - 3) + b"\x00" + tail
    return encoded == expected


def _when(value: Any) -> int:
    return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())


class _Record:
    """One envelope, decoded as far as it decodes."""

    def __init__(self, envelope: dict[str, Any]) -> None:
        self.envelope = envelope
        self.statement: dict[str, Any] | None = None
        self.header: dict[str, Any] = {}
        self.claims: dict[str, Any] = {}
        self.signing_input = b""
        self.proof_sig = b""
        self.body = b""
        try:
            self.statement = json.loads(base64.b64decode(str(envelope["payload"]), validate=True))
        except (KeyError, ValueError, TypeError):
            return
        try:
            pred = self.predicate
            parts = str(pred["proof"]["jws"]).split(".")
            if len(parts) != 3:
                raise ValueError("compact JWS has three parts")
            self.header = json.loads(b64url_decode(parts[0]))
            self.claims = json.loads(b64url_decode(parts[1]))
            self.signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            self.proof_sig = b64url_decode(parts[2])
            self.body = base64.b64decode(str(pred["request"]["bodyBase64"]), validate=True)
        except (KeyError, ValueError, TypeError, UnicodeEncodeError):
            self.header, self.claims = {}, {}

    @property
    def predicate(self) -> dict[str, Any]:
        assert self.statement is not None
        return dict(self.statement["predicate"])

    def well_formed(self) -> bool:
        s = self.statement
        if not isinstance(s, dict) or s.get("_type") != STATEMENT_TYPE:
            return False
        if s.get("predicateType") != PREDICATE_TYPE:
            return False
        subject = s.get("subject")
        if not (
            isinstance(subject, list)
            and len(subject) == 1
            and isinstance(subject[0], dict)
            and isinstance(subject[0].get("digest"), dict)
            and isinstance(subject[0]["digest"].get("sha256"), str)
        ):
            return False
        pred = s.get("predicate")
        try:
            assert isinstance(pred, dict)
            for key in ("method", "path", "bodyBase64"):
                assert isinstance(pred["request"][key], str)
            assert isinstance(pred["proof"]["jws"], str)
            assert isinstance(pred["proof"]["typ"], str)
            for key in ("issuer", "subject", "jwkThumbprint"):
                assert isinstance(pred["principal"][key], str)
            assert isinstance(pred["principal"]["jwk"], dict)
            _when(pred["observedAt"])
        except (AssertionError, KeyError, TypeError, ValueError):
            return False
        return bool(self.claims) and bool(self.header)

    def recorder_signed(self, recorder: bytes) -> bool:
        try:
            sigs = self.envelope["signatures"]
            sig = base64.b64decode(str(sigs[0]["sig"]), validate=True)
            payload = base64.b64decode(str(self.envelope["payload"]), validate=True)
        except (KeyError, IndexError, ValueError, TypeError):
            return False
        if len(sigs) != 1 or self.envelope.get("payloadType") != PAYLOAD_TYPE:
            return False
        rail = _rail()
        return bool(rail.ed25519_verify(recorder, rail.pae(PAYLOAD_TYPE, payload), sig))

    def profile(self) -> dict[str, Any] | None:
        return PROFILES.get(str(self.predicate["proof"]["typ"]))

    def typ_mismatch(self) -> bool:
        return self.profile() is None or self.header.get("typ") != self.predicate["proof"]["typ"]

    def alg_not_allowed(self) -> bool:
        profile = self.profile() or {"alg": "RS256"}
        return self.header.get("alg") != profile["alg"] or any(
            k in self.header for k in EMBEDDED_KEY_HEADERS
        )

    def thumbprint_mismatch(self) -> bool:
        principal = self.predicate["principal"]
        try:
            return bool(rsa_thumbprint(principal["jwk"]) != principal["jwkThumbprint"])
        except (KeyError, TypeError):
            return True

    def proof_verifies(self) -> bool:
        return rs256_verify(self.predicate["principal"]["jwk"], self.signing_input, self.proof_sig)

    def principal_mismatch(self) -> bool:
        principal = self.predicate["principal"]
        return bool(
            self.claims.get("iss") != principal["issuer"]
            or self.claims.get("sub") != principal["subject"]
        )

    def htm_htu_mismatch(self) -> bool:
        request = self.predicate["request"]
        return bool(
            self.claims.get("htm") != request["method"] or self.claims.get("htu") != request["path"]
        )

    def body_digest_mismatch(self) -> bool:
        digest = _sha(self.body)
        assert self.statement is not None
        return (
            self.claims.get("body_sha256") != digest
            or self.statement["subject"][0]["digest"]["sha256"] != digest
        )

    def expired(self) -> bool:
        iat, exp = self.claims.get("iat"), self.claims.get("exp")
        if not (isinstance(iat, int) and isinstance(exp, int)):
            return True
        observed = _when(self.predicate["observedAt"])
        lifetime = (self.profile() or {"maxLifetime": 0})["maxLifetime"]
        return not (iat <= observed < exp) or exp - iat > lifetime

    def replay_key(self) -> tuple[str, str]:
        return (str(self.claims.get("iss")), str(self.claims.get("jti")))


def _load(case_path: Path) -> tuple[bytes, list[_Record]]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    recorder = base64.b64decode(str(case["recorderKey"]), validate=True)
    records = [
        _Record(json.loads((case_path.parent / name).read_text(encoding="utf-8")))
        for name in case["envelopes"]
    ]
    return recorder, records


def _first_failure(
    recorder: bytes, record: _Record, seen: set[tuple[str, str]], skip: frozenset[str]
) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. No later check
    can read a malformed statement, so skipping that check passes it.
    """
    if not record.well_formed():
        return None if "statement_malformed" in skip else "statement_malformed"
    failures: dict[str, Callable[[], bool]] = {
        "statement_malformed": lambda: False,
        "recorder_signature_invalid": lambda: not record.recorder_signed(recorder),
        "typ_mismatch": record.typ_mismatch,
        "alg_not_allowed": record.alg_not_allowed,
        "thumbprint_mismatch": record.thumbprint_mismatch,
        "proof_signature_invalid": lambda: not record.proof_verifies(),
        "principal_mismatch": record.principal_mismatch,
        "htm_htu_mismatch": record.htm_htu_mismatch,
        "body_digest_mismatch": record.body_digest_mismatch,
        "proof_expired": record.expired,
        "replayed_jti": lambda: record.replay_key() in seen,
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for the last record of one case.

    Every earlier record must verify, or the case is rejected with the reason of
    the first earlier record that does not.
    """
    recorder, records = _load(case_path)
    seen: set[tuple[str, str]] = set()
    for record in records:
        failure = _first_failure(recorder, record, seen, skip)
        if failure is not None:
            return {"decision": REJECTED, "reason": failure}
        seen.add(record.replay_key())
    return {"decision": VERIFIED, "reason": "request_bound"}


def proof_signature_verifies(case_path: Path) -> bool:
    """Whether the last record's proof verifies under the JWK the record carries."""
    _, records = _load(case_path)
    last = records[-1]
    return last.well_formed() and last.proof_verifies()


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
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
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. A case whose
    declared proof-signature property does not hold is a corpus error, whichever
    verifier is under test.
    """
    try:
        entries, manifest_error = _validated_entries(root)
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
        case_path = directory / "case.json"
        if proof_signature_verifies(case_path) != entry["proofSignatureVerifies"]:
            errors.append(f"{name}: declared proof signature property does not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE,
        "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {
            "vectors": total,
            "conform": total - len(errors),
            "fail": len(errors),
            "suiteRefusals": 0,
        },
        "failures": errors,
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
