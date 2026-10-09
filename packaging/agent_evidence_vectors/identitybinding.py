"""Judge DSSE-signed agent records whose subject is a DID.

A record signed by an agent names its subject by DID. A verifier that checks the
DSSE signature and nothing else learns that some key signed the bytes; it does
not learn that the key belongs to the DID the record is about. The corpus this
module reads separates those questions. Five of its rejected records carry a
signature that verifies under the key the envelope names, and are still wrong:
the key belongs to a different DID, was rotated out before the record was
signed, was never authorised for authentication or assertion, or is served
under a did:wba path whose binding fingerprint names a different key.

Each case ships the DID documents a resolver would return, as resolution
fixtures with their version history, so no network is read. The reader checks
in a fixed order and names the first check that fails:

1. the subject DID and the signer DID are well formed did:web or did:wba
   strings (``did_malformed``);
2. the DID the signing key belongs to is the record's subject
   (``signer_not_subject``);
3. a resolution fixture exists for that DID (``did_unresolvable``);
4. a did:wba path DID's final ``e1_`` segment is the RFC 7638 thumbprint of an
   Ed25519 Multikey its document authorises for authentication
   (``binding_fingerprint_mismatch``);
5. the document version in effect at the record's signing time still carries
   the key, and the DID is not deactivated by then, where an earlier version
   carried it (``key_rotated_out``);
6. that version lists the key under ``authentication`` or ``assertionMethod``
   (``key_not_authorized``);
7. the DSSE signature verifies under that key (``signature_invalid``).

A record that passes all seven is ``verified`` with reason ``subject_bound``.

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
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "agent-did-identity-binding/v1"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "did_malformed",
    "signer_not_subject",
    "did_unresolvable",
    "binding_fingerprint_mismatch",
    "key_rotated_out",
    "key_not_authorized",
    "signature_invalid",
)
AUTHORISING = ("authentication", "assertionMethod")
MULTIKEY_ED25519 = b"\xed\x01"
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-identity-binding" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-identity-binding")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "pae")

_HOST = (r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
         r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:%3A[0-9]{1,5})?")
_SEGMENT = r"[A-Za-z0-9._-]+"
_DID_WEB = re.compile(rf"did:web:{_HOST}(?::{_SEGMENT})*")
_DID_WBA = re.compile(rf"did:wba:{_HOST}(?:(?::{_SEGMENT})*:e1_[A-Za-z0-9_-]{{43}})?")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


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


def well_formed(did: str) -> bool:
    """Whether a string is a did:web DID or a did:wba DID this suite accepts.

    A did:wba path DID must end in an ``e1_`` binding fingerprint segment, the
    default path scheme of the did:wba method specification, Section 2.2.1.
    """
    return bool(_DID_WEB.fullmatch(did) or _DID_WBA.fullmatch(did))


def b58decode(text: str) -> bytes:
    """Decode base58-btc, the alphabet of a ``z`` multibase value."""
    number = 0
    for char in text:
        index = _B58.find(char)
        if index < 0:
            raise ValueError(f"{char!r} is not a base58-btc character")
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + body


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(public: bytes) -> str:
    """The RFC 7638 thumbprint of an Ed25519 public key, base64url without padding."""
    member = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": _b64url(public)},
                        separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(member.encode()).digest())


def public_key(method: dict[str, Any]) -> bytes | None:
    """The 32 Ed25519 public key bytes of a verification method, or None."""
    multibase = method.get("publicKeyMultibase")
    if isinstance(multibase, str) and multibase.startswith("z"):
        try:
            raw = b58decode(multibase[1:])
        except ValueError:
            return None
        if raw[:2] == MULTIKEY_ED25519 and len(raw) == 34:
            return raw[2:]
        return None
    jwk = method.get("publicKeyJwk")
    if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        try:
            raw = base64.urlsafe_b64decode(str(jwk.get("x", "")) + "==")
        except ValueError:
            return None
        return raw if len(raw) == 32 else None
    return None


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _absolute(doc: dict[str, Any], ref: str) -> str:
    return f"{doc.get('id', '')}{ref}" if ref.startswith("#") else ref


def _methods(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every verification method a document carries, by absolute id."""
    found: dict[str, dict[str, Any]] = {}
    embedded = [entry for rel in ("verificationMethod", *AUTHORISING)
                for entry in doc.get(rel, []) if isinstance(entry, dict)]
    for method in embedded:
        found[_absolute(doc, str(method.get("id", "")))] = method
    return found


def authorised(doc: dict[str, Any], keyid: str) -> bool:
    """Whether a document lists keyid under authentication or assertionMethod."""
    for relationship in AUTHORISING:
        for entry in doc.get(relationship, []):
            ref = entry.get("id", "") if isinstance(entry, dict) else entry
            if _absolute(doc, str(ref)) == keyid:
                return True
    return False


@dataclass(frozen=True)
class _Case:
    envelope: dict[str, Any]
    subject: str
    signed_at: datetime
    keyid: str
    signer: str
    resolution: dict[str, Any] | None

    def versions(self) -> list[dict[str, Any]]:
        return list(self.resolution["versions"]) if self.resolution else []

    def in_effect(self) -> dict[str, Any] | None:
        """The document version in effect when the record was signed."""
        current = None
        for version in self.versions():
            if _when(version["didDocumentMetadata"]["updated"]) <= self.signed_at:
                current = version
        return current

    def method(self) -> dict[str, Any] | None:
        """The verification method keyid names, from any version of the document."""
        for version in reversed(self.versions()):
            method = _methods(version["didDocument"]).get(self.keyid)
            if method is not None:
                return method
        return None


def subject_of(envelope: dict[str, Any]) -> str:
    """The subject DID a DSSE envelope's payload names."""
    record = json.loads(base64.b64decode(envelope["payload"]))
    return str(record["subject"]["id"])


def _load(case_path: Path) -> _Case:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    envelope = json.loads((base / case["envelope"]).read_text(encoding="utf-8"))
    record = json.loads(base64.b64decode(envelope["payload"]))
    keyid = str(envelope["signatures"][0]["keyid"])
    signer = keyid.split("#", 1)[0]
    name = case.get("resolutions", {}).get(signer)
    resolution = None
    if name is not None and (base / name).is_file():
        resolution = json.loads((base / name).read_text(encoding="utf-8"))
    return _Case(envelope, str(record["subject"]["id"]), _when(record["signedAt"]),
                 keyid, signer, resolution)


def _fingerprint_mismatch(c: _Case) -> bool:
    if not c.signer.startswith("did:wba:") or ":e1_" not in c.signer:
        return False
    version = c.in_effect()
    if version is None:
        return False
    doc = version["didDocument"]
    segment = c.signer.rsplit(":", 1)[1]
    methods = _methods(doc)
    for entry in doc.get("authentication", []):
        ref = entry.get("id", "") if isinstance(entry, dict) else entry
        method = methods.get(_absolute(doc, str(ref)))
        key = public_key(method) if method and method.get("type") == "Multikey" else None
        if key is not None and segment == "e1_" + jwk_thumbprint(key):
            return False
    return True


def _rotated_out(c: _Case) -> bool:
    version = c.in_effect()
    reached = [v for v in c.versions()
               if _when(v["didDocumentMetadata"]["updated"]) <= c.signed_at]
    if version is None or not any(authorised(v["didDocument"], c.keyid) for v in reached):
        return False
    doc, meta = version["didDocument"], version["didDocumentMetadata"]
    if doc.get("deactivated") is True or meta.get("deactivated") is True:
        return True
    return not authorised(doc, c.keyid)


def _not_authorised(c: _Case) -> bool:
    version = c.in_effect()
    return version is None or not authorised(version["didDocument"], c.keyid)


def signature_verifies(c: _Case) -> bool:
    """Whether the DSSE signature verifies under the key keyid names in the document."""
    method = c.method()
    key = public_key(method) if method else None
    if key is None:
        return False
    try:
        sig = base64.b64decode(str(c.envelope["signatures"][0]["sig"]), validate=True)
        payload = base64.b64decode(str(c.envelope["payload"]), validate=True)
    except ValueError:
        return False
    rail = _rail()
    return bool(rail.ed25519_verify(key, rail.pae(str(c.envelope["payloadType"]), payload), sig))


def _first_failure(c: _Case, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. Every check is
    total on its own, so switching an earlier one off cannot crash a later one.
    """
    failures: dict[str, Callable[[], bool]] = {
        "did_malformed": lambda: not (well_formed(c.subject) and well_formed(c.signer)),
        "signer_not_subject": lambda: c.signer != c.subject,
        "did_unresolvable": lambda: c.resolution is None,
        "binding_fingerprint_mismatch": lambda: _fingerprint_mismatch(c),
        "key_rotated_out": lambda: _rotated_out(c),
        "key_not_authorized": lambda: _not_authorised(c),
        "signature_invalid": lambda: not signature_verifies(c),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    failure = _first_failure(_load(case_path), skip)
    if failure is not None:
        return {"decision": REJECTED, "reason": failure}
    return {"decision": VERIFIED, "reason": "subject_bound"}


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
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
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
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. A case whose
    declared signature property does not hold is a corpus error, whichever
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
        if signature_verifies(_load(case_path)) != entry["signatureVerifies"]:
            errors.append(f"{name}: declared signature property does not hold")
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
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
