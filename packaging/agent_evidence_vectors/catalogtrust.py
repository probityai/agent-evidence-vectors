"""Reference reader for catalog-trust-manifest/v1: one signed ARD or AI Catalog object.

A case directory holds the catalog bytes as published (`catalog.json`), the DID
documents an offline resolver would return (`did-documents.json`, keyed by the
DID resolved), the artifact bytes the entry names (`artifact.json`), any vendored
attestation documents, and `context.json`: the construction to apply, which
object to judge, the role claimed for its signer and the time of the check.

The construction is a closed term (spec/profiles/catalog-trust-manifest/v1.md):

  ard-draft-bu-00      JCS(trustManifest minus `signature`), detached JWS string
                       (draft-bu-dawn-ard-discovery-00 section 3.5)
  field-whole-entry    JCS(entry minus trustManifest.signature): measured practice,
                       defined by no specification revision
  ai-catalog-2026-11   JCS(trustManifests[i] minus its immediate signature.jws and
                       additionalSignatures), typ ai-catalog-trust-manifest+jws
  ai-catalog-snapshot  JCS(catalog minus its immediate signature.jws and
                       additionalSignatures), typ ai-catalog+jws

A verdict says which key signed which bytes under which construction, and that
the signed subject binds the entry and its artifact. It never says the artifact
is safe or that the claims it carries are true.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import decimal
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import p256

SUITE = "catalog-trust-manifest/v1"
SUITES = (SUITE,)
ACCEPT, REJECT = "accept", "reject"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
DRAFT, FIELD = "ard-draft-bu-00", "field-whole-entry"
AIC, SNAPSHOT = "ai-catalog-2026-11", "ai-catalog-snapshot"
CONSTRUCTIONS = (DRAFT, FIELD, AIC, SNAPSHOT)
ARD_SHAPED = (DRAFT, FIELD)
TYP = {AIC: "ai-catalog-trust-manifest+jws", SNAPSHOT: "ai-catalog+jws"}
ALGS = {DRAFT: ("ES256", "EdDSA"), FIELD: ("ES256", "EdDSA"), AIC: ("ES256",),
        SNAPSHOT: ("ES256",)}
KEY_SOURCES = ("jku", "jwk", "x5u", "x5c")
SAFE = 2**53 - 1
PASS_REASON = {DRAFT: "signature_covers_release", FIELD: "signature_covers_release",
               AIC: "signature_covers_release", SNAPSHOT: "snapshot_signature_valid"}
IN_TOTO = "https://in-toto.io/Statement/v1"
DSSE_TYPE = "application/vnd.in-toto+json"

# Gates end the read: no later check has an object to look at. They are not switchable.
GATES = ("construction_unknown", "signature_missing")
CHECKS = (
    "duplicate_member",
    "jws_malformed",
    "typ_missing_or_mismatched",
    "alg_not_allowed_for_profile",
    "key_source_in_header",
    "b64_forbidden_for_profile",
    "jws_crit_unsupported",
    "b64_without_crit",
    "kid_not_under_identity",
    "did_document_not_identity",
    "kid_not_in_did_document",
    "key_not_assertion_method",
    "alg_key_mismatch",
    "number_not_interoperable",
    "no_canonical_form",
    "signature_invalid",
    "signer_not_contributor",
    "subject_missing",
    "subject_entry_mismatch",
    "entry_digest_missing_for_url",
    "artifact_digest_mismatch",
    "url_origin_unbound",
    "attestation_digest_mismatch",
    "attestation_unsigned",
    "attestation_transplanted",
    "publisher_not_signer",
    "publisher_authorization_absent",
    "issued_in_future",
    "manifest_expired",
)
REASONS = GATES + CHECKS

_HERE = Path(__file__).resolve().parent
_IN_WHEEL = (_HERE / "corpora").exists()
ROOTS = {SUITE: (_HERE / "corpora" / "vectors-catalog-trust-manifest" if _IN_WHEEL
                 else _HERE.parents[1] / "corpora" / "vectors-catalog-trust-manifest")}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_DID_WEB = re.compile(r"did:web:[a-z0-9.-]+")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class Refused(Exception):
    """A check failed; ``args[0]`` is its reason code."""


class Duplicate(ValueError):
    """A JSON object repeats a member name."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise Duplicate(key)
        out[key] = value
    return out


def _constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def strict_loads(data: bytes) -> Any:
    """Parse UTF-8 JSON, refusing a repeated member and the non-JSON constants."""
    return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)


def b64url_decode(text: str) -> bytes:
    """Strict unpadded base64url (RFC 7515 section 2)."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("non-canonical base64url")
    return raw


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- RFC 8785

def _number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > SAFE:
            raise Refused("number_not_interoperable")
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise Refused("no_canonical_form")
    if abs(value) > SAFE:
        raise Refused("number_not_interoperable")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    _, numerals, exponent = decimal.Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, numerals))
    stripped = digits.rstrip("0")
    point = len(digits) + int(exponent)
    digits = stripped.lstrip("0") or "0"
    point -= len(stripped) - len(digits)
    k = len(digits)
    if k <= point <= 21:
        text = digits + "0" * (point - k)
    elif 0 < point <= 21:
        text = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        text = "0." + "0" * (-point) + digits
    else:
        e = point - 1
        fraction = "." + digits[1:] if k > 1 else ""
        text = digits[0] + fraction + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + text


_ESCAPES = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}


def _string(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Refused("no_canonical_form") from exc
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif code < 0x20:
            out.append(_ESCAPES.get(code, f"\\u{code:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes; integers past 2**53 - 1 are refused as not interoperable."""
    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, (int, float)):
            return _number(v)
        if isinstance(v, str):
            return _string(v)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
            return "{" + ",".join(_string(k) + ":" + ser(v[k]) for k in keys) + "}"
        raise Refused("no_canonical_form")
    return ser(value).encode("utf-8")


def _numbers_first(value: Any) -> None:
    """Report an out-of-range number before any other canonical-form fault."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        if abs(value) > SAFE:
            raise Refused("number_not_interoperable")
        return
    for item in value.values() if isinstance(value, dict) else value:
        _numbers_first(item)


# --------------------------------------------------------------------------- signing inputs

def payload(construction: str, catalog: dict[str, Any], entry: int, manifest: int) -> Any:
    """The JSON value whose RFC 8785 bytes a construction signs."""
    if construction == SNAPSHOT:
        out = copy.deepcopy(catalog)
        out.get("signature", {}).pop("jws", None)
        out.pop("additionalSignatures", None)
        return out
    item = catalog["entries"][entry]
    if construction == DRAFT:
        out = copy.deepcopy(item["trustManifest"])
        out.pop("signature", None)
        return out
    if construction == FIELD:
        out = copy.deepcopy(item)
        out["trustManifest"].pop("signature", None)
        return out
    out = copy.deepcopy(item["trustManifests"][manifest])
    out.get("signature", {}).pop("jws", None)
    out.pop("additionalSignatures", None)
    return out


def signed_object(construction: str, catalog: dict[str, Any], entry: int,
                  manifest: int) -> dict[str, Any] | None:
    """The object that carries the signature, or None when the path names nothing."""
    try:
        if construction == SNAPSHOT:
            return catalog if isinstance(catalog.get("signature"), dict) else None
        item = catalog["entries"][entry]
        if construction in ARD_SHAPED:
            value = item.get("trustManifest")
        else:
            value = item.get("trustManifests", [])[manifest]
        return value if isinstance(value, dict) else None
    except (KeyError, IndexError, TypeError, AttributeError):
        return None


def jws_of(construction: str, obj: dict[str, Any]) -> Any:
    if construction in ARD_SHAPED:
        return obj.get("signature")
    signature = obj.get("signature")
    return signature.get("jws") if isinstance(signature, dict) else None


def identity_of(construction: str, obj: dict[str, Any]) -> Any:
    if construction in ARD_SHAPED:
        return obj.get("identity")
    signature = obj.get("signature")
    return signature.get("signer") if isinstance(signature, dict) else None


def times_of(construction: str, obj: dict[str, Any]) -> tuple[Any, Any]:
    holder = obj if construction in ARD_SHAPED else obj.get("signature") or {}
    return holder.get("issuedAt"), holder.get("expiresAt")


# --------------------------------------------------------------------------- keys

def _public_key(method: dict[str, Any]) -> tuple[str, Any]:
    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        return "none", None
    try:
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            raw = b64url_decode(jwk["x"])
            return ("EdDSA", raw) if len(raw) == 32 else ("none", None)
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            point = (int.from_bytes(b64url_decode(jwk["x"]), "big"),
                     int.from_bytes(b64url_decode(jwk["y"]), "big"))
            return ("ES256", point) if p256.on_curve(point) else ("none", None)
    except (KeyError, ValueError):
        pass
    return "none", None


_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")


def _rail() -> Any:
    """The rail module, resolved at call time; see receiptsignature._rail."""
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
    raise ImportError("the reference rail is not importable, so Ed25519 is unavailable")


def _ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    return bool(_rail().ed25519_verify(public, message, signature))


def verify_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    if alg == "EdDSA":
        return len(signature) == 64 and _ed25519_verify(key, message, signature)
    return p256.verify(key, message, signature)


def _methods(document: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    methods: dict[str, dict[str, Any]] = {}
    for method in document.get("verificationMethod", []) or []:
        if isinstance(method, dict) and isinstance(method.get("id"), str):
            methods[method["id"]] = method
    assertion: set[str] = set()
    for item in document.get("assertionMethod", []) or []:
        if isinstance(item, str):
            assertion.add(item)
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            assertion.add(item["id"])
            methods[item["id"]] = item
    return methods, assertion


# --------------------------------------------------------------------------- the verdict

def _time(text: Any) -> datetime | None:
    if not isinstance(text, str) or not _TIME.fullmatch(text):
        return None
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _publisher(identifier: Any) -> str | None:
    parts = identifier.split(":") if isinstance(identifier, str) else []
    return parts[2] if len(parts) > 3 and parts[:2] == ["urn", "air"] else None


def _origin(url: Any) -> str | None:
    match = re.fullmatch(r"(https://[^/?#]+)(?:[/?#].*)?", url) if isinstance(url, str) else None
    return match.group(1) if match else None


def _dsse_pae(payload_type: str, body: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def _attestations(construction: str, case: Path, obj: dict[str, Any], entry: dict[str, Any],
                  context: dict[str, Any], documents: dict[str, Any],
                  skip: frozenset[str]) -> None:
    files = context.get("attestationFiles") or []
    items = obj.get("attestations") or []
    for index, item in enumerate(items):
        name = files[index] if index < len(files) else None
        if not name:
            continue
        data = (case / name).read_bytes()
        if "attestation_digest_mismatch" not in skip and \
                item.get("digest") != "sha256:" + sha256_hex(data):
            raise Refused("attestation_digest_mismatch")
        statement = _signed_statement(data, documents)
        if statement is None:
            if "attestation_unsigned" not in skip:
                raise Refused("attestation_unsigned")
            continue
        subjects = statement.get("subject") or []
        digests = {"sha256:" + s.get("digest", {}).get("sha256", "") for s in subjects
                   if isinstance(s, dict) and isinstance(s.get("digest"), dict)}
        if "attestation_transplanted" not in skip and entry.get("digest") not in digests:
            raise Refused("attestation_transplanted")


def _signed_statement(data: bytes, documents: dict[str, Any]) -> dict[str, Any] | None:
    """The in-toto Statement inside a DSSE envelope whose signature verifies, else None."""
    try:
        envelope = strict_loads(data)
        body = base64.b64decode(envelope["payload"], validate=True)
        kind = envelope["payloadType"]
        signatures = envelope["signatures"]
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
        return None
    if kind != DSSE_TYPE or not isinstance(signatures, list):
        return None
    for signature in signatures:
        keyid = signature.get("keyid") if isinstance(signature, dict) else None
        if not isinstance(keyid, str) or "#" not in keyid:
            continue
        document = documents.get(keyid.split("#", 1)[0])
        if not isinstance(document, dict):
            continue
        methods, assertion = _methods(document)
        if keyid not in methods or keyid not in assertion:
            continue
        alg, key = _public_key(methods[keyid])
        try:
            raw = base64.b64decode(signature.get("sig", ""), validate=True)
        except (binascii.Error, ValueError):
            continue
        if key is not None and verify_signature(alg, key, _dsse_pae(kind, body), raw):
            try:
                statement = strict_loads(body)
            except (ValueError, UnicodeDecodeError):
                return None
            return statement if statement.get("_type") == IN_TOTO else None
    return None


def verify(suite: str, case: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """Judge one case directory; the answer is {"decision", "reason"}."""
    if suite != SUITE:
        raise ValueError(f"unknown suite {suite!r}")
    try:
        reason = _judge(case, skip)
    except Refused as refusal:
        return {"decision": REJECT, "reason": str(refusal.args[0])}
    return {"decision": ACCEPT, "reason": reason}


def _lenient_jws(parts: list[str]) -> tuple[dict[str, Any], bytes]:
    """What a lenient verifier reads: padding allowed, an attached payload ignored."""
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except (ValueError, binascii.Error) as exc:
        raise Refused("jws_malformed") from exc
    if not isinstance(header, dict):
        raise Refused("jws_malformed")
    return header, signature


def _judge(case: Path, skip: frozenset[str]) -> str:  # noqa: C901 - one ordered check list
    def fail(code: str) -> None:
        if code not in skip:
            raise Refused(code)

    context = json.loads((case / "context.json").read_text(encoding="utf-8"))
    construction = context.get("construction")
    if construction not in CONSTRUCTIONS:
        raise Refused("construction_unknown")
    entry_index, manifest_index = context.get("entry", 0), context.get("manifest", 0)
    raw_catalog = (case / "catalog.json").read_bytes()
    raw_documents = (case / "did-documents.json").read_bytes()
    try:
        catalog, documents = strict_loads(raw_catalog), strict_loads(raw_documents)
    except Duplicate:
        fail("duplicate_member")
        catalog, documents = json.loads(raw_catalog), json.loads(raw_documents)
    found = signed_object(construction, catalog, entry_index, manifest_index)
    if found is None or not isinstance(jws_of(construction, found), str):
        raise Refused("signature_missing")
    obj: dict[str, Any] = found
    jws: str = jws_of(construction, obj)
    parts = jws.split(".")
    try:
        if len(parts) != 3 or parts[1] != "":
            raise ValueError("not detached compact serialization")
        header = strict_loads(b64url_decode(parts[0]))
        signature = b64url_decode(parts[2])
        if not isinstance(header, dict):
            raise ValueError("header is not an object")
    except (ValueError, UnicodeDecodeError) as exc:
        if "jws_malformed" not in skip or len(parts) != 3:
            raise Refused("jws_malformed") from exc
        header, signature = _lenient_jws(parts)
    if construction in TYP and header.get("typ") != TYP[construction]:
        fail("typ_missing_or_mismatched")
    alg = header.get("alg")
    if alg not in ALGS[construction]:
        fail("alg_not_allowed_for_profile")
    if any(name in header for name in KEY_SOURCES):
        fail("key_source_in_header")
    if construction not in ARD_SHAPED and "b64" in header:
        fail("b64_forbidden_for_profile")
    crit = header.get("crit")
    if crit is not None and (not isinstance(crit, list) or not crit
                             or any(name != "b64" or name not in header for name in crit)):
        fail("jws_crit_unsupported")
    if "b64" in header and not (isinstance(crit, list) and "b64" in crit):
        fail("b64_without_crit")
    identity = identity_of(construction, obj)
    kid = header.get("kid")
    kid_ok = (isinstance(kid, str) and isinstance(identity, str)
              and re.fullmatch(re.escape(identity) + r"#[A-Za-z0-9._~-]+", kid) is not None)
    if not kid_ok:
        fail("kid_not_under_identity")
    document = documents.get(identity) if isinstance(identity, str) else None
    if not isinstance(document, dict) or document.get("id") != identity:
        fail("did_document_not_identity")
    methods, assertion = _methods(document if isinstance(document, dict) else {})
    if kid not in methods:
        fail("kid_not_in_did_document")
    if kid not in assertion:
        fail("key_not_assertion_method")
    key_alg, key = _public_key(methods.get(kid, {})) if isinstance(kid, str) else ("none", None)
    if key_alg != alg:
        fail("alg_key_mismatch")
    signed = payload(construction, catalog, entry_index, manifest_index)
    try:
        _numbers_first(signed)
    except Refused:
        fail("number_not_interoperable")
    try:
        body = canonical(signed)
    except Refused as refusal:
        fail(str(refusal.args[0]) if refusal.args[0] != "number_not_interoperable"
             else "no_canonical_form")
        body = json.dumps(signed, sort_keys=True).encode("utf-8", "surrogatepass")
    unencoded = header.get("b64") is False
    message = parts[0].encode() + b"." + (body if unencoded else b64url(body).encode())
    if key is None or key_alg != alg or not verify_signature(alg, key, message, signature):
        fail("signature_invalid")
    if construction == SNAPSHOT:
        _times(construction, catalog, context, fail)
        return PASS_REASON[construction]
    entry = catalog["entries"][entry_index]
    if construction == AIC and obj.get("contributor") != identity:
        fail("signer_not_contributor")
    subject = obj.get("subject")
    if not isinstance(subject, dict):
        fail("subject_missing")
        subject = {}
    for member in ("identifier", "type", "digest"):
        if subject.get(member) != entry.get(member):
            fail("subject_entry_mismatch")
    if ("version" in subject) != ("version" in entry) or \
            subject.get("version") != entry.get("version"):
        fail("subject_entry_mismatch")
    if "digest" not in entry and ("url" in entry or construction == AIC):
        fail("entry_digest_missing_for_url")
    artifact = case / "artifact.json"
    artifact_bytes = artifact.read_bytes() if artifact.is_file() else None
    if artifact_bytes is None or entry.get("digest") != "sha256:" + sha256_hex(artifact_bytes):
        fail("artifact_digest_mismatch")
    publisher = _publisher(entry.get("identifier"))
    if construction in ARD_SHAPED and _origin(entry.get("url")) != f"https://{publisher}":
        try:
            descriptor = strict_loads(artifact_bytes) if artifact_bytes else {}
        except (ValueError, UnicodeDecodeError):
            descriptor = {}
        declared = descriptor.get("identifier") if isinstance(descriptor, dict) else None
        if declared != entry.get("identifier"):
            fail("url_origin_unbound")
    _attestations(construction, case, obj, entry, context, documents, skip)
    if context.get("role") == "publisher":
        expected = f"did:web:{publisher}" if publisher else None
        if identity != expected:
            fail("publisher_not_signer" if construction == AIC
                 else "publisher_authorization_absent")
    _times(construction, obj, context, fail)
    return PASS_REASON[construction]


def _times(construction: str, holder: dict[str, Any], context: dict[str, Any],
           fail: Callable[[str], None]) -> None:
    issued, expires = times_of(construction, holder)
    at = _time(context.get("at"))
    start = _time(issued)
    if at is None or (issued is not None and start is None) or (start is not None and at < start):
        fail("issued_in_future")
    end = _time(expires) if expires is not None else None
    if at is not None and expires is not None and (end is None or at >= end):
        fail("manifest_expired")


# --------------------------------------------------------------------------- the corpus harness

def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    declared = entry.get("files")
    if not isinstance(declared, dict) or not directory.is_dir():
        return "case directory or file list missing"
    present = {p.name for p in directory.iterdir() if p.is_file()}
    if present != set(declared):
        return "file set does not match the manifest"
    for name, digest in declared.items():
        if sha256_hex((directory / name).read_bytes()) != digest:
            return f"{name} digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if sha256_hex(_manifest_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != {e["id"] for e in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], directory: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, SUITE, str(directory), "--json"],
                                capture_output=True, text=True, timeout=90, check=False)
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


def check(suite: str = SUITE, verifier: str | list[str] | None = None, root: Path | None = None,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader."""
    base = ROOTS[suite] if root is None else root
    try:
        entries, manifest_error = _validated_entries(base)
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
        name, directory = entry["id"], base / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(suite, directory, skip)
        else:
            ran, observed = _external_answer(command, directory)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def runner(suite: str) -> Callable[[str, list[str] | None, str, str], int]:
    """The run function the package harness calls for ``suite``."""
    def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
        directory = Path(root)
        answered, errors = check(suite, verifier, directory)
        try:
            manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
            total = len(manifest["vectors"])
        except (OSError, ValueError, KeyError, TypeError):
            manifest, total = {}, 0
        for error in errors:
            print(error)
        rail = "reference reader" if verifier is None else shlex.join(verifier)
        print(f"{suite}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
        if not answered or not total:
            print("no report written: no case was answered")
            return 2
        report = {
            "suite": suite, "rail": "own-reader" if verifier is None else "external",
            "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
            "corpusDigest": manifest["corpusDigest"],
            "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                       "suiteRefusals": 0},
            "failures": errors,
        }
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
        return 1 if errors or answered != total else 0
    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("case", nargs="?", help="judge one case directory")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(args.suite, Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.suite, args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOTS[args.suite] / "MANIFEST.json").read_text(
        encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
