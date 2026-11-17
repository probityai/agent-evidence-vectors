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
import math
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from fractions import Fraction
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
# The AI Catalog did:web Signer Profile, selected by its exact reserved name.
SIGNER_PROFILE = "did-web-v1"
ROLES = ("publisher", "contributor")
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
DSSE_TYPE = "application/vnd.in-toto+json"

# Gates end the read: no later check has an object to look at. They are not switchable.
GATES = ("construction_unknown", "role_unknown", "json_invalid", "signature_missing")
CHECKS = (
    "duplicate_member",
    "jws_malformed",
    "typ_missing_or_mismatched",
    "alg_not_allowed_for_profile",
    "key_source_in_header",
    "b64_forbidden_for_profile",
    "jws_crit_unsupported",
    "b64_without_crit",
    "profile_unsupported",
    "signer_not_root_did_web",
    "kid_not_under_identity",
    "did_document_not_identity",
    "kid_not_in_did_document",
    "verification_method_ambiguous",
    "key_not_assertion_method",
    "method_controller_mismatch",
    "jwk_not_signing_key",
    "alg_key_mismatch",
    "number_not_interoperable",
    "no_canonical_form",
    "signature_invalid",
    "signer_not_contributor",
    "subject_missing",
    "subject_entry_mismatch",
    "entry_delivery_not_one",
    "entry_digest_missing_for_url",
    "artifact_digest_mismatch",
    "url_origin_unbound",
    "attestation_digest_mismatch",
    "attestation_unsigned",
    "attestation_transplanted",
    "publisher_not_signer",
    "publisher_authorization_absent",
    "timestamp_invalid",
    "issued_in_future",
    "manifest_expired",
)
REASONS = GATES + CHECKS

_HERE = Path(__file__).resolve().parent
_IN_WHEEL = (_HERE / "corpora").exists()
ROOTS = {SUITE: (_HERE / "corpora" / "vectors-catalog-trust-manifest" if _IN_WHEEL
                 else _HERE.parents[1] / "corpora" / "vectors-catalog-trust-manifest")}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
# A non-empty RFC 3986 fragment: pchar, "/" and "?", percent-escapes well formed.
_FRAGMENT = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# A root did:web DID: a lowercase ASCII domain (A-labels allowed), no port, path or
# trailing dot (AI Catalog, "The did:web Signer Profile").
_ROOT_DID_WEB = re.compile(rf"did:web:(?:{_LABEL}\.)*{_LABEL}")
# RFC 3339 section 5.6 date-time; "T" and "Z" may be lowercase (section 5.6 NOTE).
# ASCII digits only: a str pattern's \d also matches other scripts' digits, which
# int() then reads, and RFC 3339 is ASCII.
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
                   r"(\.[0-9]+)?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))")
# The UTC days that end in a leap second, from the IERS list (leap-seconds.list, file hash
# a9bad145 84c31c70 758402aa b37bfd54 5923836a, expires 28 June 2027). A second of 60
# names a real instant only at 23:59:60 UTC on one of them (RFC 3339 section 5.7).
LEAP_SECOND_DAYS = (
    (1972, 6, 30), (1972, 12, 31), (1973, 12, 31), (1974, 12, 31), (1975, 12, 31),
    (1976, 12, 31), (1977, 12, 31), (1978, 12, 31), (1979, 12, 31), (1981, 6, 30),
    (1982, 6, 30), (1983, 6, 30), (1985, 6, 30), (1987, 12, 31), (1989, 12, 31),
    (1990, 12, 31), (1992, 6, 30), (1993, 6, 30), (1994, 6, 30), (1995, 12, 31),
    (1997, 6, 30), (1998, 12, 31), (2005, 12, 31), (2008, 12, 31), (2012, 6, 30),
    (2015, 6, 30), (2016, 12, 31))
# A JSON text with more than this many arrays and objects open at once is refused before
# it is parsed, so every reader holds the same values (json_invalid).
MAX_NESTING = 64
# DSSE: "Either standard or URL-safe base64 encodings are allowed. Signers may use either,
# and verifiers MUST accept either" (protocol.md); one alphabet per string, padded (RFC 4648).
_DSSE_B64 = (re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
             re.compile(r"(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?"))


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


def too_deep(data: bytes) -> bool:
    """True when more than MAX_NESTING arrays and objects are open at once. Structural
    characters are ASCII and no UTF-8 sequence holds an ASCII byte, so bytes suffice."""
    depth, in_string, escaped = 0, False, False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_NESTING:
                return True
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return False


def strict_loads(data: bytes) -> Any:
    """Parse UTF-8 JSON, refusing a repeated member, the non-JSON constants and nesting
    past MAX_NESTING."""
    text = data.decode("utf-8")
    if too_deep(data):
        raise ValueError(f"more than {MAX_NESTING} arrays and objects open at once")
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def dsse_b64_decode(text: Any) -> bytes:
    """A DSSE base64 field: standard or URL-safe alphabet, padded, nothing else."""
    if not isinstance(text, str) or len(text) % 4:
        raise ValueError("not padded base64")
    if _DSSE_B64[0].fullmatch(text):
        return base64.b64decode(text, validate=True)
    if _DSSE_B64[1].fullmatch(text):
        return base64.urlsafe_b64decode(text)
    raise ValueError("not standard or URL-safe base64")


def index_of(value: Any) -> int | None:
    """A context index: a non-negative JSON integer (1.0 is the integer 1), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and 0 <= value <= 2**31 else None


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

def payload(construction: str, catalog: dict[str, Any], entry: int | None,
            manifest: int | None) -> Any:
    """The JSON value whose RFC 8785 bytes a construction signs."""
    if construction == SNAPSHOT:
        out = copy.deepcopy(catalog)
        out.get("signature", {}).pop("jws", None)
        out.pop("additionalSignatures", None)
        return out
    assert entry is not None and (manifest is not None or construction != AIC)
    item = catalog["entries"][entry]
    if construction == DRAFT:
        out = copy.deepcopy(item["trustManifest"])
        out.pop("signature", None)
        return out
    if construction == FIELD:
        out = copy.deepcopy(item)
        out["trustManifest"].pop("signature", None)
        return out
    assert manifest is not None
    out = copy.deepcopy(item["trustManifests"][manifest])
    out.get("signature", {}).pop("jws", None)
    out.pop("additionalSignatures", None)
    return out


def signed_object(construction: str, catalog: dict[str, Any], entry: int | None,
                  manifest: int | None) -> dict[str, Any] | None:
    """The object that carries the signature, or None when the path names nothing."""
    try:
        if construction == SNAPSHOT:
            return catalog if isinstance(catalog.get("signature"), dict) else None
        if entry is None or (manifest is None and construction == AIC):
            return None
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


def _der_integer(data: bytes, at: int) -> tuple[int, int] | None:
    """One minimal, non-negative DER INTEGER with a short-form length at ``at``."""
    if at + 2 > len(data) or data[at] != 0x02 or not 0 < data[at + 1] < 0x80:
        return None
    end = at + 2 + data[at + 1]
    body = data[at + 2:end]
    if end > len(data) or body[0] & 0x80 or (len(body) > 1 and body[0] == 0 and body[1] < 0x80):
        return None
    return int.from_bytes(body, "big"), end


def der_signature(data: bytes) -> bytes | None:
    """An ECDSA-Sig-Value (RFC 3279 section 2.2.3) in strict DER as raw r || s, else None."""
    if len(data) < 2 or data[0] != 0x30 or data[1] >= 0x80 or data[1] != len(data) - 2:
        return None
    first = _der_integer(data, 2)
    second = _der_integer(data, first[1]) if first else None
    if first is None or second is None or second[1] != len(data):
        return None
    r, s = first[0], second[0]
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") if max(r, s) < 2**256 else None


def verify_dsse_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    """A DSSE signature: as JWS, and for ES256 also the DER form signers commonly write."""
    if verify_signature(alg, key, message, signature):
        return True
    raw = der_signature(signature) if alg == "ES256" else None
    return raw is not None and verify_signature(alg, key, message, raw)


def _jwk_fault(method: dict[str, Any], alg: Any) -> bool:
    """True when the method's JWK is not a public key fit to verify ``alg`` (RFC 7517 4.2-4.4,
    RFC 7518 6.2.1, AI Catalog "JWS Algorithm and Key Requirements")."""
    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        return False  # no key at all is alg_key_mismatch
    if any(name in jwk for name in PRIVATE_JWK_MEMBERS):
        return True
    if "use" in jwk and jwk["use"] != "sig":
        return True
    if "key_ops" in jwk and not (isinstance(jwk["key_ops"], list) and "verify" in jwk["key_ops"]):
        return True
    if "alg" in jwk and jwk["alg"] != alg:
        return True
    if jwk.get("kty") == "EC":
        try:
            return len(b64url_decode(jwk["x"])) != 32 or len(b64url_decode(jwk["y"])) != 32
        except (KeyError, ValueError):
            return True
    return False


def _absolute(ref: Any, base: Any) -> Any:
    """A DID URL with a relative reference resolved against the document id (DID Core 3.2.2)."""
    if isinstance(ref, str) and ref.startswith("#") and isinstance(base, str):
        return base + ref
    return ref


def _methods(document: dict[str, Any]) -> tuple[list[dict[str, Any]], set[str]]:
    """Every verification method with its id made absolute, and the assertion ids."""
    base = document.get("id")
    methods: list[dict[str, Any]] = []
    assertion: set[str] = set()
    listed = document.get("verificationMethod", [])
    for method in listed if isinstance(listed, list) else []:
        if isinstance(method, dict) and isinstance(method.get("id"), str):
            methods.append({**method, "id": _absolute(method["id"], base)})
    granted = document.get("assertionMethod", [])
    for item in granted if isinstance(granted, list) else []:
        if isinstance(item, str):
            assertion.add(_absolute(item, base))
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            embedded = {**item, "id": _absolute(item["id"], base)}
            assertion.add(embedded["id"])
            methods.append(embedded)
    return methods, assertion


def _selected(methods: list[dict[str, Any]], kid: Any) -> list[dict[str, Any]]:
    return [m for m in methods if m["id"] == kid]


# --------------------------------------------------------------------------- the verdict

def root_did_web(identity: Any) -> bool:
    """A root did:web DID: labels of a lowercase ASCII domain of at most 253 octets
    (RFC 1035 section 2.3.4) whose last label is not all digits (RFC 3696 section 2), which
    also excludes a dotted IPv4 address."""
    if not isinstance(identity, str) or not _ROOT_DID_WEB.fullmatch(identity):
        return False
    domain = identity[len("did:web:"):]
    return len(domain) <= 253 and not domain.rsplit(".", 1)[-1].isdigit()


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 in the proleptic Gregorian calendar, for every year RFC 3339
    can write, 0000 included (the datetime module stops at year 1)."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _instant(text: Any) -> Fraction | None:
    """An RFC 3339 date-time as exact seconds since 1970, or None when it is not one."""
    match = _TIME.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match[n]) for n in range(1, 7))
    if month < 1 or month > 12 or day < 1 or day > _days_in_month(year, month) or \
            hour > 23 or minute > 59 or second > 60:
        return None
    seconds = Fraction(_days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60
                       + second)
    if match[7]:
        seconds += Fraction(match[7][1:]) / 10 ** (len(match[7]) - 1)
    if not match[8]:
        offset_hours, offset_minutes = int(match[10]), int(match[11])
        if offset_hours > 23 or offset_minutes > 59:
            return None
        offset = (offset_hours * 60 + offset_minutes) * 60
        seconds -= offset if match[9] == "+" else -offset
    if second == 60 and not _leap_second(math.floor(seconds) - 1):
        return None
    return seconds


_LEAP_DAYS = frozenset(_days_from_civil(*day) for day in LEAP_SECOND_DAYS)


def _leap_second(before: int) -> bool:
    """True when ``before`` (whole UTC seconds since 1970) is 23:59:59 on a leap day, so
    the second after it is 23:59:60."""
    day, of_day = divmod(before, 86400)
    return of_day == 86399 and day in _LEAP_DAYS


def _publisher(identifier: Any) -> str | None:
    parts = identifier.split(":") if isinstance(identifier, str) else []
    return parts[2] if len(parts) > 3 and parts[:2] == ["urn", "air"] else None


def _origin(url: Any) -> str | None:
    """The RFC 6454 origin of an https URL as https://<host>, or None. The scheme and host
    are case-insensitive and port 443 is the default; a URL with userinfo is not read
    (RFC 9110 section 4.2.4: a recipient treats it as an error), nor is a host with a
    percent-escape or an IP literal."""
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(?:[/?#].*)?", url) \
        if isinstance(url, str) else None
    if match is None or match[1].lower() != "https" or "@" in match[2]:
        return None
    host, _, port = match[2].partition(":")
    if not host or "%" in host or "[" in host or port not in ("", "443"):
        return None
    return "https://" + host.lower()


def _dsse_pae(payload_type: str, body: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def _attestations(construction: str, case: Path, obj: dict[str, Any], entry: dict[str, Any],
                  context: dict[str, Any], documents: dict[str, Any],
                  skip: frozenset[str]) -> None:
    files = context.get("attestationFiles") or []
    items = obj.get("attestations") or []
    for index, item in enumerate(items if isinstance(items, list) else []):
        name = files[index] if isinstance(files, list) and index < len(files) else None
        if not name:
            continue
        # A vendored file is named by one path segment of the case directory itself.
        single = isinstance(name, str) and not any(c in name for c in "/\\\0") and \
            name not in (".", "..")
        path = case / name if single else None
        data = path.read_bytes() if path is not None and path.is_file() else None
        digest = item.get("digest") if isinstance(item, dict) else None
        if "attestation_digest_mismatch" not in skip and \
                (data is None or digest != "sha256:" + sha256_hex(data)):
            raise Refused("attestation_digest_mismatch")
        statement = _signed_statement(data, documents) if data is not None else None
        if statement is None:
            if "attestation_unsigned" not in skip:
                raise Refused("attestation_unsigned")
            continue
        subjects = statement.get("subject")
        digests = {"sha256:" + s["digest"]["sha256"]
                   for s in (subjects if isinstance(subjects, list) else [])
                   if isinstance(s, dict) and isinstance(s.get("digest"), dict)
                   and isinstance(s["digest"].get("sha256"), str)}
        if "attestation_transplanted" not in skip and entry.get("digest") not in digests:
            raise Refused("attestation_transplanted")


def _dsse_key(keyid: Any, documents: dict[str, Any]) -> tuple[str, Any]:
    """The algorithm and key a DSSE keyid names, or ("none", None)."""
    if not isinstance(keyid, str) or "#" not in keyid:
        return "none", None
    did = keyid.split("#", 1)[0]
    document = documents.get(did)
    if not isinstance(document, dict) or document.get("id") != did:
        return "none", None
    methods, assertion = _methods(document)
    selected = _selected(methods, keyid)
    if len(selected) != 1 or keyid not in assertion:
        return "none", None
    alg, key = _public_key(selected[0])
    return ("none", None) if _jwk_fault(selected[0], alg) else (alg, key)


def _signed_statement(data: bytes, documents: dict[str, Any]) -> dict[str, Any] | None:
    """The in-toto Statement inside a DSSE envelope whose signature verifies, else None.

    The key is one the DID document of the keyid's DID authorizes for assertions, and that
    document's id is that DID, as for the manifest signer."""
    try:
        envelope = strict_loads(data)
        body = dsse_b64_decode(envelope["payload"])
        kind = envelope["payloadType"]
        signatures = envelope["signatures"]
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
        return None
    if kind != DSSE_TYPE or not isinstance(signatures, list):
        return None
    for signature in signatures:
        keyid = signature.get("keyid") if isinstance(signature, dict) else None
        alg, key = _dsse_key(keyid, documents)
        if key is None:
            continue
        try:
            raw = dsse_b64_decode(signature.get("sig", ""))
        except (binascii.Error, ValueError, TypeError):
            continue
        if key is not None and verify_dsse_signature(alg, key, _dsse_pae(kind, body), raw):
            try:
                statement = strict_loads(body)
            except (ValueError, UnicodeDecodeError):
                return None
            if isinstance(statement, dict) and statement.get("_type") == IN_TOTO:
                return statement
            return None
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


def _judge(case: Path, skip: frozenset[str]) -> str:
    """The ordered check list of the profile; the first check that fails is the reason."""
    read = _Read(case, skip)
    read.load()
    read.signature_object()
    read.read_header()
    read.signer()
    read.select_key()
    read.signed_bytes()
    if read.construction == SNAPSHOT:
        read.times(read.catalog)
        return PASS_REASON[read.construction]
    read.subject()
    read.artifact()
    read.origin()
    _attestations(read.construction, case, read.obj, read.entry, read.context, read.documents,
                  skip)
    read.publisher_rule()
    read.times(read.obj)
    return PASS_REASON[read.construction]


class _Read:
    """One case being judged: each method applies a run of consecutive checks."""

    def __init__(self, case: Path, skip: frozenset[str]) -> None:
        self.case, self.skip = case, skip
        self.context: dict[str, Any] = {}
        self.construction = ""
        self.entry_index: int | None = 0
        self.manifest_index: int | None = 0
        self.catalog: dict[str, Any] = {}
        self.documents: dict[str, Any] = {}
        self.obj: dict[str, Any] = {}
        self.entry: dict[str, Any] = {}
        self.parts: list[str] = []
        self.header_value: dict[str, Any] = {}
        self.signature = b""
        self.alg: Any = None
        self.identity: Any = None
        self.kid: Any = None
        self.key_alg = "none"
        self.public_key: Any = None
        self.artifact_bytes: bytes | None = None
        self.publisher_domain: str | None = None

    def fail(self, code: str) -> None:
        if code not in self.skip:
            raise Refused(code)

    def load(self) -> None:
        """The gates: a closed construction and role, and JSON the reader can hold."""
        self.context = json.loads((self.case / "context.json").read_text(encoding="utf-8"))
        construction = self.context.get("construction")
        if not isinstance(construction, str) or construction not in CONSTRUCTIONS:
            raise Refused("construction_unknown")
        self.construction = construction
        if self.context.get("role") not in ROLES:
            raise Refused("role_unknown")
        self.entry_index = index_of(self.context.get("entry", 0))
        self.manifest_index = index_of(self.context.get("manifest", 0))
        raw_catalog = (self.case / "catalog.json").read_bytes()
        raw_documents = (self.case / "did-documents.json").read_bytes()
        try:
            catalog, documents = strict_loads(raw_catalog), strict_loads(raw_documents)
        except Duplicate:
            self.fail("duplicate_member")
            catalog, documents = json.loads(raw_catalog), json.loads(raw_documents)
        except (ValueError, UnicodeDecodeError) as exc:
            raise Refused("json_invalid") from exc
        if not isinstance(catalog, dict) or not isinstance(documents, dict):
            raise Refused("json_invalid")
        self.catalog, self.documents = catalog, documents

    def signature_object(self) -> None:
        found = signed_object(self.construction, self.catalog, self.entry_index,
                              self.manifest_index)
        if found is None or not isinstance(jws_of(self.construction, found), str):
            raise Refused("signature_missing")
        self.obj = found
        self.parts = jws_of(self.construction, found).split(".")
        if self.construction != SNAPSHOT:
            assert self.entry_index is not None  # signed_object found the entry
            self.entry = self.catalog["entries"][self.entry_index]

    def read_header(self) -> None:
        """jws_malformed through b64_without_crit: the protected header alone."""
        parts = self.parts
        try:
            if len(parts) != 3 or parts[1] != "":
                raise ValueError("not detached compact serialization")
            header = strict_loads(b64url_decode(parts[0]))
            self.signature = b64url_decode(parts[2])
            if not isinstance(header, dict):
                raise ValueError("header is not an object")
        except (ValueError, UnicodeDecodeError) as exc:
            if "jws_malformed" not in self.skip or len(parts) != 3:
                raise Refused("jws_malformed") from exc
            header, self.signature = _lenient_jws(parts)
        self.header_value = header
        if "b64" in header and not isinstance(header["b64"], bool):
            self.fail("jws_malformed")  # RFC 7797 section 3: the b64 value is a boolean
        if self.construction in TYP and header.get("typ") != TYP[self.construction]:
            self.fail("typ_missing_or_mismatched")
        self.alg = header.get("alg")
        if self.alg not in ALGS[self.construction]:
            self.fail("alg_not_allowed_for_profile")
        if any(name in header for name in KEY_SOURCES):
            self.fail("key_source_in_header")
        self.critical(header)

    def critical(self, header: dict[str, Any]) -> None:
        if self.construction not in ARD_SHAPED and "b64" in header:
            self.fail("b64_forbidden_for_profile")
        crit = header.get("crit")
        if crit is not None and (not isinstance(crit, list) or not crit
                                 or any(name != "b64" or name not in header for name in crit)):
            self.fail("jws_crit_unsupported")
        if "b64" in header and not (isinstance(crit, list) and "b64" in crit):
            self.fail("b64_without_crit")

    def signer(self) -> None:
        """profile_unsupported through did_document_not_identity: who claims to have signed."""
        self.identity = identity = identity_of(self.construction, self.obj)
        if self.construction not in ARD_SHAPED:
            # AI Catalog "Profile Selection": the named procedure, never one inferred.
            if self.obj["signature"].get("profile") != SIGNER_PROFILE:
                self.fail("profile_unsupported")
            if not root_did_web(identity):
                self.fail("signer_not_root_did_web")
        self.kid = kid = self.header_value.get("kid")
        kid_ok = (isinstance(kid, str) and isinstance(identity, str)
                  and re.fullmatch(re.escape(identity) + "#" + _FRAGMENT, kid) is not None)
        if not kid_ok:
            self.fail("kid_not_under_identity")
        document = self.documents.get(identity) if isinstance(identity, str) else None
        if not isinstance(document, dict) or document.get("id") != identity:
            self.fail("did_document_not_identity")

    def select_key(self) -> None:
        """kid_not_in_did_document through alg_key_mismatch: the key the document gives."""
        identity, kid = self.identity, self.kid
        document = self.documents.get(identity) if isinstance(identity, str) else None
        methods, assertion = _methods(document if isinstance(document, dict) else {})
        selected = _selected(methods, kid)
        if not selected:
            self.fail("kid_not_in_did_document")
        if len(selected) > 1:
            self.fail("verification_method_ambiguous")  # exactly one method has the kid
        if kid not in assertion:
            self.fail("key_not_assertion_method")
        method = selected[-1] if selected else {}
        if self.construction not in ARD_SHAPED and method.get("controller") != identity:
            self.fail("method_controller_mismatch")
        self.key_alg, self.public_key = _public_key(method)
        if _jwk_fault(method, self.alg):
            self.fail("jwk_not_signing_key")
        if self.key_alg != self.alg:
            self.fail("alg_key_mismatch")

    def signed_bytes(self) -> None:
        """number_not_interoperable, no_canonical_form and signature_invalid."""
        signed = payload(self.construction, self.catalog, self.entry_index, self.manifest_index)
        try:
            _numbers_first(signed)
        except Refused:
            self.fail("number_not_interoperable")
        try:
            body = canonical(signed)
        except Refused as refusal:
            self.fail(str(refusal.args[0]) if refusal.args[0] != "number_not_interoperable"
                      else "no_canonical_form")
            body = json.dumps(signed, sort_keys=True).encode("utf-8", "surrogatepass")
        unencoded = self.header_value.get("b64") is False
        message = self.parts[0].encode() + b"." + (body if unencoded else b64url(body).encode())
        if self.public_key is None or self.key_alg != self.alg or \
                not verify_signature(self.key_alg, self.public_key, message, self.signature):
            self.fail("signature_invalid")

    def subject(self) -> None:
        """signer_not_contributor through subject_entry_mismatch."""
        obj, entry = self.obj, self.entry
        if self.construction == AIC and obj.get("contributor") != self.identity:
            self.fail("signer_not_contributor")
        subject = obj.get("subject")
        if not isinstance(subject, dict):
            self.fail("subject_missing")
            subject = {}
        for member in ("identifier", "type"):
            # Both are required strings on the entry (draft section 3.1, AI Catalog entry).
            if not isinstance(entry.get(member), str) or subject.get(member) != entry.get(member):
                self.fail("subject_entry_mismatch")
        if subject.get("digest") != entry.get("digest"):
            self.fail("subject_entry_mismatch")
        if ("version" in subject) != ("version" in entry) or \
                subject.get("version") != entry.get("version"):
            self.fail("subject_entry_mismatch")

    def artifact(self) -> None:
        entry = self.entry
        # Draft 3.1 and the AI Catalog Catalog Entry: exactly one of url and data.
        if ("url" in entry) == ("data" in entry):
            self.fail("entry_delivery_not_one")
        if "digest" not in entry and ("url" in entry or self.construction == AIC):
            self.fail("entry_digest_missing_for_url")
        if "data" in entry and "url" not in entry:
            # AI Catalog "digest": for data, hash the UTF-8 JCS-canonicalized JSON value; the
            # draft's digest is "of the target artifact referenced by url (or inline data)".
            try:
                self.artifact_bytes = canonical(entry["data"])
            except Refused:
                self.artifact_bytes = None
        else:
            artifact = self.case / "artifact.json"
            self.artifact_bytes = artifact.read_bytes() if artifact.is_file() else None
        if self.artifact_bytes is None or \
                entry.get("digest") != "sha256:" + sha256_hex(self.artifact_bytes):
            self.fail("artifact_digest_mismatch")

    def origin(self) -> None:
        """url_origin_unbound: draft 6.2 binds a url to its origin; inline data has none."""
        entry = self.entry
        self.publisher_domain = publisher = _publisher(entry.get("identifier"))
        if self.construction not in ARD_SHAPED or "url" not in entry:
            return
        if publisher is not None and _origin(entry.get("url")) == f"https://{publisher.lower()}":
            return
        try:
            descriptor = strict_loads(self.artifact_bytes) if self.artifact_bytes else {}
        except (ValueError, UnicodeDecodeError):
            descriptor = {}
        declared = descriptor.get("identifier") if isinstance(descriptor, dict) else None
        if declared != entry.get("identifier"):
            self.fail("url_origin_unbound")

    def publisher_rule(self) -> None:
        if self.context.get("role") != "publisher":
            return
        domain = self.publisher_domain
        if self.identity != (f"did:web:{domain}" if domain else None):
            self.fail("publisher_not_signer" if self.construction == AIC
                      else "publisher_authorization_absent")

    def times(self, holder: dict[str, Any]) -> None:
        """RFC 3339 instants; the AI Catalog Signature object requires issuedAt, the draft
        only recommends it, and expiresAt, when present, is later than issuedAt."""
        issued, expires = times_of(self.construction, holder)
        at, start = _instant(self.context.get("at")), _instant(issued)
        end = _instant(expires)
        if at is None or (issued is None and self.construction not in ARD_SHAPED) or \
                (issued is not None and start is None) or (expires is not None and end is None) \
                or (start is not None and end is not None and end <= start):
            self.fail("timestamp_invalid")
        if at is not None and start is not None and at < start:
            self.fail("issued_in_future")
        if at is not None and end is not None and at >= end:
            self.fail("manifest_expired")


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
