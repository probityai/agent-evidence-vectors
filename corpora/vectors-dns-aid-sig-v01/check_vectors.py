"""A reader for the DNS-AID `sig` binding, written from the profile in MANIFEST.json.

    python3 corpora/vectors-dns-aid-sig-v01/check_vectors.py <case.json>
        judge one member: the last stdout line is the rail report (verdict, codes,
        decision); exit 0 for valid (agrees), 1 for invalid
    python3 corpora/vectors-dns-aid-sig-v01/check_vectors.py
        judge every member and compare with MANIFEST.json; exit 0 when all agree

It imports nothing from the generators. Checks run in a fixed order and the first
that fails names the code, so a member carries exactly one. A malformed input is a
verdict (contradicted), never an exception. Without a key authority a valid
signature tops out at cannot-tell: the key set travels with the evidence, and a
signature only binds the record to whoever holds that key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path(__file__).resolve().parent
SKEW = 300
B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")
#: RFC 7493 section 2.2: an integer beyond this magnitude is not exact in every receiver.
SAFE_INTEGER = 2**53 - 1
#: The only JWKS URL shape read here: https, a host of LDH labels, an optional port, an
#: RFC 3986 path and query, and nothing else (no userinfo, no backslash, no fragment).
#: A WHATWG parser reads "https://evil\\@host/" as host evil, a RFC 3986 one as host.
JWKS_URL = re.compile(
    r"\Ahttps://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?"
    r"(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?\Z"
)
REGISTERED_HEADERS = {
    "alg",
    "jku",
    "jwk",
    "kid",
    "x5u",
    "x5c",
    "x5t",
    "x5t#S256",
    "typ",
    "cty",
    "crit",
}
DECISION = {
    "key-unusable": "cannot-tell",
    "zone-absent": "cannot-tell",
    "key-authority-absent": "cannot-tell",
    "key-authority-kind-unread": "cannot-tell",
    "iat-in-future": "cannot-tell",
    "svcb-claim-absent": "cannot-tell",
}


class Finding(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


def ub64(text: Any, what: str) -> bytes:
    if not isinstance(text, str) or not B64URL.match(text) or len(text) % 4 == 1:
        raise Finding("jws-malformed", f"{what} is not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text:
        raise Finding(
            "base64url-non-canonical", f"{what} is not the canonical base64url of its bytes"
        )
    return raw


def not_unicode_scalar_text(text: str) -> bool:
    """RFC 7493 section 2.1: no surrogate and no noncharacter code point."""
    return any(
        0xD800 <= (o := ord(ch)) <= 0xDFFF or 0xFDD0 <= o <= 0xFDEF or (o & 0xFFFE) == 0xFFFE
        for ch in text
    )


def scalar_text_throughout(value: Any) -> bool:
    """Every member name and string in value is Unicode scalar text with no noncharacter."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if any(not_unicode_scalar_text(k) for k in item):
                return False
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and not_unicode_scalar_text(item):
            return False
    return True


def i_json(raw: bytes, what: str, dup_code: str, parse_code: str, text_code: str) -> Any:
    """Parse I-JSON or raise: a duplicate name, a NaN or Infinity literal (not JSON at
    all, though Python's json accepts them), and a surrogate or noncharacter in a name
    or string each refuse the input."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise Finding(dup_code, f"{what} names {k!r} twice (not I-JSON)")
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise Finding(parse_code, f"{what}: {name} is not a JSON value")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (
        UnicodeDecodeError,
        ValueError,
        RecursionError,
    ) as exc:  # nesting too deep is not a crash
        raise Finding(parse_code, f"{what}: {exc}") from None
    if not scalar_text_throughout(value):
        raise Finding(
            text_code, f"{what}: a name or string holds a surrogate or noncharacter (RFC 7493 2.1)"
        )
    return value


def strict_object(raw: bytes, what: str, dup_code: str) -> dict[str, Any]:
    header = what == "header"
    value = i_json(
        raw,
        what,
        dup_code,
        "jws-malformed" if header else "payload-not-object",
        "jws-malformed" if header else "payload-not-i-json",
    )
    if not isinstance(value, dict):
        raise Finding(
            "jws-malformed" if header else "payload-not-object", f"{what} is not an object"
        )
    return value


def is_int(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -SAFE_INTEGER <= value <= SAFE_INTEGER
    )


ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def norm(name: Any) -> str | None:
    """A DNS name compared the way DNS compares it: ASCII case only (RFC 4343) and one
    optional root dot. str.lower() would fold the Kelvin sign to k and make a served
    target that resolves elsewhere equal the signed one."""
    if not isinstance(name, str):
        return None
    return (name[:-1] if name.endswith(".") else name).translate(ASCII_LOWER)


def within(name: Any, zone: Any) -> bool:
    n, z = norm(name), norm(zone)
    return bool(n) and bool(z) and (n == z or n.endswith("." + z))  # the root is no publishing zone


def svcb1(params: dict[str, Any]) -> str:
    covered = {k: v for k, v in params.items() if v is not None}
    raw = (
        b"svcb1:"
        + json.dumps(covered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def jwks_fingerprint(key_set: dict[str, Any]) -> str:
    lines = sorted(
        ":".join(str(k.get(f, "")) for f in ("kty", "crv", "x", "y", "n", "e"))
        for k in key_set.get("keys", [])
        if isinstance(k, dict)
    )
    return (
        base64.urlsafe_b64encode(hashlib.sha256("\n".join(lines).encode()).digest())
        .decode()
        .rstrip("=")
    )


def signing_key(k: Any) -> ec.EllipticCurvePublicKey | None:
    """The P-256 verification key a JWK holds, or None when it holds none.

    RFC 7517 section 5 says to ignore a JWK that is missing required members or whose
    values are out of range, so one bad key does not void the set. A key whose `use`
    is not sig (4.2), whose `key_ops` lacks verify (4.3) or whose `alg` is not ES256
    (4.4) was published for something else, and RFC 7518 6.2.1.2 requires each
    coordinate to be the full 32 octets."""
    if not (isinstance(k, dict) and k.get("kty") == "EC" and k.get("crv") == "P-256"):
        return None
    if k.get("use", "sig") != "sig" or k.get("alg", "ES256") != "ES256":
        return None
    if "key_ops" in k and not (isinstance(k["key_ops"], list) and "verify" in k["key_ops"]):
        return None
    try:
        xb, yb = ub64(k.get("x"), "jwk x"), ub64(k.get("y"), "jwk y")
    except Finding:
        return None
    if len(xb) != 32 or len(yb) != 32:
        return None
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(xb, "big"), int.from_bytes(yb, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError:
        return None


def keys_for(key_set: Any, kid: Any) -> list[ec.EllipticCurvePublicKey]:
    if not isinstance(key_set, dict) or not isinstance(key_set.get("keys"), list):
        return []
    usable = [(k, key) for k in key_set["keys"] if (key := signing_key(k)) is not None]
    if kid is not None:
        usable = [
            p for p in usable if p[0].get("kid") == kid
        ] or usable  # RFC 7515 4.1.4: kid is a hint
    return [key for _, key in usable]


def check_crit(header: dict[str, Any]) -> None:
    if "crit" not in header:
        return
    crit = header["crit"]
    if not isinstance(crit, list) or not crit:
        raise Finding("crit-refused", "RFC 7515 4.1.11: crit must be a non-empty list")
    if any(name in REGISTERED_HEADERS for name in crit):
        raise Finding(
            "crit-refused",
            "RFC 7515 4.1.11: crit names a header parameter the specification defines",
        )
    raise Finding(
        "crit-refused",
        f"RFC 7515 4.1.11: crit {crit!r} names an extension this reader does not support",
    )


def check_authority(case: dict[str, Any], record: dict[str, Any]) -> None:
    zone = record.get("zone")
    if zone is None or not within(record.get("fqdn"), zone):
        raise Finding("zone-absent", "no publishing zone that contains the fqdn")
    url = case.get("jwks_url")
    if url is not None:
        shape = JWKS_URL.match(url) if isinstance(url, str) else None
        host = norm(shape.group(1)) if shape and int(shape.group(2) or 443) <= 65535 else None
        if host not in (f"dns-aid.{norm(zone)}", norm(zone)):
            raise Finding(
                "jwks-host-not-zone",
                f"JWKS URL {url!r} is not https on dns-aid.{zone} or {zone} "
                "with no userinfo, backslash or fragment",
            )
    authority = case.get("key_authority")
    fingerprint = jwks_fingerprint(case["jwks"])
    if authority is None:
        raise Finding(
            "key-authority-absent", f"nothing ties key set {fingerprint} to the owner of {zone}"
        )
    if authority.get("kind") != "pin":
        raise Finding(
            "key-authority-kind-unread",
            f"key authority kind {authority.get('kind')!r} is not read here",
        )
    if authority.get("jwks_fingerprint") != fingerprint:
        raise Finding(
            "key-set-not-pinned", "the supplied key set is not the one pinned for the zone"
        )


def check_header(parts: list[str]) -> dict[str, Any]:
    header = strict_object(ub64(parts[0], "header"), "header", "header-duplicate-member")
    check_crit(header)
    if "b64" in header:
        raise Finding(
            "jws-malformed",
            "RFC 7797: b64 changes what is signed, and this profile defines no unencoded payload",
        )
    if header.get("alg") != "ES256":
        raise Finding("alg-not-es256", f"alg {header.get('alg')!r} is not ES256")
    return header


def check_signature(parts: list[str], header: dict[str, Any], key_set: Any) -> None:
    signature = ub64(parts[2], "signature")
    if len(signature) != 64:
        raise Finding("signature-length", "an ES256 signature is 64 bytes")
    keys = keys_for(key_set, header.get("kid"))
    if not keys:
        raise Finding("key-unusable", "no usable P-256 key in the key set")
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    for key in keys:
        try:
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            return
        except InvalidSignature:
            continue
    raise Finding("signature-invalid", "the signature does not verify under any published key")


def check_payload(segment: str, now: int) -> dict[str, Any]:
    body = strict_object(ub64(segment, "payload"), "payload", "payload-duplicate-member")
    for field in ("port", "iat", "exp"):
        if not is_int(body.get(field)):
            raise Finding(
                "payload-integer-required",
                f"{field} is not a JSON integer within I-JSON's exact range ({body.get(field)!r})",
            )
    if not 0 <= body["port"] <= 65535:
        raise Finding(
            "payload-integer-required", f"port {body['port']} is not a 16-bit port (RFC 9460 7.2)"
        )
    if body["exp"] <= body["iat"]:
        raise Finding("validity-window-inverted", "exp is at or before iat: the window is empty")
    if body["exp"] <= now:
        raise Finding("expired", "expired at the check time")
    return body


def check_endpoint(body: dict[str, Any], record: dict[str, Any]) -> None:
    protocol = record["proto"] if "proto" in record else record.get("alpn")
    named = all(isinstance(body.get(f), str) for f in ("fqdn", "target", "alpn"))
    if not (
        named
        and norm(body["fqdn"]) == norm(record.get("fqdn"))
        and norm(body["target"]) == norm(record.get("target"))
        and body["port"] == record.get("port")
        and body["alpn"] == protocol
    ):
        raise Finding("endpoint-mismatch", "the signed endpoint differs from the served record")
    if "svcb" in body and body["svcb"] != svcb1(record.get("params") or {}):
        raise Finding("svcb1-digest-mismatch", "the svcb1 digest differs from the served params")


def judge(case: dict[str, Any]) -> tuple[str, str]:
    """(code, detail); code is the empty string for agrees. The checks run in a fixed
    order and the first that fails names the code."""
    record, now = case["record"], case["now"]
    parts = case["sig"].split(".") if isinstance(case.get("sig"), str) else []
    if len(parts) != 3:
        raise Finding("jws-malformed", "not a compact JWS")
    check_signature(parts, check_header(parts), case.get("jwks"))
    body = check_payload(parts[1], now)
    check_endpoint(body, record)
    check_authority(case, record)
    if body["iat"] > now + SKEW:
        raise Finding("iat-in-future", "issued after the check time plus the skew")
    if "svcb" not in body:
        raise Finding("svcb-claim-absent", "valid, endpoint only: the params are not attested")
    return "", "ES256 valid, unexpired, endpoint and svcb1 bound, key set pinned for the zone"


def load_case(raw: bytes) -> Any:
    """A member file is I-JSON too: a case that names a record field twice binds one
    value in a first-wins reader and another in a last-wins one."""
    try:
        return i_json(raw, "member", "jws-malformed", "jws-malformed", "jws-malformed")
    except Finding as finding:
        return finding


def report(case: Any) -> dict[str, Any]:
    try:
        if isinstance(case, Finding):
            raise case
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("record"), dict)
            or not isinstance(case.get("jwks"), dict)
        ):
            raise Finding("jws-malformed", "the member is not a record, a JWS and a key set")
        code, detail = judge(case)
    except Finding as finding:
        code, detail = finding.code, str(finding)
    except Exception as exc:  # noqa: BLE001 - malformed input is a verdict, never a crash
        code, detail = "jws-malformed", f"malformed: {type(exc).__name__}: {exc}"
    decision = "agrees" if not code else DECISION.get(code, "contradicted")
    return {
        "codes": [code] if code else [],
        "decision": decision,
        "detail": detail,
        "verdict": "valid" if not code else "invalid",
    }


def self_check(root: Path = ROOT) -> list[str]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    problems = []
    for entry in manifest["vectors"]:
        got = report(load_case((root / entry["file"]).read_bytes()))
        want = entry["expected"]
        for field in ("verdict", "decision", "codes"):
            if got[field] != want[field]:
                problems.append(
                    f"{entry['id']}: {field} {got[field]!r}, "
                    f"manifest {want[field]!r} ({got['detail']})"
                )
    return problems


def main(argv: list[str]) -> int:
    if argv:
        rep = report(load_case(Path(argv[0]).read_bytes()))
        print(json.dumps(rep, sort_keys=True))
        return 0 if rep["verdict"] == "valid" else 1
    problems = self_check()
    for line in problems:
        print(f"FAIL {line}")
    count = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(
        f"{count - len({p.split(':')[0] for p in problems})} of {count} members "
        "behave as MANIFEST.json declares"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
