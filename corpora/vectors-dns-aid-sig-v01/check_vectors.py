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
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path(__file__).resolve().parent
SKEW = 300
B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")
REGISTERED_HEADERS = {"alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit"}
DECISION = {
    "key-unusable": "cannot-tell", "zone-absent": "cannot-tell", "key-authority-absent": "cannot-tell",
    "key-authority-kind-unread": "cannot-tell", "iat-in-future": "cannot-tell",
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
        raise Finding("base64url-non-canonical", f"{what} is not the canonical base64url of its bytes")
    return raw


def strict_object(raw: bytes, what: str, dup_code: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise Finding(dup_code, f"{what} names {k!r} twice (not I-JSON)")
            out[k] = v
        return out
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Finding("jws-malformed" if what == "header" else "payload-not-object", f"{what}: {exc}") from None
    if not isinstance(value, dict):
        raise Finding("jws-malformed" if what == "header" else "payload-not-object", f"{what} is not an object")
    return value


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def norm(name: Any) -> str | None:
    return name.rstrip(".").lower() if isinstance(name, str) else None


def within(name: Any, zone: Any) -> bool:
    n, z = norm(name), norm(zone)
    return n is not None and z is not None and (n == z or n.endswith("." + z))


def svcb1(params: dict[str, Any]) -> str:
    covered = {k: v for k, v in params.items() if v is not None}
    raw = b"svcb1:" + json.dumps(covered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def jwks_fingerprint(key_set: dict[str, Any]) -> str:
    lines = sorted(":".join(str(k.get(f, "")) for f in ("kty", "crv", "x", "y", "n", "e"))
                   for k in key_set.get("keys", []) if isinstance(k, dict))
    return base64.urlsafe_b64encode(hashlib.sha256("\n".join(lines).encode()).digest()).decode().rstrip("=")


def keys_for(key_set: Any, kid: Any) -> list[ec.EllipticCurvePublicKey]:
    if not isinstance(key_set, dict):
        return []
    usable = [k for k in key_set.get("keys", []) if isinstance(k, dict) and k.get("kty") == "EC"
              and k.get("crv") == "P-256"]
    if kid is not None:
        usable = [k for k in usable if k.get("kid") == kid] or usable  # RFC 7515 4.1.4: kid is a hint
    out = []
    for k in usable:
        x, y = int.from_bytes(ub64(k.get("x"), "jwk x"), "big"), int.from_bytes(ub64(k.get("y"), "jwk y"), "big")
        try:
            out.append(ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key())
        except ValueError:
            continue
    return out


def check_crit(header: dict[str, Any]) -> None:
    if "crit" not in header:
        return
    crit = header["crit"]
    if not isinstance(crit, list) or not crit:
        raise Finding("crit-refused", "RFC 7515 4.1.11: crit must be a non-empty list")
    if any(name in REGISTERED_HEADERS for name in crit):
        raise Finding("crit-refused", "RFC 7515 4.1.11: crit names a header parameter the specification defines")
    raise Finding("crit-refused", f"RFC 7515 4.1.11: crit {crit!r} names an extension this reader does not support")


def check_authority(case: dict[str, Any], record: dict[str, Any]) -> None:
    zone = record.get("zone")
    if zone is None or not within(record.get("fqdn"), zone):
        raise Finding("zone-absent", "no publishing zone that contains the fqdn")
    url = case.get("jwks_url")
    if url is not None:
        parts = urlsplit(url)
        if parts.scheme != "https" or norm(parts.hostname) not in (f"dns-aid.{norm(zone)}", norm(zone)):
            raise Finding("jwks-host-not-zone", f"JWKS host {parts.hostname!r} is not dns-aid.{zone} or {zone}")
    authority = case.get("key_authority")
    fingerprint = jwks_fingerprint(case["jwks"])
    if authority is None:
        raise Finding("key-authority-absent", f"nothing ties key set {fingerprint} to the owner of {zone}")
    if authority.get("kind") != "pin":
        raise Finding("key-authority-kind-unread", f"key authority kind {authority.get('kind')!r} is not read here")
    if authority.get("jwks_fingerprint") != fingerprint:
        raise Finding("key-set-not-pinned", "the supplied key set is not the one pinned for the zone")


def judge(case: dict[str, Any]) -> tuple[str, str]:
    """(code, detail); code is the empty string for agrees."""
    record, now = case["record"], case["now"]
    parts = case["sig"].split(".") if isinstance(case.get("sig"), str) else []
    if len(parts) != 3:
        raise Finding("jws-malformed", "not a compact JWS")
    header = strict_object(ub64(parts[0], "header"), "header", "header-duplicate-member")
    check_crit(header)
    if header.get("alg") != "ES256":
        raise Finding("alg-not-es256", f"alg {header.get('alg')!r} is not ES256")
    signature = ub64(parts[2], "signature")
    if len(signature) != 64:
        raise Finding("signature-length", "an ES256 signature is 64 bytes")
    keys = keys_for(case.get("jwks"), header.get("kid"))
    if not keys:
        raise Finding("key-unusable", "no usable P-256 key in the key set")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    for key in keys:
        try:
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
            break
        except InvalidSignature:
            continue
    else:
        raise Finding("signature-invalid", "the signature does not verify under any published key")
    body = strict_object(ub64(parts[1], "payload"), "payload", "payload-duplicate-member")
    for field in ("port", "iat", "exp"):
        if not is_int(body.get(field)):
            raise Finding("payload-integer-required", f"{field} is not a JSON integer ({body.get(field)!r})")
    if body["exp"] <= now:
        raise Finding("expired", "expired at the check time")
    protocol = record.get("proto") or record.get("alpn")
    if not (norm(body.get("fqdn")) == norm(record.get("fqdn")) and norm(body.get("target")) == norm(record.get("target"))
            and body["port"] == record.get("port") and body.get("alpn") == protocol):
        raise Finding("endpoint-mismatch", "the signed endpoint differs from the served record")
    if "svcb" in body and body["svcb"] != svcb1(record.get("params") or {}):
        raise Finding("svcb1-digest-mismatch", "the svcb1 digest differs from the served params")
    check_authority(case, record)
    if body["iat"] > now + SKEW:
        raise Finding("iat-in-future", "issued after the check time plus the skew")
    if "svcb" not in body:
        raise Finding("svcb-claim-absent", "valid, endpoint only: the params are not attested")
    return "", "ES256 valid, unexpired, endpoint and svcb1 bound, key set pinned for the zone"


def report(case: Any) -> dict[str, Any]:
    try:
        if not isinstance(case, dict) or not isinstance(case.get("record"), dict) or not isinstance(case.get("jwks"), dict):
            raise Finding("jws-malformed", "the member is not a record, a JWS and a key set")
        code, detail = judge(case)
    except Finding as finding:
        code, detail = finding.code, str(finding)
    except Exception as exc:  # noqa: BLE001 - malformed input is a verdict, never a crash
        code, detail = "jws-malformed", f"malformed: {type(exc).__name__}: {exc}"
    decision = "agrees" if not code else DECISION.get(code, "contradicted")
    return {"codes": [code] if code else [], "decision": decision, "detail": detail,
            "verdict": "valid" if not code else "invalid"}


def self_check(root: Path = ROOT) -> list[str]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    problems = []
    for entry in manifest["vectors"]:
        got = report(json.loads((root / entry["file"]).read_text(encoding="utf-8")))
        want = entry["expected"]
        for field in ("verdict", "decision", "codes"):
            if got[field] != want[field]:
                problems.append(f"{entry['id']}: {field} {got[field]!r}, manifest {want[field]!r} ({got['detail']})")
    return problems


def main(argv: list[str]) -> int:
    if argv:
        rep = report(json.loads(Path(argv[0]).read_text(encoding="utf-8")))
        print(json.dumps(rep, sort_keys=True))
        return 0 if rep["verdict"] == "valid" else 1
    problems = self_check()
    for line in problems:
        print(f"FAIL {line}")
    count = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"{count - len({p.split(':')[0] for p in problems})} of {count} members behave as MANIFEST.json declares")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
