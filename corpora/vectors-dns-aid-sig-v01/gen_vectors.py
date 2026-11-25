"""Build the deterministic DNS-AID `sig` binding vectors.

    uv run --locked --extra generators python corpora/vectors-dns-aid-sig-v01/gen_vectors.py

A DNS-AID publisher signs a compact JWS (ES256) over the endpoint it serves in
an SVCB record and over a domain-separated digest of the record's SvcParams
(the `svcb1` digest), and publishes the key set at https://dns-aid.<zone>/. Each
member here is one record as served, the JWS beside it, the key set that came
with it and the consumer's key authority for the zone, if any. The manifest
holds the decision a reader must reach (agrees, contradicted or cannot-tell),
mapped onto the rail contract (agrees is valid; the other two are invalid with
the reason codes listed).

Every member, the manifest and the index are functions of this file alone:
keys come from fixed labels and every signature is RFC 6979 deterministic
ECDSA, so a regeneration writes the same bytes. ``gen_vectors_independent.py``
builds the same members with its own P-256, RFC 6979, JSON writer and base64url
code, and the corpus test requires the two to agree byte for byte.

The fixtures are synthetic: no real zone, host or key appears in any of them.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parent
SUITE = "dns-aid-sig-binding/v1"
NOW = 1790000000
ZONE = "example.com"
JWKS_URL = f"https://dns-aid.{ZONE}/.well-known/dns-aid-jwks.json"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HEADER = {"alg": "ES256", "kid": "k1", "typ": "JWT"}

SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "scope": (
        "The `sig` binding of a DNS-AID SVCB record: a compact JWS (RFC 7515, ES256 with a "
        "raw 64-byte signature) whose payload names the endpoint (fqdn, target, port, agent "
        "protocol), an issue and an expiry time, and optionally the `svcb1` digest of the "
        "record's SvcParams. The digest is SHA-256 over the ASCII prefix `svcb1:` followed by "
        "the canonical JSON of the non-null params (keys sorted, no whitespace). A reader "
        "reaches agrees only when the signature verifies, the endpoint and digest match the "
        "served record, the record is unexpired and issued no later than five minutes after "
        "the check time, and a key authority the consumer holds (today a pin of the key-set "
        "fingerprint) ties the key set to the owner of the zone. All fixtures are synthetic."
    ),
    "profile": {
        "payload": "I-JSON (RFC 7493): a duplicate member name, a NaN or Infinity literal, and a "
        "surrogate or noncharacter code point in a name or string are refused; the member file "
        "itself is I-JSON too",
        "integers": "port, iat and exp are JSON integers from -(2^53-1) to 2^53-1 (RFC 7493 "
        "section 2.2); 443.0 is not 443; port is 0 to 65535",
        "names": "fqdn, target and zone compare by ASCII case only (RFC 4343) with one optional "
        "root dot",
        "keys": "a JWK verifies only when it is EC P-256 with 32-octet coordinates, its use is sig "
        "or absent, its key_ops name verify or are absent, and its alg is ES256 or absent; any "
        "other key in the set is ignored (RFC 7517 section 5)",
        "iatSkewSeconds": 300,
        "window": "exp after iat; a window whose exp is at or before its iat is refused",
        "crit": "a crit header is refused (RFC 7515 section 4.1.11): this profile defines no "
        "extension",
        "base64url": "the strict alphabet without padding, and the canonical encoding only",
        "protocol": "the payload's fqdn, target and alpn are strings; its alpn is compared with the "
        "record's proto when that member is present (an empty proto names nothing), else with its "
        "alpn",
        "jwksHost": "https://dns-aid.<zone> or https://<zone>, with an optional port from 0 to "
        "65535, path and query and no userinfo, backslash, percent-encoded host or fragment",
    },
    "sources": [
        "RFC 7515 JSON Web Signature, sections 2, 4.1.11 and 7.1",
        "RFC 7518 JSON Web Algorithms, sections 3.4 (ES256) and 6.2.1.2 (coordinate length)",
        "RFC 7517 JSON Web Key, sections 4.2 to 4.4 and 5",
        "RFC 4343 DNS case insensitivity",
        "RFC 7493 The I-JSON Message Format",
        "RFC 9460 Service Binding and Parameter Specification via the DNS (SVCB)",
        "RFC 4648 section 3.5 (canonical encoding)",
        "RFC 6979 Deterministic Usage of DSA and ECDSA (fixture signing)",
        "IETF draft on DNS-based agent discovery, section 3.1.1 (record shape)",
    ],
    "verifierContract": (
        "verifier <case file>: the last stdout line is one JSON object with `verdict` (valid "
        "or invalid), `codes` (the reason codes, a set) and optionally `decision` (agrees, "
        "contradicted or cannot-tell); exit 0 for valid, 1 for invalid."
    ),
}

#: The reason code a reader reports for each way a member fails, and the decision it
#: implies. cannot-tell is never agrees: it is invalid on the rail.
CODES: dict[str, str] = {
    "jws-malformed": "contradicted",
    "base64url-non-canonical": "contradicted",
    "header-duplicate-member": "contradicted",
    "crit-refused": "contradicted",
    "alg-not-es256": "contradicted",
    "signature-length": "contradicted",
    "signature-invalid": "contradicted",
    "key-unusable": "cannot-tell",
    "payload-not-object": "contradicted",
    "payload-duplicate-member": "contradicted",
    "payload-integer-required": "contradicted",
    "payload-not-i-json": "contradicted",
    "validity-window-inverted": "contradicted",
    "expired": "contradicted",
    "endpoint-mismatch": "contradicted",
    "svcb1-digest-mismatch": "contradicted",
    "zone-absent": "cannot-tell",
    "jwks-host-not-zone": "contradicted",
    "key-authority-absent": "cannot-tell",
    "key-authority-kind-unread": "cannot-tell",
    "key-set-not-pinned": "contradicted",
    "iat-in-future": "cannot-tell",
    "svcb-claim-absent": "cannot-tell",
}


# ---------------------------------------------------------------------------
# Encoding and signing
# ---------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def cjson(value: Any) -> bytes:
    """Compact JSON with sorted keys, UTF-8: the bytes every signed object is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def svcb1(params: dict[str, Any], prefix: bytes = b"svcb1:") -> str:
    covered = {k: v for k, v in params.items() if v is not None}
    return b64u(hashlib.sha256(prefix + cjson(covered)).digest())


def private_key(label: str) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(
        hashlib.sha256(f"vectors-dns-aid-sig-v01/{label}".encode()).digest(), "big"
    )
    return ec.derive_private_key(scalar % (P256_N - 1) + 1, ec.SECP256R1())


def jwks(label: str) -> dict[str, Any]:
    numbers = private_key(label).public_key().public_numbers()
    return {
        "keys": [
            {
                "crv": "P-256",
                "kid": "k1",
                "kty": "EC",
                "x": b64u(numbers.x.to_bytes(32, "big")),
                "y": b64u(numbers.y.to_bytes(32, "big")),
            }
        ]
    }


def jwks_fingerprint(key_set: dict[str, Any]) -> str:
    """SHA-256 over the sorted key-material lines (kty:crv:x:y:n:e), base64url."""
    lines = sorted(
        ":".join(str(k.get(f, "")) for f in ("kty", "crv", "x", "y", "n", "e"))
        for k in key_set["keys"]
    )
    return b64u(hashlib.sha256("\n".join(lines).encode()).digest())


def raw_signature(label: str, signing_input: bytes) -> bytes:
    der = private_key(label).sign(
        signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    )
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def compact(label: str, payload: bytes, header: dict[str, Any] | None = None) -> str:
    h = b64u(cjson(HEADER if header is None else header))
    p = b64u(payload)
    return f"{h}.{p}.{b64u(raw_signature(label, f'{h}.{p}'.encode()))}"


# ---------------------------------------------------------------------------
# Records and payloads
# ---------------------------------------------------------------------------

PARAMS_FULL = {
    "bap": None,
    "cap": "https://chat.example.com/.well-known/agent-cap.json",
    "cap-sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "connect-class": None,
    "connect-meta": None,
    "enroll-uri": None,
    "policy": "https://example.com/agent-policy",
    "realm": "prod",
    "well-known": None,
}
PARAMS_NO_REALM = {**PARAMS_FULL, "realm": None}
RECORD = {
    "alpn": "a2a",
    "fqdn": "_chat._a2a._agents.example.com",
    "params": PARAMS_FULL,
    "port": 443,
    "target": "chat.example.com",
    "zone": ZONE,
}
RECORD_NO_REALM = {
    "alpn": "a2a",
    "fqdn": "chat.example.com",
    "params": PARAMS_NO_REALM,
    "port": 443,
    "target": "chat.example.com",
    "zone": ZONE,
}


def payload(
    rec: dict[str, Any],
    *,
    params: dict[str, Any] | None = None,
    svcb: bool = True,
    alpn: str | None = None,
    iat: int = NOW - 60,
    exp: int = NOW + 86400,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "alpn": alpn or rec["alpn"],
        "exp": exp,
        "fqdn": rec["fqdn"],
        "iat": iat,
        "port": rec["port"],
        "target": rec["target"],
    }
    if svcb:
        body["svcb"] = svcb1(rec["params"] if params is None else params)
    return body


def pin(label: str) -> dict[str, Any]:
    return {"jwks_fingerprint": jwks_fingerprint(jwks(label)), "kind": "pin"}


def member(
    rec: dict[str, Any],
    sig: str,
    key_label: str = "owner",
    *,
    url: str | None = JWKS_URL,
    authority: dict[str, Any] | None | str = "pin-owner",
) -> dict[str, Any]:
    case: dict[str, Any] = {"jwks": jwks(key_label), "now": NOW, "record": rec, "sig": sig}
    if url is not None:
        case["jwks_url"] = url
    if authority == "pin-owner":
        case["key_authority"] = pin("owner")
    elif authority is not None:
        case["key_authority"] = authority
    return case


def with_record(base: dict[str, Any], **changes: Any) -> dict[str, Any]:
    rec = copy.deepcopy(base)
    params = changes.pop("params", None)
    rec.update(changes)
    if params:
        rec["params"] = {**rec["params"], **params}
    return rec


def non_canonical_tail(segment: str) -> str:
    """Set the unused low bits of the last base64url character: same bytes, other text."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    value = alphabet.index(segment[-1])
    spare = {2: 0b1111, 3: 0b11}[len(segment) % 4]
    return segment[:-1] + alphabet[value | spare]


# ---------------------------------------------------------------------------
# Members: (id, builder, codes, description)
# ---------------------------------------------------------------------------

Build = Callable[[], dict[str, Any]]


def _good() -> str:
    return compact("owner", cjson(payload(RECORD)))


def _crafted(body: bytes, header: dict[str, Any] | None = None) -> str:
    return compact("owner", body, header)


def _split(sig: str) -> list[str]:
    return sig.split(".")


def _bitflip() -> dict[str, Any]:
    h, p, s = _split(_good())
    raw = bytearray(base64.urlsafe_b64decode(s + "=="))
    raw[5] ^= 1
    return member(RECORD, f"{h}.{p}.{b64u(bytes(raw))}")


def _non_canonical() -> dict[str, Any]:
    h, p, s = _split(_good())
    return member(RECORD, f"{h}.{p}.{non_canonical_tail(s)}")


def _alg_none() -> dict[str, Any]:
    _, p, _ = _split(_good())
    return member(RECORD, b64u(cjson({"alg": "none", "kid": "k1"})) + "." + p + ".")


def _dup_member() -> dict[str, Any]:
    body = cjson(payload(RECORD)).decode()
    return member(RECORD, _crafted(('{"fqdn":"_x._a2a._agents.evil.example",' + body[1:]).encode()))


def _port_float() -> dict[str, Any]:
    body = cjson(payload(RECORD)).decode().replace('"port":443', '"port":443.0')
    return member(RECORD, _crafted(body.encode()))


def _field_boundary_served() -> dict[str, Any]:
    signed = {**PARAMS_FULL, "cap": "u", "realm": "t"}
    served = with_record(RECORD, params={"cap": "u\nrealm=t", "realm": None})
    return member(served, compact("owner", cjson(payload(RECORD, params=signed))))


def _field_boundary_signed() -> dict[str, Any]:
    signed = {**PARAMS_FULL, "cap": "u\nrealm=t", "realm": None}
    served = with_record(RECORD, params={"cap": "u", "realm": "t"})
    return member(served, compact("owner", cjson(payload(RECORD, params=signed))))


def _no_domain_prefix() -> dict[str, Any]:
    body = payload(RECORD)
    body["svcb"] = svcb1(PARAMS_FULL, prefix=b"")
    return member(RECORD, compact("owner", cjson(body)))


def _crit(value: Any, extra: dict[str, Any] | None = None) -> Build:
    def build() -> dict[str, Any]:
        header = {**HEADER, "crit": value, **(extra or {})}
        return member(RECORD_NO_REALM, compact("owner", cjson(payload(RECORD_NO_REALM)), header))

    return build


def _injected(param: str, value: str) -> Build:
    def build() -> dict[str, Any]:
        served = with_record(RECORD_NO_REALM, params={param: value})
        return member(served, compact("owner", cjson(payload(RECORD_NO_REALM))))

    return build


def _raw_header(header_text: bytes) -> dict[str, Any]:
    h, p = b64u(header_text), b64u(cjson(payload(RECORD)))
    return member(RECORD, f"{h}.{p}.{b64u(raw_signature('owner', f'{h}.{p}'.encode()))}")


def _truncated() -> dict[str, Any]:
    h, p, s = _split(_good())
    return member(RECORD, f"{h}.{p}.{b64u(base64.urlsafe_b64decode(s + '==')[:63])}")


def _rsa_only() -> dict[str, Any]:
    case = member(RECORD, _good())
    case["jwks"] = {
        "keys": [
            {
                "e": "AQAB",
                "kid": "k1",
                "kty": "RSA",
                "n": b64u(hashlib.sha256(b"vectors-dns-aid-sig-v01/rsa-n").digest()),
            }
        ]
    }
    return case


def _no_zone() -> dict[str, Any]:
    rec = copy.deepcopy(RECORD)
    del rec["zone"]
    return member(rec, _good())


def _payload_tail(extra: bytes) -> dict[str, Any]:
    """The good payload with raw JSON text appended before its closing brace."""
    return member(RECORD, _crafted(cjson(payload(RECORD))[:-1] + extra + b"}"))


def _signed_as(signed: dict[str, Any], served: dict[str, Any]) -> dict[str, Any]:
    return member(served, compact("owner", cjson(payload(signed))))


def _jwk(**changes: Any) -> Build:
    def build() -> dict[str, Any]:
        case = member(RECORD, _good())
        case["jwks"]["keys"][0].update(changes)
        return case

    return build


def _x_33_bytes() -> dict[str, Any]:
    case = member(RECORD, _good())
    key = case["jwks"]["keys"][0]
    key["x"] = b64u(b"\x00" + base64.urlsafe_b64decode(key["x"] + "="))
    return case


def _skips_malformed_key() -> dict[str, Any]:
    header = {"alg": "ES256", "typ": "JWT"}
    case = member(RECORD, compact("owner", cjson(payload(RECORD)), header))
    case["jwks"]["keys"].insert(
        0, {"crv": "P-256", "kid": "k0", "kty": "EC", "x": "not base64url!", "y": ""}
    )
    case["key_authority"] = {"jwks_fingerprint": jwks_fingerprint(case["jwks"]), "kind": "pin"}
    return case


def _no_target() -> dict[str, Any]:
    rec = {k: v for k, v in RECORD.items() if k != "target"}
    body = {k: v for k, v in payload(RECORD).items() if k != "target"}
    return member(rec, compact("owner", cjson(body)))


#: Member files whose text is edited after writing, so that one is not I-JSON:
#: (the line to find, the line put in front of it).
TEXT_EDITS = {
    "member-duplicate-target": (
        '  "target": "chat.example.com",\n',
        '  "target": "evil.example.net",\n',
    ),
}


def _dawn_shape() -> dict[str, Any]:
    served = with_record(RECORD_NO_REALM, alpn="h2,h3", proto="a2a")
    return member(served, compact("owner", cjson(payload(RECORD_NO_REALM, alpn="a2a"))))


MEMBERS: tuple[tuple[str, Build, list[str], str], ...] = (
    (
        "full-coverage-valid",
        lambda: member(RECORD, _good()),
        [],
        "ES256 valid, unexpired, endpoint and svcb1 digest match, key set pinned for the zone",
    ),
    (
        "endpoint-only",
        lambda: member(RECORD, compact("owner", cjson(payload(RECORD, svcb=False)))),
        ["svcb-claim-absent"],
        "valid, but the payload carries no svcb digest: cap, cap-sha256, policy and realm are not "
        "attested",
    ),
    (
        "param-tamper-cap-sha256",
        lambda: member(
            with_record(RECORD, params={"cap-sha256": "AAAA" + PARAMS_FULL["cap-sha256"][4:]}),
            _good(),
        ),
        ["svcb1-digest-mismatch"],
        "served cap-sha256 differs from the signed svcb1 digest",
    ),
    (
        "endpoint-tamper-target",
        lambda: member(with_record(RECORD, target="evil.example.net"), _good()),
        ["endpoint-mismatch"],
        "served target differs from the signed target",
    ),
    (
        "expired",
        lambda: member(
            RECORD, compact("owner", cjson(payload(RECORD, iat=NOW - 7200, exp=NOW - 3600)))
        ),
        ["expired"],
        "exp is before the check time",
    ),
    (
        "wrong-key",
        lambda: member(RECORD, compact("second", cjson(payload(RECORD)))),
        ["signature-invalid"],
        "signed by a key the published and pinned key set does not hold",
    ),
    (
        "alg-none",
        _alg_none,
        ["alg-not-es256"],
        "alg none with an empty signature: only ES256 is allowed",
    ),
    ("sig-bitflip", _bitflip, ["signature-invalid"], "one signature bit flipped"),
    (
        "svcb1-field-boundary",
        _field_boundary_served,
        ["svcb1-digest-mismatch"],
        "signed {cap: u, realm: t}; served cap 'u\\nrealm=t' with no realm must not bind",
    ),
    (
        "dup-member-fqdn",
        _dup_member,
        ["payload-duplicate-member"],
        "the signed payload names fqdn twice; a first-wins and a last-wins parser bind different "
        "names",
    ),
    (
        "port-float",
        _port_float,
        ["payload-integer-required"],
        "port is 443.0, which is not the JSON integer 443",
    ),
    (
        "iat-future",
        lambda: member(
            RECORD, compact("owner", cjson(payload(RECORD, iat=NOW + 86400, exp=NOW + 2 * 86400)))
        ),
        ["iat-in-future"],
        "issued a day after the check time, beyond the 300 second skew: not yet attested",
    ),
    (
        "foreign-key-no-provenance",
        lambda: member(
            RECORD_NO_REALM,
            compact("attacker", cjson(payload(RECORD_NO_REALM))),
            "attacker",
            url=None,
            authority=None,
        ),
        ["key-authority-absent"],
        "a self-consistent triple under a key nothing ties to the zone owner: the key set travels "
        "with the evidence",
    ),
    (
        "foreign-key-wrong-host",
        lambda: member(
            RECORD_NO_REALM,
            compact("attacker", cjson(payload(RECORD_NO_REALM))),
            "attacker",
            url="https://dns-aid.attacker.example/.well-known/dns-aid-jwks.json",
            authority=None,
        ),
        ["jwks-host-not-zone"],
        "the key set was fetched from a host that is neither dns-aid.<zone> nor the zone",
    ),
    (
        "foreign-key-pinned-owner",
        lambda: member(
            RECORD_NO_REALM, compact("attacker", cjson(payload(RECORD_NO_REALM))), "attacker"
        ),
        ["key-set-not-pinned"],
        "the supplied key set's fingerprint differs from the consumer's pin for the zone",
    ),
    (
        "owner-key-pinned-control",
        lambda: member(RECORD_NO_REALM, compact("owner", cjson(payload(RECORD_NO_REALM)))),
        [],
        "control: owner key, derived host, pin matches, full svcb1 coverage",
    ),
    (
        "crit-unknown-extension",
        _crit(["x-scope"], {"x-scope": "tenant-a"}),
        ["crit-refused"],
        "crit names an extension the reader does not understand (RFC 7515 section 4.1.11 MUST)",
    ),
    (
        "crit-empty-list",
        _crit([]),
        ["crit-refused"],
        "crit is an empty list, which RFC 7515 section 4.1.11 forbids",
    ),
    (
        "crit-names-registered-header",
        _crit(["alg"]),
        ["crit-refused"],
        "crit names alg, a header parameter the JWS specification defines, which RFC 7515 forbids",
    ),
    (
        "proto-field-agent-protocol",
        _dawn_shape,
        [],
        "record in the newer draft shape: alpn carries the transports, proto the agent protocol "
        "the payload names",
    ),
    (
        "malformed-header-base64url",
        lambda: member(RECORD_NO_REALM, "a." + _split(_good())[1] + ".AAAA"),
        ["jws-malformed"],
        "the header segment is not decodable base64url: contradicted, never a crash",
    ),
    (
        "realm-empty-injected",
        _injected("realm", ""),
        ["svcb1-digest-mismatch"],
        "realm was never set and is served as an empty string: an empty value is a value",
    ),
    (
        "realm-value-injected",
        _injected("realm", "prod"),
        ["svcb1-digest-mismatch"],
        "realm was never set and is served with a value the digest does not cover",
    ),
    (
        "bap-empty-injected",
        _injected("bap", ""),
        ["svcb1-digest-mismatch"],
        "a second unset param served as an empty string: the rule is per param, not specific to "
        "realm",
    ),
    (
        "svcb1-without-domain-prefix",
        _no_domain_prefix,
        ["svcb1-digest-mismatch"],
        "the signed digest omits the svcb1: prefix; a digest of the bare JSON must not bind",
    ),
    (
        "svcb1-newline-in-signed-value",
        _field_boundary_signed,
        ["svcb1-digest-mismatch"],
        "signed cap 'u\\nrealm=t' with no realm; served {cap: u, realm: t} must not bind",
    ),
    (
        "header-duplicate-alg",
        lambda: _raw_header(b'{"alg":"none","alg":"ES256","kid":"k1","typ":"JWT"}'),
        ["header-duplicate-member"],
        "the header names alg twice; a first-wins parser reads none, a last-wins one ES256",
    ),
    (
        "signature-truncated",
        _truncated,
        ["signature-length"],
        "an ES256 signature one byte short of 64",
    ),
    (
        "key-set-without-ec-key",
        _rsa_only,
        ["key-unusable"],
        "the key set holds only an RSA key, so nothing can check an ES256 signature: not read as "
        "a failure of the record",
    ),
    (
        "payload-array",
        lambda: member(RECORD, _crafted(b'["_chat._a2a._agents.example.com"]')),
        ["payload-not-object"],
        "the signed payload is a JSON array, not an object",
    ),
    (
        "record-without-zone",
        _no_zone,
        ["zone-absent"],
        "the served record names no publishing zone, so no key authority can be looked up for it",
    ),
    (
        "key-authority-dnssec-chain",
        lambda: member(RECORD, _good(), authority={"kind": "dnssec-chain"}),
        ["key-authority-kind-unread"],
        "the key authority is a DNSSEC chain, which this profile's pin reader does not read",
    ),
    (
        "signature-base64url-non-canonical",
        _non_canonical,
        ["base64url-non-canonical"],
        "the signature verifies once decoded, but its text sets unused low bits: the encoding is "
        "not canonical",
    ),
    (
        "payload-nan-literal",
        lambda: _payload_tail(b',"z":NaN'),
        ["payload-not-object"],
        "the signed payload holds a NaN literal, which is not JSON though a lenient parser reads it",
    ),
    (
        "header-infinity-literal",
        lambda: _raw_header(b'{"alg":"ES256","kid":"k1","typ":"JWT","x":-Infinity}'),
        ["jws-malformed"],
        "the protected header holds a -Infinity literal, which is not JSON",
    ),
    (
        "payload-lone-surrogate",
        lambda: _payload_tail(b',"z":"\\ud800"'),
        ["payload-not-i-json"],
        "the signed payload holds a lone surrogate escape, which RFC 7493 section 2.1 forbids",
    ),
    (
        "payload-noncharacter",
        lambda: _payload_tail(',"z":"\ufdd0"'.encode()),
        ["payload-not-i-json"],
        "the signed payload holds the noncharacter U+FDD0, which RFC 7493 section 2.1 forbids",
    ),
    (
        "exp-beyond-safe-integer",
        lambda: member(RECORD, compact("owner", cjson(payload(RECORD, exp=2**53)))),
        ["payload-integer-required"],
        "exp is 2^53, past the exact integer range RFC 7493 section 2.2 names",
    ),
    (
        "port-out-of-range",
        lambda: _signed_as(with_record(RECORD, port=65536), with_record(RECORD, port=65536)),
        ["payload-integer-required"],
        "port 65536 on both sides: signed and served agree, but it is not a 16-bit port",
    ),
    (
        "jwks-url-backslash-userinfo",
        lambda: member(
            RECORD_NO_REALM,
            compact("owner", cjson(payload(RECORD_NO_REALM))),
            url="https://evil.example\\@dns-aid.example.com/.well-known/dns-aid-jwks.json",
        ),
        ["jwks-host-not-zone"],
        "a WHATWG parser fetches this URL from evil.example and an RFC 3986 parser from "
        "dns-aid.example.com",
    ),
    (
        "jwks-url-userinfo",
        lambda: member(
            RECORD_NO_REALM,
            compact("owner", cjson(payload(RECORD_NO_REALM))),
            url="https://agent@dns-aid.example.com/.well-known/dns-aid-jwks.json",
        ),
        ["jwks-host-not-zone"],
        "the JWKS URL carries userinfo, which the profile's URL shape does not allow",
    ),
    (
        "target-kelvin-sign",
        lambda: _signed_as(
            with_record(RECORD, target="kchat.example.com"),
            with_record(RECORD, target="\u212achat.example.com"),
        ),
        ["endpoint-mismatch"],
        "signed target kchat, served target with the Kelvin sign U+212A: Unicode lowercasing "
        "makes them equal, DNS does not",
    ),
    (
        "target-two-trailing-dots",
        lambda: member(with_record(RECORD, target="chat.example.com.."), _good()),
        ["endpoint-mismatch"],
        "served target ends in two dots; only one root dot is dropped before comparing",
    ),
    (
        "target-root-dot",
        lambda: member(with_record(RECORD, target="chat.example.com."), _good()),
        [],
        "control: served target ends in the root dot, which names the same host",
    ),
    (
        "fqdn-ascii-case",
        lambda: member(with_record(RECORD, fqdn="_CHAT._A2A._AGENTS.Example.COM"), _good()),
        [],
        "control: served fqdn differs from the signed one in ASCII case only (RFC 4343)",
    ),
    (
        "jwk-use-enc",
        _jwk(use="enc"),
        ["key-unusable"],
        "the only key is published for encryption (use enc, RFC 7517 section 4.2), so it "
        "verifies no signature",
    ),
    (
        "jwk-key-ops-derive",
        _jwk(key_ops=["deriveBits"]),
        ["key-unusable"],
        "the only key's key_ops do not name verify (RFC 7517 section 4.3)",
    ),
    (
        "jwk-alg-es384",
        _jwk(alg="ES384"),
        ["key-unusable"],
        "the only key is published for ES384 (RFC 7517 section 4.4), not for this ES256 signature",
    ),
    (
        "jwk-x-33-bytes",
        _x_33_bytes,
        ["key-unusable"],
        "x carries a leading zero octet: the same integer, but RFC 7518 section 6.2.1.2 "
        "requires 32 octets",
    ),
    (
        "jwk-set-skips-malformed-key",
        _skips_malformed_key,
        [],
        "control: a header with no kid and a key set whose first key is malformed: that key is "
        "ignored (RFC 7517 section 5)",
    ),
    (
        "record-proto-empty",
        lambda: member(with_record(RECORD, proto=""), _good()),
        ["endpoint-mismatch"],
        "the record carries an empty proto, which names no protocol, so the signed alpn a2a "
        "does not match",
    ),
    (
        "target-absent-both-sides",
        _no_target,
        ["endpoint-mismatch"],
        "neither the payload nor the record names a target: an endpoint that names no host "
        "binds nothing",
    ),
    (
        "validity-window-inverted",
        lambda: member(
            RECORD, compact("owner", cjson(payload(RECORD, iat=NOW + 120, exp=NOW + 60)))
        ),
        ["validity-window-inverted"],
        "iat is two minutes after the check time (inside the skew) and exp one minute after it: "
        "an empty window",
    ),
    (
        "jwks-url-port-out-of-range",
        lambda: member(
            RECORD_NO_REALM,
            compact("owner", cjson(payload(RECORD_NO_REALM))),
            url="https://dns-aid.example.com:99999/.well-known/dns-aid-jwks.json",
        ),
        ["jwks-host-not-zone"],
        "the JWKS URL names port 99999, which no client can connect to",
    ),
    (
        "svcb1-covers-ipv4hint",
        lambda: member(with_record(RECORD, params={"ipv4hint": "192.0.2.66"}), _good()),
        ["svcb1-digest-mismatch"],
        "a served ipv4hint the signer never saw: every present param enters the digest, not "
        "only the DNS-AID ones",
    ),
    (
        "member-duplicate-target",
        lambda: member(RECORD, _good()),
        ["jws-malformed"],
        "the member file names the record's target twice; a first-wins reader serves "
        "evil.example.net",
    ),
)


def decision(codes: list[str]) -> str:
    if not codes:
        return "agrees"
    return CODES[codes[0]]


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_digest() -> Any:
    """digest.py, loaded by path: the preimage lives there so verification needs no package."""
    spec = importlib.util.spec_from_file_location("dns_aid_sig_digest", ROOT / "digest.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"{ROOT / 'digest.py'} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Imported rather than restated: one preimage, one spelling.
corpus_digest = _load_digest().corpus_digest


def members() -> dict[str, bytes]:
    """Every member file, by its path under the corpus directory."""
    out = {}
    for name, build, _, _ in MEMBERS:
        case = build()
        case["case"] = name
        data = _json(case)
        if name in TEXT_EDITS:
            find, before = TEXT_EDITS[name]
            if data.count(find.encode()) != 1:
                raise ValueError(f"{name}: the text edit does not find exactly one {find!r}")
            data = data.replace(find.encode(), (before + find).encode())
        out[f"cases/{name}.json"] = data
    return out


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# DNS-AID sig binding vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Suite: `{SUITE}`.",
        "",
        f"Corpus digest: `{digest}`",
        "",
        "| id | kind | decision | codes | case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        codes = ", ".join(f"`{c}`" for c in x["codes"]) or "none"
        lines.append(
            f"| `{e['id']}` | {e['kind']} | {x['decision']} | {codes} | {e['description']} |"
        )
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every member, the manifest and the index."""
    files = members()
    (root / "cases").mkdir(parents=True, exist_ok=True)
    for stale in (root / "cases").glob("*.json"):
        if f"cases/{stale.name}" not in files:
            stale.unlink()
    entries = []
    for name, _, codes, description in MEMBERS:
        path = f"cases/{name}.json"
        (root / path).write_bytes(files[path])
        entries.append(
            {
                "description": description,
                "expected": {
                    "codes": sorted(codes),
                    "decision": decision(codes),
                    "verdict": "invalid" if codes else "valid",
                },
                "file": path,
                "id": name,
                "kind": "reject" if codes else "accept",
                "sha256": _sha(files[path]),
            }
        )
    digest = corpus_digest({"vectors": entries}, root)
    manifest = {
        "corpusDigest": digest,
        "counts": {
            kind: n
            for kind in ("accept", "reject")
            if (n := sum(e["kind"] == kind for e in entries))
        },
        "specification": SPECIFICATION,
        "suite": SUITE,
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
