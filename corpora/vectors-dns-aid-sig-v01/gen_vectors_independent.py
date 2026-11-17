"""A second, independent generator for corpora/vectors-dns-aid-sig-v01.

    python3 corpora/vectors-dns-aid-sig-v01/gen_vectors_independent.py <out dir>

It shares no code with gen_vectors.py and imports nothing beyond the standard
library: its own P-256 arithmetic, RFC 6979 nonce derivation (HMAC-DRBG over
SHA-256, section 3.2), JSON writer and base64url. It writes every member file
from the case table below. The corpus test runs both generators and requires
the member files to be identical, so a defect in either one's encoding, key
derivation or signing shows up as a byte difference rather than as a case that
quietly tests something else.
"""

from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path
from typing import Any

# P-256 (SEC 2, FIPS 186-4 D.1.2.3)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
NOW = 1790000000
ZONE = "example.com"
URL = "https://dns-aid.example.com/.well-known/dns-aid-jwks.json"


def add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return x, (lam * (p1[0] - x) - p1[1]) % P


def mul(k: int, point: tuple[int, int]) -> tuple[int, int]:
    out: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            out = add(out, addend)
        addend = add(addend, addend)
        k >>= 1
    assert out is not None
    return out


def enc(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    bits += "0" * (-len(bits) % 6)
    return "".join(ALPHABET[int(bits[i:i + 6], 2)] for i in range(0, len(bits), 6))


def dec(text: str) -> bytes:
    bits = "".join(f"{ALPHABET.index(c):06b}" for c in text)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))


def string(s: str, ascii_only: bool) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif o < 0x20 or (ascii_only and o > 0x7E):
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def scalar(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    raise TypeError(type(v))


def compact(v: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 text (the signed form)."""
    if isinstance(v, dict):
        return "{" + ",".join(string(k, False) + ":" + compact(v[k]) for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ",".join(compact(x) for x in v) + "]"
    return string(v, False) if isinstance(v, str) else scalar(v)


def pretty(v: Any, depth: int = 0) -> str:
    """Sorted keys, one-space indent, ASCII only (the member file form)."""
    pad, inner = " " * depth, " " * (depth + 1)
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{\n" + ",\n".join(inner + string(k, True) + ": " + pretty(v[k], depth + 1) for k in sorted(v)) + "\n" + pad + "}"
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + ",\n".join(inner + pretty(x, depth + 1) for x in v) + "\n" + pad + "]"
    return string(v, True) if isinstance(v, str) else scalar(v)


def secret(label: str) -> int:
    return int.from_bytes(hashlib.sha256(f"vectors-dns-aid-sig-v01/{label}".encode()).digest(), "big") % (N - 1) + 1


def rfc6979_k(x: int, h1: bytes) -> int:
    xb, hb = x.to_bytes(32, "big"), (int.from_bytes(h1, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(label: str, message: bytes) -> bytes:
    x = secret(label)
    h1 = hashlib.sha256(message).digest()
    e = int.from_bytes(h1, "big")
    k = rfc6979_k(x, h1)
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (e + r * x) % N
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def key_set(label: str) -> dict[str, Any]:
    qx, qy = mul(secret(label), G)
    return {"keys": [{"crv": "P-256", "kid": "k1", "kty": "EC", "x": enc(qx.to_bytes(32, "big")),
                      "y": enc(qy.to_bytes(32, "big"))}]}


def fingerprint(ks: dict[str, Any]) -> str:
    lines = sorted(":".join(k.get(f, "") for f in ("kty", "crv", "x", "y", "n", "e")) for k in ks["keys"])
    return enc(hashlib.sha256("\n".join(lines).encode()).digest())


def digest(params: dict[str, Any], prefix: str = "svcb1:") -> str:
    return enc(hashlib.sha256((prefix + compact({k: v for k, v in params.items() if v is not None})).encode()).digest())


HDR = {"alg": "ES256", "kid": "k1", "typ": "JWT"}
FULL = {"bap": None, "cap": "https://chat.example.com/.well-known/agent-cap.json",
        "cap-sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "connect-class": None,
        "connect-meta": None, "enroll-uri": None, "policy": "https://example.com/agent-policy",
        "realm": "prod", "well-known": None}
BARE = dict(FULL, realm=None)
REC = {"alpn": "a2a", "fqdn": "_chat._a2a._agents.example.com", "params": FULL, "port": 443,
       "target": "chat.example.com", "zone": ZONE}
REC2 = {"alpn": "a2a", "fqdn": "chat.example.com", "params": BARE, "port": 443,
        "target": "chat.example.com", "zone": ZONE}


def body(rec: dict[str, Any], params: dict[str, Any] | None = None, svcb: bool = True, alpn: str | None = None,
         iat: int = NOW - 60, exp: int = NOW + 86400) -> dict[str, Any]:
    out = {"alpn": alpn or rec["alpn"], "exp": exp, "fqdn": rec["fqdn"], "iat": iat, "port": rec["port"],
           "target": rec["target"]}
    if svcb:
        out["svcb"] = digest(rec["params"] if params is None else params)
    return out


def jws(label: str, payload_text: str, header: dict[str, Any] = HDR) -> str:
    h, p = enc(compact(header).encode()), enc(payload_text.encode())
    return f"{h}.{p}.{enc(sign(label, f'{h}.{p}'.encode()))}"


def raw_header(header_text: str) -> str:
    h, p = enc(header_text.encode()), enc(compact(body(REC)).encode())
    return f"{h}.{p}.{enc(sign('owner', f'{h}.{p}'.encode()))}"


def case(rec: dict[str, Any], sig: str, keys: str = "owner", url: str | None = URL, authority: Any = "owner") -> dict[str, Any]:
    out: dict[str, Any] = {"jwks": key_set(keys), "now": NOW, "record": rec, "sig": sig}
    if url is not None:
        out["jwks_url"] = url
    if authority == "owner":
        out["key_authority"] = {"jwks_fingerprint": fingerprint(key_set("owner")), "kind": "pin"}
    return out


def served(rec: dict[str, Any], **kw: Any) -> dict[str, Any]:
    params = kw.pop("params", {})
    out = dict(rec, **kw)
    out["params"] = dict(rec["params"], **params)
    return out


def tail(extra: str) -> str:
    """The good payload text with raw JSON appended before its closing brace."""
    return jws("owner", compact(body(REC))[:-1] + extra + "}")


def jwk_case(sig: str, **changes: Any) -> dict[str, Any]:
    out = case(REC, sig)
    out["jwks"]["keys"][0].update(changes)
    return out


def with_malformed_first_key() -> dict[str, Any]:
    out = case(REC, jws("owner", compact(body(REC)), {"alg": "ES256", "typ": "JWT"}))
    out["jwks"]["keys"].insert(0, {"crv": "P-256", "kid": "k0", "kty": "EC", "x": "not base64url!", "y": ""})
    out["key_authority"] = {"jwks_fingerprint": fingerprint(out["jwks"]), "kind": "pin"}
    return out


#: Member files whose text is edited after writing: (the line to find, the line put in front of it).
EDITS = {"member-duplicate-target": ('  "target": "chat.example.com",\n', '  "target": "evil.example.net",\n')}


def table() -> dict[str, dict[str, Any]]:
    good = jws("owner", compact(body(REC)))
    h, p, s = good.split(".")
    flipped = bytearray(dec(s))
    flipped[5] ^= 1
    last = ALPHABET.index(s[-1]) | 0b1111
    dup = '{"fqdn":"_x._a2a._agents.evil.example",' + compact(body(REC))[1:]
    floated = compact(body(REC)).replace('"port":443', '"port":443.0')
    nopre = dict(body(REC), svcb=digest(FULL, prefix=""))
    return {
        "full-coverage-valid": case(REC, good),
        "endpoint-only": case(REC, jws("owner", compact(body(REC, svcb=False)))),
        "param-tamper-cap-sha256": case(served(REC, params={"cap-sha256": "AAAA" + FULL["cap-sha256"][4:]}), good),
        "endpoint-tamper-target": case(served(REC, target="evil.example.net"), good),
        "expired": case(REC, jws("owner", compact(body(REC, iat=NOW - 7200, exp=NOW - 3600)))),
        "wrong-key": case(REC, jws("second", compact(body(REC)))),
        "alg-none": case(REC, enc(compact({"alg": "none", "kid": "k1"}).encode()) + "." + p + "."),
        "sig-bitflip": case(REC, f"{h}.{p}.{enc(bytes(flipped))}"),
        "svcb1-field-boundary": case(served(REC, params={"cap": "u\nrealm=t", "realm": None}),
                                     jws("owner", compact(body(REC, params=dict(FULL, cap="u", realm="t"))))),
        "dup-member-fqdn": case(REC, jws("owner", dup)),
        "port-float": case(REC, jws("owner", floated)),
        "iat-future": case(REC, jws("owner", compact(body(REC, iat=NOW + 86400, exp=NOW + 2 * 86400)))),
        "foreign-key-no-provenance": case(REC2, jws("attacker", compact(body(REC2))), "attacker", None, None),
        "foreign-key-wrong-host": case(REC2, jws("attacker", compact(body(REC2))), "attacker",
                                       "https://dns-aid.attacker.example/.well-known/dns-aid-jwks.json", None),
        "foreign-key-pinned-owner": case(REC2, jws("attacker", compact(body(REC2))), "attacker"),
        "owner-key-pinned-control": case(REC2, jws("owner", compact(body(REC2)))),
        "crit-unknown-extension": case(REC2, jws("owner", compact(body(REC2)), dict(HDR, crit=["x-scope"], **{"x-scope": "tenant-a"}))),
        "crit-empty-list": case(REC2, jws("owner", compact(body(REC2)), dict(HDR, crit=[]))),
        "crit-names-registered-header": case(REC2, jws("owner", compact(body(REC2)), dict(HDR, crit=["alg"]))),
        "proto-field-agent-protocol": case(served(REC2, alpn="h2,h3", proto="a2a"), jws("owner", compact(body(REC2, alpn="a2a")))),
        "malformed-header-base64url": case(REC2, "a." + p + ".AAAA"),
        "realm-empty-injected": case(served(REC2, params={"realm": ""}), jws("owner", compact(body(REC2)))),
        "realm-value-injected": case(served(REC2, params={"realm": "prod"}), jws("owner", compact(body(REC2)))),
        "bap-empty-injected": case(served(REC2, params={"bap": ""}), jws("owner", compact(body(REC2)))),
        "svcb1-without-domain-prefix": case(REC, jws("owner", compact(nopre))),
        "svcb1-newline-in-signed-value": case(served(REC, params={"cap": "u", "realm": "t"}),
                                              jws("owner", compact(body(REC, params=dict(FULL, cap="u\nrealm=t", realm=None))))),
        "header-duplicate-alg": case(REC, raw_header('{"alg":"none","alg":"ES256","kid":"k1","typ":"JWT"}')),
        "signature-truncated": case(REC, f"{h}.{p}.{enc(dec(s)[:63])}"),
        "key-set-without-ec-key": dict(case(REC, good), jwks={"keys": [{"e": "AQAB", "kid": "k1", "kty": "RSA",
                                       "n": enc(hashlib.sha256(b"vectors-dns-aid-sig-v01/rsa-n").digest())}]}),
        "payload-array": case(REC, jws("owner", '["_chat._a2a._agents.example.com"]')),
        "record-without-zone": case({k: v for k, v in REC.items() if k != "zone"}, good),
        "key-authority-dnssec-chain": dict(case(REC, good, authority=None), key_authority={"kind": "dnssec-chain"}),
        "signature-base64url-non-canonical": case(REC, f"{h}.{p}.{s[:-1]}{ALPHABET[last]}"),
        "payload-nan-literal": case(REC, tail(',"z":NaN')),
        "header-infinity-literal": case(REC, raw_header('{"alg":"ES256","kid":"k1","typ":"JWT","x":-Infinity}')),
        "payload-lone-surrogate": case(REC, tail(',"z":"\\ud800"')),
        "payload-noncharacter": case(REC, tail(',"z":"\ufdd0"')),
        "exp-beyond-safe-integer": case(REC, jws("owner", compact(body(REC, exp=9007199254740992)))),
        "port-out-of-range": case(dict(REC, port=65536), jws("owner", compact(body(dict(REC, port=65536))))),
        "jwks-url-backslash-userinfo": case(REC2, jws("owner", compact(body(REC2))),
                                            url="https://evil.example\\@dns-aid.example.com/.well-known/dns-aid-jwks.json"),
        "jwks-url-userinfo": case(REC2, jws("owner", compact(body(REC2))),
                                  url="https://agent@dns-aid.example.com/.well-known/dns-aid-jwks.json"),
        "target-kelvin-sign": case(served(REC, target="\u212achat.example.com"),
                                   jws("owner", compact(body(dict(REC, target="kchat.example.com"))))),
        "target-two-trailing-dots": case(served(REC, target="chat.example.com.."), good),
        "target-root-dot": case(served(REC, target="chat.example.com."), good),
        "fqdn-ascii-case": case(served(REC, fqdn="_CHAT._A2A._AGENTS.Example.COM"), good),
        "jwk-use-enc": jwk_case(good, use="enc"),
        "jwk-key-ops-derive": jwk_case(good, key_ops=["deriveBits"]),
        "jwk-alg-es384": jwk_case(good, alg="ES384"),
        "jwk-x-33-bytes": jwk_case(good, x=enc(b"\x00" + dec(key_set("owner")["keys"][0]["x"]))),
        "jwk-set-skips-malformed-key": with_malformed_first_key(),
        "record-proto-empty": case(served(REC, proto=""), good),
        "target-absent-both-sides": case({k: v for k, v in REC.items() if k != "target"},
                                         jws("owner", compact({k: v for k, v in body(REC).items() if k != "target"}))),
        "validity-window-inverted": case(REC, jws("owner", compact(body(REC, iat=NOW + 120, exp=NOW + 60)))),
        "jwks-url-port-out-of-range": case(REC2, jws("owner", compact(body(REC2))),
                                           url="https://dns-aid.example.com:99999/.well-known/dns-aid-jwks.json"),
        "svcb1-covers-ipv4hint": case(served(REC, params={"ipv4hint": "192.0.2.66"}), good),
        "header-b64-false": case(REC, raw_header('{"alg":"ES256","b64":false,"kid":"k1","typ":"JWT"}')),
        "signature-high-s": case(REC, f"{h}.{p}.{enc(dec(s)[:32] + (N - int.from_bytes(dec(s)[32:], 'big')).to_bytes(32, 'big'))}"),
        "member-duplicate-target": case(REC, good),
    }


def main(argv: list[str]) -> int:
    out = Path(argv[0]) / "cases"
    out.mkdir(parents=True, exist_ok=True)
    for name, member in table().items():
        member["case"] = name
        text = pretty(member) + "\n"
        if name in EDITS:
            find, before = EDITS[name]
            assert text.count(find) == 1, name
            text = text.replace(find, before + find)
        (out / f"{name}.json").write_text(text, encoding="ascii")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
