"""An independent, stdlib-only verifier for the Proof-of-Control evidence artifacts.

It shares no code with the specification's reference implementation. Its
Merkle checks use the recursive definition of RFC 6962 / RFC 9162 (the
reference uses the iterative bit-twiddling form), its canonicalization is
written from RFC 8785, and Ed25519 verification is RFC 8032 in plain integers.
A case in the corpus is only trusted when this twin and the corpus agree.

Result convention: every check returns None for accept, or a short code for
reject. Codes follow the reference validator where it defines one.
"""

from __future__ import annotations

import hashlib
import json
import re

# ------------------------------------------------------------------ ed25519
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P:
        raise ValueError("not on curve")
    return _P - x if x & 1 else x


_BY = 4 * _inv(5) % _P
_B = (_xrecover(_BY), _BY, 1, _xrecover(_BY) * _BY % _P)


def _add(p, q):
    """Extended homogeneous coordinates (X, Y, Z, T), RFC 8032 section 5.1.4."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(p, e):
    r = (0, 1, 1, 0)
    while e:
        if e & 1:
            r = _add(r, p)
        p = _add(p, p)
        e >>= 1
    return r


def _affine(p):
    zi = _inv(p[2])
    return (p[0] * zi % _P, p[1] * zi % _P)


def _ext(p):
    return (p[0], p[1], 1, p[0] * p[1] % _P)


def _decode_point(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    if x & 1 != sign:
        x = _P - x
    return _ext((x, y))


def ed25519_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        a = _decode_point(pk)
        r = _decode_point(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pk + msg).digest(), "little") % _L
    return _affine(_mul(_B, s)) == _affine(_add(r, _mul(a, h)))


# ------------------------------------------------------------- canonical form
def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def _jstr(s: str) -> str:
    esc = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    return (
        '"'
        + "".join(esc.get(c) or (f"\\u{ord(c):04x}" if ord(c) < 0x20 else c) for c in s)
        + '"'
    )


def jcs(o) -> bytes:
    return _jcs(o).encode("utf-8")


def _jcs(o) -> str:
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, str):
        return _jstr(o)
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        if o == int(o) and abs(o) < 1e21:
            return str(int(o))
        return repr(o)
    if isinstance(o, list):
        return "[" + ",".join(_jcs(v) for v in o) + "]"
    if isinstance(o, dict):
        return (
            "{"
            + ",".join(_jstr(k) + ":" + _jcs(o[k]) for k in sorted(o, key=_utf16_key))
            + "}"
        )
    raise TypeError(type(o).__name__)


class Duplicate(Exception):
    pass


def _strict(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Duplicate(k)
        d[k] = v
    return d


def parse(text: str):
    return json.loads(text, object_pairs_hook=_strict)


# -------------------------------------------------------------------- tokens
_DIGEST = re.compile(
    r"^(sha-256:[0-9a-f]{64}|sha-384:[0-9a-f]{96}|"
    r"sha-512:[0-9a-f]{128}|sha3-256:[0-9a-f]{64})$"
)
_HEX = re.compile(r"^[0-9a-f]+$")
_PROFILE = "https://advancedaisociety.org/poc/v0.1"
_HOOKS = {
    "TASK_INITIALIZATION",
    "CONTEXT_ASSEMBLY",
    "PLAN_GENERATION",
    "PRE_CALL_TOOL_INVOCATION",
    "POST_CALL_TOOL_RESULT",
    "MEMORY_WRITE",
    "SUBAGENT_DELEGATION",
    "TASK_COMPLETION",
}
_VERDICTS = {"ALLOW", "DENY", "MODIFY", "ESCALATE"}
_ALGS = {"EdDSA", "ES256", "ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-44"}
_PLATFORMS = {"INTEL_TDX", "AMD_SEV_SNP", "ARM_CCA", "AWS_NITRO", "SOFTWARE"}
_DIGEST_CLAIMS = (
    "agbom_digest",
    "chain_head",
    "merkle_root",
    "policy_bundle_hash",
    "canonical_snapshot_hash",
    "path_summary_hash",
)


def _isint(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _structure(t) -> bool:
    """True when the token has the claim-set shape."""
    if not isinstance(t, dict):
        return False
    for k in ("iss", "iat", "nonce", "eat_profile", "poc_claims", "submods"):
        if k not in t:
            return False
    if (
        not isinstance(t["iss"], str)
        or not isinstance(t["nonce"], str)
        or len(t["nonce"]) < 8
    ):
        return False
    if isinstance(t["iat"], bool) or not isinstance(t["iat"], (int, float)):
        return False
    if t["eat_profile"] != _PROFILE:
        return False
    c, sm = t["poc_claims"], t["submods"]
    if not isinstance(c, dict) or not isinstance(sm, dict):
        return False
    need = (
        "agent_id",
        "initiating_user",
        "agbom_digest",
        "interception_point",
        "step_index",
        "chain_head",
        "merkle_root",
        "tree_size",
        "policy_bundle_hash",
        "target_resource",
        "canonical_snapshot_hash",
        "path_summary_hash",
        "verdict",
        "alg",
    )
    if any(k not in c for k in need):
        return False
    for k in ("agent_id", "initiating_user"):
        if not isinstance(c[k], str) or not c[k]:
            return False
    if not isinstance(c["target_resource"], str):
        return False
    for k in _DIGEST_CLAIMS + (
        ("dispatched_snapshot_hash",) if "dispatched_snapshot_hash" in c else ()
    ):
        if not isinstance(c[k], str) or not _DIGEST.match(c[k]):
            return False
    if (
        c["interception_point"] not in _HOOKS
        or c["verdict"] not in _VERDICTS
        or c["alg"] not in _ALGS
    ):
        return False
    if not _isint(c["step_index"]) or c["step_index"] < 0:
        return False
    if not _isint(c["tree_size"]) or c["tree_size"] < 1:
        return False
    if "reason" in c and (not isinstance(c["reason"], str) or c["reason"] == ""):
        return False  # absent is not empty (rule 7)
    att = sm.get("attestation")
    if not isinstance(att, dict) or att.get("platform") not in _PLATFORMS:
        return False
    if "reference_values_uri" in att and (
        not isinstance(att["reference_values_uri"], str)
        or att["reference_values_uri"] == ""
    ):
        return False
    m = att.get("measurement")
    if not isinstance(m, str) or not _DIGEST.match(m):
        return False
    if "signature" in t and (
        not isinstance(t["signature"], str) or not _HEX.match(t["signature"])
    ):
        return False
    return True


def _scan_canonical(o):
    if isinstance(o, dict):
        for v in o.values():
            r = _scan_canonical(v)
            if r:
                return r
    elif isinstance(o, list):
        for v in o:
            r = _scan_canonical(v)
            if r:
                return r
    elif isinstance(o, float):
        return "float-in-claims"
    elif isinstance(o, int) and not isinstance(o, bool) and abs(o) > 2**53 - 1:
        return "canonical"  # not exactly representable in an IEEE double
    elif isinstance(o, str) and ":" in o:
        alg, _, hx = o.partition(":")
        if alg in ("sha-256", "sha-384", "sha-512", "sha3-256") and hx != hx.lower():
            return "hex-case"
    return None


def _has_surrogate(o) -> bool:
    if isinstance(o, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in o)
    if isinstance(o, list):
        return any(_has_surrogate(v) for v in o)
    if isinstance(o, dict):
        return any(_has_surrogate(k) or _has_surrogate(v) for k, v in o.items())
    return False


# platforms whose measurement register is SHA-384 wide
_SHA384_PLATFORMS = {"INTEL_TDX", "AMD_SEV_SNP"}


def check_token(text: str, pubkey_hex: str | None):
    """None when the token conforms, else a reject code."""
    try:
        t = parse(text)
    except Duplicate:
        return "duplicate-key"
    except ValueError:
        return "parse"
    if _has_surrogate(t):
        return "parse"  # no UTF-8 bytes exist for an unpaired surrogate
    if not _structure(t):
        return "schema"
    r = _scan_canonical(t)
    if r:
        return r
    c = t["poc_claims"]
    if c["tree_size"] <= c["step_index"]:
        return "tree-size"
    if c["verdict"] == "MODIFY" and "dispatched_snapshot_hash" not in c:
        return "modify-unbound"
    if (
        c["verdict"] == "MODIFY"
        and c["dispatched_snapshot_hash"] == c["canonical_snapshot_hash"]
    ):
        return "semantic"  # MODIFY means dispatched differs from proposed
    att = t["submods"]["attestation"]
    if att["platform"] in _SHA384_PLATFORMS and not att["measurement"].startswith(
        "sha-384:"
    ):
        return "semantic"
    if pubkey_hex:
        if "signature" not in t:
            return "unsigned"
        body = {k: v for k, v in t.items() if k != "signature"}
        try:
            data = jcs(body)
        except (TypeError, UnicodeEncodeError):
            return "canonical"
        if not ed25519_verify(
            bytes.fromhex(pubkey_hex), bytes.fromhex(t["signature"]), data
        ):
            return "signature"
    return None


# ------------------------------------------------------------ RFC 6962 trees
def leaf_hash(b: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_from_path(index, size, leaf, proof):
    """Recursive RFC 6962 audit-path reconstruction. None when the proof has
    the wrong length for (index, size)."""
    if size == 1:
        return leaf if not proof else None
    if not proof:
        return None
    k = _split(size)
    sib, rest = proof[-1], proof[:-1]
    if index < k:
        sub = _root_from_path(index, k, leaf, rest)
        return None if sub is None else node_hash(sub, sib)
    sub = _root_from_path(index - k, size - k, leaf, rest)
    return None if sub is None else node_hash(sib, sub)


def check_inclusion(index, size, leaf: bytes, proof, root: bytes):
    if not (isinstance(index, int) and isinstance(size, int)):
        return "not-included"
    if size < 1 or not 0 <= index < size:
        return "not-included"
    got = _root_from_path(index, size, leaf, list(proof))
    return None if got == root else "not-included"


def _sub(m, n, b, proof, known_old):
    if m == n:
        if b:
            return known_old, known_old
        if not proof:
            return None
        h = proof.pop()
        return h, h
    if not proof:
        return None
    k = _split(n)
    sib = proof.pop()
    if m <= k:
        r = _sub(m, k, b, proof, known_old)
        return None if r is None else (r[0], node_hash(r[1], sib))
    r = _sub(m - k, n - k, False, proof, known_old)
    return None if r is None else (node_hash(sib, r[0]), node_hash(sib, r[1]))


def check_consistency(m, n, root_m: bytes, root_n: bytes, proof):
    if not (isinstance(m, int) and isinstance(n, int)) or m < 1 or m > n:
        return "not-consistent"
    if m == n:
        return None if not proof and root_m == root_n else "not-consistent"
    p = list(proof)
    r = _sub(m, n, True, p, root_m)
    if r is None or p:
        return "not-consistent"
    return None if (r[0] == root_m and r[1] == root_n) else "not-consistent"


# --------------------------------------------------------------------- chains
def _material_leaf(token) -> bytes:
    c = token["poc_claims"]
    return leaf_hash(
        jcs(
            {
                "snapshot": c["canonical_snapshot_hash"].split(":", 1)[1],
                "verdict": c["verdict"],
            }
        )
    )


def check_chain(records, pubkey_hex, expected_measurement_hex, anchor):
    """Replay a list of evidence records. `anchor` is None or
    {"index": n, "root": <hex chain head after n steps>}."""
    head = hashlib.sha256(b"poc-genesis").hexdigest()
    pk = bytes.fromhex(pubkey_hex)
    for i, tok in enumerate(records):
        body = {k: v for k, v in tok.items() if k != "signature"}
        if not ed25519_verify(pk, bytes.fromhex(tok["signature"]), jcs(body)):
            return "signature"
        c = tok["poc_claims"]
        if (
            tok["submods"]["attestation"]["measurement"].split(":", 1)[1]
            != expected_measurement_hex
        ):
            return "measurement"
        if c["step_index"] != i:
            return "sequence-gap"
        want = hashlib.sha256(
            (
                head + c["canonical_snapshot_hash"].split(":", 1)[1] + c["verdict"]
            ).encode()
        ).hexdigest()
        if want != c["chain_head"].split(":", 1)[1]:
            return "chain-break"
        head = want
    if anchor is not None:
        if anchor["index"] > len(records):
            return "truncation"
        at = records[anchor["index"] - 1]["poc_claims"]["chain_head"].split(":", 1)[1]
        if at != anchor["root"]:
            return "history-rewritten"
    return None
