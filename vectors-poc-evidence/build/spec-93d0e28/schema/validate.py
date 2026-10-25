#!/usr/bin/env python3
"""Validator for Proof-of-Control Evidence tokens.

Three layers, because they catch different mistakes:

  1. STRUCTURE   the JSON Schema. Types, required claims, enumerated values,
                 digest syntax.
  2. CANONICAL   RFC 8785 serialization, plus the profile restrictions in
                 canonicalization.md. This is the layer that catches the bugs
                 which do not look like bugs -- key order, hex case, an integer
                 written as 1.0.
  3. SEMANTIC    the checks a schema cannot express. A SOFTWARE platform cannot
                 support a Tier 3 claim; a signature must actually verify; a
                 tree_size must be consistent with a step_index.

Usage:
    python3 validate.py --vectors            run every published test vector
    python3 validate.py TOKEN.json [...]     validate tokens
    python3 validate.py --canonical T.json   print canonical bytes and digest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "poc-evidence.schema.json"
VECTORS = HERE / "vectors"


# ------------------------------------------------------------ RFC 8785 (JCS)
#
# Implemented here rather than pulled from a library so that the normative
# behaviour is readable in one place, and so the repository has no dependency
# that a standards reader would have to trust.

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)  # non-ASCII is emitted literally
    out.append('"')
    return "".join(out)


def _jcs_number(n) -> str:
    """ECMAScript Number::toString, to the extent the profile permits numbers.

    The claim set forbids floating point, so the integer branch is the only one
    a conforming claim set exercises. The float branch exists for snapshots,
    which carry application data.
    """
    if isinstance(n, bool):
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        return str(n)
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError(f"{n} has no JSON representation")
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    r = repr(n)
    if "e" in r:  # 1e-07 -> 1e-7, ECMAScript style
        mant, exp = r.split("e")
        exp = int(exp)
        r = f"{mant}e{'+' if exp > 0 else '-'}{abs(exp)}"
    return r


def _sort_key(k: str):
    """RFC 8785 sorts by UTF-16 code unit, not code point. The two differ for
    characters above the BMP; see canonicalization.md."""
    return k.encode("utf-16-be")


def jcs(obj) -> bytes:
    """Canonical bytes per RFC 8785."""
    return _jcs(obj).encode("utf-8")


def _jcs(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, (int, float)):
        return _jcs_number(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_jcs(v) for v in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: _sort_key(kv[0]))
        return "{" + ",".join(f"{_jcs_string(k)}:{_jcs(v)}" for k, v in items) + "}"
    raise TypeError(f"not serializable: {type(obj).__name__}")


def python_canonical(obj) -> bytes:
    """What the reference implementation emits. Equal to jcs() for the claim
    set; may differ for snapshots with non-BMP keys or floats."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def signing_input(token: dict) -> bytes:
    """The exact bytes a signature covers: the token with `signature` removed."""
    return jcs({k: v for k, v in token.items() if k != "signature"})


# ------------------------------------------------------------ parsing
class ValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code, self.message = code, message


def _no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValidationError(
                "duplicate-key",
                f"duplicate object key {k!r}: a last-wins "
                f"parser lets one token mean two things",
            )
        seen[k] = v
    return seen


def load_token(raw: str | bytes) -> dict:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=_no_duplicates)


# ------------------------------------------------------------ layer 1
def check_structure(token: dict) -> None:
    try:
        import jsonschema
    except ImportError:  # pragma: no cover
        raise ValidationError(
            "no-validator", "pip install jsonschema to run structural checks"
        )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    errors = sorted(v.iter_errors(token), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        where = "/".join(str(p) for p in e.absolute_path) or "(root)"
        raise ValidationError("schema", f"{where}: {e.message}")


# ------------------------------------------------------------ layer 2
def check_canonical(token: dict, raw: bytes | None = None) -> None:
    # every digest lowercase and tagged -- the schema pattern covers syntax,
    # this covers the case where a value is syntactically fine but upper-cased
    def walk(o, path=""):
        if isinstance(o, dict):
            for k, val in o.items():
                walk(val, f"{path}/{k}")
        elif isinstance(o, list):
            for i, val in enumerate(o):
                walk(val, f"{path}[{i}]")
        elif isinstance(o, str) and ":" in o:
            alg, _, hexpart = o.partition(":")
            if alg in ("sha-256", "sha-384", "sha-512", "sha3-256"):
                if hexpart != hexpart.lower():
                    raise ValidationError(
                        "hex-case", f"{path}: digest is not lowercase"
                    )
        elif isinstance(o, float):
            raise ValidationError(
                "float-in-claims",
                f"{path}: the claim set forbids floating point "
                f"(found {o!r}); see canonicalization.md",
            )

    walk(token)

    # a token that round-trips must reproduce its own canonical form
    if jcs(token) != jcs(load_token(jcs(token))):
        raise ValidationError("canonical", "token is not canonicalization-stable")


# ------------------------------------------------------------ layer 3
TIER_CAPABLE_PLATFORMS = {"INTEL_TDX", "AMD_SEV_SNP", "ARM_CCA", "AWS_NITRO"}


def check_semantics(token: dict, public_key_hex: str | None = None) -> list[str]:
    """Returns warnings. MUST NOT mutate `token`: the signature is computed over
    the token's canonical form, so adding so much as an advisory field here
    would invalidate the very signature this function goes on to check."""
    warnings: list[str] = []
    c = token["poc_claims"]
    att = token["submods"]["attestation"]

    # A tree root covering fewer leaves than the step it indexes is impossible:
    # a record is a leaf of the tree its own root commits to.
    if c["tree_size"] <= c["step_index"]:
        raise ValidationError(
            "tree-size",
            f"tree_size {c['tree_size']} does not cover step_index "
            f"{c['step_index']}: the record cannot be in its own tree",
        )

    # MODIFY means the dispatched action is not the proposed one. If the token
    # commits only to the proposal, it evidences an action that never ran while
    # a different action executes unevidenced -- the substitution gap C7.1.4
    # exists to close. A schema cannot express this: the requirement is
    # conditional on a sibling value.
    if c["verdict"] == "MODIFY" and "dispatched_snapshot_hash" not in c:
        raise ValidationError(
            "modify-unbound",
            "verdict MODIFY without dispatched_snapshot_hash: the token "
            "commits to the proposed action, but a different one executes",
        )

    # Software attestation is honest evidence of a software claim. It is not
    # evidence of anything a Tier 3 conformance statement asserts, and the
    # commonest way to overclaim is to let it pass silently.
    if att["platform"] not in TIER_CAPABLE_PLATFORMS:
        warnings.append(
            f"platform {att['platform']}: evidence supports Tier 2 at most; "
            f"no hardware isolation is attested"
        )

    if public_key_hex:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            from cryptography.exceptions import InvalidSignature
        except ImportError:  # pragma: no cover
            return warnings
        if "signature" not in token:
            raise ValidationError("unsigned", "no signature to verify")
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            pk.verify(bytes.fromhex(token["signature"]), signing_input(token))
        except InvalidSignature:
            raise ValidationError(
                "signature",
                "signature does not verify over the canonical signing input",
            )
    return warnings


def validate(token: dict, public_key_hex: str | None = None) -> list[str]:
    """Run all three layers. Returns warnings; raises ValidationError on
    anything that makes the token non-conforming."""
    check_structure(token)
    check_canonical(token)
    return check_semantics(token, public_key_hex)


# ------------------------------------------------------------ vectors
def run_vectors() -> int:
    manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
    pk = manifest.get("public_key")
    passed = failed = 0

    print("Positive vectors -- these MUST validate\n")
    for entry in manifest["positive"]:
        path = VECTORS / entry["file"]
        try:
            tok = load_token(path.read_text(encoding="utf-8"))
            warns = validate(tok, pk)
            note = f"  ({warns[0][:52]}...)" if warns else ""
            print(f"  ok    {entry['file']:<38} {entry['description']}{note}")
            passed += 1
        except (ValidationError, ValueError) as e:
            print(f"  FAIL  {entry['file']:<38} unexpectedly rejected: {e}")
            failed += 1

    print("\nNegative vectors -- these MUST be rejected, for the stated reason\n")
    for entry in manifest["negative"]:
        path = VECTORS / entry["file"]
        want = entry["expect_code"]
        try:
            tok = load_token(path.read_text(encoding="utf-8"))
            validate(tok, pk)
        except ValidationError as e:
            if e.code == want:
                print(f"  ok    {entry['file']:<38} rejected: {e.code}")
                passed += 1
            else:
                print(
                    f"  FAIL  {entry['file']:<38} rejected as {e.code!r}, "
                    f"expected {want!r} -- right answer, wrong reason"
                )
                failed += 1
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", type(e).__name__)
            if code == want:
                print(f"  ok    {entry['file']:<38} rejected: {code}")
                passed += 1
            else:
                print(f"  FAIL  {entry['file']:<38} raised {code}, expected {want}")
                failed += 1
        else:
            print(f"  FAIL  {entry['file']:<38} ACCEPTED, must be rejected ({want})")
            failed += 1

    print("\nCanonical-form vectors -- published bytes must be reproduced\n")
    for entry in manifest.get("canonical", []):
        path = VECTORS / entry["file"]
        obj = load_token(path.read_text(encoding="utf-8"))
        got = jcs(obj)
        want_hex = entry["canonical_sha256"]
        import hashlib

        got_hex = hashlib.sha256(got).hexdigest()
        if got_hex == want_hex:
            print(f"  ok    {entry['file']:<38} {entry['description']}")
            passed += 1
        else:
            print(
                f"  FAIL  {entry['file']:<38} canonical digest {got_hex[:16]} "
                f"!= published {want_hex[:16]}"
            )
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("tokens", nargs="*", type=Path)
    ap.add_argument(
        "--vectors", action="store_true", help="run the published test vectors"
    )
    ap.add_argument(
        "--canonical",
        action="store_true",
        help="print canonical bytes and digest instead of validating",
    )
    ap.add_argument("--key", help="Ed25519 public key (hex) to verify against")
    args = ap.parse_args()

    if args.vectors:
        return run_vectors()
    if not args.tokens:
        ap.print_help()
        return 2

    import hashlib

    rc = 0
    for p in args.tokens:
        tok = load_token(p.read_text(encoding="utf-8"))
        if args.canonical:
            b = jcs(tok)
            print(f"{p}:")
            print(f"  canonical bytes  {len(b)}")
            print(f"  sha-256          sha-256:{hashlib.sha256(b).hexdigest()}")
            print(
                f"  signing input    sha-256:"
                f"{hashlib.sha256(signing_input(tok)).hexdigest()}"
            )
            continue
        try:
            for w in validate(tok, args.key):
                print(f"  warning: {w}")
            print(f"  ok  {p}")
        except ValidationError as e:
            print(f"  INVALID  {p}: {e}")
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
