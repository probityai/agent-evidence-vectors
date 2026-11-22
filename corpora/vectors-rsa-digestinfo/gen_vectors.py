"""Write the RSA DigestInfo slice: blocks that end in the right SHA-256 digest and must still be
refused.

The key is derived from the seed label ``agent-evidence-vectors/rsa-digestinfo/v1/`` (primes found
by a deterministic search over a SHA-256 stream), so the corpus regenerates byte for byte. Each
signature is the raw RSA private operation on a hand-built block.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import rsadigestinfo as reader  # noqa: E402
from agent_evidence_vectors.monitorcoverage import _json, _sha  # noqa: E402

SUITE = reader.SUITE
SEED = "agent-evidence-vectors/rsa-digestinfo/v1/"
BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71)
MESSAGE = "an action evidence package's canonical bytes"


def _stream(label: str, nbytes: int) -> bytes:
    out, counter = b"", 0
    while len(out) < nbytes:
        out += hashlib.sha256(f"{SEED}{label}/{counter}".encode()).digest()
        counter += 1
    return out[:nbytes]


def _probable_prime(n: int) -> bool:
    if n < 2 or any(n % p == 0 for p in BASES if n != p):
        return n in BASES
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for a in BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(label: str, bits: int, e: int) -> int:
    attempt = 0
    while True:
        candidate = int.from_bytes(_stream(f"{label}/{attempt}", bits // 8), "big")
        candidate |= (3 << (bits - 2)) | 1
        if _probable_prime(candidate) and (candidate - 1) % e != 0:
            return candidate
        attempt += 1


def key(bits: int = 2048, e: int = 65537) -> tuple[int, int, int]:
    p, q = _prime("p", bits // 2, e), _prime("q", bits // 2, e)
    n = p * q
    phi = (p - 1) * (q - 1)
    return n, e, pow(e, -1, phi)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_b64u(value: int) -> str:
    return _b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def cases() -> list[tuple[str, dict, str, str, str]]:
    n, e, d = key()
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(MESSAGE.encode()).digest()

    def sign(block: bytes) -> str:
        return _b64u(pow(int.from_bytes(block, "big"), d, n).to_bytes(k, "big"))

    def record(signature: str, message: str = MESSAGE) -> dict:
        return {
            "hash": "sha-256",
            "key": {"e": _int_b64u(e), "kty": "RSA", "n": _int_b64u(n)},
            "message": message,
            "signature": signature,
        }

    short_head = b"\x00\x01" + b"\x00"
    full_t = reader.SHA256_DIGEST_INFO_ABSENT_PARAMS + digest
    short = short_head + b"\x42" * (k - len(short_head) - len(full_t)) + full_t
    return [
        (
            "rfc8017-null-parameters",
            record(sign(reader.block(reader.SHA256_DIGEST_INFO + digest, k))),
            "valid",
            "rfc8017",
            "control: the RFC 8017 encoding",
        ),
        (
            "absent-null-parameters-exact",
            record(sign(reader.block(reader.SHA256_DIGEST_INFO_ABSENT_PARAMS + digest, k))),
            "profile-dependent",
            "absent_null_parameters",
            "the exact block with the NULL parameters omitted: accepted or refused by the "
            "consumer's profile",
        ),
        (
            "garbage-prefix",
            record(sign(reader.block(b"\x13" * 17 + digest, k))),
            "invalid",
            "block_not_exact_encoding",
            "arbitrary bytes between the padding and the digest",
        ),
        (
            "garbage-after-legacy-prefix",
            record(
                sign(
                    reader.block(reader.SHA256_DIGEST_INFO_ABSENT_PARAMS + b"\x00" * 64 + digest, k)
                )
            ),
            "invalid",
            "block_not_exact_encoding",
            "bytes after a DigestInfo prefix and before the digest",
        ),
        (
            "sha512-oid",
            record(
                sign(reader.block(bytes.fromhex("302f300b06096086480165030402030420") + digest, k))
            ),
            "invalid",
            "block_not_exact_encoding",
            "a SHA-512 OID carrying a 32-byte value",
        ),
        (
            "short-padding",
            record(sign(short)),
            "invalid",
            "block_not_exact_encoding",
            "a padding string shorter than the modulus requires, with filler before the digest",
        ),
        (
            "wrong-message",
            record(sign(reader.block(reader.SHA256_DIGEST_INFO + digest, k)), MESSAGE + "."),
            "invalid",
            "block_not_exact_encoding",
            "control: the right encoding over another message",
        ),
        (
            "signature-one-byte-short",
            record(sign(reader.block(reader.SHA256_DIGEST_INFO + digest, k))[:-2]),
            "invalid",
            "signature_length",
            "control: a signature shorter than the modulus",
        ),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    entries = []
    for name, record, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "record.json").write_bytes(data)
        entries.append(
            {
                "edit": edit,
                "expected": {"decision": decision, "reason": reason},
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
            }
        )
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "keySeedLabel": SEED,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": (
            "verifier record.json --json; exit 0 valid, 1 invalid, 2 profile-dependent"
        ),
        "vectors": entries,
    }
    words = [e["expected"]["decision"] for e in entries]
    manifest["counts"] = {w: words.count(w) for w in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    print(json.dumps(generate()["counts"], sort_keys=True))
