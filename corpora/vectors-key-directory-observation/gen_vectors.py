"""Build the Web Bot Auth key-directory observation cases byte-identically.

Every case is one fetch of a key directory a verifier made while checking a
signed request: the directory URL, the ``keyid`` the request names, the key
thumbprints the verifier held in its cache for that URL before the fetch, and
the fetch as observed (a transport failure, or a status, a media type and a
body). The expected answer pins the decision for the request in hand and the
cache the verifier holds afterwards, from
draft-ietf-webbotauth-httpsig-protocol-01 Sections 5.5, 5.5.1 and 6.10.

Two cases use the Ed25519 test key of that draft's Section 5.5.1 example, whose
``x`` is ``JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs``. The example gives it
``kid`` ``NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw``, which is not its RFC
7638 thumbprint; Appendix E gives it ``poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U``,
which is. Every other key is an Ed25519 public key derived from a published
label, so anyone can rebuild the corpus. They are test keys and protect nothing.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import keydirectory as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/web-bot-auth-key-directory-observation/v1/"
SOURCE = {
    "document": "draft-ietf-webbotauth-httpsig-protocol-01",
    "url": "https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-01.txt",
    "sha256": "28d85996810063563cd3fd65611275b2b118d7dbc68d380bc51c24b180ba1193",
    "sections": ["5.5", "5.5.1", "5.5.2", "6.10"],
}
WELL_KNOWN = "https://agent.example/.well-known/http-message-signatures-directory"
OTHER_URL = "https://keys.example/jwks.json"
DIRECTORY_TYPE = reader.DIRECTORY_MEDIA_TYPE
DRAFT_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
DRAFT_WRONG_KID = "NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def jwk(label: str, **extra: str) -> dict[str, str]:
    """The public JWK of the test key derived from ``label``."""
    seed = hashlib.sha256((SEED_PREFIX + label).encode()).digest()
    public = rail.ed25519_public_key(seed)
    return {"crv": "Ed25519", "kty": "OKP", "x": reader._b64url(public), "use": "sig", **extra}


def draft_jwk(**extra: str) -> dict[str, str]:
    return {"crv": "Ed25519", "kty": "OKP", "x": DRAFT_X, "use": "sig", **extra}


def thumb(key: dict[str, str]) -> str:
    value = reader.jwk_thumbprint(key)
    assert value is not None
    return value


K1, K2, K3 = jwk("k1"), jwk("k2"), jwk("k3")
DRAFT_THUMB = thumb(draft_jwk())


def jwks(*keys: dict[str, str]) -> bytes:
    return _json({"keys": list(keys)})


def response(status: int, media: str | None, body: bytes | None) -> dict[str, Any]:
    return {"outcome": "response", "status": status, "mediaType": media, "body": body}


HTML_ERROR = (b"<!doctype html><html><head><title>502 Bad Gateway</title></head>"
              b"<body><h1>Origin is unreachable</h1></body></html>\n")


def cases() -> list[tuple[str, str, str, list[str], dict[str, Any], str, str, str, list[str], str]]:
    """(id, url, keyid, cached, fetch, decision, reason, cache, cacheAfter, what it tests)."""
    t1, t2, t3 = thumb(K1), thumb(K2), thumb(K3)
    ok, no = reader.ATTRIBUTED, reader.NOT_ATTRIBUTED
    rep, kept = reader.REPLACED, reader.KEPT
    return [
        ("key-listed", WELL_KNOWN, t1, [],
         response(200, DIRECTORY_TYPE, jwks(K1)), ok, "key_in_directory", rep, [t1],
         "the directory lists the key the request names"),
        ("key-listed-among-several", WELL_KNOWN, t2, [t1],
         response(200, DIRECTORY_TYPE, jwks(K1, K2)), ok, "key_in_directory", rep, [t1, t2],
         "a rotation in progress: the old and the new key are both listed"),
        ("empty-key-set-evicts", WELL_KNOWN, t1, [t1],
         response(200, DIRECTORY_TYPE, jwks()), no, "key_absent_from_directory", rep, [],
         "the operator withdrew the agent and serves an empty key set with 200: evidence, "
         "so the cached key is evicted"),
        ("refused-with-empty-key-set-keeps-cache", WELL_KNOWN, t1, [t1],
         response(403, DIRECTORY_TYPE, jwks()), no, "discovery_failed", kept, [t1],
         "the same bytes as empty-key-set-evicts behind a refusal: the status says the load "
         "failed, so an empty key set read out of it is not evidence and nothing is evicted"),
        ("limit-refused-keeps-cache", WELL_KNOWN, t1, [t1],
         {"outcome": "limit_refused", "status": None, "mediaType": None, "body": None},
         no, "discovery_failed", kept, [t1],
         "the verifier's own limit (size, key count, timeout or address range) refused the "
         "load: nothing was read, so nothing is withdrawn"),
        ("no-keys-member-keeps-cache", WELL_KNOWN, t1, [t1],
         response(200, DIRECTORY_TYPE, _json({"error": "directory temporarily unavailable"})),
         no, "not_a_directory", kept, [t1],
         "a 200 that is JSON without a keys array is not an empty key set"),
        ("empty-body-keeps-cache", WELL_KNOWN, t1, [t1],
         response(200, DIRECTORY_TYPE, b""), no, "not_a_directory", kept, [t1],
         "a 200 with no bytes is an empty response, not an empty key set"),
        ("key-removed-other-kept", WELL_KNOWN, t1, [t1, t2],
         response(200, DIRECTORY_TYPE, jwks(K2)), no, "key_absent_from_directory", rep, [t2],
         "the directory stopped listing one key and still lists the other"),
        ("status-404-keeps-cache", WELL_KNOWN, t2, [t1],
         response(404, "text/plain", b"Not Found\n"), no, "discovery_failed", kept, [t1],
         "a 404 is a discovery failure, not a removal: the cached key stays"),
        ("status-503-keeps-cache", WELL_KNOWN, t2, [t1],
         response(503, "text/plain", b"Service Unavailable\n"), no, "discovery_failed", kept,
         [t1], "an operator outage must not revoke its keys at the verifier"),
        ("transport-failure-keeps-cache", WELL_KNOWN, t2, [t1],
         {"outcome": "connect_failure", "status": None, "mediaType": None, "body": None},
         no, "discovery_failed", kept, [t1],
         "the connection failed before any response: nothing was observed"),
        ("redirect-not-followed", WELL_KNOWN, t2, [t1],
         response(302, "text/plain", b"Found\n"), no, "redirect_not_followed", kept, [t1],
         "a verifier must not follow a redirect from the directory URL"),
        ("html-error-page-with-200", WELL_KNOWN, t2, [t1],
         response(200, "text/html", HTML_ERROR), no, "not_a_directory", kept, [t1],
         "a CDN error page served with 200 is not an empty directory: the cached key stays"),
        ("wrong-media-type-at-well-known", WELL_KNOWN, t2, [t1],
         response(200, "application/json", jwks(K2)), no, "not_a_directory", kept, [t1],
         "a JWK Set at the well-known URI without the registered media type"),
        ("kid-not-thumbprint-at-well-known", WELL_KNOWN, DRAFT_THUMB, [],
         response(200, DIRECTORY_TYPE, jwks(draft_jwk(kid=DRAFT_WRONG_KID))),
         no, "kid_not_thumbprint", rep, [],
         "the draft's own Section 5.5.1 example: its kid is not the key's thumbprint, so the "
         "entry is malformed and dropped"),
        ("kid-thumbprint-at-well-known", WELL_KNOWN, DRAFT_THUMB, [],
         response(200, DIRECTORY_TYPE, jwks(draft_jwk(kid=DRAFT_THUMB))),
         ok, "key_in_directory", rep, [DRAFT_THUMB],
         "the same key with the kid Appendix E gives it"),
        ("kid-label-off-well-known", OTHER_URL, t3, [],
         response(200, "application/json", jwks(dict(K3, kid="signing-2026"))),
         ok, "key_in_directory", rep, [t3],
         "away from the well-known URI a kid is an operator label; the verifier matches by "
         "computed thumbprint"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, url, keyid, cached, fetch, decision, reason, cache, after, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        files: dict[str, bytes] = {}
        recorded = {key: value for key, value in fetch.items() if key != "body"}
        if fetch["body"] is not None:
            files["response.body"] = fetch["body"]
            recorded["body"] = "response.body"
        else:
            recorded["body"] = None
        case = {"cached": sorted(cached), "directoryUrl": url, "fetch": recorded, "keyid": keyid,
                "schema_version": "web-bot-auth-key-directory-observation-case/v1"}
        files["case.json"] = _json(case)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "edit": edit,
            "expected": {"cache": cache, "cacheAfter": sorted(after), "decision": decision,
                         "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "corpusDigest": _sha(_json(entries)), "source": SOURCE, "suite": SUITE,
        "verifierContract": ("verifier case.json --json; prints decision, reason, cache and "
                             "cacheAfter; exit 0 attributed, 1 not_attributed"),
        "vectors": entries,
    }
    words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: words.count(word) for word in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
