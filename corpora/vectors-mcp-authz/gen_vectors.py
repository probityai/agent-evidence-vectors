"""Build the deterministic MCP authorization observation vectors.

    python3 corpora/vectors-mcp-authz/gen_vectors.py

Each member is one recorded observation of what an MCP server publishes about
its OAuth protection, with the verdict and the finding codes a verifier must
return for it. The corpus holds inputs and expected answers only. Every
member, the manifest and the index are functions of this file alone. The
fixtures are synthetic: no real host, account, token or key appears in any of
them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "mcp-authz-observation/v1"
RESOURCE = "https://mcp.example.test/mcp"
ISSUER = "https://auth.example.test"
PRM_URL = "https://mcp.example.test/.well-known/oauth-protected-resource/mcp"
NOW = 1790000000
Obs = dict[str, Any]
Build = Callable[[], Obs]
Mutation = Callable[[Obs], None]
# (id, builder, mutation or None, expected codes, description)
Member = tuple[str, Build, Mutation | None, list[str], str]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "scope": (
        "What an MCP server publishes about its OAuth protection, read from outside: Protected Resource "
        "Metadata (RFC 9728), Authorization Server metadata (RFC 8414), the Bearer challenge on a request "
        "with no token (RFC 6750 section 3), the server's authorization settings, and whether a request "
        "with no token, or with a token that lacks a required scope, is refused. JWTs are carried "
        "decoded; signatures are outside this corpus. All fixtures are synthetic."
    ),
    "sources": [
        "RFC 9728 OAuth 2.0 Protected Resource Metadata",
        "RFC 8414 OAuth 2.0 Authorization Server Metadata",
        "RFC 6750 Bearer Token Usage, section 3",
        "MCP specification, Authorization",
    ],
    "verifierContract": (
        "verifier <observation file>: the last stdout line is one JSON object with `verdict` "
        "(valid or invalid) and `codes` (the finding codes, a set); exit 0 for valid, 1 for invalid."
    ),
}


def _baseline() -> Obs:
    """A server whose published surfaces agree: the observation every defect is a change to."""
    return {
        "schema": SUITE,
        "evaluated_at": NOW,
        "fixture": {"synthetic": True},
        "server": {
            "resource": RESOURCE,
            "issuer": ISSUER,
            "required_scopes": ["mcp:read"],
            "registration": {"enabled": True, "valid_scopes": ["mcp:read", "mcp:write"]},
        },
        "observed": {
            "prm": {
                "status": 200,
                "body": {
                    "resource": RESOURCE,
                    "authorization_servers": [ISSUER],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:read", "mcp:write"],
                },
            },
            "as_metadata": {
                "status": 200,
                "body": {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "registration_endpoint": f"{ISSUER}/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["mcp:read", "mcp:write"],
                    "token_endpoint_auth_methods_supported": ["none"],
                },
            },
            "unauthenticated": {
                "status": 401,
                "www_authenticate": f'Bearer resource_metadata="{PRM_URL}", scope="mcp:read"',
            },
            "under_scoped": {
                "status": 403,
                "www_authenticate": (
                    f'Bearer error="insufficient_scope", scope="mcp:read mcp:write", resource_metadata="{PRM_URL}"'
                ),
            },
        },
    }


def _prm_defective(o: Obs) -> None:
    prm = o["observed"]["prm"]["body"]
    prm["resource"] = "https://mcp.example.test/mcp/"
    prm["authorization_servers"] = []
    prm["bearer_methods_supported"] = ["body"]
    prm["scopes_supported"] = ["mcp:read", "offline_access"]
    o["observed"]["unauthenticated"] = {"status": 401, "www_authenticate": ""}


def _as_defective(o: Obs) -> None:
    body = o["observed"]["as_metadata"]["body"]
    body["issuer"] = "https://other.example.test"
    del body["token_endpoint"]
    del body["registration_endpoint"]
    body["response_types_supported"] = ["token"]
    body["code_challenge_methods_supported"] = ["plain"]


def _challenge_defective(o: Obs) -> None:
    o["observed"]["unauthenticated"] = {"status": 401, "www_authenticate": 'Bearer scope="mcp:read offline_access"'}
    o["observed"]["under_scoped"] = {"status": 401, "www_authenticate": 'Bearer error="invalid_token"'}


def _config_defective(o: Obs) -> None:
    o["server"]["resource"] = None
    o["server"]["required_scopes"] = ["mcp:read", "mcp:write"]
    o["server"]["registration"]["valid_scopes"] = ["mcp:read"]
    o["observed"]["prm"] = None
    o["observed"]["as_metadata"] = {"status": 200}
    o["observed"]["unauthenticated"] = {"status": 401, "www_authenticate": 'Basic realm="mcp"'}


def _unauthenticated_served(o: Obs) -> None:
    o["observed"]["prm"] = {"status": 404}
    o["observed"]["unauthenticated"] = {"status": 200}
    o["observed"]["under_scoped"] = {"status": 200}


CORE_MEMBERS: tuple[Member, ...] = (
    (
        "resource-metadata-defective",
        _baseline,
        _prm_defective,
        [
            "challenge-missing",
            "prm-authorization-servers-missing",
            "prm-bearer-header-missing",
            "prm-resource-not-identical",
            "prm-scope-offline-access",
        ],
        "resource metadata names a different resource, no authorization server, no header method and offline_access, and the 401 carries no challenge",
    ),
    (
        "authorization-server-metadata-defective",
        _baseline,
        _as_defective,
        [
            "as-issuer-mismatch",
            "as-issuer-not-in-prm",
            "as-pkce-s256-missing",
            "as-registration-endpoint-missing",
            "as-required-field-missing",
            "as-response-type-code-missing",
        ],
        "authorization server metadata without S256, the code response type, a token endpoint or a registration endpoint, under another issuer",
    ),
    (
        "challenge-defective",
        _baseline,
        _challenge_defective,
        [
            "challenge-insufficient-scope-not-403",
            "challenge-resource-metadata-missing",
            "challenge-scope-offline-access",
        ],
        "the 401 challenge asks for offline_access and points to no resource metadata, and an under-scoped token is answered 401",
    ),
    (
        "settings-inconsistent",
        _baseline,
        _config_defective,
        [
            "as-metadata-not-json",
            "challenge-scheme-not-bearer",
            "config-resource-url-missing",
            "config-scopes-not-obtainable",
        ],
        "no resource identifier, a required scope a registered client cannot obtain, non-JSON server metadata and a Basic challenge",
    ),
    (
        "unauthenticated-request-served",
        _baseline,
        _unauthenticated_served,
        ["prm-not-served", "required-scope-not-enforced", "unauthenticated-request-accepted"],
        "a request with no token and a token without the required scope are both served, and the metadata endpoint is missing",
    ),
)

MEMBERS: tuple[Member, ...] = CORE_MEMBERS


def corpus_digest(manifest: dict[str, Any], root: str | Path = ROOT) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        data = (base / entry["file"]).read_bytes()
        if _sha(data) != entry["sha256"]:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append(entry)
    return _sha(_json(entries))


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# MCP authorization observation vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Suite: `{SUITE}`.",
        "",
        f"Corpus digest: `{digest}`",
        "",
        "| id | kind | verdict | codes | case |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        codes = ", ".join(f"`{c}`" for c in x["codes"]) or "none"
        lines.append(f"| `{e['id']}` | {e['kind']} | {x['verdict']} | {codes} | {e['description']} |")
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every observation, the manifest and the index."""
    (root / "observations").mkdir(parents=True, exist_ok=True)
    entries = []
    for name, build, mutate, codes, description in MEMBERS:
        observation = build()
        if mutate is not None:
            mutate(observation)
        observation["case_id"] = f"vectors-mcp-authz-{name}"
        data = _json(copy.deepcopy(observation))
        (root / "observations" / f"{name}.json").write_bytes(data)
        entries.append(
            {
                "id": name,
                "kind": "reject" if codes else "accept",
                "file": f"observations/{name}.json",
                "sha256": _sha(data),
                "description": description,
                "expected": {"verdict": "invalid" if codes else "valid", "codes": codes},
            }
        )
    digest = _sha(_json(entries))
    manifest = {
        "suite": SUITE,
        "counts": {
            kind: sum(e["kind"] == kind for e in entries) for kind in ("accept", "reject")
        },
        "vectors": entries,
        "specification": SPECIFICATION,
        "corpusDigest": digest,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
