"""Build the agent-to-principal binding cases byte-identically.

Each case is one binding of an agent to the principal it acts for and the scope
it may use, written in the native form of one effort that defines such a
binding, plus the relying party's request: the agent, principal and scope it
is being asked to accept. The question is the same for every form: does the
binding produce a record a verifier can recompute, and does the verifier
refuse when one field is changed?

Two native forms are covered:

- ``uma-for-agents``: the terms agreement of UMA for Agents, a profile of UMA
  2.0 that is a candidate update in the Kantara UMA Work Group. The owner's
  authorization server proffers a terms template; the agent echoes it and
  signs it as a compact JWS with its own key (https://u4a.ai/docs/reference/
  wire-contract/, Beat 3).
- ``hcp-grant``: the grant object of the Human Context Protocol 2.0 draft 3
  (https://github.com/loyalagents/hcp-spec, specification section 6.1.5). The
  draft defines the grant the Authorization Service records but no signature
  over it, so the cases carry it inside an envelope signed by the
  Authorization Service over its RFC 8785 form.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild
every signature. They are test keys and protect nothing.
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

import run_vectors as rail  # noqa: E402

SUITE = "agent-principal-binding/v1"
SEED_PREFIX = "agent-evidence-vectors/agent-principal-binding/v1/"
OWNER_AS = "https://alice-as.uma.lab"
OTHER_AS = "https://bob-as.uma.lab"
GRANT_TYPE = "https://hcp.example/spec/authorization/context-access"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> bytes:
    return bytes(rail.ed25519_public_key(_seed(label)))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def agent_id(label: str) -> str:
    """A pseudonymous agent is its key: ``agent:`` and the first 16 hex digits
    of the SHA-256 of its public key."""
    return "agent:" + _sha(_public(label))[:16]


# ---------------------------------------------------------------- UMA for Agents

TEMPLATE: dict[str, Any] = {
    "expires_in": 172800,
    "family": "fam-7Qm2",
    "nonce": "n-41c9e0",
    "prohibited": ["retention-after-review", "marketing", "model-training"],
    "proffered_by": OWNER_AS,
    "purpose": "Suitability review for advisory onboarding",
    "resource_id": "alice-vault/get_positions",
    "scope": ["positions:read"],
    "template_id": "alice/advisor-tier1/v2",
    "terms_uri": OWNER_AS + "/terms/alice/advisor-tier1/v2",
}


def agreement(signer: str = "agent", **changes: Any) -> dict[str, Any]:
    """The template echoed by the agent, as Beat 3 sends it."""
    body = {key: TEMPLATE[key] for key in (
        "template_id", "terms_uri", "purpose", "scope", "expires_in", "prohibited",
        "family", "nonce")}
    body.update({"aud": OWNER_AS, "iat": 1794733200, "iss": agent_id(signer),
                 "reason": "Suitability review before Thursday's client meeting."})
    body.update(changes)
    return body


def jws(payload: dict[str, Any], signer: str = "agent") -> bytes:
    """A compact JWS, EdDSA, whose protected header carries the signing key."""
    header = {"alg": "EdDSA", "jwk": {"crv": "Ed25519", "kty": "OKP",
                                      "x": _b64u(_public(signer))}}
    signing_input = (_b64u(rail.jcs_dumps(header)) + "." +
                     _b64u(rail.jcs_dumps(payload))).encode("ascii")
    sig = rail.ed25519_sign(_seed(signer), signing_input)
    return signing_input + b"." + _b64u(sig).encode("ascii")


def jws_with_payload(token: bytes, payload: dict[str, Any]) -> bytes:
    """Replace a JWS payload and keep its old signature, as an editor without
    the agent key must."""
    header, _, sig = token.split(b".")
    return header + b"." + _b64u(rail.jcs_dumps(payload)).encode("ascii") + b"." + sig


# -------------------------------------------------------------------- HCP grant

def grant(**changes: Any) -> dict[str, Any]:
    """An HCP 2.0 draft 3 grant: the agent is the HCP Client, the principal is
    the Authorizing Principal, the scope is the derived scope strings."""
    body: dict[str, Any] = {
        "access": [{"actions": ["read"], "categories": ["financial_context"],
                    "purposes": [{"code": "https://hcp.example/purpose/advisory-review",
                                  "description": "Suitability review for advisory onboarding"}],
                    "type": GRANT_TYPE}],
        "authorizingPrincipal": {"id": "pseud-alice-7f3a"},
        "client": {"id": agent_id("agent"), "name": "Advisor onboarding agent",
                   "operator": {"id": "op-example-advisors", "name": "Example Advisors"}},
        "expiresAt": "2026-11-18T09:00:00Z",
        "grantId": "urn:uuid:5b0c6f0e-7a51-4d7e-9a43-2f1d8e0c9b11",
        "grantType": "temporary",
        "issuedAt": "2026-11-16T09:00:00Z",
        "scopes": ["hcp:financial_context:read"],
        "status": "active",
        "subject": {"id": "pseud-alice-7f3a"},
    }
    body.update(changes)
    return body


def envelope(body: dict[str, Any], signer: str = "authorization-service") -> bytes:
    sig = rail.ed25519_sign(_seed(signer), rail.jcs_dumps(body))
    return _json({"grant": body, "kid": "authorization-service",
                  "sig": base64.b64encode(sig).decode()})


def envelope_edited(body: dict[str, Any], **changes: Any) -> bytes:
    """Change grant fields after the Authorization Service signed, keeping the
    old signature."""
    signed = json.loads(envelope(body))
    signed["grant"].update(changes)
    return _json(signed)


# ------------------------------------------------------------------------ cases

UMA_REQUEST = {"agent": agent_id("agent"), "principal": OWNER_AS, "scope": ["positions:read"]}
HCP_REQUEST = {"agent": agent_id("agent"), "principal": "pseud-alice-7f3a",
               "scope": ["hcp:financial_context:read"]}

Case = tuple[str, str, bytes, dict[str, Any], str, str, str, str]


def cases() -> list[Case]:
    """Every case: id, profile, binding bytes, request, expected decision and
    reason, the accept case it pairs with, and what it changes."""
    signed = jws(agreement())
    edited = jws_with_payload(signed, agreement(purpose="Marketing outreach"))
    other_agent = {**UMA_REQUEST, "agent": agent_id("other-agent")}
    hcp = envelope(grant())
    return [
        ("uma-bound", "uma-for-agents", signed, UMA_REQUEST, "verified", "agent_bound", "",
         "control: the agent echoed the proffered terms and signed them with its key"),
        ("uma-other-agent", "uma-for-agents", signed, other_agent, "rejected",
         "agent_mismatch", "uma-bound", "the request names another agent"),
        ("uma-other-principal", "uma-for-agents", signed,
         {**UMA_REQUEST, "principal": OTHER_AS}, "rejected", "principal_mismatch",
         "uma-bound", "the request names another owner's authorization server"),
        ("uma-scope-widened", "uma-for-agents", signed,
         {**UMA_REQUEST, "scope": ["positions:read", "trades:execute"]}, "rejected",
         "scope_exceeded", "uma-bound", "the request asks for a scope the terms do not grant"),
        ("uma-edited-after-signing", "uma-for-agents", edited, UMA_REQUEST, "rejected",
         "signature_invalid", "uma-bound",
         "the agreement's purpose edited after the agent signed, signature kept"),
        ("uma-signed-by-other-key", "uma-for-agents", jws(agreement(), "other-agent"),
         UMA_REQUEST, "rejected", "signature_invalid", "uma-bound",
         "a valid signature by a key that is not the agent's, over the agreement naming it"),
        ("uma-purpose-not-echoed", "uma-for-agents",
         jws(agreement(purpose="Portfolio analytics")), UMA_REQUEST, "rejected",
         "echo_mismatch", "uma-bound",
         "the agent signed a purpose other than the one proffered"),
        ("uma-scope-not-echoed", "uma-for-agents",
         jws(agreement(scope=["positions:read", "trades:execute"])),
         {**UMA_REQUEST, "scope": ["positions:read", "trades:execute"]}, "rejected",
         "echo_mismatch", "uma-bound",
         "the agent signed a wider scope than proffered and the request asks for it"),
        ("uma-prohibition-dropped", "uma-for-agents",
         jws(agreement(prohibited=["retention-after-review", "marketing"])), UMA_REQUEST,
         "rejected", "terms_weakened", "uma-bound",
         "the agent's echo leaves out the model-training prohibition"),
        ("uma-expiry-extended", "uma-for-agents", jws(agreement(expires_in=2592000)),
         UMA_REQUEST, "rejected", "terms_weakened", "uma-bound",
         "the agent's echo extends expires_in from two days to thirty"),
        ("hcp-bound", "hcp-grant", hcp, HCP_REQUEST, "verified", "agent_bound", "",
         "control: an active grant naming the agent as client and the principal as "
         "Authorizing Principal"),
        ("hcp-other-agent", "hcp-grant", hcp, {**HCP_REQUEST, "agent": agent_id("other-agent")},
         "rejected", "agent_mismatch", "hcp-bound", "the request names another agent"),
        ("hcp-other-principal", "hcp-grant", hcp,
         {**HCP_REQUEST, "principal": "pseud-bob-11c2"}, "rejected", "principal_mismatch",
         "hcp-bound", "the request names another Authorizing Principal"),
        ("hcp-scope-widened", "hcp-grant", hcp,
         {**HCP_REQUEST, "scope": ["hcp:financial_context:read", "hcp:financial_context:write"]},
         "rejected", "scope_exceeded", "hcp-bound",
         "the request asks for a scope the grant does not hold"),
        ("hcp-edited-after-signing", "hcp-grant",
         envelope_edited(grant(), client={**grant()["client"], "id": agent_id("other-agent")}),
         {**HCP_REQUEST, "agent": agent_id("other-agent")}, "rejected", "signature_invalid",
         "hcp-bound", "the grant's client edited to another agent after signing"),
        ("hcp-grant-revoked", "hcp-grant", envelope(grant(status="revoked")), HCP_REQUEST,
         "rejected", "grant_inactive", "hcp-bound",
         "the Authorizing Principal revoked the grant"),
        ("hcp-scopes-beyond-access", "hcp-grant",
         envelope(grant(scopes=["hcp:financial_context:read", "hcp:financial_context:write"])),
         {**HCP_REQUEST, "scope": ["hcp:financial_context:read", "hcp:financial_context:write"]},
         "rejected", "scope_not_backed", "hcp-bound",
         "the scope strings grant write, which the grant's access does not"),
        ("hcp-principal-not-subject", "hcp-grant",
         envelope(grant(authorizingPrincipal={"id": "pseud-mallory-90af"})),
         {**HCP_REQUEST, "principal": "pseud-mallory-90af"}, "rejected",
         "principal_mismatch", "hcp-bound",
         "the Authorizing Principal is not the Context Subject and the grant names no "
         "delegation"),
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


def _case(profile: str, request: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if profile == "uma-for-agents":
        return ({"binding": "binding.jws", "keys": {"agent": _public("agent").hex()},
                 "profile": profile, "request": request,
                 "schema_version": "agent-principal-binding-case/v1",
                 "template": TEMPLATE}, "binding.jws")
    return ({"binding": "binding.json",
             "keys": {"authorization-service": _public("authorization-service").hex()},
             "profile": profile, "request": request,
             "schema_version": "agent-principal-binding-case/v1"}, "binding.json")


def _b64u_decode(text: bytes) -> bytes:
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


def _signature_verifies(profile: str, binding: bytes) -> bool:
    """Whether the binding's signature verifies under the key the case trusts,
    computed here and not by the reader, so the reader is checked against it."""
    if profile == "uma-for-agents":
        header, payload, sig = binding.strip().split(b".")
        key = _b64u_decode(json.loads(_b64u_decode(header))["jwk"]["x"].encode())
        return key == _public("agent") and bool(rail.ed25519_verify(
            key, header + b"." + payload, _b64u_decode(sig)))
    signed = json.loads(binding)
    return bool(rail.ed25519_verify(_public("authorization-service"),
                                    rail.jcs_dumps(signed["grant"]),
                                    base64.b64decode(signed["sig"])))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, profile, binding, request, decision, reason, pair, change in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case, binding_name = _case(profile, request)
        files = {"case.json": _json(case),
                 binding_name: binding if binding.endswith(b"\n") else binding + b"\n"}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entry: dict[str, Any] = {
            "bindingSignatureVerifies": _signature_verifies(profile, binding),
            "change": change, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}", "profile": profile,
        }
        if pair:
            entry["pairsWith"] = pair
        entries.append(entry)
    manifest = {
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
