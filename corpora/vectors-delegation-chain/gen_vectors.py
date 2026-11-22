"""Build the delegation-chain cases byte-identically.

Every case is one record: a signed chain of four grants, a -> b -> c -> d, so three delegation hops below the
root grant. The keys are derived from fixed seeds and Ed25519 signatures are deterministic, so the files do
not change between runs. Each denied case departs from the conformant chain on exactly one axis, and the
widening axes each depart at a different hop so a verifier that checks only the last hop still fails. The
public wording the cases follow is in README.md.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import delegationchain as reader  # noqa: E402

SUITE = reader.SUITE
AT = "2026-11-21T12:00:00+00:00"
ISSUED = "2026-11-21T00:00:00+00:00"
AGENTS = ["a", "b", "c", "d"]
RECEIVER = "d"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_sha(f"delegation-chain/v1 key {name}".encode()).encode()[:32])


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(_raw(key)).decode()


KEYS = {name: _key(name) for name in ["root", "other", *AGENTS]}
ROOT_KEY_ID = _sha(_raw(KEYS["root"]))


def at(hours: int) -> str:
    """An instant ``hours`` hours after the issue time, written with an offset."""
    base = int(ISSUED[8:10]) * 24 + hours
    return f"2026-11-{base // 24:02d}T{base % 24:02d}:00:00+00:00"


def body(depth: int, *, issuer: str | None = None, tools: dict[str, dict[str, Any]] | None = None,
         audience: list[str] | None = None, expires: str | None = None, uses: int | None = None,
         max_depth: int | None = None, parent: str | None = None, holder: str | None = None) -> dict[str, Any]:
    """The grant at ``depth`` (0 is the root grant to ``a``); every argument is a departure from the conformant one."""
    holder_name = holder or AGENTS[depth]
    issuer_name = issuer or ("root" if depth == 0 else AGENTS[depth - 1])
    return {
        "budget": {"uses": 8 - depth if uses is None else uses},
        "context": {"audience": {"type": "one_of", "values": sorted(audience or AGENTS[depth:])}},
        "expiresAt": expires or at(24 - 2 * depth),
        "grantId": f"g{depth}",
        "holderKey": _b64(KEYS[holder_name]),
        "issuerKey": _b64(KEYS[issuer_name]),
        "maxDepth": 3 - depth if max_depth is None else max_depth,
        "notBefore": at(-1),
        "parent": parent,
        "tools": tools if tools is not None else base_tools(depth),
    }


def base_tools(depth: int) -> dict[str, dict[str, Any]]:
    pool = ["search", "read", "write", "deploy"][: 4 - depth]
    regions = ["eu", "us", "ap"][: max(1, 3 - depth)]
    return {t: {"args": {"region": {"type": "one_of", "values": regions}}} for t in pool}


def sign(grant: dict[str, Any]) -> dict[str, Any]:
    """Sign ``grant`` with the key its own ``issuerKey`` names."""
    key = next(k for k in KEYS.values() if _b64(k) == grant["issuerKey"])
    message = reader.GRANT_DOMAIN + _rail().jcs_dumps(grant)
    return {"body": grant, "sig": base64.b64encode(key.sign(message)).decode()}


def _rail() -> Any:
    return reader._rail()


def chain(**overrides: dict[str, Any]) -> list[dict[str, Any]]:
    """The conformant four-grant chain; ``overrides`` maps a depth to the departures at that depth."""
    links: list[dict[str, Any]] = []
    for depth in range(4):
        parent = None if depth == 0 else reader.grant_digest(links[-1]["body"])
        grant = body(depth, parent=parent, **overrides.get(f"d{depth}", {}))
        links.append(sign(grant))
    return links


def record(links: list[dict[str, Any]] | None = None, *, revoked: list[str] | None = None,
           receiver: str = RECEIVER, contract: str | None = reader.CONTRACT_ID,
           at_time: str = AT) -> dict[str, Any]:
    out: dict[str, Any] = {
        "at": at_time, "chain": links if links is not None else chain(), "receiver": receiver,
        "revoked": revoked or [], "rootKeyIds": [ROOT_KEY_ID],
    }
    if contract is not None:
        out["contractId"] = contract
    return out


def broken(mutate: Any) -> dict[str, Any]:
    """The conformant record with one structural change applied by ``mutate``."""
    out = copy.deepcopy(record())
    mutate(out)
    return out


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    ok = reader.ALLOWED
    wide_tools = {**base_tools(2), "admin": {"args": {"region": {"type": "one_of", "values": ["eu"]}}}}
    wide_args = {t: {"args": {"region": {"type": "one_of", "values": ["eu", "us", "ap", "sa"]}}}
                 for t in base_tools(3)}
    mid = chain()
    spliced = copy.deepcopy(mid)
    spliced[2] = sign(body(2, parent=_sha(b"a grant from another task")))
    spliced[3] = sign(body(3, parent=reader.grant_digest(spliced[2]["body"])))
    swapped = chain()
    swapped[2] = sign(body(2, issuer="other", parent=reader.grant_digest(swapped[1]["body"])))
    swapped[3] = sign(body(3, parent=reader.grant_digest(swapped[2]["body"])))
    offsetless = chain(d3={"expires": "2026-11-21T20:00:00"})
    forged = chain()
    forged[3] = {"body": forged[3]["body"], "sig": forged[2]["sig"]}
    return [
        ("allow-three-hop-chain", record(), "allow", ok,
         "control: four grants a to d, each narrower than the one above, receiver d"),
        ("allow-equal-grant-at-every-axis-but-depth", record(chain(
            d1={"tools": base_tools(0), "audience": AGENTS[1:], "uses": 7, "expires": at(24)},
            d2={"tools": base_tools(0), "audience": AGENTS[2:], "uses": 7, "expires": at(24)},
            d3={"tools": base_tools(0), "audience": AGENTS[3:], "uses": 7, "expires": at(24)},
        )), "allow", ok, "control: tools, arguments, expiry and budget are held equal down the chain; only depth falls"),
        ("allow-expiry-at-the-parent-instant", record(chain(
            d3={"expires": at(20)})), "allow", ok,
         "control: the last grant expires at the same instant as its parent"),
        ("reject-widened-tools-in-the-middle", record(chain(d2={"tools": wide_tools})), "deny",
         "widens_tools", "the second delegation adds a tool its parent did not hold; the last grant narrows again"),
        ("reject-widened-arguments", record(chain(d3={"tools": wide_args})), "deny", "widens_arguments",
         "the last delegation allows a region its parent excluded"),
        ("reject-widened-audience", record(chain(d2={"audience": ["c", "d", "e"]})), "deny",
         "widens_audience", "the second delegation names an agent its parent did not"),
        ("reject-widened-expiry", record(chain(d3={"expires": at(26)})), "deny", "widens_expiry",
         "the last grant outlives its parent"),
        ("reject-widened-budget", record(chain(d2={"uses": 9})), "deny", "widens_budget",
         "the second delegation allows more uses than its parent"),
        ("reject-depth-not-falling", record(chain(d3={"max_depth": 1})), "deny", "depth_exceeded",
         "the last grant allows as many further delegations as its parent"),
        ("reject-issuer-swapped", record(swapped), "deny", "issuer_not_authorised",
         "the third grant is signed by an agent that never held the grant above it"),
        ("reject-spliced-chain", record(spliced), "deny", "parent_mismatch",
         "the third grant names the digest of a grant from another task as its parent"),
        ("reject-revoked-ancestor", record(revoked=[reader.grant_digest(chain()[1]["body"])]), "deny",
         "ancestor_revoked", "the second grant is on the revocation list while the chain below it is intact"),
        ("reject-offsetless-timestamp", record(offsetless), "deny", "malformed_record",
         "a grant expiry is written without a UTC offset and is refused, never compared"),
        ("reject-signature-from-another-grant", record(forged), "deny", "signature_invalid",
         "the last grant carries the signature of the grant above it"),
        ("reject-expired-link", record(at_time="2026-11-22T00:00:00+00:00"), "deny", "grant_not_in_window",
         "the judging instant is after the last grant's expiry"),
        ("reject-receiver-outside-audience", record(receiver="a"), "deny", "receiver_outside_audience",
         "the receiving agent is not in the last grant's audience"),
        ("malformed-chain-empty", broken(lambda r: r.update(chain=[])), "deny", "malformed_record",
         "the chain holds no grants"),
        ("malformed-uses-not-integer", broken(lambda r: r["chain"][1]["body"]["budget"].update(uses="many")),
         "deny", "malformed_record", "a grant's use budget is text"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown", record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, rec, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(rec)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)}, "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: words.count(word) for word in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
