"""Build the actor-marker-survival cases byte-identically.

Every case is one chain of signed statements: an origin issuer's statement of the
principals it sent, then one statement per hop of what that hop received and what it
sent onward. Each refusal is an accepted chain with one edit, re-sealed so that every
check before the one it names still passes. Keys are derived from public seeds below:
every member is synthetic, and the keys sign nothing outside this corpus.

The rules come from public standards text only: RFC 8693 section 4.1 (the ``act``
claim and its nesting), RFC 7515 section 4.1.11 (``crit``), RFC 9449 section 4.2 (a
proof carried in an HTTP header is a signed JWT), draft-ietf-oauth-identity-assertion-
authz-grant-06 section 9.10 (keep the actor distinct from the resource owner), the
truncation report on that draft's issue 73, and the ``actorChain`` shape proposed in
a2aproject/A2A issue 2028.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import actormarker as reader  # noqa: E402

SUITE = reader.SUITE
U = "user:alice@example.com"
T0 = 1795359600  # 2026-11-21T15:00:00Z
EXP = T0 + 3600
RESOURCE = "api.example"
WRITERS = {
    "idp.example": "origin",
    "agent:planner": "agent",
    "agent:researcher": "agent",
    "agent:writer": "agent",
    "agent:intruder": "agent",
    "gateway:edge": "relay",
    "queue:jobs": "relay",
    "bridge:a2a-oauth": "relay",
}
SOURCES = {
    "a2a-2028": {
        "title": "Actor-chain extension: a standard payload shape for on-behalf-of delegation",
        "url": "https://github.com/a2aproject/A2A/issues/2028",
    },
    "idjag-06": {
        "title": "draft-ietf-oauth-identity-assertion-authz-grant-06",
        "url": "https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/",
    },
    "idjag-73": {
        "title": "oauth-wg/oauth-identity-assertion-authz-grant issue 73",
        "url": "https://github.com/oauth-wg/oauth-identity-assertion-authz-grant/issues/73"
        "#issuecomment-5079449594",
    },
    "rfc7515": {"title": "RFC 7515", "url": "https://www.rfc-editor.org/rfc/rfc7515"},
    "rfc8693": {"title": "RFC 8693", "url": "https://www.rfc-editor.org/rfc/rfc8693"},
    "rfc9449": {"title": "RFC 9449", "url": "https://www.rfc-editor.org/rfc/rfc9449"},
}
#: One sentence per rule, quoted from the source (whitespace normalised).
ANCHORS = {
    "nesting": (
        "rfc8693",
        "4.1",
        'The outermost "act" claim represents the current actor while '
        'nested "act" claims represent prior actors. The least recent actor is the most '
        "deeply nested.",
    ),
    "history": (
        "rfc8693",
        "4.1",
        'The nested "act" claims serve as a history trail that connects '
        "the initial request and subject through the various delegation steps undertaken "
        "before reaching the current actor.",
    ),
    "distinct": (
        "idjag-06",
        "9.10",
        "When such profiles or extensions use an act claim, they should "
        "preserve the distinction between the actor identified by act and the resource "
        "owner identified by sub.",
    ),
    "truncation": (
        "idjag-73",
        "comment 2026-07-25",
        "Silent truncation is worse than rejection for "
        "anyone reconstructing a chain after the fact, because the resulting token still "
        "looks well-formed and simply attributes the work to the wrong principal.",
    ),
    "append": (
        "a2a-2028",
        "issue body",
        "Peers that do declare it append their own hop when delegating onward.",
    ),
    "audit": (
        "a2a-2028",
        "issue body",
        "A payload field any caller can write must never function "
        "as a credential, and the extension text should say so normatively.",
    ),
    "crit": (
        "rfc7515",
        "4.1.11",
        "If any of the listed extension Header Parameters are not "
        "understood and supported by the recipient, then the JWS is invalid.",
    ),
    "signed-header": (
        "rfc9449",
        "4.2",
        "A DPoP proof is a JWT [RFC7519] that is signed (using JSON "
        "Web Signature (JWS) [RFC7515]) with a private key chosen by the client",
    ),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(offset: int) -> str:
    return reader.datetime.fromtimestamp(T0 + offset, reader.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def key(name: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"actor-marker-survival/v1 test key " + name.encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public(name: str) -> str:
    raw = key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return reader.b64url(raw)


def trust() -> dict[str, Any]:
    return {
        "contractId": reader.CONTRACT_ID,
        "writers": {n: {"key": public(n), "role": r} for n, r in sorted(WRITERS.items())},
    }


# Chain building ---------------------------------------------------------------------------

Hop = dict[str, Any]


def hop(
    writer: str,
    to: str,
    protocol: str = "rfc8693",
    *,
    deferred: tuple[int, int] | None = None,
    rewrite: Callable[[reader.Principals], reader.Principals] | None = None,
    headers: dict[str, str] | None = None,
) -> Hop:
    """One hop spec. ``rewrite`` replaces what a correct hop would send."""
    return {
        "writer": writer,
        "to": to,
        "protocol": protocol,
        "deferred": deferred,
        "rewrite": rewrite,
        "headers": headers,
    }


def build(
    hops: list[Hop],
    *,
    origin_protocol: str = "rfc8693",
    human: bool = True,
    origin_header: dict[str, Any] | None = None,
    subject: str = U,
) -> list[dict[str, Any]]:
    """Unsealed statement entries for a chain: origin first, then each hop."""

    def token(
        protocol: str, principals: reader.Principals, header: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = reader.encode(protocol, principals, EXP if protocol == "rfc8693" else None)
        if header is not None and protocol == "rfc8693":
            body["header"] = {**body["header"], **header}
        return body

    origin: dict[str, Any] = {
        "kind": "origin",
        "writer": "idp.example",
        "sent": {
            "at": at(0),
            "protocol": origin_protocol,
            "to": hops[0]["writer"],
            "token": token(origin_protocol, (subject, ()), origin_header),
        },
    }
    if human:
        origin["humanEvidence"] = {"at": at(-30), "method": "user-presence"}
    entries = [{"statement": origin}]
    previous, clock = origin["sent"], 0
    for spec in hops:
        received = copy.deepcopy({k: previous[k] for k in ("protocol", "token")})
        clock += 10
        received["at"] = at(clock)
        subject_now, actors = reader.decode(received)
        if WRITERS.get(spec["writer"]) == "agent" or spec["writer"] == "agent:unregistered":
            actors = (*actors, spec["writer"])
        principals = (subject_now, actors)
        if spec["rewrite"] is not None:
            principals = spec["rewrite"](principals)
        statement: dict[str, Any] = {"kind": "hop", "received": received, "writer": spec["writer"]}
        if spec["deferred"] is not None:
            enqueued, dispatched = spec["deferred"]
            statement["deferred"] = {"dispatchedAt": at(dispatched), "enqueuedAt": at(enqueued)}
            clock = dispatched
        else:
            clock += 1
        statement["sent"] = {
            "at": at(clock),
            "protocol": spec["protocol"],
            "to": spec["to"],
            "token": token(spec["protocol"], principals),
        }
        entry: dict[str, Any] = {"statement": statement}
        if spec["headers"] is not None:
            entry["transport"] = {"headers": spec["headers"]}
        entries.append(entry)
        previous = statement["sent"]
    return entries


def seal(
    entries: list[dict[str, Any]], signers: dict[int, str] | None = None
) -> list[dict[str, Any]]:
    """Link each hop to the statement before it and sign every statement."""
    signers = signers or {}
    out = []
    for index, entry in enumerate(entries):
        entry = copy.deepcopy(entry)
        statement = entry["statement"]
        if index:
            statement["prev"] = _sha(reader.signing_input(out[index - 1]["statement"]))
        signer = signers.get(index, statement["writer"])
        signature = key(signer).sign(reader.signing_input(statement))
        entry["signature"] = reader.b64url(signature)
        out.append(entry)
    return out


def record(
    statements: list[dict[str, Any]], contract: str | None = reader.CONTRACT_ID
) -> dict[str, Any]:
    body: dict[str, Any] = {"statements": statements}
    if contract is not None:
        body["contractId"] = contract
    return body


def two_hop(**kw: Any) -> list[Hop]:
    return [hop("agent:planner", "gateway:edge", **kw), hop("gateway:edge", RESOURCE)]


FOUR_HOP = [
    hop("agent:planner", "agent:researcher"),
    hop("agent:researcher", "gateway:edge"),
    hop("gateway:edge", "agent:writer"),
    hop("agent:writer", RESOURCE),
]


def four_hop(index: int, rewrite: Callable[[reader.Principals], reader.Principals]) -> list[Hop]:
    hops = copy.deepcopy(FOUR_HOP)
    hops[index]["rewrite"] = rewrite
    return hops


def deferred_hops(
    dispatch: int, rewrite: Callable[[reader.Principals], reader.Principals] | None = None
) -> list[Hop]:
    return [
        hop("agent:planner", "queue:jobs"),
        hop("queue:jobs", "gateway:edge", deferred=(20, dispatch), rewrite=rewrite),
        hop("gateway:edge", RESOURCE),
    ]


def bridge_hops(
    rewrite: Callable[[reader.Principals], reader.Principals] | None = None,
) -> list[Hop]:
    return [
        hop("agent:planner", "agent:researcher", "a2a-actor-chain"),
        hop("agent:researcher", "bridge:a2a-oauth", "a2a-actor-chain"),
        hop("bridge:a2a-oauth", RESOURCE, "rfc8693", rewrite=rewrite),
    ]


def _edit_after_seal(
    entries: list[dict[str, Any]], edit: Callable[[list[dict[str, Any]]], None]
) -> list[dict[str, Any]]:
    sealed = seal(entries)
    edit(sealed)
    return sealed


def _forge(sealed: list[dict[str, Any]]) -> None:
    sealed[1]["statement"]["sent"]["at"] = at(12)


def _drop_gateway(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sealed = seal(entries)
    return [s for s in sealed if s["statement"]["writer"] != "gateway:edge"]


def _replay(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The gateway's statement from another chain (same principals, another origin)."""
    sealed = seal(entries)
    other = build(two_hop())
    other[0]["statement"]["sent"]["at"] = at(-600)
    other[0]["statement"]["humanEvidence"]["at"] = at(-630)
    foreign = seal(other)[2]
    return [*sealed[:2], foreign]


def _wrong_audience(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries[1]["statement"]["sent"]["to"] = "gateway:other"
    return seal(entries)


def _changed_in_transit(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The gateway received a token with the planner removed; it forwards what it got."""
    received = entries[2]["statement"]["received"]
    received["token"] = reader.encode("rfc8693", (U, ()), EXP)
    entries[2]["statement"]["sent"]["token"] = reader.encode("rfc8693", (U, ()), EXP)
    entries[3]["statement"]["received"]["token"] = copy.deepcopy(
        entries[2]["statement"]["sent"]["token"]
    )
    researcher = reader.decode(entries[3]["statement"]["received"])
    owed = (researcher[0], (*researcher[1], "agent:researcher"))
    entries[3]["statement"]["sent"]["token"] = reader.encode("rfc8693", owed, EXP)
    return seal(entries)


def _unregistered(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return seal(entries)


def _swap_actors(p: reader.Principals) -> reader.Principals:
    return p[0], tuple(reversed(p[1]))


Case = tuple[str, dict[str, Any], str, str, str, list[str]]


def cases() -> list[Case]:
    """id, record, expected decision, reason, the edit, and the anchors it rests on."""
    a, r = reader.ACCEPT, reader.REJECT
    ok = reader.ACCEPT_REASON
    crit_header = {"crit": ["x-delegation-profile"], "x-delegation-profile": "v2"}
    return [
        (
            "accept-two-hop",
            record(seal(build(two_hop()))),
            a,
            ok,
            "control: an agent appends itself and a gateway forwards unchanged",
            ["nesting", "append"],
        ),
        (
            "accept-four-hop",
            record(seal(build(FOUR_HOP))),
            a,
            ok,
            "control: three agents append in order through a gateway",
            ["nesting", "history"],
        ),
        (
            "accept-deferred-hop",
            record(seal(build(deferred_hops(620)))),
            a,
            ok,
            "control: a queue stores the principals and dispatches them ten minutes later",
            ["history"],
        ),
        (
            "accept-protocol-change",
            record(seal(build(bridge_hops(), origin_protocol="a2a-actor-chain"))),
            a,
            ok,
            "control: a bridge carries an A2A actorChain into nested act claims, in order",
            ["nesting", "append"],
        ),
        (
            "accept-user-alone-with-presence",
            record(seal(build([hop("gateway:edge", RESOURCE)]))),
            a,
            ok,
            "control: the user acts alone through a gateway, with user-presence evidence",
            ["distinct"],
        ),
        (
            "accept-noncritical-extension",
            record(seal(build(two_hop(), origin_header={"x-trace": "7f3a"}))),
            a,
            ok,
            "control: an unknown header parameter that is not listed in crit is ignored",
            ["crit"],
        ),
        (
            "accept-marker-signed-and-in-header",
            record(seal(build(two_hop(headers={"X-Agent-Id": "agent:planner"})))),
            a,
            ok,
            "control: the agent marks itself in the signed token; a header copy changes nothing",
            ["signed-header"],
        ),
        (
            "accept-non-ascii-subject",
            record(seal(build(two_hop(), subject="user:zoë@example.com"))),
            a,
            ok,
            "control: a subject outside ASCII signs and links under RFC 8785",
            ["nesting"],
        ),
        (
            "contract-id-missing",
            record(seal(build(two_hop())), contract=None),
            r,
            "contract_id_missing",
            "the record names no contract",
            [],
        ),
        (
            "contract-id-unknown",
            record(seal(build(two_hop())), contract=reader.CONTRACT_ID[:-1] + "x"),
            r,
            "contract_id_unknown",
            "the record names another contract",
            [],
        ),
        (
            "token-protocol-unknown",
            record(_protocol_unknown()),
            r,
            "record_malformed",
            "the gateway's sent token names a protocol this contract does not read",
            [],
        ),
        (
            "writer-not-in-trust-bundle",
            record(
                _unregistered(
                    build(
                        [hop("agent:unregistered", "gateway:edge"), hop("gateway:edge", RESOURCE)]
                    )
                )
            ),
            r,
            "statement_writer_unknown",
            "the first hop's writer is not in the trust bundle",
            [],
        ),
        (
            "signature-forged",
            record(_edit_after_seal(build(two_hop()), _forge)),
            r,
            "statement_signature_invalid",
            "the planner's statement is edited after it was signed",
            [],
        ),
        (
            "signature-swapped-key",
            record(seal(build(two_hop()), signers={1: "agent:intruder"})),
            r,
            "statement_signature_invalid",
            "the planner's statement is signed with another writer's key",
            [],
        ),
        (
            "statement-dropped-from-chain",
            record(_drop_gateway(build(FOUR_HOP))),
            r,
            "hop_link_broken",
            "the gateway's statement is removed from a four-hop chain",
            ["history"],
        ),
        (
            "hop-replayed-from-another-chain",
            record(_replay(build(two_hop()))),
            r,
            "hop_link_broken",
            "the gateway's statement is replayed from an earlier chain with the same principals",
            ["history"],
        ),
        (
            "audience-mismatch",
            record(_wrong_audience(build(two_hop()))),
            r,
            "audience_mismatch",
            "the planner sent to another gateway than the one that wrote the next hop",
            [],
        ),
        (
            "changed-in-transit",
            record(_changed_in_transit(build(FOUR_HOP))),
            r,
            "received_not_sent",
            "the gateway received a token without the planner and forwarded what it received",
            ["history"],
        ),
        (
            "unknown-critical-attribute-ignored",
            record(seal(build(two_hop(), origin_header=crit_header))),
            r,
            "unknown_critical_attribute_ignored",
            "the planner acted on a token whose crit lists a parameter it does not understand",
            ["crit"],
        ),
        (
            "deferred-dispatch-after-expiry",
            record(seal(build(deferred_hops(7300)))),
            r,
            "principals_expired_at_use",
            "the queue dispatches the stored principals after their exp",
            [],
        ),
        (
            "marker-only-in-unsigned-header",
            record(
                seal(
                    build(
                        two_hop(
                            rewrite=lambda p: (p[0], ()), headers={"X-Agent-Id": "agent:planner"}
                        )
                    )
                )
            ),
            r,
            "marker_unsigned",
            "the planner names itself in an unsigned header and sends the user alone in the token",
            ["signed-header", "audit"],
        ),
        (
            "deferred-dispatch-without-stored-principals",
            record(seal(build(deferred_hops(620, rewrite=lambda p: ("service:job-runner", ()))))),
            r,
            "deferred_dispatch_without_stored_principals",
            "the queue dispatches as its own service account instead of the stored principals",
            ["history"],
        ),
        (
            "subject-replaced",
            record(
                seal(
                    build(
                        [
                            hop("agent:planner", "gateway:edge"),
                            hop(
                                "gateway:edge",
                                RESOURCE,
                                rewrite=lambda p: ("user:bob@example.com", p[1]),
                            ),
                        ]
                    )
                )
            ),
            r,
            "subject_replaced",
            "the gateway forwards the actors for another user",
            ["distinct"],
        ),
        (
            "downgraded-to-user-alone",
            record(seal(build(four_hop(2, lambda p: (p[0], ()))))),
            r,
            "downgraded_to_user_alone",
            "the gateway receives two agents and forwards the user alone",
            ["distinct", "truncation"],
        ),
        (
            "chain-truncated-well-formed",
            record(seal(build(four_hop(3, lambda p: (p[0], p[1][-1:]))))),
            r,
            "chain_truncated",
            "the last agent sends a well-formed token naming only itself",
            ["truncation", "history"],
        ),
        (
            "own-marker-stripped",
            record(seal(build(four_hop(1, lambda p: (p[0], p[1][:-1]))))),
            r,
            "marker_stripped",
            "the researcher acts and forwards the planner's marker without its own",
            ["append", "nesting"],
        ),
        (
            "agent-replaced-by-gateway",
            record(
                seal(
                    build(
                        two_hop()[:1]
                        + [
                            hop(
                                "gateway:edge",
                                RESOURCE,
                                rewrite=lambda p: (p[0], ("gateway:edge",)),
                            )
                        ]
                    )
                )
            ),
            r,
            "agent_replaced",
            "the gateway puts its own identity where the planner was",
            ["distinct", "nesting"],
        ),
        (
            "actor-order-reversed-by-bridge",
            record(seal(build(bridge_hops(_swap_actors), origin_protocol="a2a-actor-chain"))),
            r,
            "actor_order_changed",
            "the bridge nests the A2A list outermost-first, reversing it",
            ["nesting", "append"],
        ),
        (
            "actor-inserted",
            record(
                seal(
                    build(
                        two_hop()[:1]
                        + [
                            hop(
                                "gateway:edge",
                                RESOURCE,
                                rewrite=lambda p: (p[0], (*p[1], "agent:writer")),
                            )
                        ]
                    )
                )
            ),
            r,
            "actor_inserted",
            "the gateway adds an agent it did not receive",
            ["history"],
        ),
        (
            "user-alone-without-presence",
            record(seal(build([hop("gateway:edge", RESOURCE)], human=False))),
            r,
            "user_alone_without_human_evidence",
            "the chain delivers the user alone and the origin carries no user-presence evidence",
            ["distinct"],
        ),
    ]


def _protocol_unknown() -> list[dict[str, Any]]:
    entries = build(two_hop())
    entries[2]["statement"]["sent"]["protocol"] = "saml2"
    return seal(entries)


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
    """Write TRUST.json, every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    trust_bytes = _json(trust())
    (root / "TRUST.json").write_bytes(trust_bytes)
    bundle = trust()
    entries = []
    for name, body, decision, reason, edit, anchors in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"record.json": _json(body)}
        for index, item in enumerate(body["statements"]):
            files[f"signing-input-{index}.jcs"] = reader.signing_input(item["statement"])
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json", root / "TRUST.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "anchors": [
                    {"quote": ANCHORS[k][2], "section": ANCHORS[k][1], "source": ANCHORS[k][0]}
                    for k in anchors
                ],
                "edit": edit,
                "expected": expected,
                "files": {k: _sha(v) for k, v in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(body, bundle),
            }
        )
    words = [e["expected"]["decision"] for e in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {w: words.count(w) for w in sorted(set(words))},
        "sources": SOURCES,
        "suite": SUITE,
        "synthetic": True,
        "trustSha256": _sha(trust_bytes),
        "verifierContract": (
            "verifier record.json --trust TRUST.json --json; exit 0 accept, 1 reject"
        ),
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
