"""Build the assertion-grade cases byte-identically.

Each case is one record bundle a relying party receives and the trust it pins. A bundle carries
assertions about a tenant's agent, about a gateway's own decision, or a counterparty's receipt; a
log the assertions are committed to (RFC 9162 tree, C2SP checkpoints with Ed25519 log signatures
and cosignature/v1 witness lines); and the evidence each route rests on: a counterparty key binding
(a domain key document under a certificate chain, a naming log entry made under domain-control
validation, or a rail operator's listing), a (permit id, stage) receipt map proof, an enclave
quote, a notary statement, a hardware module's signed per-key usage log, a journal quote over the
verifier's challenge, a tenant agent's proof-of-possession signature.

The expected answer of every case is written here by hand, per assertion: the grade, the route,
whom it is independent of, the custody holder, the submission boundary, the trust anchors, the
witnesses that count (their coverage interval is the first and last cosignature time this file
gives them), the properties, the label and the qualifier. The reader never writes an expectation.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild every signature. They
are test keys and protect nothing. The attestation root is a corpus test root, so every TEE fixture
here prints "staging-grade"; fixtures under a vendor's production root come from real hardware and
are not in a corpus anyone can regenerate.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402

SUITE = "assertion-grade/v1"
SEED_PREFIX = "agent-evidence-vectors/assertion-grade/v1/"
T0 = 1795305600  # 2026-11-22T00:00:00Z
YEAR = 31536000
TENANT, US, TARGET = "tenant:northwind", "gateway:relay-1", "pay.example"
HOSTED_LOG, SELF_LOG = "log.relay.example/northwind", "log.northwind.example/journal"
MAP_KEY_DOMAIN = b"agent-evidence-receipt-map/v1 key"
MAP_COMMITMENT = "agent-evidence-receipt-map-commitment/v1"
ALPHA, BETA, OLD = "witness.alpha.example", "witness.beta.example", "witness.old.example"
CUSTOMER, OURS, PEER = "witness.northwind.example", "witness.relay.example", "witness.pay.example"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def pub(label: str) -> bytes:
    h = hashlib.sha512(_seed(label)).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return bytes(rail._pt_compress(rail._pt_mul(a, rail._B)))


def sign(label: str, message: bytes) -> bytes:
    return bytes(rail.ed25519_sign(_seed(label), message))


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def jcs(value: Any) -> bytes:
    return bytes(rail.jcs_dumps(value))


def kid(label: str) -> str:
    return sha(pub(label)).hex()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def signed(label: str, body: dict[str, Any]) -> str:
    return b64(sign(label, jcs(body)))


# --- RFC 9162 ------------------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return sha(b"\x00" + data)


def node(left: bytes, right: bytes) -> bytes:
    return sha(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node(mth(leaves[:k]), mth(leaves[k:]))


def path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return [*path(m, leaves[:k]), mth(leaves[k:])]
    return [*path(m - k, leaves[k:]), mth(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], whole: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if whole else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], whole), mth(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), mth(leaves[:k])]


def consistency(m: int, leaves: list[bytes]) -> list[bytes]:
    return _subproof(m, leaves, True)


# --- receipt map ---------------------------------------------------------------------------------


def _u16(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def map_key(issuer_pub: bytes, permit: str, stage: str) -> bytes:
    return sha(MAP_KEY_DOMAIN + sha(issuer_pub) + _u16(permit.encode()) + _u16(stage.encode()))


def map_entry(key: bytes, index: int, leaf: bytes) -> bytes:
    return sha(b"\x00" + key + index.to_bytes(8, "big") + leaf)


def _bit(key: bytes, depth: int) -> int:
    return (int.from_bytes(key, "big") >> (255 - depth)) & 1


def _smt(entries: list[tuple[bytes, int, bytes]], depth: int) -> bytes:
    if not entries:
        return bytes(32)
    if len(entries) == 1:
        return map_entry(*entries[0])
    left = [e for e in entries if not _bit(e[0], depth)]
    right = [e for e in entries if _bit(e[0], depth)]
    return node(_smt(left, depth + 1), _smt(right, depth + 1))


def smt_prove(entries: list[tuple[bytes, int, bytes]], key: bytes) -> dict[str, Any]:
    siblings: list[str | None] = []
    cur, depth = entries, 0
    while len(cur) > 1:
        left = [e for e in cur if not _bit(e[0], depth)]
        right = [e for e in cur if _bit(e[0], depth)]
        other, cur = (left, right) if _bit(key, depth) else (right, left)
        h = _smt(other, depth + 1)
        siblings.append(None if h == bytes(32) else b64(h))
        depth += 1
    terminal = (
        None
        if not cur
        else {"index": cur[0][1], "key": cur[0][0].hex(), "leafHash": cur[0][2].hex()}
    )
    return {"key": key.hex(), "siblings": siblings, "terminal": terminal}


# --- C2SP notes ----------------------------------------------------------------------------------


def key_hash(name: str, sig_type: int, key: bytes) -> bytes:
    return sha(name.encode() + b"\n" + bytes([sig_type]) + key)[:4]


@dataclass
class Cosig:
    witness: str
    at: int
    signer: str = ""  # seed label that signs; defaults to the witness's own key
    keyhash_of: str = ""  # seed label whose key hash the line names; defaults to the signer


def note(origin: str, size: int, root: bytes, log_signer: str, cosigs: list[Cosig]) -> str:
    body = f"{origin}\n{size}\n{b64(root)}\n"
    log_sig = key_hash(origin, 0x01, pub(log_signer)) + sign(log_signer, body.encode())
    lines = [f"— {origin} {b64(log_sig)}"]
    for c in cosigs:
        signer = c.signer or c.witness
        named = c.keyhash_of or signer
        msg = f"cosignature/v1\ntime {c.at}\n".encode() + body.encode()
        blob = key_hash(c.witness, 0x04, pub(named)) + c.at.to_bytes(8, "big") + sign(signer, msg)
        lines.append(f"— {c.witness} {b64(blob)}")
    return body + "\n" + "\n".join(lines) + "\n"


# --- the trust a relying party pins ---------------------------------------------------------------


def _witness(label: str, operator: str, listing: str, valid_to: int = T0 + YEAR) -> dict[str, Any]:
    return {
        "key": pub(label).hex(),
        "list": listing,
        "operator": operator,
        "valid_from": T0 - YEAR,
        "valid_to": valid_to,
    }


def _record(label: str, operator: str, role: str, root: str) -> tuple[str, dict[str, Any]]:
    return kid(label), {"key": pub(label).hex(), "operator": operator, "role": role, "root": root}


MEASURE_DECISION = sha(b"decision-path/v1").hex()
MEASURE_JOURNAL = sha(b"journal/v1").hex()
CHALLENGE = sha(b"verifier challenge 1").hex()


def base_trust() -> dict[str, Any]:
    records = dict(
        [
            _record("gateway", "us", "gateway", "ours"),
            _record("tenant-byok", "tenant", "tenant", "customer-custody"),
            _record("tenant-our-root", "tenant", "tenant", "ours"),
            _record("tenant-journal", "tenant", "tenant", "customer-custody"),
            _record("notary", "external", "notary", "notary-own"),
            _record("notary-custody", "external", "notary", "customer-custody"),
            _record("notary-tenant", "tenant", "notary", "notary-own"),
        ]
    )
    return {
        "agent_keys": {kid("agent-1"): {"key": pub("agent-1").hex()}},
        "attestation_roots": {
            "tee-vendor-test": {
                "class": "corpus-test",
                "key": pub("tee-vendor-test").hex(),
                "vendor": "corpus test root",
            }
        },
        "challenge": CHALLENGE,
        "hsm_devices": {
            "hsm-1": {
                "audit_key": pub("hsm-1-audit").hex(),
                "model": "nShield 5c",
                "per_key_usage_logging": True,
            },
            "hsm-2": {
                "audit_key": pub("hsm-2-audit").hex(),
                "model": "Luna 7",
                "per_key_usage_logging": False,
            },
        },
        "logs": {
            HOSTED_LOG: {"key": pub("log-hosted").hex(), "operator": "us"},
            SELF_LOG: {"key": pub("log-self").hex(), "operator": "tenant"},
        },
        "measurements": {"decision_path": [MEASURE_DECISION], "journal": [MEASURE_JOURNAL]},
        "naming_logs": {"names.example/log": {"key": pub("naming-log").hex()}},
        "parties": {"counterparty": TARGET, "tenant": TENANT, "us": US},
        "rail_operators": {"rail.example": {"key": pub("rail-operator").hex()}},
        "receipt_windows": {"accept": 300, "execute": 300, "final": 2592000, "settle": 172800},
        "record_keys": records,
        "schema_version": "assertion-grade-trust/v1",
        "web_roots": {"web-root-1": pub("web-root-1").hex()},
        "witnesses": {
            ALPHA: _witness(ALPHA, "external", "production"),
            BETA: _witness(BETA, "external", "staging"),
            OLD: _witness(OLD, "external", "production", valid_to=T0 + 100),
            CUSTOMER: _witness(CUSTOMER, "tenant", "production"),
            OURS: _witness(OURS, "us", "production"),
            PEER: _witness(PEER, "counterparty", "production"),
        },
    }


# --- statements ----------------------------------------------------------------------------------

REQUEST = {
    "agent": "agent:billing-7",
    "body_sha256": sha(b"amount=4200&currency=USD").hex(),
    "method": "POST",
    "nonce": "n-7f3a",
    "path": "/v1/payments",
}
REQUEST_COMMITMENT = sha(jcs({"request": REQUEST, "salt": "s-91c2"})).hex()
STAMP_DIGEST = sha(b"agent stamp agent:billing-7 permit p-1001").hex()


def event(**extra: Any) -> dict[str, Any]:
    return {
        "action": "tool.call",
        "agent": "agent:billing-7",
        "at": T0 + 90,
        "decided": "allow",
        "kind": "agent-action",
        "request_commitment": REQUEST_COMMITMENT,
        "tenant": TENANT,
        "tool": "payments.create",
        **extra,
    }


def decision(**extra: Any) -> dict[str, Any]:
    return {
        "at": T0 + 91,
        "decision": "deny",
        "kind": "gateway-decision",
        "request_commitment": REQUEST_COMMITMENT,
        "rule": "payments.limit.daily",
        "tenant": TENANT,
        **extra,
    }


def notarized(full: bool = True) -> dict[str, Any]:
    st = {
        "boundary": "submission",
        "kind": "notarized-request",
        "received_at": T0 + 89,
        "request_commitment": sha(jcs(REQUEST)).hex(),
        "tenant": TENANT,
    }
    if full:
        st["request"] = REQUEST
    return st


def receipt(
    signer: str, permit: str = "p-1001", stage: str = "execute", drop: str = "", **extra: Any
) -> dict[str, Any]:
    st = {
        "actor_stamp_digest": STAMP_DIGEST,
        "key_id": kid(signer),
        "kind": "counterparty-receipt",
        "outcome": "executed",
        "permit_id": permit,
        "request_commitment": REQUEST_COMMITMENT,
        "signed_at": T0 + 100,
        "stage": stage,
        "target_id": TARGET,
        **extra,
    }
    st.pop(drop, None)
    return st


# --- counterparty key bindings -------------------------------------------------------------------


def _cert(subject: str, key_label: str, issuer: str, issuer_label: str) -> dict[str, Any]:
    body = {
        "issuer": issuer,
        "key": pub(key_label).hex(),
        "not_after": T0 + YEAR,
        "not_before": T0 - YEAR,
        "subject": subject,
    }
    return {**body, "sig": signed(issuer_label, body)}


def domain_binding(
    key_label: str, not_after: int = T0 + 30 * 86400, root_label: str = "web-root-1"
) -> dict:
    entry = {"key": pub(key_label).hex(), "not_after": not_after, "not_before": T0 - 86400}
    doc = {"domain": TARGET, "keys": [entry]}
    chain = [
        _cert(TARGET, "pay-tls", "ca.example", "ca-intermediate"),
        _cert("ca.example", "ca-intermediate", "web-root-1", root_label),
    ]
    return {
        "chain": chain,
        "document": doc,
        "document_sig": signed("pay-tls", doc),
        "key": entry,
        "kind": "domain-document",
    }


def naming_binding(key_label: str) -> dict[str, Any]:
    entry = {
        "key": pub(key_label).hex(),
        "name": TARGET,
        "not_after": T0 + 30 * 86400,
        "not_before": T0 - 86400,
        "validation": "domain-control",
    }
    leaves = [
        leaf_hash(jcs({"name": "other.example"})),
        leaf_hash(jcs(entry)),
        leaf_hash(jcs({"name": "x"})),
    ]
    return {
        "checkpoint": note("names.example/log", 3, mth(leaves), "naming-log", []),
        "entry": entry,
        "inclusion": [b64(h) for h in path(1, leaves)],
        "kind": "naming-log",
        "leaf_index": 1,
        "origin": "names.example/log",
    }


def rail_binding(key_label: str) -> dict[str, Any]:
    listing = {
        "key": pub(key_label).hex(),
        "not_after": T0 + 30 * 86400,
        "not_before": T0 - 86400,
        "target": TARGET,
    }
    return {
        "kind": "rail-operator",
        "listing": listing,
        "rail": "rail.example",
        "sig": signed("rail-operator", listing),
    }


# --- one assertion and one case ------------------------------------------------------------------


@dataclass
class Spec:
    id: str
    about: str
    signer: str
    statement: dict[str, Any]
    claim: dict[str, Any]
    expect: dict[str, Any]
    evidence: dict[str, Any] = field(default_factory=dict)
    logged: bool = True
    checkpoint: int = 0
    tamper: dict[str, Any] = field(default_factory=dict)  # statement fields changed after signing
    receipt_map: bool = False
    hsm: dict[str, Any] | None = None  # {"device", "seq0", "reset_at", "hidden"}
    journal: dict[str, Any] | None = None  # {"nonce", "head"}
    pinned_key: bool = True


EXPECT_KEYS = (
    "grade",
    "route",
    "independentOf",
    "custody",
    "boundary",
    "witnesses",
    "anchors",
    "properties",
    "label",
    "qualifier",
)


def expect(
    grade: str,
    route: str,
    independent: list[str],
    custody: str,
    boundary: str,
    witnesses: list[str],
    anchors: list[str] | None = None,
    properties: list[str] | None = None,
    label: str = "",
    qualifier: str = "",
) -> dict[str, Any]:
    return {
        "anchors": anchors or [],
        "boundary": boundary,
        "custody": custody,
        "grade": grade,
        "independentOf": independent,
        "label": label,
        "properties": properties or [],
        "qualifier": qualifier,
        "route": route,
        "witnesses": witnesses,
    }


NONE = expect("none", "none", [], "", "", [])


@dataclass
class Case:
    id: str
    change: str
    specs: list[Spec]
    cosigs: list[list[Cosig]]  # per checkpoint
    sizes: list[int] | None = None  # checkpoint sizes; None = one checkpoint over every leaf
    decision: str = "accepted"
    reason: str = "grades_derived"
    pairs_with: str = ""
    log: str = HOSTED_LOG
    trust_edit: Callable[[dict[str, Any]], None] | None = None
    split_view: bool = False
    log_signer: str = ""


def _log_label(origin: str) -> str:
    return "log-hosted" if origin == HOSTED_LOG else "log-self"


Entry = tuple[bytes, int, bytes]


def _assertion(spec: Spec) -> dict[str, Any]:
    """The assertion as the bundle carries it, signed before any tamper edit."""
    a: dict[str, Any] = {
        "about": spec.about,
        "claim": spec.claim,
        "evidence": copy.deepcopy(spec.evidence),
        "id": spec.id,
        "sig": signed(spec.signer, spec.statement),
        "statement": {**spec.statement, **spec.tamper},
    }
    if spec.pinned_key and spec.about != "counterparty" and "tee_decision" not in spec.evidence:
        a["key_id"] = kid(spec.signer)
    return a


@dataclass
class Tree:
    """The log's leaves while a case is built, and the receipts its map holds."""

    leaves: list[bytes] = field(default_factory=list)
    index_of: dict[str, int] = field(default_factory=dict)
    receipts: list[Entry] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    commit_index: int | None = None

    def add(self, spec: Spec, a: dict[str, Any]) -> None:
        if not spec.logged:
            return
        data = jcs({"key_id": kid(spec.signer), "sig": a["sig"], "statement": spec.statement})
        self.index_of[spec.id] = len(self.leaves)
        self.leaves.append(leaf_hash(data))
        if spec.receipt_map:
            st = spec.statement
            key = map_key(pub(spec.signer), st["permit_id"], st["stage"])
            self.receipts.append((key, self.index_of[spec.id], self.leaves[-1]))

    def close(self) -> None:
        """Commit the map root (the first receipt for a key wins) and a padding leaf."""
        first: dict[bytes, Entry] = {}
        for entry in self.receipts:
            first.setdefault(entry[0], entry)
        self.entries = sorted(first.values(), key=lambda e: e[0])
        if self.receipts:
            self.commit_index = len(self.leaves)
            root = _smt(self.entries, 0).hex()
            self.leaves.append(leaf_hash(jcs({"format": MAP_COMMITMENT, "root": root})))
        self.leaves.append(leaf_hash(jcs({"kind": "padding", "n": 1})))

    def proof(self, index: int, size: int) -> list[str]:
        return [b64(h) for h in path(index, self.leaves[:size])]


def _log_doc(case: Case, tree: Tree, sizes: list[int]) -> dict[str, Any]:
    log_label = case.log_signer or _log_label(case.log)
    notes = [
        note(case.log, size, mth(tree.leaves[:size]), log_label, cosigs)
        for size, cosigs in zip(sizes, case.cosigs, strict=True)
    ]
    proofs = [
        [b64(h) for h in consistency(a, tree.leaves[:b])] if a <= b else []
        for a, b in zip(sizes, sizes[1:], strict=False)
    ]
    if case.split_view:
        forked = [*tree.leaves[: sizes[0] - 1], leaf_hash(b"rewritten history")]
        notes.append(note(case.log, sizes[0], mth(forked), log_label, case.cosigs[0]))
        proofs.append([])
    return {"checkpoints": notes, "consistency": proofs, "origin": case.log}


def _map_evidence(spec: Spec, tree: Tree, size: int) -> dict[str, Any]:
    st = spec.statement
    key = map_key(pub(spec.signer), st["permit_id"], st["stage"])
    assert tree.commit_index is not None
    return {
        "commitment": {
            "inclusion": tree.proof(tree.commit_index, size),
            "leaf_index": tree.commit_index,
        },
        "proof": smt_prove(tree.entries, key),
        "root": _smt(tree.entries, 0).hex(),
    }


def _journal_evidence(spec: Spec, tree: Tree, size: int) -> dict[str, Any]:
    journal = spec.journal or {}
    q = {
        "journal_head": (journal.get("head") or mth(tree.leaves[:size])).hex(),
        "journal_key_id": kid(spec.signer),
        "measurement": MEASURE_JOURNAL,
        "nonce": journal.get("nonce", CHALLENGE),
        "root": "tee-vendor-test",
        "tree_size": size,
    }
    return {"quote": q, "sig": signed("tee-vendor-test", q)}


def _attach(spec: Spec, a: dict[str, Any], tree: Tree, sizes: list[int]) -> None:
    """The log reference and the evidence that depends on the built log."""
    if not spec.logged:
        return
    i, size = tree.index_of[spec.id], sizes[spec.checkpoint]
    a["log"] = {"checkpoint": spec.checkpoint, "inclusion": tree.proof(i, size), "leaf_index": i}
    if spec.receipt_map and tree.commit_index is not None:
        a["evidence"]["map"] = _map_evidence(spec, tree, size)
    if spec.hsm is not None:
        a["evidence"]["hsm"] = _hsm(spec, tree.leaves, i, size)
    if spec.journal is not None:
        a["evidence"]["tee_journal"] = _journal_evidence(spec, tree, size)


def _expected(case: Case, trust: dict[str, Any], sizes: list[int]) -> list[dict[str, Any]]:
    times: dict[str, tuple[int, int]] = {}
    for cosigs in case.cosigs[: len(sizes)]:
        for c in cosigs:
            lo, hi = times.get(c.witness, (c.at, c.at))
            times[c.witness] = (min(lo, c.at), max(hi, c.at))
    out = []
    for spec in case.specs:
        e = dict(spec.expect)
        e["witnesses"] = [
            {
                "from": times[w][0],
                "name": w,
                "operator": trust["witnesses"][w]["operator"],
                "to": times[w][1],
            }
            for w in sorted(spec.expect["witnesses"])
        ]
        out.append({"id": spec.id, **{k: e[k] for k in EXPECT_KEYS}})
    return out


def build(case: Case) -> tuple[dict[str, Any], dict[str, Any]]:
    """The case file and the expected answer."""
    trust = base_trust()
    if case.trust_edit:
        case.trust_edit(trust)
    tree = Tree()
    built = []
    for spec in case.specs:
        a = _assertion(spec)
        tree.add(spec, a)
        built.append(a)
    tree.close()
    sizes = case.sizes or [len(tree.leaves)]
    for spec, a in zip(case.specs, built, strict=True):
        _attach(spec, a, tree, sizes)
    bundle = {
        "assertions": built,
        "format": "assertion-grade-bundle/v1",
        "log": _log_doc(case, tree, sizes),
    }
    doc = {"bundle": bundle, "schema_version": "assertion-grade-case/v1", "trust": trust}
    expected = {
        "assertions": _expected(case, trust, sizes),
        "decision": case.decision,
        "reason": case.reason,
    }
    return doc, expected


def _hsm(spec: Spec, leaves: list[bytes], index: int, size: int) -> dict[str, Any]:
    """A module's signed per-key usage log around the assertion's signature.

    ``reset``: the counter restarts (the partition was re-initialised). ``hidden``: the log
    shows a second signature of the key whose leaf the witnessed log does not hold."""
    h = spec.hsm or {}
    entries = [
        {"key_id": kid("other-key"), "leaf_hash": sha(b"other").hex(), "seq": 6999},
        {"key_id": kid(spec.signer), "leaf_hash": leaves[index].hex(), "seq": 7000},
    ]
    accounted = [{"inclusion": [b64(p) for p in path(index, leaves[:size])], "leaf_index": index}]
    if h.get("hidden"):
        entries.append(
            {
                "key_id": kid(spec.signer),
                "leaf_hash": sha(b"a signature never logged").hex(),
                "seq": 7001,
            }
        )
        accounted.append(
            {"inclusion": [b64(p) for p in path(index + 1, leaves[:size])], "leaf_index": index + 1}
        )
    if h.get("reset"):
        entries.append(
            {"key_id": kid("other-key"), "leaf_hash": sha(b"after re-init").hex(), "seq": 0}
        )
    device = h.get("device", "hsm-1")
    audit = [{"entry": e, "sig": signed(f"{device}-audit", e)} for e in entries]
    return {"accounted": accounted, "audit": audit, "device": device}


# --- the cases -----------------------------------------------------------------------------------

AT = T0 + 160
W_ALPHA = [Cosig(ALPHA, AT)]
W_ALPHA_CUSTOMER = [Cosig(ALPHA, AT), Cosig(CUSTOMER, AT + 2)]


def _hosted(
    claim_grade: str = "I",
    claim_route: str = "I-HOSTED-WITNESS-QUORUM",
    witnesses: list[str] | None = None,
    grade: str = "I",
    route: str = "I-HOSTED-WITNESS-QUORUM",
    independent: list[str] | None = None,
    props: list[str] | None = None,
    qualifier: str = "",
    **spec: Any,
) -> Spec:
    st = spec.pop("statement", event())
    return Spec(
        "event",
        "tenant",
        spec.pop("signer", "gateway"),
        st,
        {"grade": claim_grade, "route": claim_route},
        expect(
            grade,
            route,
            ["tenant"] if independent is None else independent,
            "us",
            "gateway ingress",
            [ALPHA] if witnesses is None else witnesses,
            properties=props,
            qualifier=qualifier,
        ),
        **spec,
    )


def _receipt_spec(
    binding: dict[str, Any],
    anchors: list[str],
    signer: str = "pay-receipts",
    claim: str = "I",
    grade: str = "I",
    route: str = "I-COUNTERPARTY",
    label: str = "",
    witnesses: list[str] | None = None,
    receipt_map: bool = True,
    independent: list[str] | None = None,
    statement: dict[str, Any] | None = None,
    aid: str = "receipt",
    **spec: Any,
) -> Spec:
    props = ["counterparty self-attests"] if grade == "I" else []
    return Spec(
        aid,
        "counterparty",
        signer,
        statement or receipt(signer),
        {"grade": claim},
        expect(
            grade,
            route,
            (["tenant"] if grade == "I" else []) if independent is None else independent,
            "counterparty",
            "target",
            witnesses if witnesses is not None else [ALPHA],
            anchors,
            props,
            label,
        ),
        evidence={"binding": binding},
        receipt_map=receipt_map,
        **spec,
    )


def _tee_quote(
    root_signer: str = "tee-vendor-test",
    measurement: str = MEASURE_DECISION,
    channel: str = "attested-tls",
) -> dict[str, Any]:
    q = {
        "channel_termination": channel,
        "enclave_key": pub("enclave").hex(),
        "measurement": measurement,
        "root": "tee-vendor-test",
        "tls_key_sha256": sha(b"enclave tls key").hex(),
    }
    return {"quote": q, "sig": signed(root_signer, q)}


def _tee_spec(
    claim: str = "I",
    grade: str = "I",
    route: str = "I-TEE",
    quote: dict | None = None,
    independent: list[str] | None = None,
    qualifier: str = "staging-grade",
    witnesses: list[str] | None = None,
) -> Spec:
    anchors = ["attestation-root:tee-vendor-test"] if grade != "none" else []
    e = expect(
        grade,
        route,
        (["tenant", "us"] if grade == "I" else []) if independent is None else independent,
        "enclave",
        "enclave channel",
        witnesses if witnesses is not None else [ALPHA],
        anchors,
        qualifier=qualifier,
    )
    if grade == "none":
        e = NONE
    return Spec(
        "decision",
        "gateway",
        "enclave",
        decision(),
        {"grade": claim, "route": "I-TEE"},
        e,
        evidence={"tee_decision": quote or _tee_quote()},
    )


def _notary_spec(
    signer: str = "notary",
    full: bool = True,
    claim: str = "I",
    grade: str = "I",
    route: str = "I-NOTARY",
    custody: str = "external",
) -> Spec:
    return Spec(
        "notarized",
        "tenant",
        signer,
        notarized(full),
        {"grade": claim},
        expect(grade, route, ["tenant", "us"] if grade == "I" else [], custody, "notary", [ALPHA]),
    )


def _byok_spec(
    signer: str = "tenant-byok",
    claim: str = "W+",
    grade: str = "W+",
    route: str = "W+-HSM-STREAM",
    hsm: dict[str, Any] | None = None,
    journal: dict[str, Any] | None = None,
    anchors: list[str] | None = None,
    qualifier: str = "",
) -> Spec:
    if anchors is None:
        anchors = ["hsm:nShield 5c"] if hsm is not None and hsm.get("device") == "hsm-1" else []
    return Spec(
        "tenant-record",
        "tenant",
        signer,
        event(),
        {"grade": claim},
        expect(grade, route, [], "tenant", "tenant signer", [ALPHA], anchors, qualifier=qualifier),
        hsm=hsm,
        journal=journal,
    )


def _gateway_spec(claim: str = "W", pop: bool = True, witnesses: list[str] | None = None) -> Spec:
    evidence = {}
    if pop:
        evidence["pop"] = {
            "agent_key_id": kid("agent-1"),
            "sig": signed("agent-1", {"request_commitment": REQUEST_COMMITMENT}),
        }
    return Spec(
        "decision",
        "gateway",
        "gateway",
        decision(),
        {"grade": claim},
        expect(
            "W",
            "W-WITNESSED",
            [],
            "us",
            "gateway ingress",
            [ALPHA] if witnesses is None else witnesses,
            properties=["mutually signed"] if pop else [],
        ),
        evidence=evidence,
    )


def cases() -> list[Case]:
    return [
        # --- honest fixtures, one per route ------------------------------------------------------
        Case(
            "hosted-external-quorum",
            "control: our gateway key signs the tenant's agent action; an external "
            "production witness cosigns: I, independent of the tenant",
            [_hosted()],
            [W_ALPHA],
        ),
        Case(
            "hosted-staging-witness",
            "control: the only external witness is on the staging list: still I, "
            "printed staging-grade",
            [_hosted(witnesses=[BETA], qualifier="staging-grade")],
            [[Cosig(BETA, AT)]],
        ),
        Case(
            "managed-customer-witness",
            "control: the shipped managed mode, our log with only the tenant's own "
            "witness: W for a third party, independent of us for the tenant",
            [
                _hosted(
                    claim_grade="W",
                    claim_route="W-MANAGED-CUSTOMER-WITNESS",
                    witnesses=[CUSTOMER],
                    grade="W",
                    route="W-MANAGED-CUSTOMER-WITNESS",
                    independent=["us"],
                    props=["customer-held witness in quorum"],
                )
            ],
            [[Cosig(CUSTOMER, AT)]],
        ),
        Case(
            "managed-plus-external",
            "control: managed mode whose quorum also holds an external witness: I",
            [_hosted(witnesses=[ALPHA, CUSTOMER], props=["customer-held witness in quorum"])],
            [W_ALPHA_CUSTOMER],
        ),
        Case(
            "notary-saw-request",
            "control: an external notary received the request itself at the submission "
            "boundary and signed what it saw: I-NOTARY",
            [_notary_spec()],
            [W_ALPHA],
            log=SELF_LOG,
        ),
        Case(
            "tee-decision-path",
            "control: the decision path in a measured enclave that terminates the agent's "
            "channel, under the corpus test root: I-TEE, staging-grade",
            [_tee_spec()],
            [W_ALPHA],
            log=SELF_LOG,
        ),
        Case(
            "counterparty-domain-document",
            "control: a receipt under a key in the target's own domain key "
            "document, certificate chain to a pinned web root, map proof: I-COUNTERPARTY",
            [_receipt_spec(domain_binding("pay-receipts"), ["web-root:web-root-1"])],
            [W_ALPHA],
        ),
        Case(
            "counterparty-naming-log",
            "control: the receipt key from a naming log entry made under domain-control validation",
            [_receipt_spec(naming_binding("pay-receipts"), ["naming-log:names.example/log"])],
            [W_ALPHA],
        ),
        Case(
            "counterparty-rail-operator",
            "control: the receipt key from a rail operator's signed listing",
            [_receipt_spec(rail_binding("pay-receipts"), ["rail:rail.example"])],
            [W_ALPHA],
        ),
        Case(
            "hsm-stream",
            "control: a tenant-custody key on an nShield partition whose signed per-key usage "
            "log accounts for every signature: W+, origin self-attested",
            [_byok_spec(hsm={"device": "hsm-1"})],
            [W_ALPHA],
        ),
        Case(
            "tee-journal",
            "control: a tenant journal key quoted by a measured journal over the verifier's own "
            "challenge and the witnessed head: W+-TEE-JOURNAL, staging-grade",
            [
                _byok_spec(
                    signer="tenant-journal",
                    route="W+-TEE-JOURNAL",
                    journal={},
                    anchors=["attestation-root:tee-vendor-test"],
                    qualifier="staging-grade",
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
        ),
        Case(
            "gateway-decision-mutually-signed",
            "control: our gateway's own deny decision, the agent's "
            "proof-of-possession signature over the request beside it: W, printed mutually signed",
            [_gateway_spec()],
            [W_ALPHA],
        ),
        Case(
            "byok-witnessed",
            "control: a tenant-custody key with no key-use counter, externally witnessed: W",
            [_byok_spec(claim="W", grade="W", route="W-WITNESSED")],
            [W_ALPHA],
        ),
        Case(
            "local-only",
            "control: a signed assertion never committed to a log: S",
            [
                Spec(
                    "event",
                    "tenant",
                    "gateway",
                    event(),
                    {"grade": "S"},
                    expect("S", "S-LOCAL", [], "us", "gateway ingress", []),
                    logged=False,
                )
            ],
            [W_ALPHA],
        ),
        Case(
            "mixed-bundle",
            "control: one bundle, three grades: the tenant event I, our gateway decision W, "
            "an unlogged note S",
            [
                _hosted(),
                _gateway_spec(pop=False),
                Spec(
                    "note",
                    "tenant",
                    "gateway",
                    event(at=T0 + 95, decided="observe"),
                    {"grade": "S"},
                    expect("S", "S-LOCAL", [], "us", "gateway ingress", []),
                    logged=False,
                ),
            ],
            [W_ALPHA],
        ),
        Case(
            "coverage-two-checkpoints",
            "control: the witness cosigned the assertion's checkpoint and a later "
            "consistent one; the claimed coverage is the computed interval",
            [_with_claim(_hosted(), coverage={"from": AT, "to": AT + 600, "witness": ALPHA})],
            [[Cosig(ALPHA, AT)], [Cosig(ALPHA, AT + 600)]],
            sizes=[1, 2],
        ),
    ]


def _with_claim(spec: Spec, **claim: Any) -> Spec:
    out = copy.deepcopy(spec)
    out.claim = {**out.claim, **claim}
    return out


def attacks() -> list[Case]:
    r = "rejected"
    return [
        Case(
            "forged-witness-cosignature",
            "the external witness line carries the right key hash and a signature by another key",
            [_hosted(grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [[Cosig(ALPHA, AT, signer="mallory", keyhash_of=ALPHA)]],
            decision=r,
            reason="witness_cosignature_invalid",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "swapped-witness-key",
            "the external witness's name, with a key the verifier never pinned",
            [_hosted(grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [[Cosig(ALPHA, AT, signer="mallory", keyhash_of="mallory")]],
            decision=r,
            reason="witness_key_mismatch",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "expired-checkpoint",
            "the only external cosignature is dated after the witness key's pinned validity ends",
            [_hosted(grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [[Cosig(OLD, AT)]],
            decision=r,
            reason="witness_key_expired",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "wrong-tenant",
            "an assertion about another tenant presented to this relying party",
            [
                Spec(
                    "event",
                    "tenant",
                    "gateway",
                    event(tenant="tenant:contoso"),
                    {"grade": "I"},
                    NONE,
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="wrong_tenant",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "w-relabelled-i",
            "managed mode with only the tenant's witness, claimed as I",
            [
                _hosted(
                    witnesses=[CUSTOMER],
                    grade="W",
                    route="W-MANAGED-CUSTOMER-WITNESS",
                    independent=["us"],
                    props=["customer-held witness in quorum"],
                )
            ],
            [[Cosig(CUSTOMER, AT)]],
            decision=r,
            reason="no_external_witness",
            pairs_with="managed-customer-witness",
        ),
        Case(
            "coverage-overclaimed",
            "the claim says the witness covered the record until a time after its last cosignature",
            [_with_claim(_hosted(), coverage={"from": AT, "to": AT + 3600, "witness": ALPHA})],
            [[Cosig(ALPHA, AT)], [Cosig(ALPHA, AT + 600)]],
            sizes=[1, 2],
            decision=r,
            reason="coverage_overclaimed",
            pairs_with="coverage-two-checkpoints",
        ),
        Case(
            "mocked-attestation-chain",
            "an honest-looking enclave quote under the pinned root's name, signed by "
            "a key the verifier never pinned",
            [_tee_spec(grade="none", quote=_tee_quote(root_signer="mallory"))],
            [W_ALPHA],
            decision=r,
            reason="attestation_chain_unverified",
            pairs_with="tee-decision-path",
            log=SELF_LOG,
        ),
        Case(
            "receipt-without-map-proof",
            "a bound, witnessed receipt with no (permit id, stage) map proof, claimed as I",
            [
                _receipt_spec(
                    domain_binding("pay-receipts"),
                    ["web-root:web-root-1"],
                    grade="W",
                    route="W-WITNESSED",
                    receipt_map=False,
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="map_proof_missing",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "tenant-declared-counterparty",
            "the tenant registers its own key as the counterparty's and claims I",
            [
                _receipt_spec(
                    {"key": pub("tenant-fake-target").hex(), "kind": "tenant-declared"},
                    [],
                    signer="tenant-fake-target",
                    grade="W",
                    route="W-WITNESSED",
                    label="tenant-declared counterparty",
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="tenant_declared_counterparty",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-forged-key-document",
            "the key document is signed by a certificate whose chain does not "
            "reach a pinned web root",
            [
                _receipt_spec(
                    domain_binding("pay-receipts", root_label="mallory"),
                    [],
                    grade="W",
                    route="W-WITNESSED",
                    label="unbound counterparty key",
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="counterparty_key_unbound",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-replayed-second-slot",
            "a second receipt for the same (permit id, stage) is logged after "
            "the first; its map proof shows the slot holds the first",
            [
                _receipt_spec(domain_binding("pay-receipts"), ["web-root:web-root-1"], aid="first"),
                _receipt_spec(
                    domain_binding("pay-receipts"),
                    ["web-root:web-root-1"],
                    aid="second",
                    grade="W",
                    route="W-WITNESSED",
                    statement=receipt("pay-receipts", outcome="refused"),
                ),
            ],
            [W_ALPHA],
            decision=r,
            reason="map_proof_mismatch",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-window-exceeded",
            "the receipt reached the log 400 s after it was signed; the execute window is 300 s",
            [
                _receipt_spec(
                    domain_binding("pay-receipts"),
                    ["web-root:web-root-1"],
                    grade="S",
                    route="S-LOCAL",
                    claim="W",
                )
            ],
            [[Cosig(ALPHA, T0 + 500)]],
            decision=r,
            reason="receipt_window_exceeded",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-window-backdated-by-tenant-witness",
            "the tenant's own witness dates its line inside "
            "the window; the external witness, which dates inclusion, cosigned 400 s after signing",
            [
                _receipt_spec(
                    domain_binding("pay-receipts"),
                    ["web-root:web-root-1"],
                    grade="S",
                    route="S-LOCAL",
                    claim="W",
                    witnesses=[ALPHA, CUSTOMER],
                )
            ],
            [[Cosig(CUSTOMER, T0 + 150), Cosig(ALPHA, T0 + 500)]],
            decision=r,
            reason="receipt_window_exceeded",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-key-expired-at-inclusion",
            "the key document lists the receipt key as valid until before "
            "the log included the receipt",
            [
                _receipt_spec(
                    domain_binding("pay-receipts", not_after=T0 + 120),
                    ["web-root:web-root-1"],
                    grade="S",
                    route="S-LOCAL",
                    claim="W",
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="receipt_key_not_valid_at_inclusion",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "receipt-without-actor-stamp",
            "the receipt does not bind the actor stamp digest the target received",
            [
                _receipt_spec(
                    domain_binding("pay-receipts"),
                    ["web-root:web-root-1"],
                    grade="W",
                    route="W-WITNESSED",
                    statement=receipt("pay-receipts", drop="actor_stamp_digest"),
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="receipt_tuple_unbound",
            pairs_with="counterparty-domain-document",
        ),
        Case(
            "rollback",
            "a second checkpoint smaller than the first, cosigned: the history the bundle shows "
            "is not one tree",
            [_hosted(grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [W_ALPHA, [Cosig(ALPHA, AT + 60)]],
            sizes=[2, 1],
            decision=r,
            reason="log_history_inconsistent",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "split-view",
            "two cosigned checkpoints of one size with different roots",
            [_hosted(grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [W_ALPHA],
            split_view=True,
            decision=r,
            reason="log_history_inconsistent",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "notary-saw-commitment-only",
            "the notary signed a request commitment without receiving the request",
            [_notary_spec(full=False, grade="W", route="W-WITNESSED")],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="notary_saw_commitment_only",
            pairs_with="notary-saw-request",
        ),
        Case(
            "notary-customer-custody-root",
            "an external notary whose key chain reaches a customer-custody root",
            [_notary_spec(signer="notary-custody", grade="W", route="W-WITNESSED")],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="customer_custody_root",
            pairs_with="notary-saw-request",
        ),
        Case(
            "notary-run-by-tenant",
            "the notary key is operated by the tenant",
            [
                _notary_spec(
                    signer="notary-tenant", grade="W", route="W-WITNESSED", custody="tenant"
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="notary_not_independent",
            pairs_with="notary-saw-request",
        ),
        Case(
            "hsm-without-usage-log",
            "a Luna partition with no per-key usage log, claimed W+",
            [_byok_spec(hsm={"device": "hsm-2"}, grade="W", route="W-WITNESSED", anchors=[])],
            [W_ALPHA],
            decision=r,
            reason="hsm_counter_not_attested",
            pairs_with="hsm-stream",
        ),
        Case(
            "hsm-partition-reinit",
            "the partition was re-initialised: the usage counter restarts mid-stream",
            [_byok_spec(hsm={"device": "hsm-1", "reset": True}, grade="W", route="W-WITNESSED")],
            [W_ALPHA],
            decision=r,
            reason="hsm_counter_gap",
            pairs_with="hsm-stream",
        ),
        Case(
            "hsm-hidden-signature",
            "the usage log shows a second signature of the key whose leaf the "
            "witnessed log does not hold",
            [_byok_spec(hsm={"device": "hsm-1", "hidden": True}, grade="W", route="W-WITNESSED")],
            [W_ALPHA],
            decision=r,
            reason="hsm_signature_unaccounted",
            pairs_with="hsm-stream",
        ),
        Case(
            "tee-journal-stale-nonce",
            "the journal quote answers another verifier's challenge",
            [
                _byok_spec(
                    signer="tenant-journal",
                    grade="W",
                    route="W-WITNESSED",
                    journal={"nonce": sha(b"someone else's challenge").hex()},
                    anchors=["attestation-root:tee-vendor-test"],
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="stale_challenge",
            pairs_with="tee-journal",
        ),
        Case(
            "tee-journal-wrong-head",
            "the journal quote covers a head other than the witnessed one",
            [
                _byok_spec(
                    signer="tenant-journal",
                    grade="W",
                    route="W-WITNESSED",
                    journal={"head": sha(b"another head")},
                    anchors=["attestation-root:tee-vendor-test"],
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="journal_head_mismatch",
            pairs_with="tee-journal",
        ),
        Case(
            "gateway-mutually-signed-claimed-i",
            "our gateway's own decision with the agent's co-signature, "
            "claimed as I: mutual signing is not a grade",
            [_gateway_spec(claim="I")],
            [W_ALPHA],
            decision=r,
            reason="gateway_self_attested",
            pairs_with="gateway-decision-mutually-signed",
        ),
        Case(
            "tenant-key-under-our-root",
            "a key the tenant operates, certified under our root, claimed I",
            [
                Spec(
                    "tenant-record",
                    "tenant",
                    "tenant-our-root",
                    event(),
                    {"grade": "I"},
                    expect("W", "W-WITNESSED", [], "tenant", "tenant signer", [ALPHA]),
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="content_self_attested",
            pairs_with="byok-witnessed",
        ),
        Case(
            "tee-measurement-unknown",
            "the enclave runs a decision path whose measurement the verifier does not allow",
            [
                _tee_spec(
                    grade="W",
                    route="W-WITNESSED",
                    quote=_tee_quote(measurement="00" * 32),
                    qualifier="",
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="measurement_not_allowed",
            pairs_with="tee-decision-path",
        ),
        Case(
            "tee-channel-on-host",
            "the agent's channel terminates on the host, not in the enclave",
            [
                _tee_spec(
                    grade="W",
                    route="W-WITNESSED",
                    quote=_tee_quote(channel="host-tls"),
                    qualifier="",
                )
            ],
            [W_ALPHA],
            log=SELF_LOG,
            decision=r,
            reason="channel_not_terminated_in_enclave",
            pairs_with="tee-decision-path",
        ),
        Case(
            "unknown-record-key",
            "the assertion names a record key the verifier does not pin",
            [Spec("event", "tenant", "stranger", event(), {"grade": "I"}, NONE)],
            [W_ALPHA],
            decision=r,
            reason="record_key_unknown",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "record-edited-after-signing",
            "the agent action's decision changed after our key signed it",
            [
                Spec(
                    "event",
                    "tenant",
                    "gateway",
                    event(),
                    {"grade": "I"},
                    NONE,
                    tamper={"decided": "deny"},
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="record_signature_invalid",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "log-not-pinned",
            "the assertion's log is one the verifier pins no key for",
            [_hosted(claim_grade="W", grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [W_ALPHA],
            log="log.unknown.example/x",
            log_signer="log-hosted",
            decision=r,
            reason="log_unknown",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "checkpoint-wrong-log-key",
            "the checkpoint is signed by a key other than the log's pinned key",
            [_hosted(claim_grade="W", grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [W_ALPHA],
            log_signer="mallory",
            decision=r,
            reason="checkpoint_signature_invalid",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "inclusion-proof-wrong",
            "the inclusion proof is for another leaf position",
            [_hosted(claim_grade="W", grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [W_ALPHA],
            decision=r,
            reason="inclusion_proof_invalid",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "self-witnessed",
            "the only cosignature is by a witness the record key's operator runs",
            [_hosted(claim_grade="W", grade="S", route="S-LOCAL", independent=[], witnesses=[])],
            [[Cosig(OURS, AT)]],
            decision=r,
            reason="not_witnessed",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "route-relabelled",
            "an I earned by the hosted quorum, claimed as I-TEE",
            [_hosted(claim_route="I-TEE")],
            [W_ALPHA],
            decision=r,
            reason="claim_route_mismatch",
            pairs_with="hosted-external-quorum",
        ),
        Case(
            "byok-without-counter",
            "a tenant key under our root with neither counter route, claimed W+",
            [
                Spec(
                    "tenant-record",
                    "tenant",
                    "tenant-our-root",
                    event(),
                    {"grade": "W+"},
                    expect("W", "W-WITNESSED", [], "tenant", "tenant signer", [ALPHA]),
                )
            ],
            [W_ALPHA],
            decision=r,
            reason="no_key_use_counter",
            pairs_with="byok-witnessed",
        ),
    ]


def all_cases() -> list[Case]:
    return cases() + attacks()


def _post_edit(case: Case, doc: dict[str, Any]) -> None:
    """Edits a case needs after its bytes are built (a proof pointed at the wrong position)."""
    if case.id == "inclusion-proof-wrong":
        doc["bundle"]["assertions"][0]["log"]["leaf_index"] = 1


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for case in all_cases():
        doc, expected = build(case)
        _post_edit(case, doc)
        directory = root / "cases" / case.id
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(doc)
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "change": case.change,
            "expected": expected,
            "files": {"case.json": hashlib.sha256(data).hexdigest()},
            "id": case.id,
            "path": f"cases/{case.id}",
        }
        if case.pairs_with:
            entry["pairsWith"] = case.pairs_with
        entries.append(entry)
    manifest: dict[str, Any] = {
        "corpusDigest": hashlib.sha256(_json(entries)).hexdigest(),
        "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 accepted, 1 rejected",
        "vectors": entries,
    }
    words = [e["expected"]["decision"] for e in entries]
    manifest["counts"] = {w: words.count(w) for w in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries))
    return manifest


def _index(entries: list[dict[str, Any]]) -> bytes:
    """One row per member: its answer and what it changes."""
    lines = [
        "# Assertion grade members",
        "",
        "Generated by `gen_vectors.py`; do not edit. Grades are per assertion, in bundle order.",
        "",
        "| Member | Decision | Reason | Grades | Pairs with | What it is |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        grades = ", ".join(f"{a['id']} {a['grade']}" for a in e["expected"]["assertions"])
        ex = e["expected"]
        lines.append(
            f"| `{e['id']}` | {ex['decision']} | `{ex['reason']}` | {grades} | "
            f"{e.get('pairsWith', '')} | {e['change']} |"
        )
    return ("\n".join(lines) + "\n").encode()


if __name__ == "__main__":
    generate()
