"""Grade every assertion of a record bundle by who could have written its content.

A record bundle carries several assertions: what a tenant's agent did, what a gateway decided,
what a counterparty acknowledged. One bundle can mix grades, so the grade is derived per
assertion, from what the bundle proves against what the relying party pins, and never from what
the producer says it is. Each grade names whom the assertion is independent OF. These grades
describe record custody and witnessing only; they are not identity assurance levels.

The grades, ascending:

* ``S``: a locally signed commitment with no qualifying witness.
* ``W``: a witnessed commitment whose content is attested only by the party it describes (the
  tenant for a tenant-custody key, the gateway operator for an assertion about its own gateway),
  or a counterparty receipt that misses one of the I conditions.
* ``W+`` (no hidden history): witnessed, origin self-attested, every signature of the key
  accounted for by an attested counter (``W+-HSM-STREAM``: a hardware module's signed per-key
  usage log; ``W+-TEE-JOURNAL``: a measured journal's quote over a nonce the verifier chose).
* ``I``: content-origin independently attested, with witnessed continuity. Routes:
  ``I-HOSTED-WITNESS-QUORUM`` (the gateway operator's key signs what the tenant's agent did and an
  external witness cosigns; independent of the tenant), ``I-NOTARY`` (a non-tenant notary
  received the REQUEST itself at the submission boundary and signed what it saw; independent of
  the tenant and the gateway operator), ``I-TEE`` (the decision path runs in a measured enclave
  that terminates the agent's channel; independent of the tenant and the gateway operator),
  ``I-COUNTERPARTY`` (a receipt under a key bound to the target from public roots, with a
  (permit id, stage) map proof; independent of the tenant only: the counterparty self-attests).

What the verifier trusts is what IT holds (``trust``): log keys, witness keys with their operator
class, list and validity, record keys with their operator and root, public roots for counterparty
keys, attestation roots and allowed measurements, hardware modules, receipt windows per stage,
agent keys, and the challenge it chose. The bundle never supplies a key the grade rests on: a
counterparty key the bundle itself declares is read, and graded no higher than W
("tenant-declared counterparty").

Every rule below is load-bearing in the corpus (``mutation_check.py``). A rule caps the grade and
records its reason; the derived grade is the lowest cap. A bundle is ``accepted`` when every
assertion is graded and no claim exceeds what was derived: a claimed grade above the derived one,
a claimed route that differs at the same grade, or a claimed witness coverage interval outside the
computed one is ``rejected`` with the first reason. "Mutually signed" (a tenant agent's
proof-of-possession signature over the request beside the gateway operator's signature) is printed
as a property and never raises a grade.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON object with
``decision``, ``reason`` and ``assertions`` (each with ``id``, ``grade``, ``route``,
``independentOf``, ``custody``, ``boundary``, ``witnesses``, ``anchors``, ``properties``, ``label``
and ``qualifier``), and exits 0 for ``accepted`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import strictb64, strictjson

SUITE = "assertion-grade/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
GRADES = ("none", "S", "W", "W+", "I")
RANK = {grade: i for i, grade in enumerate(GRADES)}
PARTIES = frozenset({"tenant", "us", "counterparty"})
STAGES = ("accept", "execute", "settle", "final")
RECEIPT_FIELDS = ("target_id", "key_id", "request_commitment", "actor_stamp_digest", "permit_id",
                  "stage", "outcome", "signed_at")
MAP_KEY_DOMAIN = b"agent-evidence-receipt-map/v1 key"
MAP_COMMITMENT = "agent-evidence-receipt-map-commitment/v1"
EM_DASH = "— "
SIG_ED25519, SIG_COSIGNATURE = 0x01, 0x04
TENANT_DECLARED = "tenant-declared counterparty"
UNBOUND = "unbound counterparty key"
STAGING = "staging-grade"
MUTUAL = "mutually signed"
CUSTOMER_WITNESS = "customer-held witness in quorum"
SELF_ATTESTS = "counterparty self-attests"

# Every rule the reader applies, in the order it checks. The mutation check switches each off.
RULES = (
    "wrong_tenant",
    "record_key_unknown",
    "attestation_chain_unverified",
    "record_signature_invalid",
    "log_unknown",
    "checkpoint_signature_invalid",
    "inclusion_proof_invalid",
    "log_history_inconsistent",
    "witness_cosignature_invalid",
    "witness_key_mismatch",
    "witness_key_expired",
    "not_witnessed",
    "receipt_key_not_valid_at_inclusion",
    "receipt_window_exceeded",
    "tenant_declared_counterparty",
    "counterparty_key_unbound",
    "receipt_tuple_unbound",
    "map_proof_missing",
    "map_proof_mismatch",
    "gateway_self_attested",
    "content_self_attested",
    "customer_custody_root",
    "notary_saw_commitment_only",
    "notary_not_independent",
    "measurement_not_allowed",
    "channel_not_terminated_in_enclave",
    "no_key_use_counter",
    "hsm_counter_not_attested",
    "hsm_counter_gap",
    "hsm_signature_unaccounted",
    "stale_challenge",
    "journal_head_mismatch",
    "no_external_witness",
    "claim_route_mismatch",
    "coverage_overclaimed",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-assertion-grade" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-assertion-grade")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")

Doc = dict[str, Any]


class Malformed(ValueError):
    """A bundle field the reader cannot read; the assertion is ungraded."""


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to dispatch."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 and RFC 8785 primitives are unavailable")


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def jcs(value: Any) -> bytes:
    return bytes(_rail().jcs_dumps(value))


def key_id(pub: bytes) -> str:
    """A key's identifier: the hex SHA-256 of its raw Ed25519 public key."""
    return sha(pub).hex()


def _key(text: Any) -> bytes:
    try:
        raw = bytes.fromhex(str(text))
    except ValueError as exc:
        raise Malformed("a key is 32 bytes of hex") from exc
    if len(raw) != 32 or raw.hex() != text:
        raise Malformed("a key is 32 bytes of lower-case hex")
    return raw


def _b64(text: Any) -> bytes:
    try:
        return strictb64.std(text)
    except (ValueError, TypeError) as exc:
        raise Malformed("not canonical base64") from exc


def _hashes(items: Any) -> list[bytes]:
    if not isinstance(items, list):
        raise Malformed("a proof is a list of base64 hashes")
    out = [_b64(item) for item in items]
    if any(len(h) != 32 for h in out):
        raise Malformed("a proof hash is 32 bytes")
    return out


def _int(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise Malformed("expected a non-negative integer")
    return value


def _pins(trust: Doc, name: str) -> dict[Any, Any]:
    value = trust.get(name)
    return value if isinstance(value, dict) else {}


def verify_sig(pub: bytes, message: bytes, signature: bytes) -> bool:
    return len(signature) == 64 and bool(_rail().ed25519_verify(pub, message, signature))


def _signed_json(pub: bytes, body: Any, sig: Any) -> bool:
    """Whether ``sig`` is an Ed25519 signature by ``pub`` over the RFC 8785 form of ``body``."""
    try:
        return isinstance(body, dict) and verify_sig(pub, jcs(body), _b64(sig))
    except Malformed:
        return False


# --- RFC 9162 Merkle tree ------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return sha(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha(b"\x01" + left + right)


def _shift_to_set(fn: int, sn: int) -> tuple[int, int]:
    """Right-shift both until the low bit of ``fn`` is set or ``fn`` is zero."""
    while fn and not fn & 1:
        fn, sn = fn >> 1, sn >> 1
    return fn, sn


def verify_inclusion(index: int, size: int, leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            fn, sn = _shift_to_set(fn, sn)
        else:
            r = node_hash(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root


def _consistency_fold(m: int, n: int, proof: list[bytes]) -> tuple[bytes, bytes] | None:
    """The two roots a consistency proof reproduces, or None when it runs out early."""
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            fn, sn = _shift_to_set(fn, sn)
        else:
            sr = node_hash(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return (fr, sr) if sn == 0 else None


def verify_consistency(m: int, n: int, first: bytes, second: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2, for 0 < m <= n."""
    if m == 0 or m > n:
        return False
    if m == n:
        return not proof and first == second
    if m & (m - 1) == 0:
        proof = [first, *proof]
    roots = _consistency_fold(m, n, proof) if proof else None
    return roots == (first, second)


# --- the (issuer, permit id, stage) receipt map: compact sparse Merkle map, depth 256 -------------


def _u16(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        raise Malformed("map key field longer than 65535 bytes")
    return len(data).to_bytes(2, "big") + data


def map_key(issuer: bytes, permit_id: str, stage: str) -> bytes:
    return sha(MAP_KEY_DOMAIN + issuer + _u16(permit_id.encode()) + _u16(stage.encode()))


def map_entry(key: bytes, index: int, leaf: bytes) -> bytes:
    return sha(b"\x00" + key + index.to_bytes(8, "big") + leaf)


def _terminal(terminal: Any) -> tuple[bytes, int, bytes] | None:
    try:
        t_key, t_leaf = bytes.fromhex(terminal["key"]), bytes.fromhex(terminal["leafHash"])
        t_index = _int(terminal["index"])
    except (KeyError, TypeError, ValueError):
        return None
    if len(t_key) != 32 or len(t_leaf) != 32 or t_index >= 2**64:
        return None
    return t_key, t_index, t_leaf


def map_proof_holds(proof: Any, root: bytes) -> tuple[bytes, int, bytes] | None:
    """The (key, leaf index, leaf hash) the map holds for the proof's key under ``root``, or None
    when the proof does not reproduce the root, or ends in an empty subtree or another key."""
    try:
        key = bytes.fromhex(proof["key"])
        siblings = [bytes(32) if s is None else _b64(s) for s in proof["siblings"]]
        entry = _terminal(proof["terminal"])
    except (KeyError, TypeError, ValueError):
        return None
    if entry is None or len(key) != 32 or len(siblings) > 256 or entry[0] != key:
        return None
    k, depth = int.from_bytes(key, "big"), len(siblings)
    h = map_entry(*entry)
    for d in range(depth - 1, -1, -1):
        h = node_hash(siblings[d], h) if (k >> (255 - d)) & 1 else node_hash(h, siblings[d])
    return entry if h == root else None


# --- C2SP signed notes and checkpoints ------------------------------------------------------------


def note_key_hash(name: str, sig_type: int, pub: bytes) -> bytes:
    return sha(name.encode() + b"\n" + bytes([sig_type]) + pub)[:4]


def parse_note(text: Any) -> tuple[bytes, list[tuple[str, bytes]]]:
    if not isinstance(text, str) or not text.endswith("\n") or "\n\n" not in text:
        raise Malformed("a signed note is text, a blank line and signature lines")
    split = text.rindex("\n\n")
    body, lines = text[: split + 1], text[split + 2:].split("\n")[:-1]
    sigs: list[tuple[str, bytes]] = []
    for line in lines:
        if not line.startswith(EM_DASH) or line.count(" ") != 2:
            raise Malformed("a signature line is an em dash, a name and base64")
        _, name, blob = line.split(" ")
        sigs.append((name, _b64(blob)))
    return body.encode(), sigs


def parse_checkpoint_body(body: bytes) -> tuple[str, int, bytes]:
    lines = body.decode().split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise Malformed("a checkpoint is origin, size and root, with no extension line")
    if not lines[1].isdigit() or str(int(lines[1])) != lines[1]:
        raise Malformed("a checkpoint size is a decimal integer")
    return lines[0], int(lines[1]), _b64(lines[2])


def log_signed(origin: str, body: bytes, sigs: list[tuple[str, bytes]], key: bytes) -> bool:
    want = note_key_hash(origin, SIG_ED25519, key)
    return any(name == origin and len(blob) == 68 and blob[:4] == want
               and verify_sig(key, body, blob[4:]) for name, blob in sigs)


def _cosig_problem(name: str, blob: bytes, body: bytes, pinned: Doc,
                   skip: frozenset[str]) -> str | None:
    """Why a cosignature line under a pinned witness name is refused, or None when it counts."""
    w_key = _key(pinned["key"])
    ts = int.from_bytes(blob[4:12], "big")
    message = f"cosignature/v1\ntime {ts}\n".encode() + body
    if blob[:4] != note_key_hash(name, SIG_COSIGNATURE, w_key):
        if "witness_key_mismatch" not in skip:
            return "witness_key_mismatch"
    elif not verify_sig(w_key, message, blob[12:]) and "witness_cosignature_invalid" not in skip:
        return "witness_cosignature_invalid"
    in_validity = _int(pinned["valid_from"]) <= ts <= _int(pinned["valid_to"])
    if not in_validity and "witness_key_expired" not in skip:
        return "witness_key_expired"
    return None


class Checkpoint:
    """One cosigned checkpoint, judged against the verifier's pins for its log."""

    def __init__(self, text: Any, trust: Doc, skip: frozenset[str]) -> None:
        body, sigs = parse_note(text)
        self.origin, self.size, self.root = parse_checkpoint_body(body)
        self.problems: list[str] = []
        self.cosigs: dict[str, int] = {}  # witness name -> earliest valid cosignature time
        log = _pins(trust, "logs").get(self.origin)
        self.log_ok = log is not None and (
            "checkpoint_signature_invalid" in skip
            or log_signed(self.origin, body, sigs, _key(log["key"])))
        witnesses = _pins(trust, "witnesses")
        for name, blob in sigs:
            pinned = witnesses.get(name)
            if pinned is None or name == self.origin or len(blob) != 76:
                continue
            problem = _cosig_problem(name, blob, body, pinned, skip)
            if problem is not None:
                self.problems.append(problem)
                continue
            ts = int.from_bytes(blob[4:12], "big")
            self.cosigs[name] = min(ts, self.cosigs.get(name, ts))


class Log:
    """The bundle's view of one log: its checkpoints in order and the proofs between them."""

    def __init__(self, doc: Any, trust: Doc, skip: frozenset[str]) -> None:
        if not isinstance(doc, dict):
            raise Malformed("the bundle's log is an object")
        self.origin = doc.get("origin")
        self.pinned = _pins(trust, "logs").get(self.origin)
        self.checkpoints = [Checkpoint(text, trust, skip) for text in doc.get("checkpoints", [])]
        proofs = doc.get("consistency", [])
        if not isinstance(proofs, list) or len(proofs) != max(len(self.checkpoints) - 1, 0):
            raise Malformed("one consistency proof between each pair of consecutive checkpoints")
        self.consistent = "log_history_inconsistent" in skip or self._consistent(proofs)

    def _consistent(self, proofs: list[Any]) -> bool:
        pairs = zip(self.checkpoints, self.checkpoints[1:], proofs, strict=False)
        if not all(verify_consistency(a.size, b.size, a.root, b.root, _hashes(p))
                   for a, b, p in pairs):
            return False
        seen: dict[int, bytes] = {}
        return all(cp.origin == self.origin and seen.setdefault(cp.size, cp.root) == cp.root
                   for cp in self.checkpoints)

    def operator(self) -> str:
        return str((self.pinned or {}).get("operator", ""))


# --- per-assertion grading ------------------------------------------------------------------------


class Grade:
    """The caps one assertion collects."""

    def __init__(self, skip: frozenset[str]) -> None:
        self.skip = skip
        self.ceiling = "I"
        self.caps: list[tuple[str, str]] = []

    def cap(self, rule: str, grade: str) -> None:
        if rule in self.skip:
            return
        self.caps.append((rule, grade))
        if RANK[grade] < RANK[self.ceiling]:
            self.ceiling = grade


def _answer(aid: str) -> Doc:
    return {"id": aid, "grade": "none", "route": "none", "independentOf": [], "custody": "",
            "boundary": "", "witnesses": [], "anchors": [], "properties": [], "label": "",
            "qualifier": ""}


class Context:
    def __init__(self, trust: Doc, bundle: Doc, skip: frozenset[str]) -> None:
        self.trust, self.bundle, self.skip = trust, bundle, skip
        self.parties = _pins(trust, "parties")
        self.log = Log(bundle["log"], trust, skip) if "log" in bundle else None

    def checkpoint(self, index: int) -> Checkpoint | None:
        if self.log is None or not 0 <= index < len(self.log.checkpoints):
            return None
        return self.log.checkpoints[index]


class Assertion:
    """One assertion while it is graded: its inputs, its caps and its printout."""

    def __init__(self, a: Doc, ctx: Context) -> None:
        self.a, self.ctx = a, ctx
        self.st, self.about = a["statement"], a.get("about")
        self.evidence = a.get("evidence") or {}
        self.g = Grade(ctx.skip)
        self.out = _answer(str(a.get("id")))
        self.root_class = "production"
        self.pub, self.operator, self.root = b"", "", ""
        self.validity: Doc | None = None
        self.leaf, self.cp_index = b"", -1
        self.t_incl: int | None = None
        self.witnesses: list[Doc] = []

    def cap(self, rule: str, grade: str) -> None:
        self.g.cap(rule, grade)

    def record_role(self) -> str:
        pinned = _pins(self.ctx.trust, "record_keys").get(self.a.get("key_id"), {})
        return str(pinned.get("role"))


# --- counterparty key bindings -------------------------------------------------------------------


def _claimed_key(binding: Doc) -> bytes | None:
    """The receipt key a binding presents, before any of it is checked."""
    holder = {"tenant-declared": binding, "domain-document": binding.get("key"),
              "naming-log": binding.get("entry"),
              "rail-operator": binding.get("listing")}.get(str(binding.get("kind")))
    if not isinstance(holder, dict):
        return None
    try:
        return _key(holder.get("key"))
    except Malformed:
        return None


def _unsigned(cert: Doc) -> Doc:
    return {k: v for k, v in cert.items() if k != "sig"}


def _chain_reaches_root(chain: list[Any], trust: Doc) -> bool:
    for child, parent in zip(chain, chain[1:], strict=False):
        if child.get("issuer") != parent.get("subject") or not _signed_json(
                _key(parent["key"]), _unsigned(child), child.get("sig")):
            return False
    top = chain[-1]
    root_key = _pins(trust, "web_roots").get(top.get("issuer"))
    return root_key is not None and _signed_json(_key(root_key), _unsigned(top), top.get("sig"))


def _bound_domain(binding: Doc, trust: Doc, target: str) -> tuple[Doc, str] | None:
    doc, chain, entry = binding.get("document"), binding.get("chain"), binding.get("key")
    if not isinstance(doc, dict) or not isinstance(chain, list) or not chain:
        return None
    if not isinstance(entry, dict) or doc.get("domain") != target \
            or entry not in doc.get("keys", []):
        return None
    if not all(isinstance(c, dict) for c in chain) or chain[0].get("subject") != target:
        return None
    if not _signed_json(_key(chain[0]["key"]), doc, binding.get("document_sig")):
        return None
    if not _chain_reaches_root(chain, trust):
        return None
    return entry, f"web-root:{chain[-1]['issuer']}"


def _bound_naming(binding: Doc, trust: Doc, target: str) -> tuple[Doc, str] | None:
    entry, origin = binding.get("entry"), binding.get("origin")
    pinned = _pins(trust, "naming_logs").get(origin)
    if pinned is None or not isinstance(entry, dict) or entry.get("name") != target \
            or entry.get("validation") != "domain-control":
        return None
    body, sigs = parse_note(binding.get("checkpoint"))
    found, size, root = parse_checkpoint_body(body)
    if found != origin or not log_signed(str(origin), body, sigs, _key(pinned["key"])):
        return None
    if not verify_inclusion(_int(binding.get("leaf_index")), size, leaf_hash(jcs(entry)),
                            _hashes(binding.get("inclusion")), root):
        return None
    return entry, f"naming-log:{origin}"


def _bound_rail(binding: Doc, trust: Doc, target: str) -> tuple[Doc, str] | None:
    rail, listing = binding.get("rail"), binding.get("listing")
    pinned = _pins(trust, "rail_operators").get(rail)
    if pinned is None or not isinstance(listing, dict) or listing.get("target") != target:
        return None
    if not _signed_json(_key(pinned["key"]), listing, binding.get("sig")):
        return None
    return listing, f"rail:{rail}"


_BINDINGS = {"domain-document": _bound_domain, "naming-log": _bound_naming,
             "rail-operator": _bound_rail}


def _attested(quote_doc: Any, trust: Doc) -> tuple[Doc | None, str, str]:
    """A quote signed by an attestation root the verifier pins: (quote, anchor, root class)."""
    if not isinstance(quote_doc, dict) or not isinstance(quote_doc.get("quote"), dict):
        return None, "", ""
    quote = quote_doc["quote"]
    root = _pins(trust, "attestation_roots").get(quote.get("root"))
    if root is None or not _signed_json(_key(root["key"]), quote, quote_doc.get("sig")):
        return None, "", ""
    return quote, f"attestation-root:{quote['root']}", str(root.get("class", ""))


# --- key resolution ------------------------------------------------------------------------------


def _counterparty_label(x: Assertion, binding: Doc, pub: bytes) -> str:
    """The label the receipt key earns: tenant-declared, unbound, or '' when bound."""
    label = TENANT_DECLARED if binding.get("kind") == "tenant-declared" else ""
    if not label:
        check = _BINDINGS.get(str(binding.get("kind")))
        target = str(x.ctx.parties.get("counterparty"))
        bound = check(binding, x.ctx.trust, target) if check else None
        if bound is None:
            label = UNBOUND
        else:
            x.validity = bound[0]
            x.out["anchors"].append(bound[1])
    pinned = _pins(x.ctx.trust, "record_keys").get(key_id(pub))
    if pinned is not None and pinned.get("operator") == "tenant":
        label = TENANT_DECLARED
    return label


def _resolve_counterparty(x: Assertion) -> bool:
    binding = x.evidence.get("binding")
    pub = _claimed_key(binding) if isinstance(binding, dict) else None
    if pub is None or not isinstance(binding, dict):
        x.cap("counterparty_key_unbound", "none")
        return False
    label = _counterparty_label(x, binding, pub)
    rule = {TENANT_DECLARED: "tenant_declared_counterparty",
            UNBOUND: "counterparty_key_unbound"}.get(label)
    if rule is not None and rule not in x.ctx.skip:
        x.cap(rule, "W")
        x.out["label"] = label
    x.pub, x.operator, x.root = pub, "counterparty", "counterparty"
    return True


def _resolve_enclave(x: Assertion) -> bool:
    quote, anchor, root_class = _attested(x.evidence["tee_decision"], x.ctx.trust)
    if quote is None:
        if "attestation_chain_unverified" not in x.ctx.skip:
            x.cap("attestation_chain_unverified", "none")
            return False
        quote = x.evidence["tee_decision"].get("quote") or {}
        anchor, root_class = f"attestation-root:{quote.get('root')}", "unpinned"
    x.out["anchors"].append(anchor)
    x.root_class = root_class
    x.pub, x.operator, x.root = _key(quote["enclave_key"]), "enclave", "vendor-attestation"
    return True


def _resolve(x: Assertion) -> bool:
    """Fill in the key the assertion is signed under; False when it is unresolved."""
    if x.about == "counterparty":
        return _resolve_counterparty(x)
    if "tee_decision" in x.evidence:
        return _resolve_enclave(x)
    pinned = _pins(x.ctx.trust, "record_keys").get(x.a.get("key_id"))
    if pinned is None:
        x.cap("record_key_unknown", "none")
        return False
    x.pub, x.operator = _key(pinned["key"]), str(pinned["operator"])
    x.root = str(pinned["root"])
    return True


# --- the log and its witnesses -------------------------------------------------------------------


def _included(x: Assertion) -> Checkpoint | None:
    """The checkpoint the assertion is proven included in, or None (capped at S)."""
    ref, log = x.a.get("log"), x.ctx.log
    if not isinstance(ref, dict) or log is None:
        x.cap("not_witnessed", "S")
        return None
    if log.pinned is None:
        x.cap("log_unknown", "S")
        return None
    x.cp_index = _int(ref["checkpoint"])
    cp = x.ctx.checkpoint(x.cp_index)
    if cp is None:
        raise Malformed("the assertion names a checkpoint the bundle does not carry")
    if not cp.log_ok:
        x.cap("checkpoint_signature_invalid", "S")
        return None
    proven = verify_inclusion(_int(ref["leaf_index"]), cp.size, x.leaf,
                              _hashes(ref["inclusion"]), cp.root)
    if not proven and "inclusion_proof_invalid" not in x.ctx.skip:
        x.cap("inclusion_proof_invalid", "S")
        return None
    if not log.consistent:
        x.cap("log_history_inconsistent", "S")
        return None
    return cp


def _cosignature_times(x: Assertion, log: Log) -> dict[str, list[int]]:
    times: dict[str, list[int]] = {}
    for cp in log.checkpoints[x.cp_index:]:
        if not cp.log_ok:
            continue
        for problem in cp.problems:
            x.cap(problem, "S")  # a refused line under a pinned witness name: not trusted
        for name, ts in cp.cosigs.items():
            times.setdefault(name, []).append(ts)
    return times


def _witnessing(x: Assertion) -> None:
    """Check the log and collect the counted witnesses and the inclusion time."""
    log = x.ctx.log
    if _included(x) is None or log is None:
        return
    times = _cosignature_times(x, log)
    # Excluded: the parties that administer the record key or the log. An external entity is
    # never one of the three parties, so it is never excluded here.
    excluded = {x.operator, log.operator()} & PARTIES
    if "not_witnessed" in x.ctx.skip:
        excluded = set()
    pins = _pins(x.ctx.trust, "witnesses")
    x.witnesses = [{"name": name, "operator": str(pins[name]["operator"]), "from": min(ts),
                    "to": max(ts)} for name, ts in sorted(times.items())
                   if pins[name]["operator"] not in excluded]
    x.out["witnesses"] = x.witnesses
    if not x.witnesses:
        x.cap("not_witnessed", "S")
        return
    # Inclusion time is attested by the earliest external cosignature when there is one: a
    # witness the tenant runs could date its own line early.
    timed = [w for w in x.witnesses if w["operator"] == "external"] or x.witnesses
    x.t_incl = min(w["from"] for w in timed)


# --- routes --------------------------------------------------------------------------------------


def _receipt_tuple(x: Assertion) -> None:
    st = x.st
    bound = (all(f in st for f in RECEIPT_FIELDS) and st.get("stage") in STAGES
             and st.get("target_id") == x.ctx.parties.get("counterparty")
             and st.get("key_id") == key_id(x.pub) and type(st.get("signed_at")) is int)
    if not bound:
        x.cap("receipt_tuple_unbound", "W")


def _receipt_window(x: Assertion) -> None:
    if x.t_incl is None:
        return
    validity = x.validity
    if validity is not None and not (
            _int(validity["not_before"]) <= x.t_incl <= _int(validity["not_after"])):
        x.cap("receipt_key_not_valid_at_inclusion", "S")
    window = _pins(x.ctx.trust, "receipt_windows").get(x.st.get("stage"))
    signed_at = x.st.get("signed_at")
    if type(signed_at) is not int or window is None or not 0 <= x.t_incl - signed_at <= window:
        x.cap("receipt_window_exceeded", "S")


def _map_holds(x: Assertion, proof: Doc) -> bool:
    cp, st = x.ctx.checkpoint(x.cp_index), x.st
    if cp is None or not isinstance(st.get("permit_id"), str) or st.get("stage") not in STAGES:
        return False
    root = bytes.fromhex(str(proof.get("root", "")))
    commit = proof.get("commitment") or {}
    c_index, a_index = commit.get("leaf_index"), _int(x.a["log"]["leaf_index"])
    commit_leaf = leaf_hash(jcs({"format": MAP_COMMITMENT, "root": root.hex()}))
    entry = map_proof_holds(proof.get("proof"), root)
    key = map_key(sha(x.pub), st["permit_id"], st["stage"])
    return (type(c_index) is int and c_index > a_index
            and verify_inclusion(c_index, cp.size, commit_leaf, _hashes(commit.get("inclusion")),
                                 cp.root)
            and entry == (key, a_index, x.leaf))


def _counterparty(x: Assertion) -> tuple[str, list[str], str]:
    _receipt_tuple(x)
    _receipt_window(x)
    proof = x.evidence.get("map")
    if not isinstance(proof, dict):
        x.cap("map_proof_missing", "W")
    elif not _map_holds(x, proof):
        x.cap("map_proof_mismatch", "W")
    return "I-COUNTERPARTY", ["tenant"], "target"


def _enclave(x: Assertion) -> tuple[str, list[str], str]:
    quote = x.evidence["tee_decision"].get("quote", {})
    allowed = _pins(x.ctx.trust, "measurements").get("decision_path", [])
    if quote.get("measurement") not in allowed:
        x.cap("measurement_not_allowed", "W")
    if quote.get("channel_termination") != "attested-tls":
        x.cap("channel_not_terminated_in_enclave", "W")
    return "I-TEE", ["tenant", "us"], "enclave channel"


def _notary(x: Assertion) -> tuple[str, list[str], str]:
    request = x.st.get("request")
    if not isinstance(request, dict) or x.st.get("request_commitment") != sha(jcs(request)).hex():
        x.cap("notary_saw_commitment_only", "W")
    if x.operator != "external":
        x.cap("notary_not_independent", "W")
    return "I-NOTARY", ["tenant", "us"], "notary"


def _route(x: Assertion) -> tuple[str, list[str], str]:
    """The I route the assertion aims at, whom it would be independent of, and its boundary;
    the route's rules cap the grade on the way."""
    if x.about == "counterparty":
        return _counterparty(x)
    if x.operator == "enclave":
        return _enclave(x)
    if x.operator in ("external", "tenant", "us") and x.record_role() == "notary":
        return _notary(x)
    if x.about == "gateway":
        x.cap("gateway_self_attested", "W")
        return "I-HOSTED-WITNESS-QUORUM", [], "gateway ingress"
    if x.operator == "tenant":
        x.cap("content_self_attested", "W+")
        return "", [], "tenant signer"
    return "I-HOSTED-WITNESS-QUORUM", ["tenant"], "gateway ingress"


# --- the W+ counter routes -----------------------------------------------------------------------


def _hsm_audit(x: Assertion, hsm: Doc) -> list[Doc] | None:
    """The module's signed usage-log entries, or None when the counter is not attested."""
    device = _pins(x.ctx.trust, "hsm_devices").get(hsm.get("device"))
    if device is None or device.get("per_key_usage_logging") is not True:
        return None
    x.out["anchors"].append(f"hsm:{device['model']}")
    audit_key, entries = _key(device["audit_key"]), hsm.get("audit", [])
    if not entries or not all(_signed_json(audit_key, e.get("entry"), e.get("sig"))
                              for e in entries):
        return None
    return [e["entry"] for e in entries]


def _hsm_accounted(x: Assertion, rows: list[Doc], accounted: list[Any]) -> bool:
    """Every signature of this key in the usage log has its leaf in the witnessed log."""
    mine = [r for r in rows if r.get("key_id") == key_id(x.pub)]
    cp = x.ctx.checkpoint(x.cp_index)
    leaves = {r.get("leaf_hash") for r in mine}
    if cp is None or len(accounted) != len(mine) or x.leaf.hex() not in leaves:
        return False
    return all(verify_inclusion(_int(acc["leaf_index"]), cp.size, bytes.fromhex(r["leaf_hash"]),
                                _hashes(acc["inclusion"]), cp.root)
               for r, acc in zip(mine, accounted, strict=True))


def _hsm_route(x: Assertion, hsm: Doc) -> str:
    rows = _hsm_audit(x, hsm)
    if rows is None:
        x.cap("hsm_counter_not_attested", "W")
        return ""
    seqs: list[Any] = [r.get("seq") for r in rows]
    if any(type(s) is not int for s in seqs) or seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        x.cap("hsm_counter_gap", "W")
    if not _hsm_accounted(x, rows, hsm.get("accounted", [])):
        x.cap("hsm_signature_unaccounted", "W")
    return "W+-HSM-STREAM"


def _journal_route(x: Assertion, doc: Any) -> str:
    quote, anchor, root_class = _attested(doc, x.ctx.trust)
    if quote is None:
        x.cap("attestation_chain_unverified", "W")
        return ""
    x.out["anchors"].append(anchor)
    x.root_class = root_class
    allowed = _pins(x.ctx.trust, "measurements").get("journal", [])
    if quote.get("measurement") not in allowed or quote.get("journal_key_id") != key_id(x.pub):
        x.cap("measurement_not_allowed", "W")
    if quote.get("nonce") != x.ctx.trust.get("challenge"):
        x.cap("stale_challenge", "W")
    cp = x.ctx.checkpoint(x.cp_index)
    if cp is None or quote.get("journal_head") != cp.root.hex() \
            or quote.get("tree_size") != cp.size:
        x.cap("journal_head_mismatch", "W")
    return "W+-TEE-JOURNAL"


def _counter_route(x: Assertion) -> str:
    """The W+ route a self-attested key earns, or '' (capped at W)."""
    if "hsm" in x.evidence:
        return _hsm_route(x, x.evidence["hsm"])
    if "tee_journal" in x.evidence:
        return _journal_route(x, x.evidence["tee_journal"])
    x.cap("no_key_use_counter", "W")
    return ""


def _mutual(x: Assertion) -> bool:
    """Whether a tenant agent key's proof-of-possession signature covers the request."""
    pop = x.evidence.get("pop")
    if not isinstance(pop, dict) or "request_commitment" not in x.st:
        return False
    agent = _pins(x.ctx.trust, "agent_keys").get(pop.get("agent_key_id"))
    body = {"request_commitment": x.st["request_commitment"]}
    return agent is not None and _signed_json(_key(agent["key"]), body, pop.get("sig"))


# --- one assertion end to end --------------------------------------------------------------------


def _properties(x: Assertion) -> None:
    if x.about in ("gateway", "tenant") and _mutual(x):
        x.out["properties"].append(MUTUAL)
    if x.operator == "us" and any(w["operator"] == "tenant" for w in x.witnesses):
        x.out["properties"].append(CUSTOMER_WITNESS)
    if x.g.ceiling == "I" and x.about == "counterparty":
        x.out["properties"].append(SELF_ATTESTS)


def _place(x: Assertion, route_i: str, independent: list[str], counter_route: str) -> None:
    """The route and independence the final grade prints."""
    final = x.g.ceiling
    if final == "I":
        x.out["route"], x.out["independentOf"] = route_i, independent
    elif final == "W+":
        x.out["route"] = counter_route
    elif final == "W":
        managed = x.operator == "us" and x.about == "tenant" \
            and CUSTOMER_WITNESS in x.out["properties"]
        x.out["route"] = "W-MANAGED-CUSTOMER-WITNESS" if managed else "W-WITNESSED"
        x.out["independentOf"] = ["us"] if managed else []
    elif final == "S":
        x.out["route"] = "S-LOCAL"


def _qualify(x: Assertion, external: list[Doc]) -> None:
    if x.g.ceiling not in ("I", "W+"):
        return
    pins = _pins(x.ctx.trust, "witnesses")
    staging = bool(external) and all(pins[w["name"]]["list"] == "staging" for w in external)
    if staging or x.root_class != "production":
        x.out["qualifier"] = STAGING


def _finish(x: Assertion) -> tuple[Doc, list[tuple[str, str]]]:
    out = x.out
    out["grade"] = x.g.ceiling
    out["properties"] = sorted(set(out["properties"]))
    out["anchors"] = sorted(set(out["anchors"]))
    if out["grade"] == "none":
        out = _answer(out["id"])
    return out, x.g.caps


def _grade(x: Assertion) -> tuple[Doc, list[tuple[str, str]]]:
    if not isinstance(x.st, dict) or x.about not in ("tenant", "gateway", "counterparty"):
        raise Malformed("an assertion is about the tenant, the gateway or the counterparty")
    if x.about != "counterparty" and x.st.get("tenant") != x.ctx.parties.get("tenant"):
        x.cap("wrong_tenant", "none")
        return _finish(x)
    if not _resolve(x):
        return _finish(x)
    x.out["custody"] = x.operator
    signed = verify_sig(x.pub, jcs(x.st), _b64(x.a.get("sig")))
    if not signed and "record_signature_invalid" not in x.ctx.skip:
        x.cap("record_signature_invalid", "none")
        return _finish(x)
    x.leaf = leaf_hash(jcs({"key_id": key_id(x.pub), "sig": x.a["sig"], "statement": x.st}))
    _witnessing(x)
    route_i, independent, boundary = _route(x)
    if x.root == "customer-custody":
        x.cap("customer_custody_root", "W+")
    counter_route = _counter_route(x) if x.g.ceiling == "W+" else ""
    external = [w for w in x.witnesses if w["operator"] == "external"]
    if x.witnesses and not external:
        x.cap("no_external_witness", "W")
    _properties(x)
    x.out["boundary"] = boundary
    _place(x, route_i, independent, counter_route)
    _qualify(x, external)
    return _finish(x)


def grade_assertion(a: Doc, ctx: Context) -> tuple[Doc, list[tuple[str, str]]]:
    """The verifier's printout for one assertion and the caps it collected, in check order."""
    try:
        return _grade(Assertion(a, ctx))
    except (Malformed, KeyError, TypeError, ValueError):
        return _answer(str(a.get("id"))), [("bundle_malformed", "none")]


def _covered(claim: Doc, witnesses: list[Doc]) -> bool:
    want = claim.get("coverage")
    if want is None:
        return True
    for w in witnesses:
        if w["name"] == want.get("witness"):
            return type(want.get("from")) is int and type(want.get("to")) is int \
                and w["from"] <= want["from"] and want["to"] <= w["to"]
    return False


def _refusal(out: Doc, caps: list[tuple[str, str]], claim: Doc,
             skip: frozenset[str]) -> str | None:
    """Why the bundle is refused on this assertion, or None."""
    claimed_grade = claim.get("grade", "S")
    claimed = RANK.get(claimed_grade, len(GRADES))
    if out["grade"] == "none" or claimed > RANK[out["grade"]]:
        # the first rule that capped the grade below what the bundle claims
        want = claimed if out["grade"] != "none" else RANK["S"]
        return next((rule for rule, cap in caps if RANK[cap] < want), "bundle_malformed")
    route_differs = claim.get("route", out["route"]) != out["route"]
    if claimed_grade == out["grade"] and route_differs and "claim_route_mismatch" not in skip:
        return "claim_route_mismatch"
    if not _covered(claim, out["witnesses"]) and "coverage_overclaimed" not in skip:
        return "coverage_overclaimed"
    return None


def _malformed() -> Doc:
    return {"assertions": [], "decision": REJECTED, "reason": "bundle_malformed"}


def decide(case: Doc, skip: frozenset[str] = frozenset()) -> Doc:
    """The reference reader's answer for one case."""
    trust, bundle = case["trust"], case["bundle"]
    try:
        ctx = Context(trust, bundle, skip)
    except (Malformed, KeyError, TypeError, ValueError):
        return _malformed()
    listed = bundle.get("assertions", [])
    ids = [str(a.get("id")) for a in listed if isinstance(a, dict)]
    if not listed or len(ids) != len(listed) or len(set(ids)) != len(ids):
        return _malformed()
    answers, refusal = [], None
    for a in listed:
        out, caps = grade_assertion(a, ctx)
        answers.append(out)
        if refusal is None:
            refusal = _refusal(out, caps, a.get("claim") or {}, skip)
    return {"assertions": answers, "decision": REJECTED if refusal else ACCEPTED,
            "reason": refusal or "grades_derived"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> Doc:
    return decide(strictjson.loads(case_path.read_text(encoding="utf-8")), skip)


# --- corpus harness -------------------------------------------------------------------------------


def _sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture_error(directory: Path, entry: Doc) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha_hex((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _twin_error(entries: list[Doc]) -> str | None:
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        if entry["expected"]["decision"] != REJECTED:
            continue
        twin = by_id.get(entry.get("pairsWith", ""))
        if twin is None or twin["expected"]["decision"] != ACCEPTED:
            return f"{entry['id']}: a rejected member must name an accepted twin"
        if entry["expected"]["reason"] not in RULES:
            return f"{entry['id']}: refusal code is not a rule this reader applies"
    return None


def _validated_entries(root: Path) -> tuple[list[Doc], str | None]:
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha_hex(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    ids = {entry["id"] for entry in entries}
    if not entries or len(ids) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != ids:
        return [], "case directories do not match manifest"
    twin_error = _twin_error(entries)
    return ([], twin_error) if twin_error else (entries, None)


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, Doc | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("assertions", "decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement."""
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        observed: Doc | str
        if command is None:
            ran, observed = True, verify(directory / "case.json", skip)
        else:
            ran, observed = _external_answer(command, directory / "case.json")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = strictjson.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    Path(report_path).write_text(text, encoding="utf-8")
    return 1 if errors or answered != total else 0


def _print_answer(answer: Doc) -> None:
    print(f"{answer['decision']} {answer['reason']}")
    for a in answer["assertions"]:
        extras = [x for x in (a["qualifier"], a["label"], ", ".join(a["properties"])) if x]
        print(f"  {a['id']}: {a['grade']} {a['route']}, independent of "
              f"{', '.join(a['independentOf']) or 'none'}; custody {a['custody'] or '-'}; "
              f"boundary {a['boundary'] or '-'}" + "".join(f"; {x}" for x in extras))
        for w in a["witnesses"]:
            print(f"    witness {w['name']} ({w['operator']}) covers {w['from']} to {w['to']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        if args.json:
            print(json.dumps(answer, sort_keys=True))
        else:
            _print_answer(answer)
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    manifest = strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    print(f"answered {answered} of {len(manifest['vectors'])} cases")
    return 1 if errors or answered != len(manifest["vectors"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
