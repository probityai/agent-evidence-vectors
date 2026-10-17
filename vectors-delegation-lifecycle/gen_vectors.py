"""Build the deterministic delegation lifecycle cases.

    uv run --extra generators python vectors-delegation-lifecycle/gen_vectors.py

Every case asks one question a relying party asks about an AI agent: does this
presenter hold this delegated authority at the time the relying party observed
the presentation? A case is a set of signed records (identifier registrations,
grants, revocations, disputes, resolutions, identifier links, retirements) and
one signed presentation, with the policy that judges them. Three sets:

* ``tree-``: revocation across a delegation tree, including a revocation that is
  disputed;
* ``rereg-``: re-registration, where an old identifier is linked to a new one;
* ``recovery-``: recovery after the old key is lost or compromised, where a
  record signed by the registry and the Responsible entity carries the old
  identifier's history to a new one, and no grant.

Every record is a DSSE v1 envelope signed with Ed25519 by the published test
keys below, so every byte in the corpus is a function of this file alone. The
expected outcome of each case is written here by hand, in ``CASES``; the Go
reader in ``corpora/delegationlifecycle.go`` derives its own and the two must
agree.

TEST KEYS ONLY. Each seed is the SHA-256 of a public label, so anyone can
re-derive the private key. Never trust these keys for anything else.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
_DIGEST = importlib.util.spec_from_file_location("delegation_lifecycle_digest", ROOT / "digest.py")
assert _DIGEST is not None and _DIGEST.loader is not None
_digest_module = importlib.util.module_from_spec(_DIGEST)
_DIGEST.loader.exec_module(_digest_module)
corpus_digest = _digest_module.corpus_digest

SUITE = "delegation-lifecycle/v1"
PAYLOAD_TYPE = "application/vnd.agent-evidence.delegation-lifecycle.v1+json"
TREE, REREG, RECOVERY = "delegation-tree", "re-registration", "recovery"

ORG = "did:example:org"
PLANNER = "did:example:planner"
WORKER = "did:example:worker"
SUB = "did:example:sub-worker"
SIBLING = "did:example:sibling"
V1 = "did:example:agent-v1"
V2 = "did:example:agent-v2"
V3 = "did:example:agent-v3"
V2B = "did:example:agent-v2b"
B1 = "did:example:agent-b-v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    """Canonical JSON for the signed bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def keyid(k: Ed25519PrivateKey) -> str:
    """The SHA-256 of the raw 32-byte public key, lowercase hex."""
    return _sha(public_raw(k))


def _identity_key(identifier: str) -> Ed25519PrivateKey:
    return key(f"{SUITE} test key for {identifier}")


REGISTRY = key(f"{SUITE} test registry key")
RELYING_PARTY = key(f"{SUITE} test relying party key")
INTRUDER = key(f"{SUITE} test key that nobody registered")


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def at(hhmm: str) -> str:
    """A time on the day every case happens."""
    return f"2026-10-01T{hhmm}:00Z"


Signer = tuple[Ed25519PrivateKey, str]


def as_self(k: Ed25519PrivateKey) -> Signer:
    return k, keyid(k)


def of(identifier: str) -> Signer:
    return as_self(_identity_key(identifier))


def posing_as(k: Ed25519PrivateKey, identifier: str) -> Signer:
    """A signature by key ``k`` that names the keyid registered to ``identifier``."""
    return k, keyid(_identity_key(identifier))


class Case:
    """One case before it is written: its records, its presentation and its policy."""

    def __init__(self) -> None:
        self.records: list[tuple[str, bytes]] = []
        self.presentation = b""

    def _sign(self, payload: dict[str, Any], signers: list[Signer]) -> bytes:
        body = canonical(payload)
        sigs = [{"keyid": kid, "sig": _b64(k.sign(pae(PAYLOAD_TYPE, body)))} for k, kid in signers]
        return canonical({"payload": _b64(body), "payloadType": PAYLOAD_TYPE, "signatures": sigs})

    def add(self, label: str, payload: dict[str, Any], signers: list[Signer]) -> None:
        name = f"{len(self.records) + 1:02d}-{payload['type']}-{label}.json"
        self.records.append((name, self._sign(payload, signers)))

    def register(self, identifier: str, when: str, responsible: str | None = None,
                 software: str | None = None) -> None:
        """Register an identifier. A recovery case also names the Responsible entity
        and the software attestation digest the registry matched."""
        k = _identity_key(identifier)
        payload: dict[str, Any] = {"type": "registration", "identifier": identifier,
                                   "keyid": keyid(k), "public_key": _b64(public_raw(k)),
                                   "registered_at": when}
        if responsible is not None:
            payload["responsible"] = responsible
        if software is not None:
            payload["software"] = software
        self.add(identifier.rsplit(":", 1)[-1], payload, [as_self(REGISTRY)])

    def retire(self, identifier: str, when: str) -> None:
        self.add(identifier.rsplit(":", 1)[-1],
                 {"type": "retirement", "identifier": identifier, "retired_at": when},
                 [as_self(REGISTRY)])

    def revoke_identifier(self, identifier: str, when: str, grounds: str) -> None:
        self.add(identifier.rsplit(":", 1)[-1],
                 {"type": "identifier-revocation", "identifier": identifier,
                  "revoked_at": when, "grounds": grounds},
                 [as_self(REGISTRY)])

    def grant(self, grant_id: str, parent: str | None, issuer: str, delegate: str,
              when: str, signer: Signer | None = None) -> None:
        self.add(grant_id, {"type": "grant", "grant_id": grant_id, "parent": parent,
                            "issuer": issuer, "delegate": delegate, "issued_at": when},
                 [signer or of(issuer)])

    def revoke(self, revocation_id: str, grant_id: str, initiator: str, grounds: str,
               effective: str, issued: str, signer: Signer | None = None) -> None:
        self.add(revocation_id,
                 {"type": "revocation", "revocation_id": revocation_id, "grant_id": grant_id,
                  "initiator": initiator, "grounds": grounds, "effective_at": effective,
                  "issued_at": issued},
                 [signer or of(initiator)])

    def dispute(self, dispute_id: str, revocation_id: str, filed_by: str, grounds: str,
                when: str) -> None:
        self.add(dispute_id,
                 {"type": "dispute", "dispute_id": dispute_id, "revocation_id": revocation_id,
                  "filed_by": filed_by, "grounds": grounds, "filed_at": when},
                 [of(filed_by)])

    def resolve(self, dispute_id: str, revocation_id: str, decided_by: str, outcome: str,
                when: str, replacement: str | None = None) -> None:
        payload: dict[str, Any] = {
            "type": "resolution", "dispute_id": dispute_id, "revocation_id": revocation_id,
            "decided_by": decided_by, "outcome": outcome, "decided_at": when}
        if replacement is not None:
            payload["replacement_grant"] = replacement
        self.add(dispute_id + "-outcome", payload, [of(decided_by)])

    def link(self, link_id: str, old: str, new: str, when: str,
             signers: list[Signer] | None = None) -> None:
        self.add(link_id, {"type": "link", "link_id": link_id, "old": old, "new": new,
                           "linked_at": when},
                 signers if signers is not None else [of(old), of(new), as_self(REGISTRY)])

    def recover(self, recovery_id: str, old: str, new: str, responsible: str, when: str,
                signers: list[Signer] | None = None) -> None:
        self.add(recovery_id, {"type": "recovery", "recovery_id": recovery_id, "old": old,
                               "new": new, "responsible": responsible, "recovered_at": when},
                 signers if signers is not None else [as_self(REGISTRY), of(responsible)])

    def present(self, presenter: str, chain: list[str], when: str,
                signers: list[Signer] | None = None) -> None:
        payload = {"type": "presentation", "presenter": presenter, "chain": chain,
                   "observed_at": when}
        self.presentation = self._sign(
            payload, signers if signers is not None else [of(presenter), as_self(RELYING_PARTY)])

    def replace(self, name_part: str, data: bytes) -> None:
        """Swap one record's bytes, keeping its file name."""
        self.records = [(n, data if name_part in n else b) for n, b in self.records]


def tree_base(c: Case) -> None:
    """The organisation delegates to a planner, which delegates to a worker and a
    sibling; the worker delegates to a sub-worker."""
    for identifier in (ORG, PLANNER, WORKER, SUB, SIBLING):
        c.register(identifier, at("08:00"))
    c.grant("g-planner", None, ORG, PLANNER, at("09:00"))
    c.grant("g-worker", "g-planner", PLANNER, WORKER, at("09:10"))
    c.grant("g-sibling", "g-planner", PLANNER, SIBLING, at("09:20"))
    c.grant("g-sub", "g-worker", WORKER, SUB, at("09:30"))


GROUNDS = "the planner's credential was used outside its task"
DISPUTE_GROUNDS = "the task log shows the planner acted inside its task"


def _revoke_planner(c: Case, effective: str = "12:00", issued: str = "12:00") -> None:
    c.revoke("r-planner", "g-planner", ORG, GROUNDS, at(effective), at(issued))


def _worker_presents(c: Case, when: str = "13:00") -> None:
    c.present(WORKER, ["g-planner", "g-worker"], at(when))


def t_chain_valid(c: Case) -> None:
    tree_base(c)
    _worker_presents(c)


def t_parent_revoked(c: Case) -> None:
    tree_base(c)
    _revoke_planner(c)
    _worker_presents(c)


def t_before_revocation(c: Case) -> None:
    tree_base(c)
    _revoke_planner(c)
    _worker_presents(c, "11:00")


def t_sibling(c: Case) -> None:
    tree_base(c)
    c.revoke("r-worker", "g-worker", PLANNER, "the worker's task was cancelled", at("12:00"),
             at("12:00"))
    c.present(SIBLING, ["g-planner", "g-sibling"], at("13:00"))


def t_grandchild(c: Case) -> None:
    tree_base(c)
    _revoke_planner(c)
    c.present(SUB, ["g-planner", "g-worker", "g-sub"], at("13:00"))


def t_child_revoked_parent_presents(c: Case) -> None:
    tree_base(c)
    c.revoke("r-worker", "g-worker", PLANNER, "the worker's task was cancelled", at("12:00"),
             at("12:00"))
    c.present(PLANNER, ["g-planner"], at("13:00"))


def t_backdated(c: Case) -> None:
    tree_base(c)
    _revoke_planner(c, effective="10:00", issued="14:00")
    _worker_presents(c)


def t_without_standing(c: Case) -> None:
    tree_base(c)
    c.revoke("r-worker", "g-worker", SIBLING, "the sibling objects to the worker", at("12:00"),
             at("12:00"))
    _worker_presents(c)


def t_incomplete(c: Case) -> None:
    tree_base(c)
    c.revoke("r-planner", "g-planner", ORG, "", at("12:00"), at("12:00"))
    _worker_presents(c)


def _disputed(c: Case, filed_by: str = WORKER) -> None:
    tree_base(c)
    _revoke_planner(c)
    c.dispute("d-planner", "r-planner", filed_by, DISPUTE_GROUNDS, at("12:30"))


def t_dispute_open(c: Case) -> None:
    _disputed(c)
    _worker_presents(c)


def _restored(c: Case) -> None:
    _disputed(c, filed_by=PLANNER)
    c.grant("g-planner-2", None, ORG, PLANNER, at("12:45"))
    c.resolve("d-planner", "r-planner", ORG, "restored", at("12:45"), replacement="g-planner-2")


def t_restored_by_new_grant(c: Case) -> None:
    _restored(c)
    c.present(PLANNER, ["g-planner-2"], at("13:00"))


def t_revoked_chain_after_restoration(c: Case) -> None:
    _restored(c)
    c.present(PLANNER, ["g-planner"], at("13:00"))


def t_cascade_victim(c: Case) -> None:
    _restored(c)
    c.present(WORKER, ["g-planner-2", "g-worker"], at("13:00"))


def t_cascade_victim_reissued(c: Case) -> None:
    _restored(c)
    c.grant("g-worker-2", "g-planner-2", PLANNER, WORKER, at("12:50"))
    c.present(WORKER, ["g-planner-2", "g-worker-2"], at("13:00"))


def t_dispute_confirmed(c: Case) -> None:
    _disputed(c)
    c.resolve("d-planner", "r-planner", ORG, "confirmed", at("12:45"))
    _worker_presents(c)


def t_resolution_without_standing(c: Case) -> None:
    _disputed(c)
    c.resolve("d-planner", "r-planner", WORKER, "restored", at("12:45"))
    _worker_presents(c)


def t_conflicting_revocations(c: Case) -> None:
    tree_base(c)
    c.revoke("r-worker-planner", "g-worker", PLANNER, "the worker's task was cancelled",
             at("12:00"), at("12:00"))
    c.revoke("r-worker-org", "g-worker", ORG, "the worker is retired at the end of the day",
             at("15:00"), at("12:10"))
    _worker_presents(c)


def t_grant_tampered(c: Case) -> None:
    tree_base(c)
    _worker_presents(c)
    for name, data in c.records:
        if "g-worker" in name:
            env = json.loads(data)
            body = json.loads(base64.b64decode(env["payload"]))
            body["issued_at"] = at("08:30")
            env["payload"] = _b64(canonical(body))
            c.replace("g-worker", canonical(env))


def t_unattested(c: Case) -> None:
    tree_base(c)
    c.present(WORKER, ["g-planner", "g-worker"], at("13:00"), signers=[of(WORKER)])


def t_chain_skips(c: Case) -> None:
    tree_base(c)
    c.present(SUB, ["g-planner", "g-sub"], at("13:00"))


def t_malformed(c: Case) -> None:
    tree_base(c)
    _worker_presents(c)
    c.replace("g-sibling", b'{"payload": ')


def t_forged_revocation(c: Case) -> None:
    tree_base(c)
    c.revoke("r-planner", "g-planner", ORG, GROUNDS, at("12:00"), at("12:00"),
             signer=posing_as(INTRUDER, ORG))
    _worker_presents(c)


def t_root_not_trusted(c: Case) -> None:
    tree_base(c)
    c.grant("g-self", None, PLANNER, WORKER, at("09:40"))
    c.present(WORKER, ["g-self"], at("13:00"))


def rereg_base(c: Case, link: bool = True, retire: bool = True) -> None:
    """The organisation grants to agent-v1, which is re-registered as agent-v2."""
    c.register(ORG, at("08:00"))
    c.register(V1, at("08:00"))
    c.register(V2, at("10:00"))
    c.grant("g-agent", None, ORG, V1, at("09:00"))
    if link:
        c.link("l-v1-v2", V1, V2, at("10:15"))
    if retire:
        c.retire(V1, at("10:30"))


def _v2_presents(c: Case) -> None:
    c.present(V2, ["g-agent"], at("13:00"))


def r_linked(c: Case) -> None:
    rereg_base(c)
    _v2_presents(c)


def r_no_link(c: Case) -> None:
    rereg_base(c, link=False)
    _v2_presents(c)


def r_wrong_key(c: Case) -> None:
    rereg_base(c, link=False, retire=False)
    c.link("l-v1-v2", V1, V2, at("10:15"),
           signers=[posing_as(_identity_key(V2), V1), of(V2), as_self(REGISTRY)])
    c.retire(V1, at("10:30"))
    _v2_presents(c)


def r_merge(c: Case) -> None:
    rereg_base(c)
    c.register(B1, at("08:00"))
    c.link("l-b1-v2", B1, V2, at("10:20"))
    _v2_presents(c)


def r_fork(c: Case) -> None:
    rereg_base(c)
    c.register(V2B, at("10:00"))
    c.link("l-v1-v2b", V1, V2B, at("10:20"))
    _v2_presents(c)


def r_link_after_revoked(c: Case) -> None:
    rereg_base(c, link=False, retire=False)
    c.revoke_identifier(V1, at("10:05"), "the agent-v1 key was reported compromised")
    c.link("l-v1-v2", V1, V2, at("10:15"))
    _v2_presents(c)


def _three_hops(c: Case, revoke_middle: bool) -> None:
    rereg_base(c)
    c.register(V3, at("11:00"))
    if revoke_middle:
        c.revoke_identifier(V2, at("11:05"), "the agent-v2 key was reported compromised")
    c.link("l-v2-v3", V2, V3, at("11:15"))
    c.retire(V2, at("11:30"))
    c.present(V3, ["g-agent"], at("13:00"))


def r_chain(c: Case) -> None:
    _three_hops(c, revoke_middle=False)


def r_chain_middle_revoked(c: Case) -> None:
    _three_hops(c, revoke_middle=True)


def r_old_after_retirement(c: Case) -> None:
    rereg_base(c)
    c.present(V1, ["g-agent"], at("13:00"))


def r_old_before_retirement(c: Case) -> None:
    rereg_base(c)
    c.present(V1, ["g-agent"], at("10:20"))


def r_revocation_follows(c: Case) -> None:
    rereg_base(c)
    c.revoke("r-agent", "g-agent", ORG, "the task the agent held was cancelled", at("12:00"),
             at("12:00"))
    _v2_presents(c)


def r_unattested_link(c: Case) -> None:
    rereg_base(c, link=False, retire=False)
    c.link("l-v1-v2", V1, V2, at("10:15"), signers=[of(V1), of(V2)])
    c.retire(V1, at("10:30"))
    _v2_presents(c)


SOFTWARE = "sha256:" + _sha(b"delegation-lifecycle/v1 test agent build 1")
OTHER_SOFTWARE = "sha256:" + _sha(b"delegation-lifecycle/v1 test agent build 2")
LOST = "the agent-v1 key was lost at redeployment"
COMPROMISED = "the agent-v1 key was reported compromised"


def recovery_base(c: Case, compromised: bool = False, history: bool = False,
                  software: str = SOFTWARE, recovery_signers: list[Signer] | None = None) -> None:
    """The organisation operates agent-v1 and grants to it. The agent-v1 key is lost,
    or reported compromised, and the same software is registered again as agent-v2.
    The registry and the organisation, as Responsible entity, sign a recovery record."""
    c.register(ORG, at("08:00"))
    c.register(V1, at("08:00"), responsible=ORG, software=SOFTWARE)
    c.grant("g-agent", None, ORG, V1, at("09:00"))
    if history:
        c.revoke("r-agent", "g-agent", ORG, "the agent acted outside its task", at("09:30"),
                 at("09:30"))
        c.dispute("d-agent", "r-agent", V1, "the task log shows the agent acted inside its task",
                  at("09:45"))
        c.resolve("d-agent", "r-agent", ORG, "confirmed", at("10:00"))
    if compromised:
        c.revoke_identifier(V1, at("10:05"), COMPROMISED)
    else:
        c.retire(V1, at("10:05"))
    c.register(V2, at("10:30"), responsible=ORG, software=software)
    c.recover("rc-v1-v2", V1, V2, ORG, at("11:00"), signers=recovery_signers)


def _regrant(c: Case) -> None:
    c.grant("g-agent-2", None, ORG, V2, at("11:30"))
    c.present(V2, ["g-agent-2"], at("13:00"))


def rc_regrant(c: Case) -> None:
    recovery_base(c)
    _regrant(c)


def rc_grant_not_carried(c: Case) -> None:
    recovery_base(c)
    _v2_presents(c)


def rc_registry_only(c: Case) -> None:
    recovery_base(c, recovery_signers=[as_self(REGISTRY)])
    _regrant(c)


def rc_software_mismatch(c: Case) -> None:
    recovery_base(c, software=OTHER_SOFTWARE)
    _regrant(c)


def rc_compromise_no_revival(c: Case) -> None:
    recovery_base(c, compromised=True)
    _v2_presents(c)


def rc_compromise_regrant(c: Case) -> None:
    recovery_base(c, compromised=True)
    _regrant(c)


def rc_history_follows(c: Case) -> None:
    recovery_base(c, history=True)
    _regrant(c)


ACCEPT, REJECT, NO_VERDICT = "accept", "reject", "no_verdict"

R_TIME = ("A revocation applies to a presentation the relying party observed at or after the "
          "revocation's effective_at; observed_at comes from the relying party's signature, "
          "never from the presenter.")
R_CASCADE = ("A presented chain fails when any grant in it is revoked, so a revocation cuts "
             "off every grant beneath the revoked one and nothing beside or above it.")
R_STANDING = ("Only the issuer of the revoked grant, or an issuer above it in the presented "
              "chain, has standing to revoke it; a revocation signed by anyone else is ignored.")
R_BACKDATED = ("Proposed: a revocation applies from its stated effective_at even when it was "
               "issued later, as an X.509 invalidity date does; this favours containment over "
               "a relying party's reliance on the earlier state.")
R_INCOMPLETE = ("Proposed: a revocation from a principal with standing that states no grounds "
                "still stops the authority, and the reason names the missing record field.")
R_DISPUTE = ("Proposed: a dispute filed by an affected principal, including one cut off by the "
             "cascade, does not suspend the revocation; until a resolution signed by a "
             "principal with standing exists, the reason says the dispute is open.")
R_RESTORE = ("A revocation is irreversible; a restoration is a new grant, which carries "
             "authority from its own issuance and does not revive the revoked grant.")
R_REVOKED_STAYS = ("A revocation is irreversible, so the revoked grant stays revoked after the "
                   "dispute is resolved in the principal's favour.")
R_CASCADE_RESTORE = ("Proposed: a restoration does not cascade; every principal cut off by the "
                     "revocation needs its own grant re-issued under the replacement, because "
                     "its old grant still names the revoked parent.")
R_CASCADE_REISSUED = ("A grant re-issued under the replacement grant forms a chain of its own "
                      "and carries authority.")
R_CONFIRMED = ("A resolution that confirms the revocation closes the dispute, and the "
               "revocation stands.")
R_RESOLUTION_STANDING = ("Proposed: a resolution counts only when its signer has standing to "
                         "revoke the grant, so a disputing principal cannot resolve its own "
                         "dispute.")
R_EARLIEST = ("When several revocations with standing name one grant, the earliest "
              "effective_at applies.")
R_SIGNATURE = ("A record counts only when its signature verifies under the key the registry "
               "bound to its signer; a grant on the presented chain that fails is named.")
R_FORGED = ("A revocation whose signature does not verify counts as absent, so a forged "
            "revocation stops nothing.")
R_ATTESTED = ("A presentation needs the presenter's signature and the relying party's "
              "signature; the relying party's signature is what fixes observed_at.")
R_CHAIN = ("Each grant's parent is the grant before it in the chain and its issuer is that "
           "grant's delegate.")
R_ROOT = "The first grant of a chain must be issued by a root the policy trusts."
R_MALFORMED = ("A record that is not a DSSE envelope over a JSON object of a known type gives "
               "no verdict.")
R_VALID = ("A chain whose every grant verifies, links to its parent and is unrevoked at "
           "observed_at, held by its last delegate, carries authority.")
R_LINK = ("A grant held by an old identifier is held by its successor when a link names old "
          "and new and carries signatures by the old identifier's key, the new identifier's "
          "key and the registry.")
R_NO_LINK = "Without a link, a new identifier holds nothing an old identifier held."
R_LINK_KEY = ("The old identifier's signature on a link must verify under the key the registry "
              "bound to the old identifier; the new identifier cannot sign for it.")
R_LINK_REGISTRY = ("A link needs the registry's signature, because that signature is what "
                   "makes linked_at trustworthy.")
R_MERGE = ("Proposed: a link is one to one; two old identifiers linked to one new one would "
           "merge two principals' authority, which needs a new grant, so it is rejected.")
R_FORK = ("Proposed: one old identifier linked to two new ones leaves the successor "
          "ambiguous, so it is rejected.")
R_LINK_INACTIVE = ("A link counts only when the registry had neither retired nor revoked the "
                   "old identifier at linked_at, so a key revoked for compromise cannot pass "
                   "its authority on.")
R_LINK_HOPS = ("Links are followed one hop at a time, and every hop is checked as a link of "
               "its own.")
R_PRESENTER = ("A presenter whose identifier the registry retired or revoked at or before "
               "observed_at holds nothing.")
R_BEFORE_RETIRE = ("Proposed: an old identifier stays usable until the registry retires it; a "
                   "link alone does not end it.")
R_FOLLOWS = ("A link carries a grant as it stands, so a revocation of the grant applies to the "
             "successor as well.")
R_RECOVERY_REGRANT = ("A new grant to the recovered identifier carries authority from its own "
                      "issuance.")
R_RECOVERY_NO_GRANT = ("Proposed: a recovery record carries history, not authority; a grant "
                       "reaches a new identifier only through a link signed by the old key, or "
                       "through a new grant.")
R_RECOVERY_SIGNERS = ("Proposed: a recovery record needs the registry's signature and the "
                      "Responsible entity's, so the registry alone cannot move an agent's "
                      "history, and a presenter named by a recovery record that fails is "
                      "refused because its history cannot be resolved.")
R_RECOVERY_MATCH = ("Proposed: a recovery counts only when the registry registered the old and "
                    "the new identifier to the same Responsible entity with the same software "
                    "attestation digest.")
R_RECOVERY_NO_REVIVAL = ("Proposed: a recovery never restores authority, including authority the "
                         "registry removed by revoking the old identifier for compromise.")
R_RECOVERY_HISTORY = ("Proposed: adverse records of the old identifier (an identifier revocation, "
                      "a revocation of a grant made to it, its disputes and their resolutions) "
                      "resolve from the successor through the recovery record, and the "
                      "acceptance names that history.")


class Spec(NamedTuple):
    """One case: its identifier, set, builder, expected outcome, twin and texts."""

    name: str
    family: str
    build: Callable[[Case], None]
    decision: str
    reason: str
    situation: str
    rule: str
    twin: str = ""


TREE_TWIN, REREG_TWIN = "tree-chain-valid", "rereg-linked-successor"
RECOVERY_TWIN = "recovery-regrant"

CASES: tuple[Spec, ...] = (
    Spec("tree-chain-valid", TREE, t_chain_valid, ACCEPT, "authority_valid",
         "The worker presents its grant and the planner's grant above it, and nothing is "
         "revoked.", R_VALID),
    Spec("tree-parent-revoked-child-presented", TREE, t_parent_revoked, REJECT, "grant_revoked",
         "The organisation revokes the planner's grant at 12:00 and the worker presents its "
         "child grant at 13:00.", R_CASCADE, "tree-child-presented-before-revocation"),
    Spec("tree-child-presented-before-revocation", TREE, t_before_revocation, ACCEPT,
         "authority_valid",
         "The same revocation, and the relying party observed the worker's presentation at "
         "11:00, before it took effect.", R_TIME),
    Spec("tree-sibling-of-revoked-child", TREE, t_sibling, ACCEPT, "authority_valid",
         "The planner revokes the worker's grant and the sibling presents its own grant from "
         "the same planner.", R_CASCADE),
    Spec("tree-grandchild-under-revoked-parent", TREE, t_grandchild, REJECT, "grant_revoked",
         "The organisation revokes the planner's grant and the sub-worker, two levels below, "
         "presents its chain.", R_CASCADE, "tree-chain-valid"),
    Spec("tree-child-revocation-keeps-parent", TREE, t_child_revoked_parent_presents, ACCEPT,
         "authority_valid",
         "The planner revokes the worker's grant and the planner presents its own grant.",
         R_CASCADE),
    Spec("tree-revocation-backdated", TREE, t_backdated, REJECT, "grant_revoked",
         "A revocation issued at 14:00 states it took effect at 10:00, and the presentation "
         "was observed at 13:00.", R_BACKDATED, "tree-child-presented-before-revocation"),
    Spec("tree-revocation-without-standing", TREE, t_without_standing, ACCEPT, "authority_valid",
         "The sibling signs a revocation of the worker's grant and the worker presents.",
         R_STANDING),
    Spec("tree-revocation-incomplete", TREE, t_incomplete, REJECT, "revocation_incomplete",
         "The organisation revokes the planner's grant without stating grounds and the worker "
         "presents.", R_INCOMPLETE, "tree-chain-valid"),
    Spec("tree-dispute-open", TREE, t_dispute_open, REJECT, "grant_revoked_dispute_open",
         "The worker, cut off by the revocation of the planner's grant, files a dispute at "
         "12:30 and presents at 13:00 with no resolution.", R_DISPUTE, "tree-chain-valid"),
    Spec("tree-dispute-restored-by-new-grant", TREE, t_restored_by_new_grant, ACCEPT,
         "authority_valid",
         "The planner disputes, the organisation resolves the dispute in its favour and issues "
         "a replacement grant, and the planner presents the replacement.", R_RESTORE),
    Spec("tree-revoked-grant-after-restoration", TREE, t_revoked_chain_after_restoration,
         REJECT, "grant_revoked",
         "After the restoration the planner presents the old, revoked grant.", R_REVOKED_STAYS,
         "tree-dispute-restored-by-new-grant"),
    Spec("tree-cascade-victim-after-restoration", TREE, t_cascade_victim, REJECT,
         "chain_broken",
         "After the restoration the worker presents its old grant under the planner's "
         "replacement grant.", R_CASCADE_RESTORE, "tree-cascade-victim-reissued"),
    Spec("tree-cascade-victim-reissued", TREE, t_cascade_victim_reissued, ACCEPT,
         "authority_valid",
         "The planner re-issues the worker's grant under the replacement and the worker "
         "presents the new chain.", R_CASCADE_REISSUED),
    Spec("tree-dispute-confirmed", TREE, t_dispute_confirmed, REJECT, "grant_revoked",
         "The organisation resolves the worker's dispute by confirming the revocation, and the "
         "worker presents.", R_CONFIRMED, "tree-chain-valid"),
    Spec("tree-resolution-without-standing", TREE, t_resolution_without_standing, REJECT,
         "grant_revoked_dispute_open",
         "The worker signs a resolution of its own dispute that restores the grant, and "
         "presents.", R_RESOLUTION_STANDING, "tree-chain-valid"),
    Spec("tree-conflicting-revocations", TREE, t_conflicting_revocations, REJECT,
         "grant_revoked",
         "The planner revokes the worker's grant from 12:00, the organisation revokes it from "
         "15:00, and the worker presents at 13:00.", R_EARLIEST, "tree-chain-valid"),
    Spec("tree-grant-tampered", TREE, t_grant_tampered, REJECT, "signature_invalid:grant",
         "The worker's grant was edited after the planner signed it.", R_SIGNATURE,
         "tree-chain-valid"),
    Spec("tree-revocation-forged", TREE, t_forged_revocation, ACCEPT, "authority_valid",
         "A revocation of the planner's grant names the organisation and is signed by a key "
         "the registry never bound to it.", R_FORGED),
    Spec("tree-presentation-unattested", TREE, t_unattested, REJECT,
         "signature_invalid:presentation",
         "The worker signs its presentation and the relying party does not.", R_ATTESTED,
         "tree-chain-valid"),
    Spec("tree-chain-skips-a-grant", TREE, t_chain_skips, REJECT, "chain_broken",
         "The sub-worker presents its grant directly under the planner's grant, leaving out "
         "the worker's.", R_CHAIN, "tree-chain-valid"),
    Spec("tree-root-not-trusted", TREE, t_root_not_trusted, REJECT, "chain_broken",
         "The planner issues a top-level grant to the worker on its own authority.", R_ROOT,
         "tree-chain-valid"),
    Spec("tree-record-not-json", TREE, t_malformed, NO_VERDICT, "malformed_record",
         "One record file in the set is not JSON.", R_MALFORMED, "tree-chain-valid"),
    Spec("rereg-linked-successor", REREG, r_linked, ACCEPT, "authority_valid_via_link",
         "agent-v1 is re-registered as agent-v2 with a link signed by both keys and the "
         "registry, agent-v1 is retired, and agent-v2 presents agent-v1's grant.", R_LINK),
    Spec("rereg-no-link", REREG, r_no_link, REJECT, "presenter_not_delegate",
         "agent-v2 presents agent-v1's grant and no link names them.", R_NO_LINK, REREG_TWIN),
    Spec("rereg-link-signed-by-wrong-key", REREG, r_wrong_key, REJECT, "signature_invalid:link",
         "The link's agent-v1 signature is made with agent-v2's key.", R_LINK_KEY, REREG_TWIN),
    Spec("rereg-link-not-registry-attested", REREG, r_unattested_link, REJECT,
         "signature_invalid:link",
         "The link carries both agents' signatures and not the registry's.", R_LINK_REGISTRY,
         REREG_TWIN),
    Spec("rereg-two-old-one-new", REREG, r_merge, REJECT, "link_conflict",
         "agent-v1 and a second agent, agent-b-v1, are both linked to agent-v2, which presents "
         "agent-v1's grant.", R_MERGE, REREG_TWIN),
    Spec("rereg-one-old-two-new", REREG, r_fork, REJECT, "link_conflict",
         "agent-v1 is linked to agent-v2 and to agent-v2b, and agent-v2 presents.", R_FORK,
         REREG_TWIN),
    Spec("rereg-link-after-old-revoked", REREG, r_link_after_revoked, REJECT,
         "link_old_inactive",
         "The registry revokes agent-v1 for key compromise at 10:05 and a link to agent-v2 is "
         "made at 10:15.", R_LINK_INACTIVE, REREG_TWIN),
    Spec("rereg-chain-old-middle-new", REREG, r_chain, ACCEPT, "authority_valid_via_link",
         "agent-v1 is linked to agent-v2, agent-v2 to agent-v3, and agent-v3 presents "
         "agent-v1's grant.", R_LINK_HOPS),
    Spec("rereg-chain-middle-revoked", REREG, r_chain_middle_revoked, REJECT,
         "link_old_inactive",
         "The registry revokes agent-v2 before the agent-v2 to agent-v3 link is made, and "
         "agent-v3 presents.", R_LINK_HOPS, "rereg-chain-old-middle-new"),
    Spec("rereg-old-presents-after-retirement", REREG, r_old_after_retirement, REJECT,
         "presenter_inactive",
         "agent-v1 presents its own grant after the registry retired it.", R_PRESENTER,
         "rereg-old-presents-before-retirement"),
    Spec("rereg-old-presents-before-retirement", REREG, r_old_before_retirement, ACCEPT,
         "authority_valid",
         "agent-v1 presents its own grant after the link and before its retirement.",
         R_BEFORE_RETIRE),
    Spec("rereg-revocation-follows-link", REREG, r_revocation_follows, REJECT, "grant_revoked",
         "The organisation revokes agent-v1's grant and agent-v2 presents it through the link.",
         R_FOLLOWS, REREG_TWIN),
    Spec("recovery-regrant", RECOVERY, rc_regrant, ACCEPT, "authority_valid",
         "The agent-v1 key is lost, the registry retires agent-v1, the registry and the "
         "organisation sign a recovery record to agent-v2, and the organisation grants agent-v2 "
         "anew, which agent-v2 presents.", R_RECOVERY_REGRANT),
    Spec("recovery-grant-not-carried", RECOVERY, rc_grant_not_carried, REJECT,
         "presenter_not_delegate",
         "After the same recovery, agent-v2 presents agent-v1's grant.", R_RECOVERY_NO_GRANT,
         RECOVERY_TWIN),
    Spec("recovery-registry-only", RECOVERY, rc_registry_only, REJECT,
         "signature_invalid:recovery",
         "The recovery record carries the registry's signature and not the organisation's, and "
         "agent-v2 presents its new grant.", R_RECOVERY_SIGNERS, RECOVERY_TWIN),
    Spec("recovery-software-mismatch", RECOVERY, rc_software_mismatch, REJECT,
         "recovery_mismatch",
         "The registry registered agent-v2 with a software attestation digest that differs from "
         "agent-v1's, and agent-v2 presents its new grant.", R_RECOVERY_MATCH, RECOVERY_TWIN),
    Spec("recovery-after-compromise-no-revival", RECOVERY, rc_compromise_no_revival, REJECT,
         "presenter_not_delegate",
         "The registry revokes agent-v1 for key compromise, a recovery record names agent-v2, "
         "and agent-v2 presents agent-v1's grant.", R_RECOVERY_NO_REVIVAL,
         "recovery-after-compromise-regrant"),
    Spec("recovery-after-compromise-regrant", RECOVERY, rc_compromise_regrant, ACCEPT,
         "authority_valid_with_history",
         "The registry revokes agent-v1 for key compromise, a recovery record names agent-v2, "
         "and the organisation grants agent-v2 anew, which agent-v2 presents.",
         R_RECOVERY_HISTORY),
    Spec("recovery-history-follows", RECOVERY, rc_history_follows, ACCEPT,
         "authority_valid_with_history",
         "agent-v1's grant was revoked, agent-v1 disputed the revocation and the organisation "
         "confirmed it; after the key is lost and recovered to agent-v2, agent-v2 presents a new "
         "grant.", R_RECOVERY_HISTORY),
)


def policy() -> dict[str, Any]:
    return {
        "payload_type": PAYLOAD_TYPE,
        "registry_key": {"keyid": keyid(REGISTRY), "public_key": _b64(public_raw(REGISTRY))},
        "relying_party_key": {"keyid": keyid(RELYING_PARTY),
                              "public_key": _b64(public_raw(RELYING_PARTY))},
        "roots": [ORG],
    }


def _write_case(root: Path, name: str, c: Case) -> dict[str, str]:
    directory = root / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.iterdir():
        stale.unlink()
    files: dict[str, bytes] = dict(c.records)
    files["presentation.json"] = c.presentation
    files["case.json"] = _pretty({"policy": policy(), "records": [n for n, _ in c.records],
                                  "presentation": "presentation.json"})
    for file, data in files.items():
        (directory / file).write_bytes(data)
    return {file: _sha(data) for file, data in sorted(files.items())}


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Delegation lifecycle cases", "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.", "",
        f"Suite: `{SUITE}`. Payload type: `{PAYLOAD_TYPE}`", "",
        f"Registry test keyid: `{keyid(REGISTRY)}`", "",
        f"Relying party test keyid: `{keyid(RELYING_PARTY)}`", "",
        f"Corpus digest: `{digest}`", "",
    ]
    titles = {TREE: "Revocation across a delegation tree", REREG: "Re-registration",
              RECOVERY: "Recovery after a lost or compromised key"}
    for family in (TREE, REREG, RECOVERY):
        lines += [f"## {titles[family]}", "",
                  "| id | outcome | reason | situation | rule |",
                  "| --- | --- | --- | --- | --- |"]
        for e in entries:
            if e["set"] != family:
                continue
            x = e["expected"]
            lines.append(f"| `{e['id']}` | {x['decision']} | `{x['reason']}` | "
                         f"{e['description']} | {e['rule']} |")
        lines.append("")
    return ("\n".join(lines)).encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest and the index."""
    entries = []
    for spec in CASES:
        c = Case()
        spec.build(c)
        entry: dict[str, Any] = {
            "id": spec.name, "set": spec.family, "path": f"cases/{spec.name}",
            "files": _write_case(root, spec.name, c), "description": spec.situation,
            "rule": spec.rule, "expected": {"decision": spec.decision, "reason": spec.reason},
        }
        if spec.decision != ACCEPT:
            entry["twin"] = spec.twin
        entries.append(entry)
    digest = _sha(_pretty(entries))
    manifest = {"suite": SUITE, "payloadType": PAYLOAD_TYPE, "vectors": entries,
                "registryKeyid": keyid(REGISTRY), "relyingPartyKeyid": keyid(RELYING_PARTY),
                "corpusDigest": digest}
    (root / "MANIFEST.json").write_bytes(_pretty(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
