"""Judge the delegation lifecycle corpus (corpora/vectors-delegation-lifecycle/).

A member is one question a relying party asks about an AI agent: does this
presenter hold this delegated authority at the time the relying party observed
the presentation? The member is a set of signed records (identifier
registrations, grants, revocations, disputes, resolutions, identifier links,
retirements, recoveries, successions) plus one signed presentation, under a
policy that pins the payload type, the registry's key, the relying party's key
and the trusted roots. Every record is a DSSE v1 envelope signed with Ed25519.

The reader names the first check that fails, in this order:

1. every record parses as a DSSE envelope over a JSON object of a known type
   with the fields that type needs (else no verdict, ``malformed_record``);
2. the presentation carries the presenter's signature and the relying party's
   (``signature_invalid:presentation``);
3. each grant on the presented chain verifies under its issuer's registered
   key (``signature_invalid:grant``), names the grant before it as its parent,
   and the first is issued by a trusted root (``chain_broken``);
4. the registry had not retired or revoked the presenter at ``observed_at``
   (``presenter_inactive``), and, for a sub-agent whose registration names a
   parent, had not retired or revoked that parent or any parent above it
   (``parent_inactive``); a parent's recovery or succession does not carry its
   sub-agents to the successor;
5. the presenter is the last grant's delegate, or reaches it through links that
   are one to one (``link_conflict``), signed by both identifiers and the
   registry (``signature_invalid:link``), and made while the old identifier was
   active (``link_old_inactive``); otherwise ``presenter_not_delegate``;
6. no grant on the chain carries a revocation, signed by a principal with
   standing, whose ``effective_at`` is at or before ``observed_at``
   (``revocation_incomplete`` when it states no grounds,
   ``grant_revoked_dispute_open`` while an affected principal's dispute has no
   resolution with standing, ``grant_revoked`` otherwise);
7. every recovery record that names the presenter as its new identifier is
   signed by the registry and the Responsible entity
   (``signature_invalid:recovery``), and the registry registered both
   identifiers to that entity, or to its predecessor under a recorded
   responsible succession, with one software attestation digest
   (``recovery_mismatch``); the registry's own succession records are followed
   the same way;
8. no retired or revoked agent of the presenter's Responsible entity and
   software is left unjoined to the presenter by a succession or recovery
   record (``succession_unrecorded``).

Neither a recovery nor a succession record carries a grant. An accepted
presenter whose predecessors, or whose parent's predecessors, left adverse
records is accepted with ``authority_valid_with_history``, or with
``authority_valid_with_history_contested`` when the Responsible entity asserted
that the presenter is a new agent. A record whose signature does not verify
counts as absent. The corpus README states each rule and which of them are
proposals.

The rules are restated in Go in ``corpusreaders/delegationlifecycle.go``. The two are
kept apart on purpose, and ``render`` prints the lines ``aee-verify`` prints, so
the two rails can be diffed.

Standard library only, so the installed package judges the corpus offline. The
Ed25519 is the reference rail's own, borrowed at call time.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

SUITE = "delegation-lifecycle/v1"
ACCEPT, REJECT, NO_VERDICT = "accept", "reject", "no_verdict"
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-delegation-lifecycle" if
        (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-delegation-lifecycle")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)

# Every rule the reader applies, by the name the mutation check switches off.
RULES = (
    "signature", "relying_party_attestation", "link_registry_attestation", "chain",
    "presenter_active", "links", "link_conflict", "link_old_active", "revocation",
    "revocation_time", "standing", "revocation_complete", "dispute", "resolution",
    "resolution_standing", "recovery_no_authority", "recovery_signature", "recovery_match",
    "recovery_history", "succession_recorded", "new_agent_assertion", "responsible_succession",
    "parent_lifespan", "parent_not_carried", "succession_no_authority", "parent_history",
)

# For each record type, the text fields it must carry non-empty and the time
# fields it must carry as RFC 3339. A field outside these lists is ignored.
REQUIRED: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "registration": (("identifier", "keyid", "public_key"), ("registered_at",)),
    "retirement": (("identifier",), ("retired_at",)),
    "identifier-revocation": (("identifier",), ("revoked_at",)),
    "grant": (("grant_id", "issuer", "delegate"), ("issued_at",)),
    "revocation": (("revocation_id", "grant_id", "initiator"), ("effective_at", "issued_at")),
    "dispute": (("dispute_id", "revocation_id", "filed_by"), ("filed_at",)),
    "resolution": (("dispute_id", "revocation_id", "decided_by", "outcome"), ("decided_at",)),
    "link": (("link_id", "old", "new"), ("linked_at",)),
    "recovery": (("recovery_id", "old", "new", "responsible"), ("recovered_at",)),
    "succession": (("succession_id", "old", "new", "responsible"), ("recorded_at",)),
    "new-agent-assertion": (
        ("assertion_id", "identifier", "succession_id", "responsible", "grounds"),
        ("asserted_at",)),
    "responsible-succession": (
        ("record_id", "old_responsible", "new_responsible"), ("succeeded_at",)),
    "presentation": (("presenter",), ("observed_at",)),
}

# The record types whose own principal signs them, and the field naming that principal.
SELF_SIGNED = {
    "grant": "issuer", "revocation": "initiator", "dispute": "filed_by",
    "resolution": "decided_by", "new-agent-assertion": "responsible",
}

# RFC 3339 as Go's time.Parse reads it: ASCII digits, a dot before any fraction,
# a ``Z`` or a numeric offset.
_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to
    dispatch the suite, so a module-level import would be a cycle."""
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
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


@lru_cache(maxsize=16384)
def _ed25519_verify(key: bytes, message: bytes, sig: bytes) -> bool:
    """The rail's pure-Python Ed25519, memoised: it is deterministic and slow, and
    the mutation sweep asks the same question once per rule."""
    return bool(_rail().ed25519_verify(key, message, sig))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def _b64(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def _read_in(directory: str | Path, rel: str) -> bytes:
    """Read a corpus-relative path; a leading slash stays relative, as in Go."""
    return Path(os.path.normpath(os.path.join(directory, rel.lstrip("/")))).read_bytes()


def _reject_constant(token: str) -> Any:
    raise ValueError(f"{token} is not JSON")


def _loads(raw: bytes) -> Any:
    """Parse JSON as Go does: invalid UTF-8 is replaced, NaN and Infinity are refused."""
    return json.loads(raw.decode("utf-8", errors="replace"), parse_constant=_reject_constant)


# ---------------------------------------------------------------------------
# Times, held as integer nanoseconds since the epoch so that instants in
# different zones compare as instants.
# ---------------------------------------------------------------------------


def _leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in(year: int, month: int) -> int:
    if month == 2:
        return 29 if _leap(year) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    return era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + doy - 719468


def parse_time(text: str) -> int | None:
    """Nanoseconds since the epoch for an RFC 3339 time, or None when it does not parse."""
    match = _TIME.fullmatch(text)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    if not (1 <= month <= 12 and 1 <= day <= _days_in(year, month)
            and hour <= 23 and minute <= 59 and second <= 59):
        return None
    nanos = int((match.group(7) or "0")[:9].ljust(9, "0"))
    seconds = _days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
    if match.group(8):
        offset_hour, offset_minute = int(match.group(9)), int(match.group(10))
        if offset_hour > 23 or offset_minute > 59:
            return None
        offset = (offset_hour * 60 + offset_minute) * 60
        seconds -= offset if match.group(8) == "+" else -offset
    return seconds * 1_000_000_000 + nanos


# ---------------------------------------------------------------------------
# Records.
# ---------------------------------------------------------------------------


@dataclass
class Record:
    """One parsed envelope. Times are parsed once, here, so that a record whose
    time does not parse is a malformed record and never a comparison against zero."""

    kind: str
    fields: dict[str, Any]
    payload: bytes
    sigs: list[tuple[str, bytes]]
    times: dict[str, int] = field(default_factory=dict)
    verified: bool = False

    def text(self, name: str) -> str:
        value = self.fields.get(name)
        return value if isinstance(value, str) else ""


def _parse_envelope(raw: bytes) -> tuple[str, bytes, list[tuple[str, bytes]]] | None:
    """(payloadType, payload, [(keyid, sig)]) for a DSSE envelope, or None."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        return None
    try:
        doc = _loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    payload_type, entries = doc.get("payloadType"), doc.get("signatures")
    if not isinstance(payload_type, str) or not payload_type:
        return None
    if not isinstance(entries, list) or not entries:
        return None
    sigs = []
    for entry in entries:
        keyid = entry.get("keyid") if isinstance(entry, dict) else None
        sig = _b64(entry.get("sig")) if isinstance(entry, dict) else None
        if not isinstance(keyid, str) or sig is None:
            return None
        sigs.append((keyid, sig))
    body = _b64(doc.get("payload"))
    return None if body is None else (payload_type, body, sigs)


def _parse_record(directory: str | Path, name: str, payload_type: str) -> Record | None:
    try:
        raw = _read_in(directory, name)
    except OSError:
        return None
    envelope = _parse_envelope(raw)
    if envelope is None or envelope[0] != payload_type:
        return None
    try:
        fields = _loads(envelope[1])
    except (ValueError, RecursionError):
        return None
    if not isinstance(fields, dict):
        return None
    record = Record("", fields, envelope[1], envelope[2])
    record.kind = record.text("type")
    required = REQUIRED.get(record.kind)
    if required is None or any(record.text(f) == "" for f in required[0]):
        return None
    for name_ in required[1]:
        parsed = parse_time(record.text(name_))
        if parsed is None:
            return None
        record.times[name_] = parsed
    return record


def _public_key(key: Any) -> bytes | None:
    """The raw key a policy key entry names, when its keyid is the key's SHA-256."""
    if not isinstance(key, dict):
        return None
    raw = _b64(key.get("public_key"))
    if raw is None or len(raw) != 32 or _sha(raw) != key.get("keyid"):
        return None
    return raw


# ---------------------------------------------------------------------------
# The decision.
# ---------------------------------------------------------------------------


class _State:
    def __init__(self, policy: dict[str, Any], skip: frozenset[str]) -> None:
        self.policy = policy
        self.payload_type = str(policy.get("payload_type", ""))
        self.skip = skip
        self.records: list[Record] = []
        self.keys: dict[str, list[bytes]] = {}
        self.via_link = False

    def off(self, rule: str) -> bool:
        return rule in self.skip

    # -- signatures ---------------------------------------------------------

    def signed_by(self, record: Record, keys: list[bytes]) -> bool:
        """Some signature on the record names one of the keys by its keyid and
        verifies over the DSSE pre-authentication encoding."""
        message = pae(self.payload_type, record.payload)
        for key in keys:
            kid = _sha(key)
            for sig_kid, sig in record.sigs:
                if sig_kid == kid and _ed25519_verify(key, message, sig):
                    return True
        return False

    def registry_keys(self) -> list[bytes]:
        key = _public_key(self.policy.get("registry_key"))
        return [] if key is None else [key]

    def bind_keys(self) -> None:
        """Read the registrations the registry signed into the key table."""
        self.keys = {}
        registry = self.registry_keys()
        for r in self.records:
            if r.kind != "registration":
                continue
            key = _public_key({"keyid": r.text("keyid"), "public_key": r.text("public_key")})
            if key is not None and (self.off("signature") or self.signed_by(r, registry)):
                self.keys.setdefault(r.text("identifier"), []).append(key)

    def verify(self, r: Record) -> bool:
        """Whether a record carries the signatures its type needs: the registry's
        for what the registry records, the signer's own registered key for what a
        principal asserts, and several for a link, a recovery or a hand-over."""
        if self.off("signature"):
            return True
        if r.kind in SELF_SIGNED:
            return self.signed_by(r, self.keys.get(r.text(SELF_SIGNED[r.kind]), []))
        registry = self.signed_by(r, self.registry_keys())
        if r.kind in ("registration", "retirement", "identifier-revocation", "succession"):
            return registry
        if r.kind == "link":
            registered = self.off("link_registry_attestation") or registry
            return (registered and self.signed_by(r, self.keys.get(r.text("old"), []))
                    and self.signed_by(r, self.keys.get(r.text("new"), [])))
        if r.kind == "recovery":
            return registry and (self.off("recovery_signature") or self.signed_by(
                r, self.keys.get(r.text("responsible"), [])))
        if r.kind == "responsible-succession":
            return registry and self.signed_by(r, self.keys.get(r.text("old_responsible"), []))
        return False

    # -- the eight checks, in order -----------------------------------------

    def decide(self, p: Record) -> tuple[str, str]:
        self.bind_keys()
        for r in self.records:
            r.verified = self.verify(r)
        if not self.presentation_attested(p):
            return REJECT, "signature_invalid:presentation"
        chain, reason = self.chain(p)
        if reason:
            return REJECT, reason
        reason = self.standing_checks(p, chain)
        if reason:
            return REJECT, reason
        return self.history_and_acceptance(p, chain)

    def standing_checks(self, p: Record, chain: list[Record]) -> str:
        """Checks 4 to 6; the reason for the first that fails, or ''."""
        presenter, observed = p.text("presenter"), p.times["observed_at"]
        if not self.off("presenter_active") and self.inactive(presenter, observed):
            return "presenter_inactive"
        if self.parent_ended(presenter, observed, set()):
            return "parent_inactive"
        self.via_link, reason = self.holder(chain[-1].text("delegate"), presenter)
        return reason or self.revoked(chain, presenter, observed)

    def history_and_acceptance(self, p: Record, chain: list[Record]) -> tuple[str, str]:
        """Checks 7 and 8, then the accepting reason."""
        presenter = p.text("presenter")
        history, contested, reason = self.recovered(presenter)
        if reason:
            return REJECT, reason
        inherited, reason = self.parent_history(presenter)
        if reason:
            return REJECT, reason
        history = history or inherited
        if not self.off("succession_recorded") and self.unjoined(presenter):
            return REJECT, "succession_unrecorded"
        if self.via_link:
            return ACCEPT, "authority_valid_via_link"
        if contested:
            return ACCEPT, "authority_valid_with_history_contested"
        return ACCEPT, "authority_valid_with_history" if history else "authority_valid"

    # -- presentation and chain ---------------------------------------------

    def presentation_attested(self, p: Record) -> bool:
        if not self.off("signature") and not self.signed_by(
                p, self.keys.get(p.text("presenter"), [])):
            return False
        if self.off("relying_party_attestation"):
            return True
        key = _public_key(self.policy.get("relying_party_key"))
        return key is not None and self.signed_by(p, [key])

    def chain(self, p: Record) -> tuple[list[Record], str]:
        """The presented grant identifiers resolved to verified grants, in order."""
        ids = p.fields.get("chain")
        if not isinstance(ids, list) or not ids:
            return [], "chain_broken"
        chain: list[Record] = []
        for raw in ids:
            grant, reason = self.grant(raw if isinstance(raw, str) else "")
            if reason or grant is None:
                return [], reason
            chain.append(grant)
        if not self.off("chain") and not self.linked(chain):
            return [], "chain_broken"
        return chain, ""

    def grant(self, grant_id: str) -> tuple[Record | None, str]:
        seen = False
        for r in self.records:
            if r.kind != "grant" or r.text("grant_id") != grant_id:
                continue
            seen = True
            if r.verified:
                return r, ""
        return None, "signature_invalid:grant" if seen else "chain_broken"

    def linked(self, chain: list[Record]) -> bool:
        roots = self.policy.get("roots")
        root = isinstance(roots, list) and chain[0].text("issuer") in roots
        if not root or chain[0].fields.get("parent") is not None:
            return False
        for i in range(1, len(chain)):
            parent = chain[i].text("parent")
            if (parent != chain[i - 1].text("grant_id")
                    or chain[i].text("issuer") != chain[i - 1].text("delegate")):
                return False
        return True

    # -- lifespans ----------------------------------------------------------

    def inactive(self, identifier: str, t: int) -> bool:
        """Whether the registry retired or revoked an identifier at or before t. A
        presenter is inactive at the instant of its retirement; a link made at the
        instant of retirement is made by an inactive identifier too."""
        for r in self.records:
            if not r.verified or r.text("identifier") != identifier:
                continue
            if r.kind == "retirement":
                when = r.times["retired_at"]
            elif r.kind == "identifier-revocation":
                when = r.times["revoked_at"]
            else:
                continue
            if when <= t:
                return True
        return False

    def ended(self, identifier: str, t: int) -> bool:
        """Whether identifier had ended at t: the registry retired or revoked it,
        or it is a sub-agent whose parent had ended."""
        return self.inactive(identifier, t) or self.parent_ended(identifier, t, set())

    def parent_ended(self, identifier: str, t: int, seen: set[str]) -> bool:
        """Whether the registry registered identifier as a sub-agent of a parent
        that had ended at t. A sub-agent's lifespan is bound to the one parent
        identifier its registration names: a recovery or succession record that
        joins that parent to a successor carries history, and neither the parent's
        grants nor its sub-agents."""
        if self.off("parent_lifespan"):
            return False
        reg = self.registration(identifier)
        if reg is None:
            return False
        parent = reg.text("parent")
        if parent == "" or parent in seen:
            return False
        seen.add(parent)
        if not self.inactive(parent, t) and not self.parent_ended(parent, t, seen):
            return False
        if self.off("parent_not_carried"):
            for r in self.records:
                if (self.joins(r) and r.verified and r.text("old") == parent
                        and not self.ended(r.text("new"), t)):
                    return False
        return True

    def registration(self, identifier: str) -> Record | None:
        for r in self.records:
            if r.kind == "registration" and r.verified and r.text("identifier") == identifier:
                return r
        return None

    # -- links --------------------------------------------------------------

    def holder(self, delegate: str, presenter: str) -> tuple[bool, str]:
        """Whether presenter holds a grant made to delegate: directly, or through a
        path of links followed one hop at a time. (via a link, reason)."""
        if delegate == presenter:
            return False, ""
        if self.off("links"):
            return False, "presenter_not_delegate"
        visited: set[str] = set()
        at = delegate
        while at not in visited:
            visited.add(at)
            following, reason = self.hop(at)
            if reason:
                return False, reason
            if following == "":
                break
            if following == presenter:
                return True, ""
            at = following
        if self.unverified_link_from(visited):
            return False, "signature_invalid:link"
        return False, "presenter_not_delegate"

    def hop(self, old: str) -> tuple[str, str]:
        """The one successor of old, or '' when it has none."""
        links = [r for r in self.records if self.carries(r) and r.verified and r.text("old") == old]
        if not links:
            return "", ""
        link = links[0]
        if not self.off("link_conflict") and (
                len(links) > 1 or self.predecessors(link.text("new")) > 1):
            return "", "link_conflict"
        if not self.off("link_old_active") and self.ended(old, linked_at(link)):
            return "", "link_old_inactive"
        return link.text("new"), ""

    def carries(self, r: Record) -> bool:
        """Whether r passes a grant on: a link always, a recovery record only when
        the recovery_no_authority rule is switched off, and a succession record only
        when the succession_no_authority rule is."""
        return (r.kind == "link" or (r.kind == "recovery" and self.off("recovery_no_authority"))
                or (r.kind == "succession" and self.off("succession_no_authority")))

    def predecessors(self, identifier: str) -> int:
        return sum(1 for r in self.records
                   if r.kind == "link" and r.verified and r.text("new") == identifier)

    def unverified_link_from(self, visited: set[str]) -> bool:
        return any(r.kind == "link" and not r.verified and r.text("old") in visited
                   for r in self.records)

    # -- revocation ---------------------------------------------------------

    def revoked(self, chain: list[Record], presenter: str, observed: int) -> str:
        """The refusal for the first grant on the chain that carries a revocation in
        force at observed, or ''."""
        if self.off("revocation"):
            return ""
        for i, grant in enumerate(chain):
            standing = {g.text("issuer") for g in chain[:i + 1]}
            affected = {presenter, *(g.text("delegate") for g in chain[i:])}
            found = self.in_force(grant.text("grant_id"), standing, observed)
            if found is not None:
                return self.refusal(found, standing, affected, observed)
        return ""

    def in_force(self, grant_id: str, standing: set[str], observed: int) -> Record | None:
        """The revocation of grant_id with the earliest effective_at at or before
        observed, among those signed by a principal with standing."""
        first: Record | None = None
        for r in self.records:
            if r.kind != "revocation" or not r.verified or r.text("grant_id") != grant_id:
                continue
            if not self.off("standing") and r.text("initiator") not in standing:
                continue
            effective = r.times["effective_at"]
            if not self.off("revocation_time") and effective > observed:
                continue
            if first is None or effective < first.times["effective_at"]:
                first = r
        return first

    def refusal(self, r: Record, standing: set[str], affected: set[str], observed: int) -> str:
        if not self.off("revocation_complete") and r.text("grounds") == "":
            return "revocation_incomplete"
        if not self.off("dispute") and self.dispute_open(
                r.text("revocation_id"), standing, affected, observed):
            return "grant_revoked_dispute_open"
        return "grant_revoked"

    def dispute_open(self, revocation_id: str, standing: set[str], affected: set[str],
                     observed: int) -> bool:
        """Whether an affected principal filed a dispute of the revocation by
        observed that no resolution with standing had closed by then."""
        for d in self.records:
            if (d.kind != "dispute" or not d.verified or d.text("revocation_id") != revocation_id
                    or d.text("filed_by") not in affected or d.times["filed_at"] > observed):
                continue
            if not self.resolved(d, standing, observed):
                return True
        return False

    def resolved(self, d: Record, standing: set[str], observed: int) -> bool:
        if self.off("resolution"):
            return False
        for r in self.records:
            if (r.kind != "resolution" or not r.verified
                    or r.text("dispute_id") != d.text("dispute_id")
                    or r.text("revocation_id") != d.text("revocation_id")
                    or r.times["decided_at"] > observed):
                continue
            if self.off("resolution_standing") or r.text("decided_by") in standing:
                return True
        return False

    # -- history ------------------------------------------------------------

    def joins(self, r: Record) -> bool:
        """Whether r carries history from an old identifier to a new one: any
        recovery record, and a succession record only when the registry signed it."""
        return r.kind == "recovery" or (r.kind == "succession" and r.verified)

    def recovered(self, presenter: str) -> tuple[bool, bool, str]:
        """Follow the recovery and succession records that end at presenter back to
        every predecessor. It refuses a recovery that does not verify or whose two
        registrations do not match, ignores a succession record the registry did not
        sign, and reports whether any predecessor left an adverse record and whether
        the Responsible entity contested a succession on the path.
        (history, contested, reason)."""
        history = contested = False
        visited: set[str] = set()
        queue = [presenter]
        while queue:
            at = queue.pop(0)
            if at in visited:
                continue
            visited.add(at)
            for r in self.records:
                if not self.joins(r) or r.text("new") != at:
                    continue
                if not r.verified:
                    return False, False, "signature_invalid:recovery"
                if not self.off("recovery_match") and not self.recovery_matches(r):
                    return False, False, "recovery_mismatch"
                old = r.text("old")
                history = history or (not self.off("recovery_history") and self.adverse(old))
                contested = contested or self.asserted_new(r)
                queue.append(old)
        return history, contested, ""

    def asserted_new(self, succession: Record) -> bool:
        """Whether the Responsible entity of succession signed an assertion that its
        new identifier is a new agent."""
        if succession.kind != "succession" or self.off("new_agent_assertion"):
            return False
        return any(
            a.kind == "new-agent-assertion" and a.verified
            and a.text("succession_id") == succession.text("succession_id")
            and a.text("identifier") == succession.text("new")
            and a.text("responsible") == succession.text("responsible")
            for a in self.records)

    def recovery_matches(self, r: Record) -> bool:
        """Whether the registry registered the new identifier to the record's
        Responsible entity, and the old one to that entity or to a predecessor it
        took over from before the record, with one software digest."""
        old, new = self.registration(r.text("old")), self.registration(r.text("new"))
        if old is None or new is None:
            return False
        responsible = r.text("responsible")
        return (self.covers(old.text("responsible"), responsible, linked_at(r))
                and new.text("responsible") == responsible
                and old.text("software") != "" and old.text("software") == new.text("software"))

    def covers(self, from_: str, successor: str, t: int) -> bool:
        """Whether successor is the Responsible entity from_, or took over from_'s
        agents through verified responsible-succession records made at or before t."""
        if from_ == "" or successor == "":
            return False
        reached = {from_}
        grew = True
        while grew and not self.off("responsible_succession"):
            grew = False
            for r in self.records:
                if (r.kind == "responsible-succession" and r.verified
                        and r.text("old_responsible") in reached
                        and r.text("new_responsible") not in reached
                        and not r.times["succeeded_at"] > t):
                    reached.add(r.text("new_responsible"))
                    grew = True
        return successor in reached

    def adverse(self, identifier: str) -> bool:
        """Whether identifier left a record a relying party must see: an identifier
        revocation, a revocation of a grant made to it, or a dispute it filed."""
        delegated = {r.text("grant_id") for r in self.records
                     if r.kind == "grant" and r.verified and r.text("delegate") == identifier}
        for r in self.records:
            if not r.verified:
                continue
            if ((r.kind == "identifier-revocation" and r.text("identifier") == identifier)
                    or (r.kind == "revocation" and r.text("grant_id") in delegated)
                    or (r.kind == "dispute" and r.text("filed_by") == identifier)):
                return True
        return False

    def unjoined(self, presenter: str) -> bool:
        """Whether the registry registered presenter with the Responsible entity and
        software of an agent it had already retired or revoked, and no succession or
        recovery record joins that agent to presenter."""
        new = self.registration(presenter)
        if new is None or new.text("software") == "":
            return False
        registered = new.times["registered_at"]
        for old in self.records:
            if (old.kind != "registration" or not old.verified
                    or old.text("identifier") == presenter
                    or old.text("software") != new.text("software")
                    or not self.covers(old.text("responsible"), new.text("responsible"), registered)
                    or not self.ended(old.text("identifier"), registered)):
                continue
            if not self.joined(old.text("identifier"), presenter):
                return True
        return False

    def joined(self, old: str, new: str) -> bool:
        return any(self.joins(r) and r.verified and r.text("old") == old and r.text("new") == new
                   for r in self.records)

    def parent_history(self, presenter: str) -> tuple[bool, str]:
        """Whether a parent of presenter, or a parent above it, carries history from
        a predecessor that left an adverse record, and refuses when that history
        cannot be resolved."""
        if self.off("parent_history"):
            return False, ""
        seen = {presenter}
        at = presenter
        while True:
            reg = self.registration(at)
            if reg is None or reg.text("parent") == "" or reg.text("parent") in seen:
                return False, ""
            at = reg.text("parent")
            seen.add(at)
            history, _, reason = self.recovered(at)
            if reason or history:
                return history, reason


def linked_at(r: Record) -> int:
    """When a link, a recovery or a succession record was made."""
    key = {"recovery": "recovered_at", "succession": "recorded_at"}.get(r.kind, "linked_at")
    return r.times[key]


def decide_dir(case_dir: str | Path, skip: frozenset[str] = frozenset()) -> tuple[str, str]:
    """Read one case directory and decide it with the named rules switched off.

    Raises ``ValueError`` when ``case.json`` itself cannot be read; ``skip`` is for
    the corpus's own mutation sweep, and a verifier never sets it.
    """
    try:
        case = _loads(_read_in(case_dir, "case.json"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"case.json cannot be read: {exc}") from exc
    if not isinstance(case, dict) or not isinstance(case.get("policy"), dict):
        raise ValueError("case.json does not parse: it carries no policy object")
    state = _State(case["policy"], skip)
    names = case.get("records") or []
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ValueError("case.json does not parse: records is not a list of file names")
    presentation = case.get("presentation")
    if not isinstance(presentation, str):
        raise ValueError("case.json does not parse: presentation is not a file name")
    for name in names:
        record = _parse_record(case_dir, name, state.payload_type)
        if record is None:
            return NO_VERDICT, "malformed_record"
        state.records.append(record)
    final = _parse_record(case_dir, presentation, state.payload_type)
    if final is None or final.kind != "presentation":
        return NO_VERDICT, "malformed_record"
    return state.decide(final)


# ---------------------------------------------------------------------------
# Judging the directory.
# ---------------------------------------------------------------------------


class Judged:
    """One corpus, judged: members with their findings, and corpus findings."""

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not findings for _, _, findings in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


def _file_findings(case_dir: Path, files: dict[str, str]) -> list[str]:
    """Compare a member's files with the digests the manifest binds."""
    findings = []
    for name in sorted(files):
        try:
            body = _read_in(case_dir, name)
        except OSError:
            findings.append(f"{name} is declared and absent")
            continue
        if _sha(body) != files[name]:
            findings.append(f"{name} does not match its manifest digest")
    return findings


def _judge_member(case_dir: Path, vector: dict[str, Any]) -> list[str]:
    files = vector.get("files")
    findings = _file_findings(case_dir, files if isinstance(files, dict) else {})
    try:
        got = decide_dir(case_dir)
    except ValueError as exc:
        return [*findings, str(exc)]
    expected = vector.get("expected")
    expected = expected if isinstance(expected, dict) else {}
    want = (expected.get("decision", ""), expected.get("reason", ""))
    if got != want:
        findings.append(f"derived {got[0]}/{got[1]}, the manifest declares {want[0]}/{want[1]}")
    return findings


def _digest_finding(manifest: dict[str, Any]) -> str:
    """The published corpus digest recomputed from the manifest rows, or why not."""
    rows = manifest.get("vectors")
    got = _sha(_pretty(rows if isinstance(rows, list) else []))
    declared = str(manifest.get("corpusDigest", ""))
    if got != declared:
        return f"corpusDigest {declared[:12]} does not match the recomputed {got[:12]}"
    return ""


def judge(directory: str | Path = ROOT) -> Judged:
    root = Path(directory)
    manifest = _loads((root / "MANIFEST.json").read_bytes())
    judged = Judged()
    rows = manifest.get("vectors") or []
    vectors = [v for v in rows if isinstance(v, dict)]
    judged.findings.extend("a manifest row does not parse: it is not an object"
                           for v in rows if not isinstance(v, dict))
    accepted = {str(v.get("id")): (v.get("expected") or {}).get("decision") == ACCEPT
                for v in vectors}
    for v in vectors:
        kind = (v.get("expected") or {}).get("decision", "")
        findings = _judge_member(root / str(v.get("path", "")), v)
        if kind != ACCEPT and not accepted.get(str(v.get("twin", "")), False):
            findings.append("a refused member must name an accepted twin")
        judged.members.append((str(v.get("id", "")), kind, findings))
    finding = _digest_finding(manifest)
    if finding:
        judged.findings.append(finding)
    return judged


def render(judged: Judged, suite: str = SUITE) -> str:
    """The lines ``aee-verify`` prints from the Go reader."""
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts = judged.counts()
    for kind in sorted(counts):
        lines.append(f"  {kind}: {counts[kind]}")
    failed = 0
    for member_id, _, findings in judged.members:
        if findings:
            failed += 1
        lines.extend(f"FAIL {member_id}: {finding}" for finding in findings)
    lines.extend(f"FAIL corpus: {finding}" for finding in judged.findings)
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} corpus-level claim(s) "
            "do not hold")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="delegationlifecycle",
        description="judge corpora/vectors-delegation-lifecycle/ with the reference reader")
    parser.add_argument("directory", nargs="?", default=str(ROOT),
                        help="a corpus directory carrying MANIFEST.json")
    args = parser.parse_args(argv)
    judged = judge(args.directory)
    sys.stdout.write(render(judged))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
