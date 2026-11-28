"""Build the authority-epoch-fence cases byte-identically.

Every case is one authority log (signed events, each linked to the one before by digest),
the signed head that closes it, one signed request and the keys a verifier pins: the
log's genesis key and one holder key per subject. The cases cover every reason the
reader names and every revocation status, and the families an authority epoch has to
get right: closed and future epochs, approvals that count once, suspension and resume,
delegation chains, a change of the log key, re-registration, owner change, a fork, and
the states that must never read closed (an open dispute, a scope that stops only new
admissions, a truncated or unreadable log).

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild every
signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import authorityepoch as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/authority-epoch-fence/v1/"
SOURCE = {
    "note": (
        "Synthetic logs, heads, requests and keys. The decision, reason and status tokens "
        "are this corpus's own. Cases marked proposed state rules offered for adoption."
    ),
    "source": "authority epochs over a signed, hash-chained log closed by a signed head",
}
LOG_ID = "authority-log-1"
T0 = 1795000000000000000
STEP = 1000000000
A, B, C = "agent-a", "agent-b", "agent-c"
OLD_KEY, NEW_KEY = "log-key-0", "log-key-1"
PROPOSED = {"epoch-dead-request-presented-two-epochs-later", "fork-second-signer-recorded"}


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> bytes:
    return bytes(rail.ed25519_public_key(_seed(label)))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _kid(label: str) -> str:
    return reader.kid(_public(label))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sign(label: str, domain: bytes, claims: dict[str, Any]) -> dict[str, Any]:
    sig = rail.ed25519_sign(_seed(label), reader.message(domain, claims))
    return {"claims": claims, "sig": _b64(sig)}


class Log:
    """An authority log under construction: events are signed as they are appended."""

    def __init__(self) -> None:
        self.key = OLD_KEY
        self.epoch = 0
        self.wires: list[dict[str, Any]] = []
        self.add("genesis")

    @property
    def seq(self) -> int:
        return len(self.wires) - 1

    def add(self, kind: str, signer: str | None = None, new_key: str | None = None,
            **members: Any) -> Log:
        """Append one event; ``members`` override any claim, so a case can break one rule."""
        signer = signer or self.key
        claims: dict[str, Any] = {
            "v": 1, "log_id": LOG_ID, "seq": len(self.wires),
            "epoch": self.epoch + (1 if kind == "epoch_open" else 0), "kind": kind,
            "subject": "", "ref": "", "parent": "", "cause": "", "scope": "",
            "at_ns": str(T0 + len(self.wires) * STEP),
            "previous": reader.digest(self.wires[-1]) if self.wires else "",
            "kid": _kid(signer),
        }
        if new_key is not None:
            members.setdefault("ref", _b64(_public(new_key)))
        claims.update(members)
        self.wires.append(_sign(signer, reader.DOMAIN_EVENT, claims))
        self.epoch = claims["epoch"]
        if new_key is not None:
            self.key = new_key
        return self

    def grant(self, ref: str, subject: str, parent: str = "") -> Log:
        return self.add("grant", ref=ref, subject=subject, parent=parent)

    def revoke(self, ref: str, subject: str, scope: str = "all") -> Log:
        return self.add("revoke", ref=ref, subject=subject, scope=scope)

    def open_epoch(self, cause: str, subject: str = "") -> Log:
        return self.add("epoch_open", cause=cause, subject=subject)

    def head(self, signer: str | None = None, **members: Any) -> dict[str, Any]:
        last = self.wires[-1]
        claims: dict[str, Any] = {
            "v": 1, "log_id": LOG_ID, "seq": last["claims"]["seq"],
            "epoch": last["claims"]["epoch"], "digest": reader.digest(last),
            "at_ns": str(T0 + len(self.wires) * STEP), "kid": _kid(signer or self.key),
        }
        claims.update(members)
        return _sign(signer or self.key, reader.DOMAIN_HEAD, claims)


def request(subject: str, grant_id: str, epoch: int = 0, approval_id: str = "",
            signer: str | None = None, **members: Any) -> dict[str, Any]:
    """A request signed by its subject's holder key unless another signer is named."""
    label = signer or f"holder/{subject}"
    claims: dict[str, Any] = {
        "v": 1, "request_id": f"request-{subject}-{grant_id}", "subject": subject,
        "grant_id": grant_id, "approval_id": approval_id, "epoch": epoch,
        "at_ns": str(T0 + 500 * STEP), "kid": _kid(label),
    }
    claims.update(members)
    return _sign(label, reader.DOMAIN_REQUEST, claims)


Files = dict[str, Any]


def bundle(log: Log, req: dict[str, Any], head: dict[str, Any] | None | bool = True,
           drop_last: bool = False) -> Files:
    """The files of one case: case.json, the events, the head and the request."""
    wires = log.wires[:-1] if drop_last else log.wires
    head_wire = log.head() if head is True else head
    names = [f"event-{i:03d}.json" for i in range(len(wires))]
    files: Files = dict(zip(names, wires, strict=True))
    files["request.json"] = req
    if head_wire:
        files["head.json"] = head_wire
    files["case.json"] = {
        "v": 1, "log_id": LOG_ID,
        "keys": {
            "genesis": _b64(_public(OLD_KEY)),
            "holders": {s: _b64(_public(f"holder/{s}")) for s in (A, B, C)},
        },
        "events": names, "head": "head.json" if head_wire else None,
        "request": "request.json", "now_ns": str(T0 + 600 * STEP),
    }
    return files


def granted() -> Log:
    return Log().grant("g1", A)


def _reregistered() -> Log:
    return granted().revoke("", A).open_epoch("re_registration", A).grant("g2", A)


def _owner_changed() -> Log:
    return granted().revoke("", A).open_epoch("owner_change", A).grant("g2", A)


def _disputed(cause: str | None) -> Log:
    log = granted().revoke("g1", A)
    log.add("dispute_open", ref=str(log.seq))
    if cause is not None:
        log.add("dispute_closed", ref=str(log.seq - 1), cause=cause)
    return log


def _root_changed(event_signer: str | None = None) -> Log:
    log = granted().add("epoch_open", cause="root_change", new_key=NEW_KEY)
    return log.add("grant", signer=event_signer, ref="g2", subject=A)


def _altered(wire: dict[str, Any], where: str, **members: Any) -> dict[str, Any]:
    """A copy with members changed after signing, inside ``claims`` or on the wire."""
    out = copy.deepcopy(wire)
    (out["claims"] if where == "claims" else out).update(members)
    return out


def _malformed() -> list[tuple[str, Files, str]]:
    log = granted()
    good = request(A, "g1")
    extra = granted()
    extra.add("suspend", subject=B, note="an extra member")
    missing = granted()
    missing.wires[-1]["claims"].pop("scope")
    v2 = Log().add("grant", ref="g1", subject=A, v=2)
    sig = good["sig"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    bad_sig = sig[:-3] + alphabet[alphabet.index(sig[-3]) ^ 1] + sig[-2:]
    return [
        ("status-malformed-event-extra-member", bundle(extra, good),
         "an event carries a member its record type does not declare, signed with it"),
        ("status-malformed-event-member-missing", bundle(missing, good),
         "an event lacks the scope member"),
        ("status-malformed-event-version-2", bundle(v2, good), "an event carries v 2"),
        ("status-malformed-request-epoch-float", bundle(log, request(A, "g1", epoch=0.0)),
         "the request's epoch is the JSON number 0.0, not an integer"),
        ("status-malformed-request-epoch-boolean", bundle(log, request(A, "g1", epoch=False)),
         "the request's epoch is false, not an integer"),
        ("status-malformed-head-time-as-number", bundle(log, good, log.head(at_ns=T0)),
         "the head's at_ns is a JSON number, which RFC 8785 cannot carry past 2^53"),
        ("status-malformed-request-time-leading-zero",
         bundle(log, request(A, "g1", at_ns="0" + str(T0))),
         "the request's at_ns has a leading zero"),
        ("status-malformed-request-signature-not-canonical",
         bundle(log, _altered(good, "wire", sig=bad_sig)),
         "the request's signature is base64 that decodes but is not its canonical spelling"),
    ]


Case = tuple[str, Files, str, str, str, str]


def _epoch_cases() -> list[Case]:
    restarted = granted().open_epoch("restart")
    acknowledged = granted().open_epoch("clock_acknowledged")
    late = str(T0 + 900 * STEP)
    dead = granted().revoke("g1", A).open_epoch("restart").open_epoch("restart")
    return [
        ("epoch-current-epoch-admitted", bundle(granted(), request(A, "g1")), "admit",
         "authority_valid", "live", "the control: a held grant, presented in the current epoch"),
        ("epoch-closed-after-restart", bundle(restarted, request(A, "g1")), "refuse",
         "epoch_closed", "live", "a restart opened epoch 1 and the request names epoch 0"),
        ("epoch-request-of-the-new-epoch-admitted", bundle(restarted, request(A, "g1", 1)),
         "admit", "authority_valid", "live",
         "the control: after the restart the same grant is presented in epoch 1"),
        ("epoch-closed-whatever-its-time",
         bundle(acknowledged, request(A, "g1", 0, at_ns=late)), "refuse", "epoch_closed",
         "live", "an acknowledged clock fault opened epoch 1; the request of epoch 0 carries "
         "a time after the epoch opened, and its time does not reopen the epoch"),
        ("epoch-ahead-of-the-log", bundle(granted(), request(A, "g1", 1)), "refuse",
         "epoch_ahead", "live", "the request names an epoch the log has not opened"),
        ("epoch-dead-request-presented-two-epochs-later", bundle(dead, request(A, "g1")),
         "refuse", "epoch_closed", "closed",
         "proposed: a request of epoch 0 on a grant revoked in epoch 0, presented again after "
         "two more epochs opened; dead is dead across epochs"),
    ]


def _approval_cases() -> list[Case]:
    log = granted().add("approval_consumed", ref="approval-1", subject=A)
    return [
        ("approval-consumed-presented-again", bundle(log, request(A, "g1", 0, "approval-1")),
         "refuse", "approval_consumed", "live",
         "the log records the approval as consumed and the request presents it again"),
        ("approval-fresh-admitted", bundle(log, request(A, "g1", 0, "approval-2")), "admit",
         "authority_valid", "live", "the control: an approval the log has not consumed"),
    ]


def _suspend_cases() -> list[Case]:
    suspended = granted().add("suspend", subject=A)
    resumed = granted().add("suspend", subject=A).add("resume", subject=A)
    after_revoke = granted().add("suspend", subject=A).revoke("g1", A).add("resume", subject=A)
    return [
        ("suspend-subject-suspended", bundle(suspended, request(A, "g1")), "refuse",
         "suspended", "suspended", "a suspension can be lifted, so it reads suspended, "
         "never closed"),
        ("suspend-resumed-admitted", bundle(resumed, request(A, "g1")), "admit",
         "authority_valid", "live", "a resume lifts the suspension"),
        ("suspend-resume-after-revoke-does-nothing", bundle(after_revoke, request(A, "g1")),
         "refuse", "revoked", "closed", "a resume lifts only a suspension, never a revocation"),
    ]


def _delegation_cases() -> list[Case]:
    child_before = granted().grant("g2", B, "g1").revoke("g1", A)
    child_after = granted().revoke("g1", A).grant("g2", B, "g1")
    siblings = granted().grant("g2", B, "g1").grant("g3", C, "g1").revoke("g2", B)
    grandchild = granted().grant("g2", B, "g1").grant("g3", C, "g2").revoke("g1", A)
    return [
        ("delegation-parent-revoked-child-presented", bundle(child_before, request(B, "g2")),
         "refuse", "revoked", "closed",
         "the child grant was issued before its parent was revoked; the revocation reaches it"),
        ("delegation-child-issued-after-parent-revoked", bundle(child_after, request(B, "g2")),
         "refuse", "parent_revoked", "closed",
         "the child grant was issued after its parent was revoked: the delegator no longer "
         "held what it granted"),
        ("delegation-sibling-unaffected", bundle(siblings, request(C, "g3")), "admit",
         "authority_valid", "live", "revoking one child grant leaves its sibling live"),
        ("delegation-grandchild-of-a-revoked-grant", bundle(grandchild, request(C, "g3")),
         "refuse", "revoked", "closed", "a revocation reaches every grant below it"),
        ("delegation-grant-held-by-another-subject", bundle(granted(), request(B, "g1")),
         "refuse", "no_grant", "live", "agent-b presents a grant the log issued to agent-a"),
    ]


def _root_cases() -> list[Case]:
    changed = _root_changed()
    stale = _root_changed(OLD_KEY)
    intruder = request(A, "g1", signer="intruder")
    return [
        ("root-change-then-request-admitted", bundle(changed, request(A, "g2", 1)), "admit",
         "authority_valid", "live", "the log key changed in epoch 1; the next event and the "
         "head are signed by the new key, which the genesis key's event named"),
        ("root-event-after-change-signed-by-old-key", bundle(stale, request(A, "g2", 1)),
         "refuse", "log_invalid", "unknown",
         "after the key change an event is still signed by the old key"),
        ("root-head-signed-by-old-key-after-change",
         bundle(changed, request(A, "g2", 1), changed.head(OLD_KEY)), "refuse",
         "history_incomplete", "unknown", "the head is signed by the key the log retired"),
        ("root-request-signed-by-unpinned-holder", bundle(granted(), intruder), "refuse",
         "unknown_holder", "live",
         "the request names agent-a and is signed by a key no verifier pins for agent-a"),
        ("root-request-altered-after-signing",
         bundle(granted(), _altered(request(A, "g1"), "claims", request_id="request-other")),
         "refuse", "request_signature_invalid", "live",
         "the request id was changed after the holder signed"),
    ]


def _identity_cases() -> list[Case]:
    rereg = granted().open_epoch("re_registration", A)
    regranted = granted().open_epoch("re_registration", A).grant("g2", A)
    owner_kept = granted().open_epoch("owner_change", A)
    newcomer = _owner_changed().grant("g3", B)
    return [
        ("rereg-grant-superseded", bundle(rereg, request(A, "g1", 1)), "refuse",
         "grant_superseded", "live", "agent-a was re-registered after the grant was issued"),
        ("rereg-new-grant-after-re-registration-admitted", bundle(regranted, request(A, "g2", 1)),
         "admit", "authority_valid", "live",
         "the control: a grant issued after the re-registration"),
        ("rereg-does-not-lift-a-kill", bundle(_reregistered(), request(A, "g2", 1)), "refuse",
         "revoked", "closed", "every grant of agent-a was revoked; a re-registration and a new "
         "grant do not bring it back"),
        ("owner-kill-survives-owner-change", bundle(_owner_changed(), request(A, "g2", 1)),
         "refuse", "revoked", "closed",
         "every grant of agent-a was revoked; a new owner and a new grant do not bring it back"),
        ("owner-new-subject-granted-after-change-admitted", bundle(newcomer, request(B, "g3", 1)),
         "admit", "authority_valid", "live",
         "a subject granted after the owner change is not touched by the earlier kill"),
        ("owner-grant-kept-across-owner-change", bundle(owner_kept, request(A, "g1", 1)),
         "admit", "authority_valid", "live",
         "an owner change opens an epoch and does not supersede a grant, unlike a "
         "re-registration"),
        ("fork-second-signer-recorded", bundle(granted().add("fork", subject=A),
                                               request(A, "g1")),
         "refuse", "fork", "closed",
         "proposed: a second signer for agent-a ends in a recorded fork, which closes it"),
    ]


def _status_cases() -> list[Case]:
    gap = granted().add("suspend", subject=B, seq=3)
    jump = granted().add("suspend", subject=B, epoch=1)
    broken = granted().add("suspend", subject=B, previous="0" * 64)
    unnamed = granted().add("dispute_open", ref="7")
    full = granted().add("suspend", subject=B)
    restored = _disputed("restored").grant("g2", A)
    return [
        ("status-open-dispute-reads-unknown", bundle(_disputed(None), request(A, "g1")),
         "refuse", "revoked_dispute_open", "unknown",
         "the revocation's dispute is open, so its effect is unresolved and never reads closed"),
        ("status-confirmed-dispute-reads-closed", bundle(_disputed("confirmed"),
                                                         request(A, "g1")),
         "refuse", "revoked", "closed", "the dispute closed with the revocation confirmed"),
        ("status-restored-dispute-still-revoked", bundle(_disputed("restored"),
                                                         request(A, "g1")),
         "refuse", "revoked", "closed",
         "the dispute closed as restored; a restoration never revives the revoked grant"),
        ("status-restoration-is-a-new-grant", bundle(restored, request(A, "g2")), "admit",
         "authority_valid", "live", "after the restoration a new grant is issued and admitted"),
        ("status-new-admissions-scope-reads-partial",
         bundle(granted().revoke("g1", A, "new_admissions"), request(A, "g1")), "refuse",
         "revoked", "partial",
         "the revocation stops new admissions only, so work already admitted may run on"),
        ("status-truncated-log-reads-unknown", bundle(full, request(A, "g1"), drop_last=True),
         "refuse", "history_incomplete", "unknown",
         "the head binds an event the log no longer holds; a missing event is never clean"),
        ("status-no-head-reads-unknown", bundle(granted(), request(A, "g1"), None), "refuse",
         "epoch_unavailable", "unknown", "no head closes the log, so the current epoch is unknown"),
        ("status-broken-previous-link-reads-unknown", bundle(broken, request(A, "g1")),
         "refuse", "log_invalid", "unknown", "an event's previous digest names no event"),
        ("status-sequence-gap-reads-unknown", bundle(gap, request(A, "g1")), "refuse",
         "log_invalid", "unknown", "an event skips a sequence number, signed and linked"),
        ("status-epoch-jump-without-open-reads-unknown", bundle(jump, request(A, "g1", 1)),
         "refuse", "log_invalid", "unknown",
         "an event raises the epoch without an epoch_open event"),
        ("status-dispute-names-no-revocation-reads-unknown", bundle(unnamed, request(A, "g1")),
         "refuse", "log_invalid", "unknown", "a dispute names a sequence number that is no "
         "revocation"),
    ]


def cases() -> list[Case]:
    """Every case: id, files, decision, reason, revocation status and what it shows."""
    malformed = [
        (name, files, "no_verdict", "malformed", "unknown", shows)
        for name, files, shows in _malformed()
    ]
    return [
        *_epoch_cases(), *_approval_cases(), *_suspend_cases(), *_delegation_cases(),
        *_root_cases(), *_identity_cases(), *_status_cases(), *malformed,
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
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries: list[dict[str, Any]] = []
    for name, files, decision, reason, status, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        written = {filename: _json(value) for filename, value in files.items()}
        for filename, data in written.items():
            (directory / filename).write_bytes(data)
        expected = {"decision": decision, "reason": reason, "revocation_status": status}
        observed = reader.verify(directory / "case.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({
            "edit": shows,
            "expected": expected,
            "files": {filename: _sha(data) for filename, data in sorted(written.items())},
            "id": name,
            "path": f"cases/{name}",
            "status": "proposed" if name in PROPOSED else "normative",
        })
    decisions = [e["expected"]["decision"] for e in entries]
    statuses = [e["expected"]["revocation_status"] for e in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: decisions.count(word) for word in sorted(set(decisions))},
        "provenance": copy.deepcopy(SOURCE),
        "revocationStatusCounts": {word: statuses.count(word) for word in sorted(set(statuses))},
        "suite": SUITE,
        "synthetic": True,
        "typeUri": reader.TYPE_URI,
        "verifierContract": "verifier case.json --json; prints decision, reason and "
        "revocation_status; exit 0 admit, 1 refuse, 2 no_verdict",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
