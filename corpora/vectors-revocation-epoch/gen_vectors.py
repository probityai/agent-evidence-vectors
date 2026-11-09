"""Build the revocation-epoch cases byte-identically.

Every case is one record read under the contract at ``contractId``: the grant a
permit rests on, the trusted list issuers, the freshness limit, every signed
revocation list (SRL), the permit and the effect with the list each was checked
against, and the witness log that orders them. Each denied case departs from a
conformant record in one place: a list's issuer, epoch or content, the list a
permit or effect names, when a list was issued or witnessed, what it revokes,
the witness log, or the record's own form. The public wording the cases follow
is in README.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import revocationepoch as reader  # noqa: E402

SUITE = reader.SUITE
BASE = reader._when("2026-11-08T12:00:00Z")
FRESH = 5
ISSUER = "key:srl-issuer-1"
HOLDER = "key:agent-1"
AUTHORITY = "key:authority-1"
digest = reader.digest


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(seconds: int) -> str:
    """An RFC 3339 instant ``seconds`` after the base instant."""
    return (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def grant(grant_id: str, holder: str, parent: str | None, depth: int) -> dict[str, Any]:
    return {
        "caveats": [], "closedWorld": True,
        "constraints": {"payments.transfer": {"amount": {"range": [1, 500]},
                                              "currency": {"exact": "EUR"}}},
        "depth": depth, "expiresAt": at(3600), "grantId": grant_id, "holder": holder,
        "hopKinds": ["tool-call"], "issuer": "key:delegator-1", "maxDepth": 2, "maxUses": 1,
        "notBefore": at(-3600), "parentDigest": parent, "tools": ["payments.transfer"],
    }


PARENT = grant("grant-root", "key:delegator-1", None, 0)
PARENT_DIGEST = digest(PARENT)
GRANT = grant("grant-7", HOLDER, PARENT_DIGEST, 1)
GRANT_DIGEST = digest(GRANT)
OTHER_DIGEST = digest(grant("grant-8", "key:agent-2", PARENT_DIGEST, 1))
ARGS_DIGEST = digest({"amount": 120, "currency": "EUR", "to": "acct-42"})


def srl(epoch: int, issued: int, revoked: list[str], issuer: str = ISSUER) -> dict[str, Any]:
    return {"epoch": epoch, "issuedAt": at(issued), "issuerKeyId": issuer, "revoked": revoked}


def ref(lst: dict[str, Any]) -> dict[str, Any]:
    return {"digest": digest(lst), "epoch": lst["epoch"]}


L1 = srl(1, 0, [OTHER_DIGEST])
Event = tuple[str, Any, int]


def record(*, lists: list[dict[str, Any]] | None = None,
           permit_srl: dict[str, Any] | None = None, effect_srl: dict[str, Any] | None = None,
           permit_at: int = 2, effect_at: int = 3, outcome: str = "applied",
           events: list[Event] | None = None, permit: dict[str, Any] | None = None,
           effect: dict[str, Any] | None = None,
           contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One record; every argument is a departure from the conformant record.

    ``events`` is the witness log in order: (kind, object or the words "permit"
    and "effect", at). Each entry's digest is the object's recomputed digest.
    """
    lists = lists if lists is not None else [L1]
    body_permit: dict[str, Any] = {
        "argsDigest": ARGS_DIGEST, "authorityKeyId": AUTHORITY, "callId": "call-1",
        "expiresAt": at(permit_at + 60), "grantDigest": GRANT_DIGEST, "issuedAt": at(permit_at),
        "permitId": "permit-1", "runId": "run-1", "srl": permit_srl or ref(lists[0]),
        "tool": "payments.transfer", "workflowId": "wf-1",
    }
    body_effect: dict[str, Any] = {
        "argsDigest": ARGS_DIGEST, "callId": "call-1", "effectId": "effect-1",
        "grantDigest": GRANT_DIGEST, "observedAt": at(effect_at), "observerKeyId": "key:egress-1",
        "outcome": outcome, "permitId": "permit-1", "runId": "run-1",
        "srl": effect_srl or ref(lists[0]), "workflowId": "wf-1",
    }
    body_permit.update(permit or {})
    body_effect.update(effect or {})
    body_permit = {k: v for k, v in body_permit.items() if v is not _DROP}
    body_effect = {k: v for k, v in body_effect.items() if v is not _DROP}
    if events is None:
        events = [("grant", GRANT, -60), *(("srl", lst, 0) for lst in lists[:1]),
                  ("permit", "permit", permit_at), ("effect", "effect", effect_at)]
    objects = {"permit": body_permit, "effect": body_effect}
    witness = [{"at": at(when), "digest": digest(objects.get(obj, obj) if isinstance(obj, str)
                                                 else obj),
                "kind": kind, "seq": n} for n, (kind, obj, when) in enumerate(events, 1)]
    body: dict[str, Any] = {
        "effect": body_effect, "freshnessSeconds": FRESH, "grant": GRANT, "permit": body_permit,
        "srls": lists, "trustedSrlIssuers": [ISSUER], "witness": witness,
    }
    if contract is not None:
        body["contractId"] = contract
    return body


_DROP = object()


def broken(mutate: Any, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """A record with one structural change applied by ``mutate``."""
    body = copy.deepcopy(base if base is not None else record())
    mutate(body)
    return body


def log(*events: Event) -> list[Event]:
    return [("grant", GRANT, -60), *events]


def P(when: int) -> Event:  # noqa: N802
    return ("permit", "permit", when)


def E(when: int) -> Event:  # noqa: N802
    return ("effect", "effect", when)


def S(lst: dict[str, Any], when: int) -> Event:  # noqa: N802
    return ("srl", lst, when)


Case = tuple[str, dict[str, Any], str, str, str]


def _controls() -> list[Case]:
    empty = srl(1, 0, [])
    l2_grant = srl(2, 4, [GRANT_DIGEST])
    l2_holder = srl(2, 4, [HOLDER])
    l2 = srl(2, 1, [OTHER_DIGEST])
    l3 = srl(3, 2, [OTHER_DIGEST, "key:agent-9"])
    l2_mid = srl(2, 3, [OTHER_DIGEST])
    r2_grant = srl(2, 3, [GRANT_DIGEST])
    r2_holder = srl(2, 3, [HOLDER])
    ok = "allow", "not_revoked"
    enforced = "allow", "revocation_enforced_at_effect"
    return [
        ("allow-other-grant-revoked", record(), *ok,
         "control: the list in force revokes a different grant"),
        ("allow-empty-list-epoch-1", record(lists=[empty]), *ok,
         "control: an empty list at epoch 1 is a stated state, not an absent one"),
        ("allow-grant-revoked-after-effect",
         record(lists=[L1, l2_grant], events=log(S(L1, 0), P(2), E(3), S(l2_grant, 4))), *ok,
         "control: the list revoking the grant was witnessed after the effect, "
         "so the effect stands"),
        ("allow-holder-revoked-after-effect",
         record(lists=[L1, l2_holder], events=log(S(L1, 0), P(2), E(3), S(l2_holder, 4))), *ok,
         "control: the holder key was revoked after the effect was witnessed"),
        ("allow-permit-list-one-second-under-limit", record(permit_at=4, effect_at=4), *ok,
         "control: the permit was checked against a list one second younger than the limit"),
        ("allow-effect-list-one-second-under-limit", record(effect_at=4), *ok,
         "control: the effect landed against a list one second younger than the limit"),
        ("allow-epochs-increase-across-three-lists",
         record(lists=[L1, l2, l3], permit_srl=ref(l3), effect_srl=ref(l3), permit_at=3,
                effect_at=4, events=log(S(L1, 0), S(l2, 1), S(l3, 2), P(3), E(4))), *ok,
         "control: three lists with increasing epochs; permit and effect use the newest"),
        ("allow-in-flight-rechecked-at-effect",
         record(lists=[L1, l2_mid], effect_srl=ref(l2_mid), effect_at=4,
                events=log(S(L1, 0), P(2), S(l2_mid, 3), E(4))), *ok,
         "control: a newer list arrived after the permit; the effect was checked against it"),
        ("allow-race-effect-witnessed-first",
         record(lists=[L1, r2_grant], events=log(S(L1, 0), P(2), E(3), S(r2_grant, 3))), *ok,
         "control: the revoking list and the effect share an instant; "
         "the log puts the effect first"),
        ("allow-same-list-carried-twice",
         record(lists=[L1, copy.deepcopy(L1)], events=log(S(L1, 0), S(L1, 1), P(2), E(3))), *ok,
         "control: the same list at the same epoch is carried and witnessed twice"),
        ("allow-revoked-in-flight-refused-at-effect",
         record(lists=[L1, r2_grant], effect_srl=ref(r2_grant), effect_at=4,
                outcome="not-applied", events=log(S(L1, 0), P(2), S(r2_grant, 3), E(4))),
         *enforced,
         "control: the worker ran a permit minted before the revocation; the enforcement point "
         "where the effect lands read the newer list and did not apply it"),
        ("allow-holder-revoked-in-flight-refused-at-effect",
         record(lists=[L1, r2_holder], effect_srl=ref(r2_holder), effect_at=4,
                outcome="not-applied", events=log(S(L1, 0), P(2), S(r2_holder, 3), E(4))),
         *enforced, "control: as above with the holder key revoked"),
    ]


def _malformed() -> list[Case]:
    bad = "deny", "malformed_record"
    return [
        ("malformed-srls-missing", broken(lambda r: r.pop("srls")), *bad,
         "the record omits the lists it is judged against"),
        ("malformed-epoch-text",
         broken(lambda r: r["srls"][0].update(epoch="1")), *bad, "a list's epoch is text"),
        ("malformed-epoch-not-integer",
         broken(lambda r: r["srls"][0].update(epoch=1.5)), *bad,
         "a list's epoch is a fraction"),
        ("malformed-srl-member-null",
         broken(lambda r: r["permit"].update(srl=None)), *bad,
         "the permit's srl member is null; a permit that checked no list omits the member"),
        ("malformed-outcome-unknown",
         broken(lambda r: r["effect"].update(outcome="maybe")), *bad,
         "the effect's outcome is not applied, not-applied or uncertain"),
        ("malformed-freshness-zero",
         broken(lambda r: r.update(freshnessSeconds=0)), *bad, "the freshness limit is zero"),
        ("malformed-issued-at",
         broken(lambda r: r["srls"][0].update(issuedAt="soon")), *bad,
         "a list's issue time is not an RFC 3339 instant"),
        ("malformed-witness-seq-repeated",
         broken(lambda r: r["witness"][2].update(seq=2)), *bad,
         "two witness entries carry one sequence number"),
        ("malformed-witness-time-goes-back",
         broken(lambda r: r["witness"][3].update(at=at(1))), *bad,
         "a witness entry is earlier than the one before it"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown", record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         "deny", "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def _lists() -> list[Case]:
    rogue = srl(1, 0, [OTHER_DIGEST], issuer="key:srl-issuer-rogue")
    twin = srl(1, 0, [GRANT_DIGEST])
    l2 = srl(2, 1, [OTHER_DIGEST])
    l2_early = srl(2, -5, [OTHER_DIGEST])
    other = srl(1, 0, ["key:agent-9"])
    return [
        ("srl-issuer-untrusted", record(lists=[rogue]), "deny", "srl_issuer_untrusted",
         "the list was issued by a key the record does not trust"),
        ("grant-binding-permit-names-other-grant",
         record(permit={"grantDigest": OTHER_DIGEST}), "deny", "grant_binding_mismatch",
         "the permit names a grant digest that is not the recomputed digest of its grant"),
        ("grant-binding-effect-names-other-permit",
         record(effect={"permitId": "permit-2"}), "deny", "grant_binding_mismatch",
         "the effect names a different permit"),
        ("epoch-reused-with-different-content",
         record(lists=[L1, twin], events=log(S(L1, 0), S(twin, 0), P(2), E(3))), "deny",
         "srl_epoch_not_monotonic", "two lists carry epoch 1 with different content"),
        ("epoch-rolled-back-in-witness-log",
         record(lists=[L1, l2], permit_srl=ref(l2), effect_srl=ref(l2),
                events=log(S(l2, 1), S(L1, 1), P(2), E(3))), "deny", "srl_epoch_not_monotonic",
         "the log witnessed epoch 1 after epoch 2: a rollback to an older list"),
        ("epoch-issued-before-predecessor",
         record(lists=[L1, l2_early], permit_srl=ref(l2_early), effect_srl=ref(l2_early),
                events=log(S(L1, 0), S(l2_early, 0), P(2), E(3))), "deny",
         "srl_epoch_not_monotonic", "epoch 2 claims an issue time before epoch 1's"),
        ("srl-absent-at-permit", record(permit={"srl": _DROP}), "deny", "srl_absent",
         "the permit records no list: it was minted without a revocation check"),
        ("srl-absent-at-effect", record(effect={"srl": _DROP}), "deny", "srl_absent",
         "the effect records no list: the enforcement point where it landed checked nothing"),
        ("srl-digest-mismatch-at-permit",
         record(permit_srl={"digest": digest(other), "epoch": 1}), "deny", "srl_digest_mismatch",
         "the permit names epoch 1 with the digest of a list the record does not carry"),
        ("srl-epoch-unknown-at-permit",
         record(permit_srl={"digest": digest(L1), "epoch": 7}), "deny", "srl_digest_mismatch",
         "the permit names epoch 7, which no list has"),
        ("srl-digest-mismatch-at-effect",
         record(effect_srl={"digest": digest(other), "epoch": 1}), "deny", "srl_digest_mismatch",
         "the effect names epoch 1 with the digest of a list the record does not carry"),
    ]


def _stale() -> list[Case]:
    l2 = srl(2, 1, [OTHER_DIGEST])
    late = srl(2, 3, [OTHER_DIGEST])
    stale = "deny", "srl_stale_at_permit"
    return [
        ("srl-stale-at-permit-at-limit", record(permit_at=5, effect_at=5), *stale,
         "the permit was checked against a list exactly the freshness limit old"),
        ("srl-stale-newer-list-witnessed-before-permit",
         record(lists=[L1, l2], effect_srl=ref(l2), events=log(S(L1, 0), S(l2, 1), P(2), E(3))),
         *stale, "epoch 2 was witnessed before the permit, which was checked against epoch 1"),
        ("srl-stale-permit-backdated",
         record(permit_at=2, effect_at=5,
                events=log(S(L1, 0), P(5), E(5))),
         *stale, "the permit claims issue at 2 s but the log first saw it at 5 s, the limit"),
        ("srl-stale-permit-list-issued-after-permit",
         record(lists=[L1, late], permit_srl=ref(late), effect_srl=ref(late), effect_at=4,
                events=log(S(L1, 0), P(2), S(late, 3), E(4))),
         *stale, "the permit names a list issued and witnessed after the permit"),
        ("srl-stale-at-effect-at-limit", record(effect_at=5), "deny", "srl_stale_at_effect",
         "the effect landed against a list exactly the freshness limit old"),
        ("srl-stale-at-effect-backdated",
         record(effect_at=3, events=log(S(L1, 0), P(2), E(5))), "deny", "srl_stale_at_effect",
         "the effect claims 3 s but the log first saw it at 5 s, the limit"),
    ]


def _revoked() -> list[Case]:
    def revokes(entry: str) -> dict[str, Any]:
        lst = srl(1, 0, [OTHER_DIGEST, entry])
        return record(lists=[lst])

    r2_grant = srl(2, 3, [GRANT_DIGEST])
    r2_holder = srl(2, 3, [HOLDER])
    r2_parent = srl(2, 3, [PARENT_DIGEST])
    l3_clear = srl(3, 4, [])
    after = "deny", "effect_after_revocation"

    def in_flight(lst: dict[str, Any], **kw: Any) -> dict[str, Any]:
        return record(lists=[L1, lst], effect_srl=ref(lst), effect_at=4,
                      events=log(S(L1, 0), P(2), S(lst, 3), E(4)), **kw)

    return [
        ("revoked-at-permit-grant", revokes(GRANT_DIGEST), "deny", "revoked_at_permit",
         "the list the permit was checked against revokes its grant"),
        ("revoked-at-permit-holder", revokes(HOLDER), "deny", "revoked_at_permit",
         "the list the permit was checked against revokes the holder key"),
        ("revoked-at-permit-parent-grant", revokes(PARENT_DIGEST), "deny", "revoked_at_permit",
         "the list revokes the parent grant, which carries the child with it"),
        ("revoked-at-permit-authority-key", revokes(AUTHORITY), "deny", "revoked_at_permit",
         "the list revokes the key that minted the permit"),
        ("effect-after-revocation-in-flight", in_flight(r2_grant), *after,
         "the permit was minted before the revocation, the revoking list was witnessed, "
         "and the in-flight effect was applied anyway"),
        ("effect-after-revocation-holder-in-flight", in_flight(r2_holder), *after,
         "the holder key was revoked while the work was in flight and the effect was applied"),
        ("effect-after-revocation-parent-in-flight", in_flight(r2_parent), *after,
         "the parent grant was revoked while the work was in flight and the effect was applied"),
        ("effect-after-revocation-outcome-uncertain", in_flight(r2_grant, outcome="uncertain"),
         *after, "the effect after the revocation is uncertain, which is not a refusal"),
        ("effect-after-revocation-race-list-first",
         record(lists=[L1, r2_grant], events=log(S(L1, 0), P(2), S(r2_grant, 3), E(3))), *after,
         "the revoking list and the effect share an instant; the log puts the list first and the "
         "worker never read it"),
        ("effect-after-revocation-dropped-in-later-list",
         record(lists=[L1, r2_grant, l3_clear], effect_srl=ref(l3_clear), effect_at=4,
                events=log(S(L1, 0), P(2), S(r2_grant, 3), S(l3_clear, 4), E(4))), *after,
         "a later list drops the revoked grant; a revocation is never undone"),
    ]


def _ambiguous() -> list[Case]:
    r2_grant = srl(2, 4, [GRANT_DIGEST])
    l2 = srl(2, 2, [OTHER_DIGEST])
    hidden = srl(2, 1, [GRANT_DIGEST])
    amb = "deny", "revocation_order_ambiguous"
    return [
        ("ambiguous-effect-not-witnessed",
         record(lists=[L1, r2_grant], events=log(S(L1, 0), P(2), S(r2_grant, 4))), *amb,
         "the revoking list is in the log and the effect is not, so nothing orders them"),
        ("ambiguous-revoking-list-not-witnessed", record(lists=[L1, r2_grant]), *amb,
         "the record carries a list revoking the grant that the log never witnessed"),
        ("ambiguous-witness-log-gap",
         broken(lambda r: [e.update(seq=e["seq"] + 1) for e in r["witness"][2:]]), *amb,
         "the log skips a sequence number before the permit; the missing entry could be a "
         "revocation"),
        ("ambiguous-effect-witnessed-before-permit",
         record(events=log(S(L1, 0), E(3), P(3))), *amb,
         "the log witnessed the effect before the permit it ran under"),
        ("ambiguous-effect-list-witnessed-after-effect",
         record(lists=[L1, l2], effect_srl=ref(l2), effect_at=4,
                events=log(S(L1, 0), P(2), E(4), S(l2, 4))), *amb,
         "the effect names a list the log witnessed only after the effect"),
        ("ambiguous-witnessed-list-not-in-record",
         record(events=log(S(L1, 0), S(hidden, 1), P(2), E(3))), *amb,
         "the log witnessed a list the record leaves out"),
        ("ambiguous-permit-not-witnessed", record(events=log(S(L1, 0), E(3))), *amb,
         "the permit is not in the log"),
    ]


def _effect_side() -> list[Case]:
    l2 = srl(2, 3, [OTHER_DIGEST])
    return [
        ("effect-epoch-behind",
         record(lists=[L1, l2], effect_at=4, events=log(S(L1, 0), P(2), S(l2, 3), E(4))),
         "deny", "effect_epoch_behind",
         "the effect landed against epoch 1 after epoch 2 had been witnessed"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [*_controls(), *_malformed(), *_lists(), *_stale(), *_revoked(), *_ambiguous(),
            *_effect_side()]


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
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
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
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
