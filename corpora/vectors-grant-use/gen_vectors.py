"""Build the grant-use cases byte-identically.

Every case is one record of an effect judged as a use of a grant, read under the
contract at ``contractId``. The record carries the grant chain from root to
leaf, the trusted root keys, the authority and worker keys, every permit minted
on the leaf grant, the other effects recorded against those permits, the effect
being judged with the call it applied, and the witness log. A record is built in
three stages, and a case may change each stage before the next one reads it:
the grants (before any permit names their digest), the permits and effects
(before the witness log records their digests), and the finished record. So
each denied case departs from a conformant record in one place, and every digest
downstream of that place is the honest digest of what the record now holds.
The public wording the cases follow is in README.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import grantuse as reader  # noqa: E402

SUITE = reader.SUITE
digest = reader.digest
DECISION = "2026-11-08T21:00:00Z"
ROOT_KEY, DELEGATOR, AUTHORITY = "key:root-1", "key:delegator-1", "key:authority-1"
WORKER, OBSERVER = "key:worker-1", "key:observer-1"
REFUND, PAYOUT, READ = "payments.refund", "payments.payout", "tickets.read"
WORKFLOW, RUN = "wf-refunds-7", "run-3"
PERMIT_SECONDS, OBSERVE_SECONDS = 300, 30
ARGS = {"account": "acct-7", "amount": 40, "currency": "EUR", "orderId": "ord-2026-118"}
SRL = {"epoch": 4, "issuedAt": "2026-11-08T07:00:00Z", "issuerKeyId": "key:revoker-1",
       "revoked": []}

Record = dict[str, Any]
Edit = Callable[[Record], None]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(instant: str, seconds: int) -> str:
    """The RFC 3339 instant ``seconds`` after ``instant``."""
    moment = reader._when(instant) + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def grant(grant_id: str, issuer: str, holder: str, **fields: Any) -> Record:
    """A grant; ``fields`` override any member, including the id, issuer and holder."""
    return {"caveats": [], "closedWorld": True, "constraints": {}, "depth": 0,
            "expiresAt": "2026-11-08T20:00:00Z", "grantId": grant_id, "holder": holder,
            "hopKinds": [], "issuer": issuer, "maxDepth": 0, "maxUses": 1,
            "notBefore": "2026-11-08T08:00:00Z", "parentDigest": None, "tools": [], **fields}


def _named(grant_id: str, issuer: str, holder: str, base: Record, fields: Record) -> Record:
    merged = {"grantId": grant_id, "holder": holder, "issuer": issuer, **base, **fields}
    return grant(merged.pop("grantId"), merged.pop("issuer"), merged.pop("holder"), **merged)


ROOT_CONSTRAINTS = {
    REFUND: {"account": {"exact": "acct-7"}, "amount": {"range": [1, 500]},
             "currency": {"oneOf": ["EUR", "USD"]}, "orderId": {"prefix": "ord-"}},
    READ: {"queue": {"prefix": "support/"}},
}
LEAF_CONSTRAINTS = {
    REFUND: {"account": {"exact": "acct-7"}, "amount": {"range": [1, 100]},
             "currency": {"exact": "EUR"}, "orderId": {"prefix": "ord-2026-"}},
}


def root_grant(**fields: Any) -> Record:
    base = {"caveats": ["no-pii-export"], "constraints": copy.deepcopy(ROOT_CONSTRAINTS),
            "hopKinds": ["child-workflow", "sub-agent", "tool-call"], "maxDepth": 2,
            "maxUses": 10, "tools": [REFUND, READ]}
    return _named("grant-root", ROOT_KEY, DELEGATOR, base, fields)


def leaf_grant(**fields: Any) -> Record:
    base = {"caveats": ["no-pii-export", "eu-only"],
            "constraints": copy.deepcopy(LEAF_CONSTRAINTS), "depth": 1,
            "expiresAt": "2026-11-08T18:00:00Z", "hopKinds": ["tool-call"], "maxDepth": 1,
            "maxUses": 3, "notBefore": "2026-11-08T09:00:00Z", "tools": [REFUND]}
    return _named("grant-refunds", DELEGATOR, AUTHORITY, base, fields)


def leaf_constraint(arg: str, constraint: dict[str, Any] | None) -> Record:
    """The leaf grant with one refund constraint replaced, or dropped when None."""
    constraints = copy.deepcopy(LEAF_CONSTRAINTS)
    if constraint is None:
        constraints[REFUND].pop(arg)
    else:
        constraints[REFUND][arg] = constraint
    return leaf_grant(constraints=constraints)


def use(n: int, issued: str, args: Record | None = None, tool: str = REFUND,
        observe: int = OBSERVE_SECONDS) -> Record:
    """One use of the leaf grant: a permit minted at ``issued`` and its effect."""
    return {"args": ARGS if args is None else args, "callId": f"call-{n}", "issued": issued,
            "n": n, "observe": observe, "tool": tool}


def args(**changes: Any) -> Record:
    """The conformant arguments with members changed, or dropped when the value is None."""
    out = {**ARGS, **changes}
    return {k: v for k, v in out.items() if v is not None}


PRIOR = use(1, "2026-11-08T10:00:00Z")
JUDGED = use(2, "2026-11-08T11:00:00Z")


def _linked(grants: list[Record]) -> list[Record]:
    out: list[Record] = []
    for g in grants:
        g = copy.deepcopy(g)
        g["parentDigest"] = None if not out else digest(out[-1])
        out.append(g)
    return out


def _permit(u: Record, leaf: Record) -> Record:
    return {"argsDigest": digest(u["args"]), "authorityKeyId": leaf["holder"],
            "callId": u["callId"], "expiresAt": at(u["issued"], PERMIT_SECONDS),
            "grantDigest": digest(leaf), "issuedAt": u["issued"], "permitId": f"permit-{u['n']}",
            "runId": RUN, "srl": {"digest": digest(SRL), "epoch": SRL["epoch"]},
            "tool": u["tool"], "workflowId": WORKFLOW}


def _effect(u: Record, permit: Record) -> Record:
    return {"argsDigest": permit["argsDigest"], "callId": permit["callId"],
            "effectId": f"effect-{u['n']}", "grantDigest": permit["grantDigest"],
            "observedAt": at(u["issued"], u["observe"]), "observerKeyId": OBSERVER,
            "outcome": "applied", "permitId": permit["permitId"], "runId": permit["runId"],
            "srl": {"digest": digest(SRL), "epoch": SRL["epoch"]},
            "workflowId": permit["workflowId"]}


def _witness(body: Record) -> list[Record]:
    """Grants, then each permit followed by the effects on it in observed order."""
    rows: list[tuple[str, Record, str]] = [
        ("grant", g, at("2026-11-08T08:00:00Z", i)) for i, g in enumerate(body["grants"])]
    effects = [*body["effects"], body["effect"]]
    placed: set[str] = set()
    for p in body["permits"]:
        rows.append(("permit", p, p["issuedAt"]))
        mine = sorted((e for e in effects if e["permitId"] == p["permitId"]),
                      key=lambda e: (e["observedAt"], e["effectId"]))
        rows += [("effect", e, e["observedAt"]) for e in mine]
        placed |= {e["effectId"] for e in mine}
    rows += [("effect", e, e["observedAt"]) for e in effects if e["effectId"] not in placed]
    return [{"at": when, "digest": digest(obj), "kind": kind, "seq": i + 1}
            for i, (kind, obj, when) in enumerate(rows)]


def record(*, grants: list[Record] | None = None, uses: list[Record] | None = None,
           judged: int = -1, call_tool: str | None = None, call_args: Record | None = None,
           authority_keys: list[str] | None = None, worker_keys: list[str] | None = None,
           on_grants: Edit | None = None, on_uses: Edit | None = None,
           on_record: Edit | None = None,
           contract: str | None = reader.CONTRACT_ID) -> Record:
    """One record; every argument is a departure from the conformant record."""
    body: Record = {
        "authorityKeys": authority_keys or [AUTHORITY, "key:authority-2"],
        "decisionTime": DECISION,
        "grants": _linked(grants if grants is not None else [root_grant(), leaf_grant()]),
        "roots": [ROOT_KEY],
        "workerKeys": worker_keys if worker_keys is not None else [WORKER],
    }
    if on_grants:
        on_grants(body)
    leaf = body["grants"][-1]
    # Every record owns its inputs, so a case's edit never reaches another case.
    chosen = copy.deepcopy(uses if uses is not None else [PRIOR, JUDGED])
    call_args = copy.deepcopy(call_args)
    permits = [_permit(u, leaf) for u in chosen]
    effects = [_effect(u, p) for u, p in zip(chosen, permits, strict=True)]
    index = judged % len(chosen)
    body["permits"] = permits
    body["effect"] = effects.pop(index)
    body["effects"] = effects
    body["call"] = {"args": chosen[index]["args"] if call_args is None else call_args,
                    "tool": chosen[index]["tool"] if call_tool is None else call_tool}
    if on_uses:
        on_uses(body)
    body["witness"] = _witness(body)
    if on_record:
        on_record(body)
    if contract is not None:
        body["contractId"] = contract
    return body


def _permit_of(body: Record) -> Record:
    found: Record = next(p for p in body["permits"]
                         if p["permitId"] == body["effect"]["permitId"])
    return found


def _set_permit(**changes: Any) -> Edit:
    return lambda body: _permit_of(body).update(changes)


def _set_effect(**changes: Any) -> Edit:
    return lambda body: body["effect"].update(changes)


def _set_leaf(**changes: Any) -> Edit:
    return lambda body: body["grants"][-1].update(changes)


def _drop_witness(kind: str, of: Callable[[Record], Record]) -> Edit:
    def edit(body: Record) -> None:
        target = digest(of(body))
        kept = [w for w in body["witness"] if (w["kind"], w["digest"]) != (kind, target)]
        body["witness"] = [{**w, "seq": i + 1} for i, w in enumerate(kept)]
    return edit


def _gap(body: Record) -> None:
    for w in body["witness"][3:]:
        w["seq"] += 1


def _permit_after_effect(body: Record) -> None:
    log = body["witness"]
    p = next(i for i, w in enumerate(log) if w["digest"] == digest(_permit_of(body)))
    e = next(i for i, w in enumerate(log) if w["digest"] == digest(body["effect"]))
    log[p], log[e] = {**log[e], "seq": log[p]["seq"]}, {**log[p], "seq": log[e]["seq"]}


def _effect_as_permit(body: Record) -> None:
    target = digest(body["effect"])
    for w in body["witness"]:
        if w["digest"] == target:
            w["kind"] = "permit"


def _second_effect(offset: int) -> Edit:
    """Another effect consuming the judged permit, ``offset`` seconds from the judged one."""
    def edit(body: Record) -> None:
        other = {**body["effect"], "effectId": "effect-9",
                 "observedAt": at(body["effect"]["observedAt"], offset)}
        body["effects"].append(other)
    return edit


def three_hop(mid_amount: dict[str, Any], leaf_amount: dict[str, Any]) -> list[Record]:
    mid_constraints = copy.deepcopy(ROOT_CONSTRAINTS)
    mid_constraints[REFUND]["amount"] = mid_amount
    leaf_constraints = copy.deepcopy(LEAF_CONSTRAINTS)
    leaf_constraints[REFUND]["amount"] = leaf_amount
    mid = grant("grant-subagent", DELEGATOR, "key:delegator-2", caveats=["no-pii-export"],
                constraints=mid_constraints, depth=1, hopKinds=["sub-agent", "tool-call"],
                maxDepth=2, maxUses=5, tools=[REFUND, READ])
    leaf = leaf_grant(constraints=leaf_constraints, depth=2, issuer="key:delegator-2",
                      maxDepth=2)
    return [root_grant(), mid, leaf]


def _raw(**changes: Any) -> Edit:
    return lambda body: body.update(changes)


Case = tuple[str, Record, str, str, str]
A = reader.ALLOW_REASON


def controls() -> list[Case]:
    four = [PRIOR, use(2, "2026-11-08T10:30:00Z"), use(3, "2026-11-08T11:00:00Z"),
            use(4, "2026-11-08T11:30:00Z")]
    equal_leaf = root_grant(depth=1, holder=AUTHORITY, issuer=DELEGATOR, grantId="grant-same")
    return [
        ("allow-two-hop-attenuated", record(), "allow", A,
         "control: a closed-world refund under a child grant that narrows its root"),
        ("allow-root-grant-direct",
         record(grants=[root_grant(holder=AUTHORITY)],
                uses=[PRIOR, use(2, JUDGED["issued"], args(amount=500, currency="USD",
                                                           orderId="ord-9"))]),
         "allow", A, "control: the root grant itself is used, at the top of its range"),
        ("allow-three-hop-attenuated",
         record(grants=three_hop({"oneOf": [39, 40, 41, 100]}, {"range": [39, 41]})),
         "allow", A, "control: a sub-agent hop narrows a range to a set and the leaf narrows "
         "that set back to a range inside it"),
        ("allow-child-equal-to-parent",
         record(grants=[root_grant(), equal_leaf]), "allow", A,
         "control: a child grant identical in authority to its parent is an attenuation"),
        ("allow-child-oneof-within-parent-range",
         record(grants=[root_grant(), leaf_constraint("amount", {"oneOf": [25, 40]})]),
         "allow", A, "control: the child narrows a range to two members of it"),
        ("allow-last-use-at-max-uses", record(uses=four[:3]), "allow", A,
         "control: the third permit on a grant whose maxUses is 3"),
        ("allow-later-permit-not-counted", record(uses=four, judged=2), "allow", A,
         "control: a fourth permit minted after this one does not spend this one's use"),
        ("allow-use-one-second-before-expiry",
         record(uses=[use(2, "2026-11-08T17:59:29Z")]), "allow", A,
         "control: the effect is observed one second before the leaf grant expires"),
        ("allow-use-at-not-before",
         record(uses=[use(2, "2026-11-08T09:00:00Z", observe=0)]), "allow", A,
         "control: the permit is minted and the effect observed at the leaf's notBefore"),
        ("allow-effect-just-before-permit-expiry",
         record(uses=[PRIOR, use(2, JUDGED["issued"], observe=PERMIT_SECONDS - 1)]),
         "allow", A, "control: the effect is observed one second before its permit expires"),
        ("allow-range-lower-bound", record(uses=[PRIOR, use(2, JUDGED["issued"],
                                                            args(amount=1))]),
         "allow", A, "control: the amount is the range's lower end, which is inclusive"),
        ("allow-range-upper-bound", record(uses=[PRIOR, use(2, JUDGED["issued"],
                                                            args(amount=100))]),
         "allow", A, "control: the amount is the range's upper end, which is inclusive"),
        ("allow-prefix-alone", record(uses=[PRIOR, use(2, JUDGED["issued"],
                                                       args(orderId="ord-2026-"))]),
         "allow", A, "control: the order id is exactly the granted prefix"),
        ("allow-open-world-unnamed-arg",
         record(grants=[root_grant(closedWorld=False), leaf_grant(closedWorld=False)],
                uses=[PRIOR, use(2, JUDGED["issued"], args(memo="goodwill"))]),
         "allow", A, "control: an open-world grant admits an argument it does not name"),
        ("allow-outcome-uncertain", record(on_uses=_set_effect(outcome="uncertain")),
         "allow", A, "control: an effect of uncertain outcome is still an authorised use"),
        ("allow-outcome-not-applied", record(on_uses=_set_effect(outcome="not-applied")),
         "allow", A, "control: an effect that did not apply is still an authorised use"),
        ("allow-first-effect-before-a-reuse", record(on_uses=_second_effect(10)),
         "allow", A, "control: the judged effect is the permit's first; a later one reuses it"),
    ]


def chain_and_widening() -> list[Case]:
    def edit_root(body: Record) -> None:
        body["grants"][0]["maxUses"] = 12

    return [
        ("chain-parent-digest-stale", record(on_grants=edit_root), "deny",
         "grant_chain_broken", "the root grant was changed after the child named its digest"),
        ("chain-root-issuer-untrusted",
         record(grants=[root_grant(issuer="key:root-9"), leaf_grant()]), "deny",
         "grant_chain_broken", "the root grant was issued by a key that is not a trusted root"),
        ("chain-issuer-not-parent-holder",
         record(grants=[root_grant(), leaf_grant(issuer="key:delegator-2")]), "deny",
         "grant_chain_broken", "the child grant was issued by a key that does not hold its parent"),
        ("chain-depth-skips-a-level",
         record(grants=[root_grant(), leaf_grant(depth=2, maxDepth=2)]), "deny",
         "grant_chain_broken", "the child grant claims depth 2 directly under the root"),
        ("chain-root-names-a-parent",
         record(on_grants=lambda b: b["grants"][0].update(parentDigest="sha256:" + "0" * 64)),
         "deny", "grant_chain_broken", "the root grant names a parent the record does not carry"),
        ("widened-child-adds-tool",
         record(grants=[root_grant(), leaf_grant(
             tools=[REFUND, PAYOUT],
             constraints={**LEAF_CONSTRAINTS, PAYOUT: {"amount": {"range": [1, 100]}}})],
             uses=[PRIOR, use(2, JUDGED["issued"], {"amount": 50}, PAYOUT)]),
         "deny", "grant_widened", "the child grant adds payments.payout, and the call uses it"),
        ("widened-exact-to-oneof",
         record(grants=[root_grant(), leaf_constraint("account",
                                                      {"oneOf": ["acct-7", "acct-9"]})],
                uses=[PRIOR, use(2, JUDGED["issued"], args(account="acct-9"))]),
         "deny", "grant_widened", "the parent fixes the account; the child admits a second one, "
         "and the call refunds to it"),
        ("widened-range",
         record(grants=[root_grant(), leaf_constraint("amount", {"range": [1, 1000]})],
                uses=[PRIOR, use(2, JUDGED["issued"], args(amount=800))]),
         "deny", "grant_widened", "the child's range runs past the parent's, and the call uses it"),
        ("widened-shorter-prefix",
         record(grants=[root_grant(), leaf_constraint("orderId", {"prefix": "ord"})],
                uses=[PRIOR, use(2, JUDGED["issued"], args(orderId="ordx-1"))]),
         "deny", "grant_widened", "the child's prefix is shorter than the parent's"),
        ("widened-constraint-type-changed",
         record(grants=[root_grant(), leaf_constraint("amount", {"prefix": "4"})],
                uses=[PRIOR, use(2, JUDGED["issued"], args(amount="40"))]),
         "deny", "grant_widened", "the child replaces an integer range with a text prefix"),
        ("widened-constraint-dropped",
         record(grants=[root_grant(), leaf_constraint("account", None)],
                uses=[PRIOR, use(2, JUDGED["issued"], args(account=None))]),
         "deny", "grant_widened", "the child drops the account constraint the parent sets"),
        ("widened-arg-parent-closed-world-refuses",
         record(grants=[root_grant(), leaf_constraint("memo", {"exact": "goodwill"})],
                uses=[PRIOR, use(2, JUDGED["issued"], args(memo="goodwill"))]),
         "deny", "grant_widened", "the child names an argument its closed-world parent refuses"),
        ("widened-closed-world-opened",
         record(grants=[root_grant(), leaf_grant(closedWorld=False)],
                uses=[PRIOR, use(2, JUDGED["issued"], args(memo="goodwill"))]),
         "deny", "grant_widened", "the child turns its parent's closed world off"),
        ("widened-max-uses", record(grants=[root_grant(), leaf_grant(maxUses=11)]), "deny",
         "grant_widened", "the child allows 11 uses under a parent that allows 10"),
        ("widened-expiry-extended",
         record(grants=[root_grant(), leaf_grant(expiresAt="2026-11-08T20:00:01Z")]),
         "deny", "grant_widened", "the child expires one second after its parent"),
        ("widened-not-before-earlier",
         record(grants=[root_grant(), leaf_grant(notBefore="2026-11-08T07:59:59Z")]),
         "deny", "grant_widened", "the child comes into force one second before its parent"),
        ("widened-max-depth",
         record(grants=[root_grant(), leaf_grant(maxDepth=3)]), "deny", "grant_widened",
         "the child allows delegation one level deeper than its parent"),
        ("widened-past-parent-max-depth",
         record(grants=[root_grant(maxDepth=0), leaf_grant(maxDepth=1)]), "deny",
         "grant_widened", "the parent allows no delegation and the child exists anyway"),
        ("widened-hop-kind-added",
         record(grants=[root_grant(), leaf_grant(hopKinds=["tool-call", "a2a"])]), "deny",
         "grant_widened", "the child allows an A2A hop its parent does not"),
        ("widened-caveat-dropped",
         record(grants=[root_grant(), leaf_grant(caveats=["eu-only"])]), "deny",
         "grant_widened", "the child drops a caveat its parent carries"),
    ]


def use_checks() -> list[Case]:
    four = [PRIOR, use(2, "2026-11-08T10:30:00Z"), use(3, "2026-11-08T11:00:00Z"),
            use(4, "2026-11-08T11:30:00Z")]
    stale = digest({**_linked([root_grant(), leaf_grant(maxUses=5)])[1]})
    unknown = "key:authority-9"
    return [
        ("use-at-leaf-expiry", record(uses=[use(2, "2026-11-08T17:59:30Z")]), "deny",
         "grant_not_in_force",
         "the effect is observed at the leaf's expiresAt, which is exclusive"),
        ("use-before-not-before",
         record(uses=[use(2, "2026-11-08T08:59:59Z", observe=0)]), "deny",
         "grant_not_in_force", "the effect is observed one second before the leaf is in force"),
        ("tool-not-in-leaf",
         record(uses=[PRIOR, use(2, JUDGED["issued"], {}, READ)]), "deny", "tool_not_granted",
         "the call reads tickets, which the root grants and the leaf does not"),
        ("call-args-not-the-effects",
         record(on_uses=lambda b: (_set_effect(argsDigest=digest(args(amount=400)))(b),
                                   _set_permit(argsDigest=digest(args(amount=400)))(b))),
         "deny", "call_args_unbound", "the permit and the effect bind a refund of 400; the record "
         "shows arguments for 40"),
        ("arg-above-range", record(uses=[PRIOR, use(2, JUDGED["issued"], args(amount=101))]),
         "deny", "argument_outside_constraint", "the amount is one above the range's upper end"),
        ("arg-below-range", record(uses=[PRIOR, use(2, JUDGED["issued"], args(amount=0))]),
         "deny", "argument_outside_constraint", "the amount is one below the range's lower end"),
        ("arg-not-exact",
         record(uses=[PRIOR, use(2, JUDGED["issued"], args(currency="USD"))]), "deny",
         "argument_outside_constraint", "the leaf fixes EUR and the call refunds USD"),
        ("arg-prefix-mismatch",
         record(uses=[PRIOR, use(2, JUDGED["issued"], args(orderId="ord-2025-9"))]), "deny",
         "argument_outside_constraint", "the order id does not start with the granted prefix"),
        ("arg-not-in-oneof",
         record(grants=[root_grant(holder=AUTHORITY)],
                uses=[PRIOR, use(2, JUDGED["issued"], args(currency="GBP"))]), "deny",
         "argument_outside_constraint", "the currency is not one of the root grant's set"),
        ("arg-type-mismatch",
         record(uses=[PRIOR, use(2, JUDGED["issued"], args(amount="40"))]), "deny",
         "argument_outside_constraint", "the amount is the text 40, not the integer"),
        ("arg-constrained-absent",
         record(uses=[PRIOR, use(2, JUDGED["issued"], args(currency=None))]), "deny",
         "argument_outside_constraint", "the call omits the currency the grant constrains"),
        ("arg-unnamed-closed-world",
         record(uses=[PRIOR, use(2, JUDGED["issued"], args(memo="goodwill"))]), "deny",
         "argument_outside_constraint", "the call carries an argument a closed-world grant "
         "does not name"),
        ("permit-not-minted", record(on_uses=_set_effect(permitId="permit-77")), "deny",
         "permit_missing", "the effect names a permit nobody minted on the grant"),
        ("uses-beyond-max", record(uses=four), "deny", "uses_exhausted",
         "the fourth permit on a grant whose maxUses is 3"),
        ("uses-unwitnessed-permit-counts",
         record(uses=four, on_record=lambda b: (
             _drop_witness("permit", lambda r: r["permits"][0])(b))),
         "deny", "uses_exhausted",
         "an earlier permit missing from the witness log still spends a use"),
        ("permit-for-parent-grant",
         record(on_uses=lambda b: (_set_permit(grantDigest=digest(b["grants"][0]))(b),
                                   _set_effect(grantDigest=digest(b["grants"][0]))(b))),
         "deny", "permit_not_for_grant", "the permit and effect name the root grant, not the leaf"),
        ("permit-for-stale-grant",
         record(on_uses=lambda b: (_set_permit(grantDigest=stale)(b),
                                   _set_effect(grantDigest=stale)(b))),
         "deny", "permit_not_for_grant", "the permit names an earlier version of the leaf grant"),
        ("permit-not-from-holder", record(on_uses=_set_permit(authorityKeyId="key:authority-2")),
         "deny", "permit_not_from_holder", "a listed authority that does not hold the grant "
         "minted the permit"),
        ("permit-authority-unknown",
         record(grants=[root_grant(), leaf_grant(holder=unknown)]), "deny",
         "permit_authority_unknown", "the grant's holder, which minted the permit, is not a "
         "listed authority key"),
        ("authority-key-in-worker",
         record(grants=[root_grant(), leaf_grant(holder=WORKER)],
                authority_keys=[AUTHORITY, WORKER]), "deny", "authority_key_in_worker",
         "the key that holds the grant and mints its permits sits inside the agent's worker"),
        ("permit-expired-at-effect",
         record(uses=[PRIOR, use(2, JUDGED["issued"], observe=PERMIT_SECONDS)]), "deny",
         "permit_not_in_force", "the effect is observed at the permit's expiresAt"),
        ("effect-before-permit",
         record(uses=[PRIOR, use(2, JUDGED["issued"], observe=-1)]), "deny",
         "permit_not_in_force", "the effect is observed one second before its permit was minted"),
        ("permit-minted-before-grant",
         record(uses=[use(2, "2026-11-08T08:59:00Z", observe=120)]), "deny",
         "permit_not_in_force", "the permit was minted before the leaf grant came into force"),
        ("permit-reused", record(on_uses=_second_effect(-10)), "deny", "permit_reused",
         "another effect already consumed this permit, witnessed before this one"),
        ("permit-workflow-differs", record(on_uses=_set_permit(workflowId="wf-refunds-8")),
         "deny", "permit_identity_mismatch", "the permit was minted for another workflow"),
        ("permit-run-differs", record(on_uses=_set_permit(runId="run-4")), "deny",
         "permit_identity_mismatch", "the permit was minted for another run"),
        ("permit-call-differs", record(on_uses=_set_permit(callId="call-5")), "deny",
         "permit_identity_mismatch", "the permit was minted for another call"),
        ("permit-tool-differs", record(on_uses=_set_permit(tool=READ)), "deny",
         "permit_identity_mismatch", "the permit was minted for another tool"),
        ("effect-args-differ-from-permit",
         record(on_uses=_set_permit(argsDigest=digest(args(amount=60)))), "deny",
         "effect_args_mismatch", "the permit authorised a refund of 60; the effect applied 40"),
        ("effect-grant-unlinked",
         record(on_uses=lambda b: _set_effect(grantDigest=digest(b["grants"][0]))(b)), "deny",
         "effect_grant_unlinked", "the effect names a grant other than its permit's"),
        ("effect-not-witnessed",
         record(on_record=_drop_witness("effect", lambda b: b["effect"])), "deny",
         "effect_unwitnessed", "the witness log does not record the effect"),
        ("permit-not-witnessed",
         record(on_record=_drop_witness("permit", _permit_of)), "deny", "effect_unwitnessed",
         "the witness log does not record the effect's permit"),
        ("witness-log-gap", record(on_record=_gap), "deny", "effect_unwitnessed",
         "the witness log skips a sequence number"),
        ("permit-witnessed-after-effect", record(on_record=_permit_after_effect), "deny",
         "effect_unwitnessed", "the permit enters the witness log after the effect it authorised"),
        ("effect-witnessed-as-permit", record(on_record=_effect_as_permit), "deny",
         "effect_unwitnessed", "the effect's digest is logged under the permit kind"),
    ]


def malformed() -> list[Case]:
    def constraint(value: Any) -> Edit:
        return lambda b: b["grants"][-1]["constraints"][REFUND].update(amount=value)

    return [
        ("malformed-grants-empty", record(on_record=_raw(grants=[])), "deny",
         "malformed_record", "the grant chain is empty"),
        ("malformed-max-uses-text", record(on_record=_set_leaf(maxUses="3")), "deny",
         "malformed_record", "maxUses is text"),
        ("malformed-max-uses-boolean", record(on_record=_set_leaf(maxUses=True)), "deny",
         "malformed_record", "maxUses is a boolean"),
        ("malformed-integer-unsafe", record(on_record=_set_leaf(maxUses=2**53)), "deny",
         "malformed_record", "maxUses is past the largest safe integer"),
        ("malformed-range-reversed", record(on_record=constraint({"range": [100, 1]})), "deny",
         "malformed_record", "a range's lower end is above its upper end"),
        ("malformed-range-float", record(on_record=constraint({"range": [1, 100.5]})), "deny",
         "malformed_record", "a range end is not an integer"),
        ("malformed-arg-float",
         record(on_record=lambda b: b["call"]["args"].update(amount=40.0)), "deny",
         "malformed_record", "the amount is the number 40.0; the contract takes integers only"),
        ("malformed-constraint-two-kinds",
         record(on_record=constraint({"exact": 40, "range": [1, 100]})), "deny",
         "malformed_record", "one constraint names two kinds"),
        ("malformed-constraint-ungranted-tool",
         record(on_record=lambda b: b["grants"][-1]["constraints"].update(
             {READ: {"queue": {"prefix": "support/"}}})),
         "deny", "malformed_record", "the grant constrains a tool it does not grant"),
        ("malformed-depth-beyond-own-max",
         record(on_record=_set_leaf(maxDepth=0)), "deny", "malformed_record",
         "a grant sits deeper than its own maxDepth"),
        ("malformed-outcome-unknown", record(on_record=_set_effect(outcome="done")), "deny",
         "malformed_record", "the effect's outcome is not one the contract names"),
        ("malformed-time-offset",
         record(on_record=_raw(decisionTime="2026-11-08T21:00:00+00:00")), "deny",
         "malformed_record", "the decision time uses an offset instead of Z"),
        ("malformed-evidence-after-decision",
         record(on_record=_raw(decisionTime="2026-11-08T11:00:10Z")), "deny", "malformed_record",
         "the effect is stamped after the instant it is judged at"),
        ("malformed-duplicate-permit-id",
         record(on_record=lambda b: b["permits"].append(copy.deepcopy(b["permits"][0]))),
         "deny", "malformed_record", "two permits carry one permit id"),
        ("malformed-call-missing", record(on_record=lambda b: b.pop("call")), "deny",
         "malformed_record", "the record omits the call the effect applied"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown", record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         "deny", "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [*controls(), *chain_and_widening(), *use_checks(), *malformed()]


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
