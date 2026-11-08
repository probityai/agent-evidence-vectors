"""Build the attenuated-delegation cases byte-identically.

Every case is one record of a capability carried across execution hops and
presented at the end, read under the contract at ``contractId``. The
generator links each hop to the one before it by recomputing the parent
grant's digest, so a case breaks the link only where it means to. Each denied
case departs from a conformant chain in one place.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import attenuateddelegation as reader  # noqa: E402

SUITE = reader.SUITE
AUTHORITY = "key:authority-1"
ORCHESTRATOR = "key:orchestrator"
HOLDER_FOR = {"child-workflow": "key:child-workflow", "sub-agent": "key:sub-agent",
              "a2a": "key:remote-agent", "tool": "key:tool-runner"}
START, END = "2026-11-08T09:00:00Z", "2026-11-08T17:00:00Z"
AT = "2026-11-08T12:00:00Z"
REFUND = "payments.refund"
ARGS = {"account": "acct-7731", "amount": 120, "currency": "USD"}
ROOT_CONSTRAINTS = {
    REFUND: {"account": {"prefix": "acct-"}, "amount": {"range": [1, 500]},
             "currency": {"oneOf": ["USD", "EUR"]}},
    "ticket.update": {"status": {"oneOf": ["open", "pending", "closed"]}},
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def root_grant(**changes: Any) -> dict[str, Any]:
    """The authority's grant to the orchestrator; ``changes`` replace fields."""
    grant: dict[str, Any] = {
        "caveats": ["audit:required"], "closedWorld": True,
        "constraints": copy.deepcopy(ROOT_CONSTRAINTS), "depth": 0, "expiresAt": END,
        "grantId": "grant-root", "holder": ORCHESTRATOR,
        "hopKinds": list(reader.HOP_KINDS), "issuer": AUTHORITY, "maxDepth": 4,
        "maxUses": 10, "notBefore": START, "parentDigest": None,
        "tools": [REFUND, "ticket.read", "ticket.update"],
    }
    grant.update(changes)
    return grant


Hop = tuple[str, dict[str, Any]]
Edit = Callable[[dict[str, Any]], None]


def child(parent: dict[str, Any], kind: str, edit: Edit | None = None,
          holder: str | None = None) -> dict[str, Any]:
    """The parent's grant handed on unchanged across a hop of ``kind``, then ``edit``ed."""
    grant = copy.deepcopy(parent)
    grant.update(grantId=f"grant-{kind}-{parent['depth'] + 1}", issuer=parent["holder"],
                 holder=holder or HOLDER_FOR[kind], depth=parent["depth"] + 1)
    if edit is not None:
        edit(grant)
    return grant


def chain(*steps: tuple[str, Edit | None]) -> list[dict[str, Any]]:
    """The root grant followed by one child per (kind, edit) step."""
    grants = [root_grant()]
    for kind, edit in steps:
        grants.append(child(grants[-1], kind, edit))
    return grants


def hops(grants: list[dict[str, Any]], kinds: list[str] | None = None,
         link: bool = True) -> list[dict[str, Any]]:
    """Hops carrying ``grants``; ``link`` recomputes every parentDigest from the grant before."""
    out = []
    for i, grant in enumerate(grants):
        grant = copy.deepcopy(grant)
        if link and i:
            grant["parentDigest"] = reader.digest(out[-1]["grant"])
        kind = "root" if i == 0 else (kinds[i] if kinds else _kind_of(grant))
        out.append({"grant": grant, "hopKind": kind, "presentedBy": grant["issuer"]})
    return out


def _kind_of(grant: dict[str, Any]) -> str:
    return grant["grantId"].split("-", 1)[1].rsplit("-", 1)[0]


def record(chain_hops: list[dict[str, Any]], *, presenter: str | None = None,
           tool: str = REFUND, args: dict[str, Any] | None = None, at: str = AT,
           contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One record; the presentation defaults to the leaf holder refunding 120 USD."""
    body: dict[str, Any] = {
        "hops": chain_hops,
        "presentation": {"args": copy.deepcopy(ARGS) if args is None else args, "at": at,
                         "presenterKeyId": presenter or chain_hops[-1]["grant"]["holder"],
                         "tool": tool},
        "trustedRoots": [AUTHORITY],
    }
    if contract is not None:
        body["contractId"] = contract
    return body


def edited(body: dict[str, Any], mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    out = copy.deepcopy(body)
    mutate(out)
    return out


def setting(**fields: Any) -> Edit:
    def apply(grant: dict[str, Any]) -> None:
        grant.update(copy.deepcopy(fields))
    return apply


def constrain(tool: str, arg: str, bound: dict[str, Any] | None) -> Edit:
    """Set (or with None, drop) one argument constraint."""
    def apply(grant: dict[str, Any]) -> None:
        table = grant["constraints"].setdefault(tool, {})
        if bound is None:
            table.pop(arg, None)
        else:
            table[arg] = bound
    return apply


def both(*edits: Edit) -> Edit:
    def apply(grant: dict[str, Any]) -> None:
        for e in edits:
            e(grant)
    return apply


# The four-hop chain: each hop narrows something, and the leaf sits at maxDepth.
FOUR = [
    ("child-workflow", setting(tools=[REFUND, "ticket.read"],
                               constraints={REFUND: copy.deepcopy(ROOT_CONSTRAINTS[REFUND])})),
    ("sub-agent", constrain(REFUND, "amount", {"range": [1, 200]})),
    ("a2a", both(setting(expiresAt="2026-11-08T15:00:00Z", maxUses=3,
                         caveats=["audit:required", "region:eu"]),
                 constrain(REFUND, "account", {"prefix": "acct-77"}))),
    ("tool", both(setting(tools=[REFUND], hopKinds=[], maxUses=1),
                  constrain(REFUND, "currency", {"exact": "USD"}))),
]


def one(kind: str, edit: Edit | None = None) -> dict[str, Any]:
    return record(hops(chain((kind, edit))))


def sub(edit: Edit | None = None, **kw: Any) -> dict[str, Any]:
    """Root to one sub-agent, the child edited by ``edit``."""
    return record(hops(chain(("sub-agent", edit))), **kw)


def four(at: int, edit: Edit, **kw: Any) -> dict[str, Any]:
    """The four-hop chain with ``edit`` applied on top of hop ``at``'s own narrowing."""
    steps = list(FOUR)
    kind, own = steps[at - 1]
    steps[at - 1] = (kind, both(own, edit) if own else edit)
    return record(hops(chain(*steps)), **kw)


Case = tuple[str, dict[str, Any], str, str, str]


def _controls() -> list[Case]:
    a = "allow"
    ok = reader.ALLOW_REASON
    return [
        ("allow-root-only", record(hops([root_grant()]), presenter=ORCHESTRATOR), a, ok,
         "control: the root holder presents the root grant itself"),
        ("allow-child-workflow-hop", one("child-workflow"), a, ok,
         "control: a child workflow receives the parent's grant unchanged"),
        ("allow-sub-agent-hop",
         one("sub-agent", setting(tools=[REFUND],
                                  constraints={REFUND: copy.deepcopy(ROOT_CONSTRAINTS[REFUND])})),
         a, ok,
         "control: a sub-agent receives the refund tool only"),
        ("allow-a2a-hop", one("a2a", constrain(REFUND, "currency", {"exact": "USD"})), a, ok,
         "control: a remote agent receives the grant with the currency pinned"),
        ("allow-tool-hop", one("tool", setting(hopKinds=[], maxUses=1)), a, ok,
         "control: a tool-to-tool call receives a single-use grant that cannot hop again"),
        ("allow-four-hop-mixed-chain", record(hops(chain(*FOUR))), a, ok,
         "control: child workflow, sub-agent, remote agent and tool each narrow something, "
         "and the leaf sits at exactly maxDepth"),
        ("allow-equal-scope-hop", sub(), a, ok,
         "control: the child keeps the parent's scope exactly; equal is an attenuation"),
        ("allow-expiry-equal-to-parent", sub(setting(expiresAt=END, notBefore=START)), a, ok,
         "control: the child starts and ends at exactly the parent's instants"),
        ("allow-narrowed-every-constraint-kind",
         sub(both(constrain(REFUND, "amount", {"exact": 500}),
                  constrain(REFUND, "currency", {"oneOf": ["EUR"]}),
                  constrain(REFUND, "account", {"prefix": "acct-7731"}),
                  constrain("ticket.update", "status", {"exact": "closed"})),
             args={"account": "acct-7731", "amount": 500, "currency": "EUR"}), a, ok,
         "control: exact at the range's upper end, a oneOf subset, a longer prefix"),
        ("allow-range-equal-bounds", sub(constrain(REFUND, "amount", {"range": [1, 500]})), a,
         ok, "control: the child restates the parent's range at both bounds"),
        ("allow-range-from-oneof-integers",
         record(hops(chain(("sub-agent", constrain(REFUND, "amount", {"oneOf": [100, 120, 121]})),
                           ("tool", constrain(REFUND, "amount", {"range": [120, 121]}))))),
         a, ok, "control: a range whose every integer the parent's oneOf lists"),
        ("allow-uses-equal-to-parent", sub(setting(maxUses=10)), a, ok,
         "control: the child keeps the parent's use count"),
        ("allow-caveat-added", sub(setting(caveats=["audit:required", "dual-control"])), a, ok,
         "control: the child adds a caveat"),
        ("allow-open-world-parent-extra-argument",
         record(hops([root_grant(closedWorld=False)]), presenter=ORCHESTRATOR,
                args={**ARGS, "memo": "duplicate charge"}), a, ok,
         "control: an open-world grant admits an argument it does not name"),
        ("allow-open-parent-closed-child",
         record(hops([root_grant(closedWorld=False),
                      child(root_grant(closedWorld=False), "sub-agent",
                            both(setting(closedWorld=True),
                                 constrain(REFUND, "memo", {"prefix": ""})))]),
                args={**ARGS, "memo": "duplicate charge"}), a, ok,
         "control: an open-world parent, a closed-world child naming one more argument"),
        ("allow-presentation-at-not-before", sub(at=START), a, ok,
         "control: presented at exactly the leaf's notBefore"),
        ("allow-presentation-last-second", sub(at="2026-11-08T16:59:59Z"), a, ok,
         "control: presented one second before the leaf expires"),
        ("allow-other-tool-without-arguments", sub(tool="ticket.read", args={}), a, ok,
         "control: a tool the leaf names with no constraints, called with no arguments"),
    ]


def _structure_denials() -> list[Case]:
    d = "deny"
    base = sub()
    other_root = root_grant(grantId="grant-root-wide", tools=[REFUND, "ticket.read",
                                                               "ticket.update", "ticket.delete"])
    parent, kid = chain(("sub-agent", None))
    grafted = child(kid, "tool")
    grafted["parentDigest"] = reader.digest(parent)
    linked = hops([parent, kid])
    linked.append({"grant": grafted, "hopKind": "tool", "presentedBy": kid["holder"]})
    repeated = hops([parent, kid])
    repeated.append(copy.deepcopy(repeated[-1]))
    return [
        ("contract-id-missing", sub(contract=None), d, "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown", sub(contract=reader.CONTRACT_ID.replace("/v1", "/v0")), d,
         "contract_id_unknown", "the record names a contract version that does not exist"),
        ("malformed-hops-empty", edited(base, lambda r: r.update(hops=[])), d,
         "malformed_record", "the record carries no hops"),
        ("malformed-grant-field-missing",
         edited(base, lambda r: r["hops"][1]["grant"].pop("maxUses")), d, "malformed_record",
         "the child grant omits maxUses"),
        ("malformed-constraint-two-kinds",
         edited(base, lambda r: r["hops"][1]["grant"]["constraints"][REFUND].update(
             amount={"exact": 120, "range": [1, 500]})), d, "malformed_record",
         "one argument constraint names two kinds at once"),
        ("malformed-range-reversed",
         edited(base, lambda r: r["hops"][1]["grant"]["constraints"][REFUND].update(
             amount={"range": [500, 1]})), d, "malformed_record",
         "a range's low bound is above its high bound"),
        ("malformed-hop-kind-unknown", edited(base, lambda r: r["hops"][1].update(
            hopKind="plugin")), d, "malformed_record", "a hop names a kind the contract lacks"),
        ("malformed-first-hop-not-root", edited(base, lambda r: r["hops"][0].update(
            hopKind="sub-agent")), d, "malformed_record", "the first hop is not the root hop"),
        ("malformed-closed-world-not-boolean",
         edited(base, lambda r: r["hops"][0]["grant"].update(closedWorld=1)), d,
         "malformed_record", "closedWorld is the integer 1, not a boolean"),
        ("malformed-time-unparseable",
         edited(base, lambda r: r["presentation"].update(at="noon")), d, "malformed_record",
         "the presentation time is not an RFC 3339 instant"),
        ("parent-digest-names-other-grant",
         record(hops([root_grant(), edited(child(root_grant(), "sub-agent"),
                                           lambda g: g.update(
                                               parentDigest=reader.digest(other_root)))],
                     link=False)), d, "chain_unlinked",
         "the child names a wider grant the authority issued, not the grant on the hop "
         "before it"),
        ("sibling-grafted-as-descendant", record(linked), d, "chain_unlinked",
         "the third grant was derived from the root, not from the grant before it"),
        ("grant-repeated-on-chain", record(repeated), d, "chain_unlinked",
         "the same grant appears twice, a digest repeats on the chain"),
        ("root-issuer-untrusted", record(hops(
            [root_grant(issuer="key:self-issued"),
             child(root_grant(issuer="key:self-issued"), "sub-agent")])), d, "root_untrusted",
         "the root grant was issued by a key that is not a trusted root"),
        ("root-names-a-parent", record(hops(
            [root_grant(parentDigest=reader.digest(other_root)),
             child(root_grant(parentDigest=reader.digest(other_root)), "sub-agent")])),
         d, "root_untrusted", "the chain starts at a grant that names a parent outside it"),
        ("root-handed-over-by-other-key",
         edited(base, lambda r: r["hops"][0].update(presentedBy="key:relay")), d,
         "root_untrusted", "the root grant was handed over by a key other than its issuer"),
    ]


def _issuer_kind_depth_denials() -> list[Case]:
    d = "deny"
    deep = chain(("sub-agent", setting(maxDepth=1)), ("tool", setting(maxDepth=1)))
    return [
        ("child-issued-by-parent-issuer", sub(setting(issuer=AUTHORITY)), d,
         "issuer_not_parent_holder",
         "the authority itself mints the sub-agent's grant, bypassing the orchestrator"),
        ("child-issued-by-unrelated-key", sub(setting(issuer="key:outsider")), d,
         "issuer_not_parent_holder", "a key that never held the parent minted the child"),
        ("child-handed-over-by-relay",
         edited(sub(), lambda r: r["hops"][1].update(presentedBy="key:relay")), d,
         "issuer_not_parent_holder",
         "a relay that does not hold the parent handed the child grant across the hop"),
        ("four-hop-a2a-issued-by-grandparent",
         four(3, setting(issuer=HOLDER_FOR["child-workflow"])), d, "issuer_not_parent_holder",
         "the remote agent's grant was minted by the child workflow, two hops up"),
        ("hop-kind-forbidden-by-parent",
         record(hops([root_grant(hopKinds=["child-workflow", "sub-agent", "tool"]),
                      child(root_grant(hopKinds=["child-workflow", "sub-agent", "tool"]),
                            "a2a", setting(hopKinds=["tool"]))])), d,
         "hop_kind_not_permitted", "an agent-to-agent hop under a grant that permits none"),
        ("hop-kinds-widened", record(hops(
            [root_grant(hopKinds=["sub-agent"]),
             child(root_grant(hopKinds=["sub-agent"]), "sub-agent",
                   setting(hopKinds=["sub-agent", "a2a"]))])), d, "hop_kind_not_permitted",
         "the child permits onward agent-to-agent hops its parent never permitted"),
        ("hop-under-terminal-tool-grant",
         record(hops(chain(("tool", setting(hopKinds=[])), ("sub-agent", None)))), d,
         "hop_kind_not_permitted", "a further hop under a tool grant that permits none"),
        ("depth-skips-a-level", sub(setting(depth=2)), d, "depth_exceeded",
         "the child claims depth 2 directly under the root"),
        ("depth-one-past-max", record(hops(deep)), d, "depth_exceeded",
         "the chain reaches depth 2 under a maxDepth of 1, one past the limit"),
        ("max-depth-raised", sub(setting(maxDepth=5)), d, "depth_exceeded",
         "the child raises maxDepth above its parent's"),
        ("root-depth-not-zero", record(hops(
            [root_grant(depth=1), child(root_grant(depth=1), "sub-agent")])), d,
         "depth_exceeded", "the root grant claims depth 1"),
    ]


def _scope_denials() -> list[Case]:
    d = "deny"
    exact_parent = ("sub-agent", constrain(REFUND, "currency", {"exact": "USD"}))
    return [
        ("tool-added-by-child", sub(setting(tools=[REFUND, "ticket.read", "ticket.update",
                                                  "ticket.delete"])), d, "tool_widened",
         "the sub-agent's grant adds ticket.delete"),
        ("four-hop-tool-restored", four(3, setting(tools=[REFUND, "ticket.read",
                                                          "ticket.update"])), d,
         "tool_widened", "the remote agent's grant restores ticket.update, dropped two hops up"),
        ("exact-widened-to-oneof",
         record(hops(chain(exact_parent, ("tool", constrain(REFUND, "currency",
                                                            {"oneOf": ["USD", "EUR"]}))))),
         d, "constraint_widened", "a pinned currency becomes a choice of two"),
        ("exact-widened-to-range",
         record(hops(chain(("sub-agent", constrain(REFUND, "amount", {"exact": 120})),
                           ("tool", constrain(REFUND, "amount", {"range": [120, 121]}))))),
         d, "constraint_widened", "a pinned amount becomes a two-value range"),
        ("oneof-superset", sub(constrain(REFUND, "currency", {"oneOf": ["USD", "EUR", "GBP"]})),
         d, "constraint_widened", "the child's currency list adds GBP"),
        ("range-wider-high-end", sub(constrain(REFUND, "amount", {"range": [1, 501]})), d,
         "constraint_widened", "the amount range ends one above the parent's"),
        ("range-wider-low-end", sub(constrain(REFUND, "amount", {"range": [0, 500]})), d,
         "constraint_widened", "the amount range starts one below the parent's"),
        ("prefix-shortened", sub(constrain(REFUND, "account", {"prefix": "acct"})), d,
         "constraint_widened", "the account prefix is shorter than the parent's"),
        ("constraint-dropped",
         record(hops([root_grant(closedWorld=False),
                      child(root_grant(closedWorld=False), "sub-agent",
                            constrain(REFUND, "amount", None))])), d,
         "constraint_widened", "under an open-world parent the child drops the amount constraint"),
        ("closed-world-relaxed", sub(setting(closedWorld=False)), d, "constraint_widened",
         "the child turns a closed-world grant open"),
        ("closed-world-argument-added",
         sub(constrain(REFUND, "memo", {"prefix": ""}), args={**ARGS, "memo": "duplicate charge"}),
         d, "constraint_widened",
         "under a closed-world parent the child names an argument the parent forbade"),
        ("four-hop-sub-agent-range-widened",
         four(2, constrain(REFUND, "amount", {"range": [1, 600]})), d, "constraint_widened",
         "the sub-agent's amount range ends above the child workflow's"),
        ("expiry-one-second-later", sub(setting(expiresAt="2026-11-08T17:00:01Z")), d,
         "lifetime_extended", "the child expires one second after its parent"),
        ("not-before-one-second-earlier", sub(setting(notBefore="2026-11-08T08:59:59Z")), d,
         "lifetime_extended", "the child starts one second before its parent"),
        ("caveat-dropped", sub(setting(caveats=[])), d, "caveat_dropped",
         "the child drops the audit caveat"),
        ("four-hop-tool-drops-caveat",
         four(4, setting(caveats=["audit:required"])), d, "caveat_dropped",
         "the tool grant drops the region caveat the remote agent's grant added"),
        ("uses-raised", sub(setting(maxUses=11)), d, "uses_raised",
         "the child allows one more use than its parent"),
    ]


def _presentation_denials() -> list[Case]:
    d = "deny"
    return [
        ("presented-by-parent-holder", sub(presenter=ORCHESTRATOR), d, "presenter_not_holder",
         "the orchestrator presents the sub-agent's grant"),
        ("presented-by-unrelated-key", record(hops(chain(*FOUR)), presenter="key:outsider"), d,
         "presenter_not_holder", "a key that holds no grant presents the leaf"),
        ("presented-tool-outside-leaf", record(hops(chain(*FOUR)), tool="ticket.read",
                                               args={}), d, "presentation_outside_leaf",
         "the tool runner calls ticket.read, which its grant dropped"),
        ("presented-amount-outside-leaf",
         record(hops(chain(*FOUR)), args={**ARGS, "amount": 250}), d,
         "presentation_outside_leaf",
         "the amount 250 is inside the root's range and outside the leaf's"),
        ("presented-extra-argument-closed-world",
         sub(args={**ARGS, "memo": "duplicate charge"}), d, "presentation_outside_leaf",
         "an argument the closed-world leaf does not name"),
        ("presented-constrained-argument-missing",
         sub(args={"amount": 120, "currency": "USD"}), d, "presentation_outside_leaf",
         "the account the leaf constrains is not supplied"),
        ("presented-at-expiry", sub(at=END), d, "presentation_outside_leaf",
         "presented at exactly the leaf's expiresAt"),
        ("presented-before-not-before", sub(at="2026-11-08T08:59:59Z"), d,
         "presentation_outside_leaf", "presented one second before the leaf's notBefore"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [*_controls(), *_structure_denials(), *_issuer_kind_depth_denials(),
            *_scope_denials(), *_presentation_denials()]


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
