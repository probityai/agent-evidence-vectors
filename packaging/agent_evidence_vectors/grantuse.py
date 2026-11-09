"""Judge whether an effect stands as an authorised use of a grant.

A grant names the tools its holder may call, the arguments each call may carry,
how many times it may be used, when it is in force, and how far it may be
delegated. A child grant may only narrow its parent. A use of the leaf grant is
one single-use permit, minted by the grant's holder, an authority whose key is
not held inside the agent's worker. The permit names the grant's digest and the
workflow, run, call, tool and argument digest it authorises. The effect record
names the permit and the grant, so an auditor walks grant to permit to effect.
A witness log orders every permit and effect.

A verifier that checks only that the leaf grant names the tool and has not
expired, which is what most capability libraries check, allows a widened chain,
an argument outside its constraint, a spent budget, a permit minted inside the
worker, a permit spent twice and an effect nobody witnessed.

The record carries the grant chain from root to leaf (``grants``), the trusted
root issuer keys (``roots``), the authority keys (``authorityKeys``), the keys
held inside the agent's worker (``workerKeys``), every permit minted on the leaf
grant so far (``permits``), the other effects recorded against them
(``effects``), the effect being judged (``effect``), the call it applied
(``call``: ``tool`` and ``args``), the witness log (``witness``) and the
judging instant (``decisionTime``).

Digests are ``sha256:`` and the lowercase hex SHA-256 of
``json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)``
encoded as UTF-8. With strings and integers only, those are the RFC 8785 bytes.
The reader recomputes every digest it relies on; a digest field is a claim.

Constraints are ``{"exact": v}``, ``{"oneOf": [...]}``, ``{"range": [lo, hi]}``
(integers, both ends inclusive) and ``{"prefix": "..."}``. A constraint narrows
another when every value it admits the other admits too. An argument the grant
constrains must be present. Under ``closedWorld`` an argument the grant does not
name is refused. A grant is in force from ``notBefore`` inclusive to
``expiresAt`` exclusive, and so is a permit. ``maxDepth`` is the greatest depth
a grant derived from this one may sit at; the root is at depth 0.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the grant-use contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, carries no number
   that is not an integer, every time parses, every count is a safe integer, no
   grant sits deeper than its own ``maxDepth``, identifiers are unique, and no
   evidence is stamped after ``decisionTime`` (``malformed_record``);
4. the root has no parent and a trusted root issued it, each grant sits one
   level below its parent, names the recomputed digest of its parent, and was
   issued by its parent's holder (``grant_chain_broken``);
5. no grant admits more than its parent: tools, constraints by type, closed
   world, uses, the in-force window, depth, hop kinds and caveats
   (``grant_widened``);
6. the effect was observed while every grant on the chain was in force
   (``grant_not_in_force``);
7. the leaf grant names the called tool (``tool_not_granted``);
8. the call's arguments have the digest the effect records
   (``call_args_unbound``);
9. the arguments satisfy every constraint of the leaf grant, and under a closed
   world carry nothing it does not name (``argument_outside_constraint``);
10. the permit the effect names is among the permits minted
    (``permit_missing``);
11. the permits on the leaf grant witnessed at or before this one, counting an
    unwitnessed permit as earlier, do not exceed ``maxUses``
    (``uses_exhausted``);
12. the permit names the recomputed digest of the leaf grant
    (``permit_not_for_grant``);
13. the leaf grant's holder minted the permit (``permit_not_from_holder``);
14. that key is a listed authority key (``permit_authority_unknown``);
15. that key is not held in the worker (``authority_key_in_worker``);
16. the permit was minted while every grant was in force, and the effect was
    observed while the permit was (``permit_not_in_force``);
17. no other effect on the same permit is witnessed before this one
    (``permit_reused``);
18. the effect's workflow, run and call, and the called tool, are the permit's
    (``permit_identity_mismatch``);
19. the effect's argument digest is the permit's (``effect_args_mismatch``);
20. the effect names the permit's grant digest (``effect_grant_unlinked``);
21. the witness log runs from 1 without a gap, and witnesses the permit and
    then the effect, each under its own kind (``effect_unwitnessed``).

A record that passes every check is ``allow`` with reason ``authorized_use``.
The effect's outcome does not move the verdict: the question is authority, not
success.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SUITE = "grant-use/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/grant-use/v1"
ALLOW, DENY = "allow", "deny"
ALLOW_REASON = "authorized_use"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "grant_chain_broken",
    "grant_widened",
    "grant_not_in_force",
    "tool_not_granted",
    "call_args_unbound",
    "argument_outside_constraint",
    "permit_missing",
    "uses_exhausted",
    "permit_not_for_grant",
    "permit_not_from_holder",
    "permit_authority_unknown",
    "authority_key_in_worker",
    "permit_not_in_force",
    "permit_reused",
    "permit_identity_mismatch",
    "effect_args_mismatch",
    "effect_grant_unlinked",
    "effect_unwitnessed",
)
OUTCOMES = ("applied", "not-applied", "uncertain")
WITNESS_KINDS = ("grant", "permit", "effect", "srl", "approval")
CONSTRAINT_KINDS = ("exact", "oneOf", "range", "prefix")
SAFE = 2**53 - 1
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-grant-use" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-grant-use")

Record = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(value: object) -> str:
    """The contract's digest of a JSON value: SHA-256 over its canonical bytes."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + _sha(data.encode("utf-8"))


def _when(value: Any) -> datetime:
    """An instant written ``YYYY-MM-DDTHH:MM:SSZ``, the only spelling the contract takes."""
    if not isinstance(value, str) or not _INSTANT.fullmatch(value):
        raise ValueError(f"not an RFC 3339 UTC instant: {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -SAFE <= value <= SAFE


def _is_texts(value: Any, nonempty: bool = False) -> bool:
    return (isinstance(value, list) and (bool(value) or not nonempty)
            and all(isinstance(v, str) for v in value) and len(set(value)) == len(value))


def _has_texts(obj: Any, names: tuple[str, ...]) -> bool:
    return isinstance(obj, dict) and all(isinstance(obj.get(n), str) for n in names)


def _is_scalar(value: Any) -> bool:
    return isinstance(value, str) or _is_int(value)


def _constraint_ok(c: Any) -> bool:
    if not isinstance(c, dict) or len(c) != 1:
        return False
    kind, value = next(iter(c.items()))
    if kind == "exact":
        return _is_scalar(value)
    if kind == "oneOf":
        return (isinstance(value, list) and bool(value) and all(_is_scalar(v) for v in value)
                and len({json.dumps(v) for v in value}) == len(value))
    if kind == "range":
        return (isinstance(value, list) and len(value) == 2 and all(_is_int(v) for v in value)
                and value[0] <= value[1])
    return kind == "prefix" and isinstance(value, str)


def _grant_ok(g: Any) -> bool:
    if not _has_texts(g, ("grantId", "issuer", "holder", "notBefore", "expiresAt")):
        return False
    if not (g.get("parentDigest") is None or isinstance(g.get("parentDigest"), str)):
        return False
    if "parentDigest" not in g or not _is_texts(g.get("tools"), nonempty=True):
        return False
    if not all(_is_int(g.get(n)) and g[n] >= 0 for n in ("maxUses", "depth", "maxDepth")):
        return False
    if g["depth"] > g["maxDepth"] or not isinstance(g.get("closedWorld"), bool):
        return False
    if not (_is_texts(g.get("hopKinds")) and _is_texts(g.get("caveats"))):
        return False
    constraints = g.get("constraints")
    if not isinstance(constraints, dict) or not set(constraints) <= set(g["tools"]):
        return False
    return all(isinstance(args, dict) and all(_constraint_ok(c) for c in args.values())
               for args in constraints.values())


PERMIT_TEXTS = ("permitId", "grantDigest", "workflowId", "runId", "callId", "tool",
                "argsDigest", "issuedAt", "expiresAt", "authorityKeyId")
EFFECT_TEXTS = ("effectId", "permitId", "grantDigest", "workflowId", "runId", "callId",
                "argsDigest", "observedAt", "observerKeyId", "outcome")


def _permit_ok(p: Any) -> bool:
    if not _has_texts(p, PERMIT_TEXTS):
        return False
    if "approvalIds" in p and not _is_texts(p["approvalIds"]):
        return False
    return "srl" not in p or isinstance(p["srl"], dict)


def _effect_ok(e: Any) -> bool:
    return (_has_texts(e, EFFECT_TEXTS) and e["outcome"] in OUTCOMES
            and ("srl" not in e or isinstance(e["srl"], dict)))


def _entry_ok(w: Any) -> bool:
    return (_has_texts(w, ("kind", "digest", "at")) and _is_int(w.get("seq"))
            and w["kind"] in WITNESS_KINDS)


def _shape(record: Record) -> bool:
    call = record.get("call")
    lists = ("grants", "permits", "effects", "witness")
    return (isinstance(record.get("decisionTime"), str)
            and _is_texts(record.get("roots"), nonempty=True)
            and _is_texts(record.get("authorityKeys"), nonempty=True)
            and _is_texts(record.get("workerKeys"))
            and all(isinstance(record.get(n), list) for n in lists) and bool(record["grants"])
            and all(_grant_ok(g) for g in record["grants"])
            and all(_permit_ok(p) for p in record["permits"])
            and all(_effect_ok(e) for e in record["effects"]) and _effect_ok(record.get("effect"))
            and all(_entry_ok(w) for w in record["witness"])
            and isinstance(call, dict) and isinstance(call.get("tool"), str)
            and isinstance(call.get("args"), dict))


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(v) for v in value.values())
    return isinstance(value, list) and any(_has_float(v) for v in value)


def _malformed(record: Record) -> bool:
    if _has_float(record) or not _shape(record):
        return True
    try:
        decided = _when(record["decisionTime"])
        for g in record["grants"]:
            if _when(g["notBefore"]) >= _when(g["expiresAt"]):
                return True
        evidence = [*(p["issuedAt"] for p in record["permits"]),
                    *(e["observedAt"] for e in [*record["effects"], record["effect"]]),
                    *(w["at"] for w in record["witness"])]
        if any(_when(t) > decided for t in evidence):
            return True
        for p in record["permits"]:
            _when(p["expiresAt"])
    except (ValueError, TypeError):
        return True
    ids = [p["permitId"] for p in record["permits"]]
    effect_ids = [e["effectId"] for e in record["effects"]]
    return len(set(ids)) != len(ids) or len(set(effect_ids)) != len(effect_ids)


def _chain_broken(record: Record) -> bool:
    grants = record["grants"]
    root = grants[0]
    if root["parentDigest"] is not None or root["issuer"] not in record["roots"]:
        return True
    for i, grant in enumerate(grants):
        if grant["depth"] != i:
            return True
        if i and (grant["parentDigest"] != digest(grants[i - 1])
                  or grant["issuer"] != grants[i - 1]["holder"]):
            return True
    return False


def _same(a: Any, b: Any) -> bool:
    """JSON value equality: an integer never equals a string or a boolean."""
    return type(a) is type(b) and a == b


def _admits(c: dict[str, Any], value: Any) -> bool:
    kind, bound = next(iter(c.items()))
    if kind == "exact":
        return _same(value, bound)
    if kind == "oneOf":
        return any(_same(value, v) for v in bound)
    if kind == "range":
        return _is_int(value) and bound[0] <= value <= bound[1]
    return isinstance(value, str) and value.startswith(bound)


def _narrows(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """Every value ``child`` admits, ``parent`` admits."""
    kind, bound = next(iter(child.items()))
    if kind == "exact":
        return _admits(parent, bound)
    if kind == "oneOf":
        return all(_admits(parent, v) for v in bound)
    if kind == "range":
        lo, hi = bound
        pkind, pbound = next(iter(parent.items()))
        if pkind == "range":
            return bool(pbound[0] <= lo and hi <= pbound[1])
        if pkind in ("exact", "oneOf"):
            values = [pbound] if pkind == "exact" else pbound
            members = {v for v in values if _is_int(v)}
            return hi - lo + 1 <= len(members) and all(v in members for v in range(lo, hi + 1))
        return False
    pkind, pbound = next(iter(parent.items()))
    return pkind == "prefix" and bound.startswith(pbound)


def _tool_widened(child: Record, parent: Record, tool: str) -> bool:
    mine = child["constraints"].get(tool, {})
    theirs = parent["constraints"].get(tool, {})
    if any(arg not in mine or not _narrows(mine[arg], c) for arg, c in theirs.items()):
        return True
    return parent["closedWorld"] and not set(mine) <= set(theirs)


def _widened_pair(child: Record, parent: Record) -> bool:
    if not set(child["tools"]) <= set(parent["tools"]):
        return True
    if parent["closedWorld"] and not child["closedWorld"]:
        return True
    if any(_tool_widened(child, parent, tool) for tool in child["tools"]):
        return True
    if child["maxUses"] > parent["maxUses"] or child["maxDepth"] > parent["maxDepth"]:
        return True
    if child["depth"] > parent["maxDepth"]:
        return True
    if _when(child["notBefore"]) < _when(parent["notBefore"]):
        return True
    if _when(child["expiresAt"]) > _when(parent["expiresAt"]):
        return True
    return not (set(child["hopKinds"]) <= set(parent["hopKinds"])
                and set(parent["caveats"]) <= set(child["caveats"]))


def _widened(record: Record) -> bool:
    grants = record["grants"]
    return any(_widened_pair(grants[i], grants[i - 1]) for i in range(1, len(grants)))


def _in_force(window: Record, instant: str) -> bool:
    return _when(window["notBefore"]) <= _when(instant) < _when(window["expiresAt"])


def _grant_not_in_force(record: Record) -> bool:
    return not all(_in_force(g, record["effect"]["observedAt"]) for g in record["grants"])


def _leaf(record: Record) -> Record:
    leaf: Record = record["grants"][-1]
    return leaf


def _tool_not_granted(record: Record) -> bool:
    return record["call"]["tool"] not in _leaf(record)["tools"]


def _args_unbound(record: Record) -> bool:
    return bool(digest(record["call"]["args"]) != record["effect"]["argsDigest"])


def _outside_constraint(record: Record) -> bool:
    leaf, call = _leaf(record), record["call"]
    named = leaf["constraints"].get(call["tool"], {})
    args = call["args"]
    if any(arg not in args or not _admits(c, args[arg]) for arg, c in named.items()):
        return True
    return leaf["closedWorld"] and not set(args) <= set(named)


def _permit(record: Record) -> Record | None:
    for p in record["permits"]:
        if p["permitId"] == record["effect"]["permitId"]:
            found: Record = p
            return found
    return None


def _seq(record: Record, kind: str, value: str) -> float:
    """The witness position of a digest, or infinity when it is not witnessed."""
    for w in record["witness"]:
        if w["kind"] == kind and w["digest"] == value:
            return float(w["seq"])
    return float("inf")


def _uses_exhausted(record: Record) -> bool:
    permit = _permit(record)
    assert permit is not None
    leaf_digest = digest(_leaf(record))
    mine = _seq(record, "permit", digest(permit))
    # An unwitnessed permit has no position, so it counts as spent before this one.
    spent = [p for p in record["permits"] if p["grantDigest"] == leaf_digest
             and (_seq(record, "permit", digest(p)) <= mine
                  or _seq(record, "permit", digest(p)) == float("inf"))]
    return len(spent) > int(_leaf(record)["maxUses"])


def _require_permit(record: Record) -> Record:
    permit = _permit(record)
    assert permit is not None
    return permit


def _permit_not_in_force(record: Record) -> bool:
    permit = _require_permit(record)
    if not all(_in_force(g, permit["issuedAt"]) for g in record["grants"]):
        return True
    window = {"notBefore": permit["issuedAt"], "expiresAt": permit["expiresAt"]}
    return not _in_force(window, record["effect"]["observedAt"])


def _reused(record: Record) -> bool:
    effect = record["effect"]
    mine = _seq(record, "effect", digest(effect))
    return any(e["permitId"] == effect["permitId"] and e["effectId"] != effect["effectId"]
               and _seq(record, "effect", digest(e)) < mine for e in record["effects"])


def _identity_mismatch(record: Record) -> bool:
    permit, effect = _require_permit(record), record["effect"]
    if any(effect[n] != permit[n] for n in ("workflowId", "runId", "callId")):
        return True
    return bool(record["call"]["tool"] != permit["tool"])


def _unwitnessed(record: Record) -> bool:
    log = record["witness"]
    if [w["seq"] for w in log] != list(range(1, len(log) + 1)):
        return True
    permit_at = _seq(record, "permit", digest(_require_permit(record)))
    effect_at = _seq(record, "effect", digest(record["effect"]))
    return not permit_at < effect_at < float("inf")


def _load(record_path: Path) -> Record:
    record: Record = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _failures(record: Record) -> dict[str, Callable[[], bool]]:
    def effect() -> Record:
        found: Record = record["effect"]
        return found

    return {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "grant_chain_broken": lambda: _chain_broken(record),
        "grant_widened": lambda: _widened(record),
        "grant_not_in_force": lambda: _grant_not_in_force(record),
        "tool_not_granted": lambda: _tool_not_granted(record),
        "call_args_unbound": lambda: _args_unbound(record),
        "argument_outside_constraint": lambda: _outside_constraint(record),
        "permit_missing": lambda: _permit(record) is None,
        "uses_exhausted": lambda: _uses_exhausted(record),
        "permit_not_for_grant":
            lambda: _require_permit(record)["grantDigest"] != digest(_leaf(record)),
        "permit_not_from_holder":
            lambda: _require_permit(record)["authorityKeyId"] != _leaf(record)["holder"],
        "permit_authority_unknown":
            lambda: _require_permit(record)["authorityKeyId"] not in record["authorityKeys"],
        "authority_key_in_worker":
            lambda: _require_permit(record)["authorityKeyId"] in record["workerKeys"],
        "permit_not_in_force": lambda: _permit_not_in_force(record),
        "permit_reused": lambda: _reused(record),
        "permit_identity_mismatch": lambda: _identity_mismatch(record),
        "effect_args_mismatch":
            lambda: effect()["argsDigest"] != _require_permit(record)["argsDigest"],
        "effect_grant_unlinked":
            lambda: effect()["grantDigest"] != _require_permit(record)["grantDigest"],
        "effect_unwitnessed": lambda: _unwitnessed(record),
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. A check that reads
    something an earlier, skipped check would have refused fails as
    ``unreadable_record``, so the tests see the difference.
    """
    failures = _failures(record)
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError, AssertionError,
                StopIteration):
            return "unreadable_record" if skip else "malformed_record"
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOW_REASON}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != value for name, value in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement.
    """
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
        record_path = directory / "record.json"
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
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
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
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
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
