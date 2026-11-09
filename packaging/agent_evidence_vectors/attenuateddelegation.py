"""Judge whether every execution hop received only an attenuation of its parent's capability.

A capability passes down a run: from the authority that issued it to an
orchestrator, then across child workflows, sub-agents, agent-to-agent calls
and tool-to-tool calls. Each hop must receive at most what its parent held,
from the one key that held it, and the call at the end must be made by the
holder of the last grant and fall inside it. A verifier that only checks that
each child's tool list is a subset of its parent's lets through a widened
argument constraint, an extended lifetime, a dropped caveat, a grant minted by
someone who never held the parent, a hop of a kind the parent forbade, and a
capability presented by a key that does not hold it.

The record carries ``hops`` (each a ``hopKind``, the ``grant`` it carried and
the key it was ``presentedBy``, that is the key that handed the grant across
the hop), ``trustedRoots`` and the final ``presentation``. Every grant digest
is ``sha256:`` plus the hex SHA-256 of the grant's JCS bytes, and the reader
recomputes each one; a ``parentDigest`` is a claim to check.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the attenuated-delegation contract
   (``contract_id_unknown``);
3. the record has the fields and types the contract names, every time parses,
   every constraint is one well-formed kind, the first hop is the ``root`` hop
   and no other is (``malformed_record``);
4. every hop's ``parentDigest`` is the recomputed digest of the grant before
   it, and the root's names no grant on the chain (``chain_unlinked``);
5. the root grant names no parent, its issuer is a trusted root, and that
   issuer handed it over (``root_untrusted``);
6. every later grant was issued, and handed across its hop, by the holder of
   the grant before it (``issuer_not_parent_holder``);
7. every hop's kind is one its parent permits onward, and its own onward kinds
   are among its parent's (``hop_kind_not_permitted``);
8. the root is at depth 0, each hop is one deeper than its parent, no hop is
   deeper than its own or any ancestor's ``maxDepth``, and no hop raises
   ``maxDepth`` (``depth_exceeded``);
9. every grant's tools are among its parent's (``tool_widened``);
10. for every tool a grant keeps, every argument its parent constrained is
    constrained at least as tightly, a closed-world parent stays closed, and a
    closed-world parent's unnamed arguments stay unnamed
    (``constraint_widened``);
11. no grant starts earlier or ends later than its parent
    (``lifetime_extended``);
12. every grant carries every caveat its parent carries (``caveat_dropped``);
13. no grant allows more uses than its parent (``uses_raised``);
14. the presenting key holds the last grant (``presenter_not_holder``);
15. the presented tool and arguments are inside the last grant and the
    presentation falls in its lifetime, ``notBefore`` inclusive and
    ``expiresAt`` exclusive (``presentation_outside_leaf``).

A record that passes all fifteen is ``allow`` with reason ``attenuated``. A
hop that keeps its parent's scope exactly is an attenuation.

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
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "attenuated-delegation/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-vectors/contract/"
               "attenuated-delegation/v1")
ALLOW, DENY = "allow", "deny"
ALLOW_REASON = "attenuated"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "chain_unlinked",
    "root_untrusted",
    "issuer_not_parent_holder",
    "hop_kind_not_permitted",
    "depth_exceeded",
    "tool_widened",
    "constraint_widened",
    "lifetime_extended",
    "caveat_dropped",
    "uses_raised",
    "presenter_not_holder",
    "presentation_outside_leaf",
)
HOP_KINDS = ("child-workflow", "sub-agent", "a2a", "tool")
CONSTRAINT_KINDS = ("exact", "oneOf", "range", "prefix")
SAFE_INTEGER = 2**53 - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-attenuated-delegation" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-attenuated-delegation")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def jcs(value: object) -> bytes:
    """JCS bytes of a value made of strings, integers, booleans, lists and objects."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value: object) -> str:
    """``sha256:`` plus the hex SHA-256 of the value's JCS bytes."""
    return "sha256:" + _sha(jcs(value))


def _when(value: Any) -> datetime:
    if not isinstance(value, str) or not _INSTANT.fullmatch(value):
        raise ValueError(f"not an RFC 3339 UTC instant: {value!r}")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_int(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and -SAFE_INTEGER <= value <= SAFE_INTEGER)


def _is_count(value: Any) -> bool:
    return _is_int(value) and value >= 0


def _is_scalar(value: Any) -> bool:
    return isinstance(value, str) or _is_int(value)


def _texts(value: Any, *, nonempty: bool = False) -> bool:
    return (isinstance(value, list) and all(isinstance(v, str) for v in value)
            and len(set(value)) == len(value) and (bool(value) or not nonempty))


def _constraint_ok(constraint: Any) -> bool:
    if not isinstance(constraint, dict) or len(constraint) != 1:
        return False
    (kind, value), = constraint.items()
    if kind == "exact":
        return _is_scalar(value)
    if kind == "oneOf":
        return (isinstance(value, list) and bool(value) and all(_is_scalar(v) for v in value)
                and len({(type(v), v) for v in value}) == len(value))
    if kind == "range":
        return (isinstance(value, list) and len(value) == 2 and all(_is_int(v) for v in value)
                and value[0] <= value[1])
    return kind == "prefix" and isinstance(value, str)


def _constraints_ok(grant: dict[str, Any]) -> bool:
    table = grant.get("constraints")
    if not isinstance(table, dict) or not set(table) <= set(grant["tools"]):
        return False
    return all(isinstance(args, dict) and all(_constraint_ok(c) for c in args.values())
               for args in table.values())


_GRANT_TEXT = ("grantId", "issuer", "holder", "notBefore", "expiresAt")


def _grant_malformed(grant: Any) -> bool:
    if not isinstance(grant, dict):
        return True
    if not all(isinstance(grant.get(name), str) for name in _GRANT_TEXT):
        return True
    parent = grant.get("parentDigest", 0)
    if parent is not None and not (isinstance(parent, str) and _DIGEST.fullmatch(parent)):
        return True
    if not (_texts(grant.get("tools"), nonempty=True) and _texts(grant.get("caveats"))
            and _texts(grant.get("hopKinds"))
            and set(grant["hopKinds"]) <= set(HOP_KINDS)):
        return True
    if not isinstance(grant.get("closedWorld"), bool):
        return True
    if not (_is_count(grant.get("depth")) and _is_count(grant.get("maxDepth"))
            and _is_int(grant.get("maxUses")) and grant["maxUses"] >= 1):
        return True
    if not _constraints_ok(grant):
        return True
    return _when(grant["notBefore"]) >= _when(grant["expiresAt"])


def _hop_malformed(hop: Any, index: int) -> bool:
    if not isinstance(hop, dict) or not isinstance(hop.get("presentedBy"), str):
        return True
    kind = hop.get("hopKind")
    if kind != ("root" if index == 0 else kind) or (index > 0 and kind not in HOP_KINDS):
        return True
    return _grant_malformed(hop.get("grant"))


def _malformed(record: dict[str, Any]) -> bool:
    hops, presentation = record.get("hops"), record.get("presentation")
    if not (isinstance(hops, list) and hops and _texts(record.get("trustedRoots"),
                                                       nonempty=True)):
        return True
    if not isinstance(presentation, dict):
        return True
    if not all(isinstance(presentation.get(n), str) for n in ("presenterKeyId", "tool")):
        return True
    args = presentation.get("args")
    if not isinstance(args, dict) or not all(_is_scalar(v) for v in args.values()):
        return True
    _when(presentation.get("at"))
    return any(_hop_malformed(hop, i) for i, hop in enumerate(hops))


def _grants(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [hop["grant"] for hop in record["hops"]]


def _pairs(record: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Each (parent hop, child hop) along the chain."""
    hops = record["hops"]
    return list(zip(hops, hops[1:], strict=False))


def _unlinked(record: dict[str, Any]) -> bool:
    grants = _grants(record)
    digests = [digest(g) for g in grants]
    if len(set(digests)) != len(digests):
        return True
    if grants[0]["parentDigest"] in digests:
        return True
    return any(grants[i]["parentDigest"] != digests[i - 1] for i in range(1, len(grants)))


def _root_untrusted(record: dict[str, Any]) -> bool:
    root = record["hops"][0]
    grant = root["grant"]
    return (grant["parentDigest"] is not None or grant["issuer"] not in record["trustedRoots"]
            or root["presentedBy"] != grant["issuer"])


def _issuer_wrong(record: dict[str, Any]) -> bool:
    return any(child["grant"]["issuer"] != parent["grant"]["holder"]
               or child["presentedBy"] != parent["grant"]["holder"]
               for parent, child in _pairs(record))


def _kind_not_permitted(record: dict[str, Any]) -> bool:
    return any(child["hopKind"] not in parent["grant"]["hopKinds"]
               or not set(child["grant"]["hopKinds"]) <= set(parent["grant"]["hopKinds"])
               for parent, child in _pairs(record))


def _depth_exceeded(record: dict[str, Any]) -> bool:
    grants = _grants(record)
    if grants[0]["depth"] != 0:
        return True
    for i, grant in enumerate(grants):
        if grant["depth"] > min(g["maxDepth"] for g in grants[: i + 1]):
            return True
        if i and (grant["depth"] != grants[i - 1]["depth"] + 1
                  or grant["maxDepth"] > grants[i - 1]["maxDepth"]):
            return True
    return False


def _tool_widened(record: dict[str, Any]) -> bool:
    return any(not set(c["grant"]["tools"]) <= set(p["grant"]["tools"])
               for p, c in _pairs(record))


def _same(a: Any, b: Any) -> bool:
    return type(a) is type(b) and a == b


def admits(constraint: dict[str, Any], value: Any) -> bool:
    """Whether one argument value satisfies one constraint."""
    (kind, bound), = constraint.items()
    if kind == "exact":
        return _same(bound, value)
    if kind == "oneOf":
        return any(_same(v, value) for v in bound)
    if kind == "range":
        return _is_int(value) and bound[0] <= value <= bound[1]
    return isinstance(value, str) and value.startswith(bound)


def within(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """Whether every value ``child`` admits, ``parent`` admits too."""
    (kind, bound), = child.items()
    (parent_kind, parent_bound), = parent.items()
    if kind == "exact":
        return admits(parent, bound)
    if kind == "oneOf":
        return all(admits(parent, v) for v in bound)
    if kind == "range":
        low, high = bound
        if parent_kind == "range":
            return bool(parent_bound[0] <= low and high <= parent_bound[1])
        if parent_kind in ("exact", "oneOf"):
            allowed = parent_bound if parent_kind == "oneOf" else [parent_bound]
            if high - low + 1 > len(allowed):
                return False
            return all(admits(parent, v) for v in range(low, high + 1))
        return False
    return parent_kind == "prefix" and bool(bound.startswith(parent_bound))


def _tool_widens(parent: dict[str, Any], child: dict[str, Any], tool: str) -> bool:
    held: dict[str, Any] = parent["constraints"].get(tool, {})
    given: dict[str, Any] = child["constraints"].get(tool, {})
    for arg, bound in held.items():
        if arg not in given or not within(given[arg], bound):
            return True
    return bool(parent["closedWorld"] and not set(given) <= set(held))


def _constraint_widened(record: dict[str, Any]) -> bool:
    for p, c in _pairs(record):
        parent, child = p["grant"], c["grant"]
        if parent["closedWorld"] and not child["closedWorld"]:
            return True
        if any(_tool_widens(parent, child, tool) for tool in child["tools"]):
            return True
    return False


def _lifetime_extended(record: dict[str, Any]) -> bool:
    return any(_when(c["grant"]["notBefore"]) < _when(p["grant"]["notBefore"])
               or _when(c["grant"]["expiresAt"]) > _when(p["grant"]["expiresAt"])
               for p, c in _pairs(record))


def _caveat_dropped(record: dict[str, Any]) -> bool:
    return any(not set(p["grant"]["caveats"]) <= set(c["grant"]["caveats"])
               for p, c in _pairs(record))


def _uses_raised(record: dict[str, Any]) -> bool:
    return any(c["grant"]["maxUses"] > p["grant"]["maxUses"] for p, c in _pairs(record))


def _presenter_wrong(record: dict[str, Any]) -> bool:
    return bool(record["presentation"]["presenterKeyId"] != record["hops"][-1]["grant"]["holder"])


def _outside_leaf(record: dict[str, Any]) -> bool:
    leaf, presentation = record["hops"][-1]["grant"], record["presentation"]
    tool, args = presentation["tool"], presentation["args"]
    if tool not in leaf["tools"]:
        return True
    bounds: dict[str, Any] = leaf["constraints"].get(tool, {})
    if any(arg not in args or not admits(bound, args[arg]) for arg, bound in bounds.items()):
        return True
    if leaf["closedWorld"] and not set(args) <= set(bounds):
        return True
    at = _when(presentation["at"])
    return not _when(leaf["notBefore"]) <= at < _when(leaf["expiresAt"])


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. The checks after
    the contract checks read a record only once ``malformed_record`` has passed,
    so a skipped ``malformed_record`` lets a malformed record fail in them.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "chain_unlinked": lambda: _unlinked(record),
        "root_untrusted": lambda: _root_untrusted(record),
        "issuer_not_parent_holder": lambda: _issuer_wrong(record),
        "hop_kind_not_permitted": lambda: _kind_not_permitted(record),
        "depth_exceeded": lambda: _depth_exceeded(record),
        "tool_widened": lambda: _tool_widened(record),
        "constraint_widened": lambda: _constraint_widened(record),
        "lifetime_extended": lambda: _lifetime_extended(record),
        "caveat_dropped": lambda: _caveat_dropped(record),
        "uses_raised": lambda: _uses_raised(record),
        "presenter_not_holder": lambda: _presenter_wrong(record),
        "presentation_outside_leaf": lambda: _outside_leaf(record),
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError):
            # A record the structural check would have refused. With that check
            # switched off, the failure is a different one, so the tests see it.
            return "unreadable_record" if "malformed_record" in skip else "malformed_record"
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
    if any(_sha((directory / name).read_bytes()) != sha for name, sha in files.items()):
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
