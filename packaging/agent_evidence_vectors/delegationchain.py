"""Judge a signed delegation chain handed from agent to agent.

A chain is a list of signed grants. The first is issued by a trusted root key to the first agent; every
later grant is issued by the previous grant's holder to the next agent, and may only narrow what it was
given. A verifier that checks each signature and nothing else accepts a chain whose third hop quietly
widened the tools, the argument values, the audience, the expiry, the budget or the remaining depth, a chain
spliced from two tasks, a chain whose middle link was signed by an agent that never held the grant above
it, and a chain with an ancestor that was revoked after the task began.

The record carries the chain, the trusted root key ids, the instant the chain is judged at, the agent
receiving the last grant, and the digests of revoked grants. A grant body is::

    {"grantId", "issuerKey", "holderKey", "parent", "notBefore", "expiresAt", "maxDepth",
     "context": {"audience": {"type": "one_of", "values": [agent names]}},
     "tools": {tool: {"args": {name: {"type": "one_of", "values": [...]}}}},
     "budget": {"uses": integer}}

A signature is Ed25519 over ``b"probity-grant-v1\\x00"`` followed by the RFC 8785 form of the body; a key id
is the SHA-256 of the raw public key; a grant digest is the SHA-256 of the RFC 8785 form of the body.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the delegation-chain contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, and every time carries a UTC offset
   (``malformed_record``);
4. every signature verifies under the grant's own ``issuerKey`` (``signature_invalid``);
5. the first grant's issuer is a trusted root and each later grant's issuer is the holder of the grant above it
   (``issuer_not_authorised``);
6. the first grant has no parent and each later grant's ``parent`` is the digest of the grant above it
   (``parent_mismatch``);
7. the judging instant is inside every grant's window (``grant_not_in_window``);
8. each grant allows one more level than the grant below it, so ``maxDepth`` falls by at least one per hop
   (``depth_exceeded``);
9. each grant's tools are inside its parent's (``widens_tools``);
10. each tool's arguments are inside the parent's, name by name and value by value (``widens_arguments``);
11. each grant's audience is inside its parent's (``widens_audience``);
12. each grant expires no later than its parent (``widens_expiry``);
13. each grant's budget is no larger than its parent's (``widens_budget``);
14. no grant in the chain is revoked (``ancestor_revoked``);
15. the receiving agent is in the last grant's audience (``receiver_outside_audience``).

A record that passes all fifteen is ``allow`` with reason ``chain_valid``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object carrying
``decision`` and ``reason``, and exits 0 for ``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from . import strictjson

SUITE = "delegation-chain/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/delegation-chain/v1"
GRANT_DOMAIN = b"probity-grant-v1\x00"
ALLOW, DENY = "allow", "deny"
ALLOWED = "chain_valid"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "signature_invalid",
    "issuer_not_authorised",
    "parent_mismatch",
    "grant_not_in_window",
    "depth_exceeded",
    "widens_tools",
    "widens_arguments",
    "widens_audience",
    "widens_expiry",
    "widens_budget",
    "ancestor_revoked",
    "receiver_outside_audience",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-delegation-chain" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-delegation-chain")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")
_OFFSET = re.compile(r"(Z|[+-]\d{2}:\d{2})$")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module, so a module-level import is a cycle."""
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


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def grant_digest(body: dict[str, Any]) -> str:
    """SHA-256 of the RFC 8785 form of a grant body."""
    return _sha(_rail().jcs_dumps(body))


def _when(value: Any) -> datetime:
    text = str(value)
    if not _OFFSET.search(text):
        raise ValueError("a time without a UTC offset")
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _one_of(value: Any) -> bool:
    return (isinstance(value, dict) and value.get("type") == "one_of"
            and isinstance(value.get("values"), list) and bool(value["values"])
            and all(isinstance(v, str) for v in value["values"]))


def _body_malformed(body: Any) -> bool:
    if not isinstance(body, dict):
        return True
    texts = ("grantId", "issuerKey", "holderKey", "notBefore", "expiresAt")
    if not all(_is_text(body.get(name)) for name in texts):
        return True
    if not (body.get("parent") is None or _is_text(body.get("parent"))):
        return True
    if not _count(body.get("maxDepth")):
        return True
    budget, context, tools = body.get("budget"), body.get("context"), body.get("tools")
    if not (isinstance(budget, dict) and _count(budget.get("uses"))):
        return True
    if not (isinstance(context, dict) and _one_of(context.get("audience"))):
        return True
    if not (isinstance(tools, dict) and tools):
        return True
    for spec in tools.values():
        if not (isinstance(spec, dict) and isinstance(spec.get("args"), dict)
                and all(_one_of(c) for c in spec["args"].values())):
            return True
    return False


def _malformed(record: dict[str, Any]) -> bool:
    chain = record.get("chain")
    shape = (
        isinstance(record.get("at"), str) and _is_text(record.get("receiver"))
        and isinstance(chain, list) and bool(chain)
        and isinstance(record.get("rootKeyIds"), list) and bool(record["rootKeyIds"])
        and all(isinstance(k, str) for k in record["rootKeyIds"])
        and isinstance(record.get("revoked"), list) and all(isinstance(d, str) for d in record["revoked"])
    )
    if not shape:
        return True
    for link in chain:
        if not (isinstance(link, dict) and isinstance(link.get("sig"), str)) or _body_malformed(link.get("body")):
            return True
    try:
        _when(record["at"])
        for link in chain:
            _when(link["body"]["notBefore"])
            _when(link["body"]["expiresAt"])
    except ValueError:
        return True
    return False


def _bodies(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [link["body"] for link in record["chain"]]


def _pairs(record: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    bodies = _bodies(record)
    return list(zip(bodies, bodies[1:], strict=False))


def _bad_signature(record: dict[str, Any]) -> bool:
    rail = _rail()
    for link in record["chain"]:
        try:
            key = base64.b64decode(link["body"]["issuerKey"], validate=True)
            sig = base64.b64decode(link["sig"], validate=True)
        except ValueError:
            return True
        if not rail.ed25519_verify(key, GRANT_DOMAIN + rail.jcs_dumps(link["body"]), sig):
            return True
    return False


def _bad_issuer(record: dict[str, Any]) -> bool:
    bodies = _bodies(record)
    root = _sha(base64.b64decode(bodies[0]["issuerKey"]))
    if root not in record["rootKeyIds"]:
        return True
    return any(child["issuerKey"] != parent["holderKey"] for parent, child in _pairs(record))


def _bad_parent(record: dict[str, Any]) -> bool:
    bodies = _bodies(record)
    if bodies[0]["parent"] is not None:
        return True
    return any(child["parent"] != grant_digest(parent) for parent, child in _pairs(record))


def _out_of_window(record: dict[str, Any]) -> bool:
    at = _when(record["at"])
    return any(not _when(b["notBefore"]) <= at < _when(b["expiresAt"]) for b in _bodies(record))


def _too_deep(record: dict[str, Any]) -> bool:
    return any(child["maxDepth"] >= parent["maxDepth"] for parent, child in _pairs(record))


def _widens_tools(record: dict[str, Any]) -> bool:
    return any(not set(child["tools"]) <= set(parent["tools"]) for parent, child in _pairs(record))


def _arguments_widen(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    for tool, spec in child["tools"].items():
        allowed = parent["tools"].get(tool)
        if allowed is None:
            continue
        for name, constraint in spec["args"].items():
            above = allowed["args"].get(name)
            if above is None or not set(constraint["values"]) <= set(above["values"]):
                return True
    return False


def _widens_arguments(record: dict[str, Any]) -> bool:
    return any(_arguments_widen(parent, child) for parent, child in _pairs(record))


def _widens_audience(record: dict[str, Any]) -> bool:
    return any(not set(c["context"]["audience"]["values"]) <= set(p["context"]["audience"]["values"])
               for p, c in _pairs(record))


def _widens_expiry(record: dict[str, Any]) -> bool:
    return any(_when(c["expiresAt"]) > _when(p["expiresAt"]) for p, c in _pairs(record))


def _widens_budget(record: dict[str, Any]) -> bool:
    return any(c["budget"]["uses"] > p["budget"]["uses"] for p, c in _pairs(record))


def _revoked(record: dict[str, Any]) -> bool:
    return any(grant_digest(b) in record["revoked"] for b in _bodies(record))


def _outside(record: dict[str, Any]) -> bool:
    return record["receiver"] not in _bodies(record)[-1]["context"]["audience"]["values"]


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = strictjson.loads(record_path.read_text(encoding="utf-8"))
    return record


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each check is forced by some member;
    a verifier never sets it. The checks after ``malformed_record`` read a record only once it has passed.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "signature_invalid": lambda: _bad_signature(record),
        "issuer_not_authorised": lambda: _bad_issuer(record),
        "parent_mismatch": lambda: _bad_parent(record),
        "grant_not_in_window": lambda: _out_of_window(record),
        "depth_exceeded": lambda: _too_deep(record),
        "widens_tools": lambda: _widens_tools(record),
        "widens_arguments": lambda: _widens_arguments(record),
        "widens_audience": lambda: _widens_audience(record),
        "widens_expiry": lambda: _widens_expiry(record),
        "widens_budget": lambda: _widens_budget(record),
        "ancestor_revoked": lambda: _revoked(record),
        "receiver_outside_audience": lambda: _outside(record),
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError):
            return "unreadable_record" if "malformed_record" in skip else "malformed_record"
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED}
def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
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
        answer = strictjson.loads(result.stdout)
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
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
