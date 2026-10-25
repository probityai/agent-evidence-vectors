"""Judge whether a delegated request stays inside the rights its delegators held.

A derived grant can be well formed, correctly narrowed at issue and unexpired,
and still carry authority nobody had the right to pass on. The delegating
principal may never have been entitled to delegate the operation. It may have
lost that entitlement after it delegated. An ancestor grant may have been
narrowed to remove the operation while the child grant stayed intact. Or the
delegate may be acting on an operation its delegator never held. A verifier that
checks the grant chain's signatures, expiry and narrowing alone allows every one
of these.

The record states the authoritative source's facts: the entitlements
(``rights``) and the scope removals that took effect at the source
(``narrowings``). A change at the source reaches enforcement within
``propagationLimitSeconds``: a request made before ``effective + limit`` may
still use cached state, and a request made at or after it must be refused.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the delegator-right contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, and every time
   parses (``malformed_record``);
4. the requested operation is in the last grant's scope, and each grant's
   scope is inside the scope of the grant before it
   (``delegate_exceeds_delegator``);
5. every grantor that is not a trusted root held an entitlement to delegate the
   requested operation when it issued its grant (``delegator_not_entitled``);
6. no such entitlement ended at least ``propagationLimitSeconds`` before the
   decision (``delegation_right_removed``);
7. no grant on the chain had the requested operation removed at the source at
   least ``propagationLimitSeconds`` before the decision
   (``ancestor_scope_removed``).

A record that passes all seven is ``allow`` with reason ``entitled``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SUITE = "delegator-right/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/delegator-right/v1"
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "delegate_exceeds_delegator",
    "delegator_not_entitled",
    "delegation_right_removed",
    "ancestor_scope_removed",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-delegator-right" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-delegator-right")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _hop_malformed(hop: Any) -> bool:
    if not isinstance(hop, dict):
        return True
    names = ("grantId", "grantor", "grantee", "issuedAt", "expiresAt")
    if not all(isinstance(hop.get(name), str) for name in names):
        return True
    if not _is_text_list(hop.get("scope")) or not isinstance(hop.get("narrowings"), list):
        return True
    return not all(isinstance(n, dict) and isinstance(n.get("operation"), str)
                   and isinstance(n.get("effectiveAt"), str) for n in hop["narrowings"])


def _right_malformed(right: Any) -> bool:
    return not (isinstance(right, dict) and isinstance(right.get("principal"), str)
                and isinstance(right.get("operation"), str)
                and isinstance(right.get("from"), str)
                and (right.get("until") is None or isinstance(right.get("until"), str)))


def _times(record: dict[str, Any]) -> list[Any]:
    out: list[Any] = [record["decisionTime"]]
    for hop in record["chain"]:
        out += [hop["issuedAt"], hop["expiresAt"], *(n["effectiveAt"] for n in hop["narrowings"])]
    for right in record["rights"]:
        out += [right["from"], *([right["until"]] if right["until"] is not None else [])]
    return out


def _malformed(record: dict[str, Any]) -> bool:
    limit = record.get("propagationLimitSeconds")
    request = record.get("request")
    shape = (
        isinstance(record.get("decisionTime"), str)
        and isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0
        and isinstance(request, dict) and isinstance(request.get("operation"), str)
        and isinstance(record.get("chain"), list) and bool(record["chain"])
        and isinstance(record.get("rights"), list) and _is_text_list(record.get("roots"))
    )
    if not shape:
        return True
    if any(_hop_malformed(h) for h in record["chain"]):
        return True
    if any(_right_malformed(r) for r in record["rights"]):
        return True
    try:
        for value in _times(record):
            _when(value)
    except ValueError:
        return True
    return False


def _exceeds(record: dict[str, Any]) -> bool:
    chain = record["chain"]
    if record["request"]["operation"] not in chain[-1]["scope"]:
        return True
    return any(not set(chain[i]["scope"]) <= set(chain[i - 1]["scope"])
               for i in range(1, len(chain)))


def _entitlement(record: dict[str, Any], hop: dict[str, Any]) -> dict[str, Any] | None:
    """The entitlement that covered ``hop``'s grantor when the grant was issued."""
    issued = _when(hop["issuedAt"])
    for right in record["rights"]:
        if (right["principal"], right["operation"]) != (
                hop["grantor"], record["request"]["operation"]):
            continue
        ends = right["until"]
        if _when(right["from"]) <= issued and (ends is None or issued < _when(ends)):
            return dict(right)
    return None


def _delegating_hops(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [h for h in record["chain"] if h["grantor"] not in record["roots"]]


def _reached(record: dict[str, Any], effective: str) -> bool:
    """Whether a change effective at the source has reached enforcement."""
    limit = timedelta(seconds=record["propagationLimitSeconds"])
    return _when(effective) + limit <= _when(record["decisionTime"])


def _not_entitled(record: dict[str, Any]) -> bool:
    return any(_entitlement(record, h) is None for h in _delegating_hops(record))


def _right_removed(record: dict[str, Any]) -> bool:
    for hop in _delegating_hops(record):
        right = _entitlement(record, hop)
        if right is not None and right["until"] is not None and _reached(record, right["until"]):
            return True
    return False


def _scope_removed(record: dict[str, Any]) -> bool:
    operation = record["request"]["operation"]
    return any(n["operation"] == operation and _reached(record, n["effectiveAt"])
               for hop in record["chain"] for n in hop["narrowings"])


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
        "delegate_exceeds_delegator": lambda: _exceeds(record),
        "delegator_not_entitled": lambda: _not_entitled(record),
        "delegation_right_removed": lambda: _right_removed(record),
        "ancestor_scope_removed": lambda: _scope_removed(record),
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
    return {"decision": ALLOW, "reason": "entitled"}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
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
