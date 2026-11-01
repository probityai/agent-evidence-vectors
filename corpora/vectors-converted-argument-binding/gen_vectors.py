"""Build the converted-argument-binding cases byte-identically.

Every case is one approved tool call: the arguments the model gave, the
arguments as converted and shown to the approver, the rebuild of the approved
arguments, the arguments the tool ran with, and the digests that bind the
approval. The rule is the one UKGovernmentBEIS/inspect_ai adopted in pull
request 5652 (design/tool-approval-arguments.md at commit
a31b3b620254426ce7c037e8036b743a52ba6636): the approver sees the converted
arguments, and what runs is rebuilt from the approved JSON and must serialize
back to exactly it. Each denied case changes one thing of an allowed call, so
the check it names is the first that fails and every earlier check passes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import a2ajcs  # noqa: E402
from agent_evidence_vectors import convertedargs as reader  # noqa: E402

SUITE = reader.SUITE
CONTRACT_SOURCE = {
    "repository": "https://github.com/UKGovernmentBEIS/inspect_ai",
    "pullRequest": 5652,
    "file": "design/tool-approval-arguments.md",
    "commit": "a31b3b620254426ce7c037e8036b743a52ba6636",
}
RECIPIENT = "ops@example.org"
PARAMS: dict[str, dict[str, Any]] = {
    "dry_run": {"default": True, "type": "boolean"},
    "priority": {"enum": ["low", "normal", "high"], "type": "string"},
    "recipient": {"type": "string"},
}
BASE: dict[str, Any] = {"dry_run": True, "priority": "high", "recipient": RECIPIENT}
CLOCK_DEFAULT = {"default": "evaluated when the call is constructed", "type": "string"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def call_digest(arguments: dict[str, Any]) -> str:
    """Digest of the call's id, function and arguments."""
    call = {"arguments": arguments, "function": "send_notice", "id": "call-1"}
    return _sha(a2ajcs.canonicalize(call))


def case(*, raw: dict[str, Any], shown: dict[str, Any] | bytes, rebuilt: dict[str, Any],
         executed: dict[str, Any] | bytes, params: dict[str, Any] | None = None,
         decision: str = "approve", modified: dict[str, Any] | None = None,
         shown_sha: str | None = None, mutated: dict[str, Any] | None = None,
         contract: str | None = reader.CONTRACT_ID, before: dict[str, Any] | None = None,
         ) -> dict[str, bytes]:
    """One case's files. ``mutated`` is the call as it stood after the approval chain
    when the chain changed it; ``before`` is the arguments the call carried into it."""
    files = {"raw.json": _json(raw),
             "shown.json": shown if isinstance(shown, bytes) else _json(shown),
             "rebuilt.json": _json(rebuilt),
             "executed.json": executed if isinstance(executed, bytes) else _json(executed)}
    if modified is not None:
        files["modified.json"] = _json(modified)
    approved = modified if modified is not None else shown
    entering = before if before is not None else approved
    leaving = mutated if mutated is not None else (modified if modified is not None else entering)
    record: dict[str, Any] = {
        "approval": {"decision": decision,
                     "shownSha256": shown_sha or _sha(files["shown.json"])},
        "callCopyAfterSha256": call_digest(leaving if isinstance(leaving, dict) else {}),
        "callCopyBeforeSha256": call_digest(entering if isinstance(entering, dict) else {}),
        "parameters": params or PARAMS,
    }
    if contract is not None:
        record["contractId"] = contract
    files["record.json"] = _json(record)
    return files


def _with(**changes: Any) -> dict[str, Any]:
    return {**BASE, **changes}


def _same(args: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"raw": args, "shown": args, "rebuilt": args, "executed": args, **extra}


NAN_SHOWN = (b'{"recipient": "ops@example.org", "score": NaN}\n')
DUPLICATE_SHOWN = (b'{"dry_run": true, "priority": "high", "recipient": "ops@example.org", '
                   b'"recipient": "ops@example.net"}\n')
REORDERED = b'{"recipient": "ops@example.org", "priority": "high", "dry_run": true}\n'
_NO_DEFAULT = {key: value for key, value in BASE.items() if key != "dry_run"}
_CLOCK_RAW = {"priority": "high", "recipient": RECIPIENT}
_CLOCK = {**BASE, "requested_at": "2026-10-24T12:00:00Z"}
_CONFIRM = {**BASE, "confirm": "false"}
_WEIGHT = {**BASE, "weight": 1.5}
_META = {**BASE, "metadata": {"ticket": 7731}}


Case = tuple[str, dict[str, bytes], str, str, str]


def cases() -> list[Case]:
    """Every case: id, files, expected decision and reason, and what the case departs
    from."""
    unknown = reader.CONTRACT_ID.replace("/v1", "/v0")
    string_param = {"type": "string"}
    return [
        ("allow-unchanged", case(**_same(BASE)), "allow", "bound",
         "control: the arguments are shown, rebuilt and executed unchanged"),
        ("allow-constructor-default-shown",
         case(raw=_NO_DEFAULT, shown=BASE, rebuilt=BASE, executed=BASE), "allow", "bound",
         "control: the constructor default dry_run is in what the approver saw and in what ran"),
        ("allow-modify-full-call",
         case(raw={"priority": "normal", "recipient": RECIPIENT},
              shown={"dry_run": True, "priority": "normal", "recipient": RECIPIENT},
              rebuilt=BASE, executed=BASE, decision="modify", modified=BASE,
              before={"dry_run": True, "priority": "normal", "recipient": RECIPIENT}),
         "allow", "bound",
         "control: the approver replaces the whole call and the replacement runs"),
        ("contract-id-missing", case(**_same(BASE), contract=None), "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown", case(**_same(BASE), contract=unknown), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
        ("approved-digest-not-shown",
         case(raw=_NO_DEFAULT, shown=BASE, rebuilt=BASE, executed=BASE,
              shown_sha=_sha(_json(_NO_DEFAULT))), "deny", "approval_not_bound_to_shown",
         "the approval names the digest of the model's arguments, not of the converted "
         "arguments the approver was shown"),
        ("shown-holds-nan",
         case(raw={"recipient": RECIPIENT, "score": "nan"}, shown=NAN_SHOWN,
              rebuilt={"recipient": RECIPIENT, "score": "nan"},
              executed={"recipient": RECIPIENT, "score": "nan"},
              params={"recipient": string_param, "score": string_param}),
         "deny", "shown_not_storable",
         "the converted arguments hold NaN, which JSON cannot store"),
        ("shown-duplicate-key", case(raw=BASE, shown=DUPLICATE_SHOWN, rebuilt=BASE,
                                     executed=BASE), "deny", "shown_not_storable",
         "the converted arguments carry the recipient member twice"),
        ("invalid-enum-approved", case(**_same(_with(priority="urgent"))), "deny",
         "invalid_call_approved",
         "the model gave a priority outside the declared enum and the call was approved"),
        ("modify-drops-defaulted-field",
         case(raw=_NO_DEFAULT, shown=BASE, rebuilt=_NO_DEFAULT, executed=_NO_DEFAULT,
              decision="modify", modified=_NO_DEFAULT, before=BASE), "deny",
         "modify_not_full_call",
         "the approver's replacement omits dry_run, which has a default"),
        ("clock-default-rebuilds-differently",
         case(raw=_CLOCK_RAW, shown=_CLOCK,
              rebuilt={**_CLOCK, "requested_at": "2026-10-24T12:00:03Z"},
              executed={**_CLOCK, "requested_at": "2026-10-24T12:00:03Z"},
              params={**PARAMS, "requested_at": CLOCK_DEFAULT}), "deny", "rebuild_not_identical",
         "a requested_at default is evaluated again at rebuild, three seconds after it "
         "was shown"),
        ("approver-edited-in-place",
         case(**_same(BASE), mutated=_with(priority="low")), "deny",
         "call_mutated_after_approval",
         "the call's digest after the approval chain differs from its digest before, "
         "although the arguments that ran are the shown ones"),
        ("bool-string-coerced",
         case(raw=_CONFIRM, shown=_CONFIRM, rebuilt=_CONFIRM,
              executed={**BASE, "confirm": True},
              params={**PARAMS, "confirm": string_param}), "deny", "shown_not_executed",
         "the approver saw the string \"false\" and the tool ran with the boolean true"),
        ("float-truncated-to-int",
         case(raw=_WEIGHT, shown=_WEIGHT, rebuilt=_WEIGHT, executed={**BASE, "weight": 1},
              params={**PARAMS, "weight": {"type": "number"}}), "deny", "shown_not_executed",
         "the approver saw 1.5 and the tool ran with 1"),
        ("dict-repr-to-string",
         case(raw=_META, shown=_META, rebuilt=_META,
              executed={**BASE, "metadata": "{'ticket': 7731}"},
              params={**PARAMS, "metadata": {"type": "object"}}), "deny", "shown_not_executed",
         "the approver saw an object and the tool ran with its Python repr as a string"),
        ("constructor-default-hidden",
         case(raw=_NO_DEFAULT, shown=_NO_DEFAULT, rebuilt=_NO_DEFAULT,
              executed={**BASE, "dry_run": False}), "deny", "shown_not_executed",
         "the executed arguments add dry_run false, which the approver was never shown"),
        ("executed-key-order-only",
         case(raw=BASE, shown=BASE, rebuilt=BASE, executed=REORDERED), "allow", "bound",
         "control: the executed file has the same members in another order, which "
         "RFC 8785 makes equal"),
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
    entries = []
    for name, files, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "shownEqualsExecuted": reader.shown_equals_executed(
                reader.Case(directory / "record.json")),
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "contractSource": CONTRACT_SOURCE,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
