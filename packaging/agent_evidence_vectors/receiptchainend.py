"""Judge whether a signed receipt chain is the whole chain, and what proves its end.

A receipt chain answers two questions. The first is integrity: every receipt
verifies, every receipt names its predecessor, sequence numbers run without a
gap. The second is the end: whether the chain the consumer holds stops where
the producer stopped. Integrity of a prefix does not establish its end. A
writer who can edit the evidence needs no key to cut the tail, and a cut chain
is a valid prefix. Only two things bound the end: a signed close of a run that
nothing resumes, and a head the consumer retained outside the writer's reach.

The reader checks in a fixed order and names the first check that fails:

1. every receipt verifies under the key it names (``signature_invalid``);
2. the first receipt's key is one of the consumer's root keys
   (``signer_untrusted``);
3. every receipt names its predecessor's hash and the next sequence number,
   and a key changes only at a rotation marker that names the real prior tail
   (``chain_link_broken``);
4. the retiring key signed an endorsement of every rotation boundary: a pinned
   successor key is not authority over the boundary, because whoever holds it
   can re-root its segment on an earlier tail (``rotation_unendorsed``);
5. every close names the run's real root hash, final sequence and receipt
   count (``close_binding_invalid``);
6. a retained head's receipt hash is in the chain (``head_missing``);
7. a retained head's position (its sequence number, the key of its segment,
   its index in the whole chain) matches the receipt it names, or for a head
   with no hash, the chain's last receipt (``head_position_mismatch``). A
   sequence number alone does not identify a position: it restarts at every
   key rotation;
8. a head retained as final is the chain's last receipt (``head_not_final``).

A chain that passes all eight is ``verified`` when its end is proven: by a
close of a run-scoped session (``end_proven_close``) or by a final retained
head whose hash names the last receipt (``end_proven_head``). Otherwise it is a
``prefix`` (``end_unproven``): a sequence number without a hash binds a length,
not a content, and an interim head proves that a prefix was written, not that
nothing followed it.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``verified``, 3 for ``prefix`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SUITE = "receipt-chain-end/v1"
VERIFIED, PREFIX, REJECTED = "verified", "prefix", "rejected"
EXIT_FOR = {VERIFIED: 0, PREFIX: 3, REJECTED: 1}
GENESIS = "genesis"
ENDORSEMENT_DOMAIN = b"pipelock-rotation-endorsement-v1\x00"
OPEN_LABEL = "pipelock.receipt.session_open.v1"
# A run-scoped session ends in the run's 16-byte nonce, written as hex.
_RUN_NONCE_HEX_DIGITS = 2 * 16
RUN_SESSION = re.compile(rf"^[^/\\]+\.run\.[0-9a-f]{{{_RUN_NONCE_HEX_DIGITS}}}$")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "signature_invalid",
    "signer_untrusted",
    "chain_link_broken",
    "rotation_unendorsed",
    "close_binding_invalid",
    "head_missing",
    "head_position_mismatch",
    "head_not_final",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-receipt-chain-end" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-receipt-chain-end")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)


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


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value: object) -> bytes:
    """The encoding a receipt is hashed and signed in: the fields in the order
    the line gives them, no spaces, non-ASCII kept as UTF-8."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _hex_sig(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value.startswith("ed25519:"):
        return None
    try:
        return bytes.fromhex(value.removeprefix("ed25519:"))
    except ValueError:
        return None


def receipt_verifies(receipt: dict[str, Any]) -> bool:
    """Whether a receipt's signature verifies under the key it names."""
    sig = _hex_sig(receipt.get("signature"))
    try:
        key = bytes.fromhex(str(receipt.get("signer_key", "")))
    except ValueError:
        return False
    if sig is None or len(key) != 32 or not isinstance(receipt.get("action_record"), dict):
        return False
    digest = hashlib.sha256(compact(receipt["action_record"])).digest()
    return bool(_rail().ed25519_verify(key, digest, sig))


def endorsement_verifies(endorsement: dict[str, Any]) -> bool:
    """Whether a rotation endorsement verifies under the retiring key it names."""
    sig = _hex_sig(endorsement.get("endorsement"))
    try:
        key = bytes.fromhex(str(endorsement.get("prior_signer_key", "")))
    except ValueError:
        return False
    if sig is None or len(key) != 32:
        return False
    body = {k: v for k, v in endorsement.items() if k != "endorsement"}
    digest = hashlib.sha256(ENDORSEMENT_DOMAIN + compact(body)).digest()
    return bool(_rail().ed25519_verify(key, digest, sig))


def session_open_genesis(payload: dict[str, Any]) -> str:
    """The bound genesis a session open commits the chain's first link to."""
    h = hashlib.sha256()

    def frame(b: bytes) -> None:
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)

    for part in (OPEN_LABEL, payload.get("run_nonce", ""), payload.get("open_nonce", ""),
                 payload.get("recorder_session", ""), payload.get("policy_hash", ""),
                 payload.get("signer_key_epoch", "")):
        frame(str(part).encode())
    frame(max(int(payload.get("heartbeat_seconds", 0)), 0).to_bytes(8, "big"))
    for name in ("genesis_anchor_head", "genesis_anchor_log", "posture_capsule_sha256",
                 "containment_nonce", "contained_uid"):
        frame(str(payload.get(name, "")).encode())
    return "g1:" + h.hexdigest()


def _control(record: dict[str, Any], kind: str) -> dict[str, Any] | None:
    control = record.get("session_control")
    if not isinstance(control, dict) or control.get("kind") != kind:
        return None
    payload = control.get(kind.removeprefix("session_"))
    return payload if isinstance(payload, dict) else None


class _Walk:
    """One pass over the chain that records what each later check needs."""

    def __init__(self, receipts: list[dict[str, Any]], lines: list[bytes]) -> None:
        self.receipts, self.lines = receipts, lines
        self.hashes = [_sha(compact(r)) for r in receipts]
        self.links_hold = True
        self.boundaries: list[tuple[int, int]] = []  # (index of prior tail, index of marker)
        self.closes_hold = True
        self.opens: dict[str, dict[str, Any]] = {}
        self._walk()

    def _first(self, record: dict[str, Any]) -> bool:
        if record.get("chain_seq") != 0 or "key_transition" in record:
            return False
        prev = record.get("chain_prev_hash")
        if prev == GENESIS:
            return True
        opened = _control(record, "session_open")
        return opened is not None and prev == session_open_genesis(opened) == opened.get(
            "genesis_hash")

    def _walk(self) -> None:
        receipts = self.receipts
        if not receipts or not self._first(receipts[0]["action_record"]):
            self.links_hold = False
            return
        key, seq, segment_count = receipts[0]["signer_key"], 0, 1
        self._lifecycle(0, segment_count)
        for i in range(1, len(receipts)):
            record = receipts[i]["action_record"]
            marker = record.get("key_transition")
            if record.get("chain_prev_hash") != self.hashes[i - 1]:
                self.links_hold = False
                return
            if isinstance(marker, dict):
                if (record.get("chain_seq") != 0 or receipts[i]["signer_key"] == key
                        or marker.get("prior_signer_key") != key
                        or marker.get("prior_chain_seq") != seq
                        or marker.get("prior_chain_hash") != self.hashes[i - 1]):
                    self.links_hold = False
                    return
                self.boundaries.append((i - 1, i))
                key, seq, segment_count = receipts[i]["signer_key"], 0, 1
            else:
                if receipts[i]["signer_key"] != key or record.get("chain_seq") != seq + 1:
                    self.links_hold = False
                    return
                seq, segment_count = seq + 1, segment_count + 1
            self._lifecycle(i, segment_count)

    def _lifecycle(self, i: int, segment_count: int) -> None:
        record = self.receipts[i]["action_record"]
        opened = _control(record, "session_open")
        if opened is not None:
            self.opens[str(opened.get("run_nonce"))] = {**opened, "_closed": False}
            return
        run = self.opens.get(str(record.get("run_nonce")))
        if run is not None and run["_closed"]:
            self.closes_hold = False
        closing = _control(record, "session_close")
        if closing is None:
            return
        if (run is None or closing.get("run_nonce") != record.get("run_nonce")
                or closing.get("open_nonce") != run.get("open_nonce")
                or closing.get("root_hash") != self.hashes[i - 1]
                or closing.get("final_seq") != record.get("chain_seq")
                or closing.get("receipt_count") != segment_count):
            self.closes_hold = False
            return
        run["_closed"] = True


def _load(case_path: Path) -> tuple[dict[str, Any], list[bytes], dict[str, Any] | None,
                                    list[dict[str, Any]]]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    lines = [line for line in (base / case["chain"]).read_bytes().split(b"\n") if line]
    head = json.loads((base / case["head"]).read_text(encoding="utf-8")) if "head" in case \
        else None
    endorsements = [json.loads((base / name).read_text(encoding="utf-8"))
                    for name in case["trust"].get("endorsements", [])]
    return case, lines, head, endorsements


def _endorsed(walk: _Walk, endorsements: list[dict[str, Any]], session: str | None) -> bool:
    """Every boundary carries a verified endorsement by its retiring key."""
    for tail, marker in walk.boundaries:
        prior, new = walk.receipts[tail], walk.receipts[marker]
        match = [e for e in endorsements if endorsement_verifies(e)
                 and e.get("session_id") == session
                 and e.get("prior_signer_key") == prior["signer_key"]
                 and e.get("prior_final_seq") == prior["action_record"].get("chain_seq")
                 and e.get("prior_tail_hash") == walk.hashes[tail]
                 and e.get("new_signer_key") == new["signer_key"]]
        if len(match) != 1:
            return False
    return True


def _head_index(walk: _Walk, head: dict[str, Any]) -> int | None:
    if "receipt_hash" in head:
        return walk.hashes.index(head["receipt_hash"]) if head["receipt_hash"] in \
            walk.hashes else None
    return len(walk.receipts) - 1


def _position_holds(walk: _Walk, head: dict[str, Any], index: int) -> bool:
    receipt = walk.receipts[index]
    return all((
        "final_seq" not in head or head["final_seq"] == receipt["action_record"].get(
            "chain_seq"),
        "segment_signer_key" not in head or head["segment_signer_key"] == receipt[
            "signer_key"],
        "receipt_index" not in head or head["receipt_index"] in (index, index - len(
            walk.receipts)),
    ))


def _first_failure(case: dict[str, Any], lines: list[bytes], head: dict[str, Any] | None,
                   endorsements: list[dict[str, Any]],
                   skip: frozenset[str] = frozenset()) -> tuple[str | None, _Walk]:
    """Name the first check in ``CHECKS`` the chain fails, or None.

    ``skip`` switches named checks off. It exists so the corpus's own tests can
    prove that every check is forced by some member; a verifier never sets it.
    """
    receipts = [json.loads(line) for line in lines]
    walk = _Walk(receipts, lines)
    trust = case["trust"]
    index = _head_index(walk, head) if head is not None else None
    failures: dict[str, Callable[[], bool]] = {
        "signature_invalid": lambda: not all(receipt_verifies(r) for r in receipts),
        "signer_untrusted": lambda: not receipts or receipts[0].get("signer_key") not in
        trust["root_keys"],
        "chain_link_broken": lambda: not walk.links_hold,
        "rotation_unendorsed": lambda: not _endorsed(walk, endorsements, trust.get("session")),
        "close_binding_invalid": lambda: not walk.closes_hold,
        "head_missing": lambda: head is not None and index is None,
        "head_position_mismatch": lambda: head is not None and index is not None
        and not _position_holds(walk, head, index),
        "head_not_final": lambda: head is not None and index is not None
        and head.get("kind") == "final" and index != len(receipts) - 1,
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name, walk
    return None, walk


def _end_proven_by_close(walk: _Walk) -> bool:
    if not walk.receipts:
        return False
    record = walk.receipts[-1]["action_record"]
    closing = _control(record, "session_close")
    if closing is None:
        return False
    run = walk.opens.get(str(closing.get("run_nonce")))
    return run is not None and bool(RUN_SESSION.match(str(run.get("recorder_session", ""))))


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case, lines, head, endorsements = _load(case_path)
    failure, walk = _first_failure(case, lines, head, endorsements, skip)
    if failure is not None:
        return {"decision": REJECTED, "reason": failure}
    if _end_proven_by_close(walk):
        return {"decision": VERIFIED, "reason": "end_proven_close"}
    if (head is not None and head.get("kind") == "final" and "receipt_hash" in head
            and walk.hashes and head["receipt_hash"] == walk.hashes[-1]):
        return {"decision": VERIFIED, "reason": "end_proven_head"}
    return {"decision": PREFIX, "reason": "end_unproven"}


def signatures_verify(case_path: Path) -> bool:
    """Whether every receipt verifies under the key it names."""
    _, lines, _, _ = _load(case_path)
    return all(receipt_verifies(json.loads(line)) for line in lines)


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


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
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
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. A case whose
    declared signature property does not hold is a corpus error, whichever
    verifier is under test.
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
        case_path = directory / "case.json"
        if signatures_verify(case_path) != entry["signaturesVerify"]:
            errors.append(f"{name}: declared signature property does not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
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
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
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
