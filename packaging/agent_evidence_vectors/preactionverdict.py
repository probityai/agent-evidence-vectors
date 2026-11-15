"""Judge a signed pre-action verdict: may a relying party credit it as an independent
verdict on this action, issued before the action ran?

The record is a Nostr event (NIP-01, kind 30078) whose ``content`` is a JSON object, signed
with BIP-340. A reader that stops at "the signature is valid and the key is trusted" credits
records it should refuse, and a reader that checks only the issuer's own clock credits a
verdict nobody can show existed before the action. The reader answers in a fixed order and
names the first check that fails:

1. ``case.json`` carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the pre-action verdict contract (``contract_id_unknown``);
3. ``case.json`` has the fields and types the contract names (``malformed_case``);
4. ``record.id`` is the SHA-256 of the NIP-01 serialisation (``event_id``);
5. ``record.sig`` is a valid BIP-340 signature over ``id`` under ``pubkey`` (``signature``);
6. ``pubkey`` is in the relying party's key set (``key_not_in_set``);
7. the tags carry the verdict schema tag (``schema``);
8. ``content.verifier_pubkey`` equals ``pubkey`` (``key_binding``);
9. ``content.decision_ref`` recomputes from the preimage fields it names (``decision_ref``);
10. the relying party's action hash equals ``content.artifact_hash`` (``action_unbound``);
11. the issuer's clock puts the verdict before the action: the beacon time is not after
    ``created_at``, and ``created_at`` is before the execution time (``not_pre_action``);
12. when the relying party states a maximum age, the verdict is not older than it
    (``stale_verdict``).

Two more checks apply only when the relying party holds Bitcoin block headers and lists them
in ``relyingParty.trustedHeaders``. Then the issuer's clock is not enough, and the verdict
has to be shown to exist before the action by a time the issuer does not control:

13. the beacon names a trusted header whose time is the beacon time (``beacon_untrusted``);
14. the case carries an anchor (``anchor_missing``);
15. the anchor commits the record: folding ``commitment`` through ``path`` with SHA-256
    reaches the header's merkle root field, and ``commitment`` is the record id
    (``anchor_commitment``);
16. the anchor's header is one of the trusted headers (``anchor_header_untrusted``);
17. the anchor header's time is before the execution time (``anchor_after_action``).

A case that passes the checks is ``allow``. Its reason is ``verified_issuer_clock`` when no
headers are held and ``verified_anchored`` when they are. The first credits the issuer's own
word about when it signed; only the second shows the verdict existed before the action.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object carrying ``decision`` and ``reason``, and exits 0 for ``allow`` and 1 for ``deny``.

The record shape and the first eight checks follow the eight-step reader contract that
babyblueviper1 published in preaction-governance-conformance. The cases here are built from
this corpus's own test keys, and the authenticated-time checks are this corpus's addition.
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

SUITE = "preaction-verdict/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/preaction-verdict/v1"
SCHEMA_TAG = ["schema", "invinoveritas.verdict_proof.v1"]
ALLOW, DENY = "allow", "deny"
REASON_ISSUER_CLOCK, REASON_ANCHORED = "verified_issuer_clock", "verified_anchored"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_case",
    "event_id",
    "signature",
    "key_not_in_set",
    "schema",
    "key_binding",
    "decision_ref",
    "action_unbound",
    "not_pre_action",
    "stale_verdict",
    "beacon_untrusted",
    "anchor_missing",
    "anchor_commitment",
    "anchor_header_untrusted",
    "anchor_after_action",
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_HEADER = re.compile(r"(?:[0-9a-f]{2}){80}")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("jcs_dumps",)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-preaction-verdict" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-preaction-verdict")

# secp256k1, the BIP-340 curve.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Point = tuple[int, int] | None


class Malformed(ValueError):
    """A value that breaks a shape rule; the caller names the check."""


def _rail() -> Any:
    """The rail module, resolved at call time; see cardreceipt._rail."""
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
    raise ImportError("the reference rail is not importable, so JCS is unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


# ---- BIP-340 over secp256k1 (stdlib only) ----

def point_add(p1: Point, p2: Point) -> Point:
    """Add two curve points; None is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return x3, (lam * (p1[0] - x3) - p1[1]) % P


def point_mul(point: Point, scalar: int) -> Point:
    """Multiply a point by a scalar."""
    result: Point = None
    for bit in range(256):
        if (scalar >> bit) & 1:
            result = point_add(result, point)
        point = point_add(point, point)
    return result


def tagged_hash(tag: str, data: bytes) -> bytes:
    """The BIP-340 tagged hash."""
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + data).digest()


def lift_x(x: int) -> Point:
    """The curve point with this x and an even y, or None."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return x, y if y % 2 == 0 else P - y


def schnorr_verify(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    """BIP-340 verification of a 64-byte signature over a 32-byte message."""
    if len(message) != 32 or len(pubkey) != 32 or len(signature) != 64:
        return False
    point = lift_x(int.from_bytes(pubkey, "big"))
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if point is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + pubkey + message),
                       "big") % N
    result = point_add(point_mul(G, s), point_mul(point, N - e))
    return result is not None and result[1] % 2 == 0 and result[0] == r


# ---- the record ----

def event_id(record: dict[str, Any]) -> str:
    """The NIP-01 id: SHA-256 of the compact, unescaped JSON array."""
    array = [0, record["pubkey"], record["created_at"], record["kind"], record["tags"],
             record["content"]]
    return _sha(json.dumps(array, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def content_of(record: dict[str, Any]) -> dict[str, Any]:
    """The record's content object, parsed."""
    value = json.loads(record["content"])
    if not isinstance(value, dict):
        raise Malformed("content is not an object")
    return value


def decision_ref(content: dict[str, Any]) -> str:
    """``sha256:`` over the JCS of the named preimage fields; an absent field is null."""
    fields = content["decision_ref_preimage_fields"]
    preimage = {name: content.get(name) for name in fields}
    return "sha256:" + _sha(_rail().jcs_dumps(preimage))


def header_hash(header: bytes) -> str:
    """The block hash of an 80-byte header, in the usual reversed hex."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def header_time(header: bytes) -> int:
    """The header's time field, little-endian."""
    return int.from_bytes(header[68:72], "little")


def fold(commitment: str, path: list[dict[str, str]]) -> bytes:
    """Fold a hex commitment through a path of ``{side, hash}`` steps with SHA-256."""
    node = bytes.fromhex(commitment)
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        node = hashlib.sha256(sibling + node if step["side"] == "left" else node + sibling).digest()
    return node


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _record_malformed(record: Any) -> bool:
    if not isinstance(record, dict):
        return True
    if not (_hex(record.get("id"), _HEX64) and _hex(record.get("pubkey"), _HEX64)
            and _hex(record.get("sig"), _HEX128)):
        return True
    if not (_is_int(record.get("created_at")) and _is_int(record.get("kind"))):
        return True
    tags = record.get("tags")
    if not (isinstance(tags, list) and all(
            isinstance(t, list) and all(isinstance(x, str) for x in t) for t in tags)):
        return True
    try:
        content = content_of(record)
    except (Malformed, ValueError, TypeError):
        return True
    fields = content.get("decision_ref_preimage_fields")
    beacon = content.get("freshness_beacon")
    return not (_hex(content.get("verifier_pubkey"), _HEX64)
                and _hex(content.get("artifact_hash"), _HEX64)
                and isinstance(content.get("decision_ref"), str)
                and isinstance(fields, list) and all(isinstance(f, str) for f in fields)
                and isinstance(beacon, dict) and _is_int(beacon.get("block_time"))
                and isinstance(beacon.get("hash"), str))


def _party_malformed(party: Any) -> bool:
    if not (isinstance(party, dict) and _hex(party.get("actionHash"), _HEX64)
            and _is_int(party.get("executedAt"))):
        return True
    if "maxAgeSeconds" in party and not _is_int(party["maxAgeSeconds"]):
        return True
    headers = party.get("trustedHeaders")
    return headers is not None and not (
        isinstance(headers, list) and all(_hex(h, _HEADER) for h in headers))


def _anchor_malformed(anchor: Any) -> bool:
    if anchor is None:
        return False
    if not (isinstance(anchor, dict) and _hex(anchor.get("commitment"), _HEX64)
            and _hex(anchor.get("header"), _HEADER) and isinstance(anchor.get("path"), list)):
        return True
    return not all(isinstance(s, dict) and s.get("side") in ("left", "right")
                   and _hex(s.get("hash"), _HEX64) for s in anchor["path"])


def _case_malformed(case: dict[str, Any]) -> bool:
    key_set = case.get("keySet")
    if not (isinstance(key_set, list) and all(_hex(k, _HEX64) for k in key_set)):
        return True
    return (_record_malformed(case.get("record")) or _party_malformed(case.get("relyingParty"))
            or _anchor_malformed(case.get("anchor")))


def _signature_fails(record: dict[str, Any]) -> bool:
    return not schnorr_verify(bytes.fromhex(record["id"]), bytes.fromhex(record["pubkey"]),
                              bytes.fromhex(record["sig"]))


def _pre_action_fails(case: dict[str, Any]) -> bool:
    created = case["record"]["created_at"]
    beacon_time = content_of(case["record"])["freshness_beacon"]["block_time"]
    return not (beacon_time <= created < case["relyingParty"]["executedAt"])


def _headers(case: dict[str, Any]) -> list[bytes] | None:
    held = case["relyingParty"].get("trustedHeaders")
    return None if held is None else [bytes.fromhex(h) for h in held]


def _beacon_fails(case: dict[str, Any]) -> bool:
    headers = _headers(case)
    if headers is None:
        return False
    beacon = content_of(case["record"])["freshness_beacon"]
    return not any(header_hash(h) == beacon["hash"] and header_time(h) == beacon["block_time"]
                   for h in headers)


def _anchor_commitment_fails(case: dict[str, Any]) -> bool:
    anchor = case["anchor"]
    if anchor["commitment"] != case["record"]["id"]:
        return True
    return fold(anchor["commitment"], anchor["path"]) != bytes.fromhex(anchor["header"])[36:68]


def _anchor_header_untrusted(case: dict[str, Any]) -> bool:
    headers = _headers(case)
    return headers is not None and bytes.fromhex(case["anchor"]["header"]) not in headers


def _anchor_late(case: dict[str, Any]) -> bool:
    stamped = header_time(bytes.fromhex(case["anchor"]["header"]))
    return not stamped < case["relyingParty"]["executedAt"]


def _first_failure(case: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    record = case.get("record", {})
    authenticated = "relyingParty" in case and case["relyingParty"].get("trustedHeaders") is not None

    def stale() -> bool:
        limit = case["relyingParty"].get("maxAgeSeconds")
        return limit is not None and case["relyingParty"]["executedAt"] - record["created_at"] > limit

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in case,
        "contract_id_unknown": lambda: case.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_case": lambda: _case_malformed(case),
        "event_id": lambda: event_id(record) != record["id"],
        "signature": lambda: _signature_fails(record),
        "key_not_in_set": lambda: record["pubkey"] not in case["keySet"],
        "schema": lambda: SCHEMA_TAG not in record["tags"],
        "key_binding": lambda: content_of(record)["verifier_pubkey"] != record["pubkey"],
        "decision_ref": lambda: decision_ref(content_of(record)) != content_of(record)[
            "decision_ref"],
        "action_unbound": lambda: case["relyingParty"]["actionHash"] != content_of(record)[
            "artifact_hash"],
        "not_pre_action": lambda: _pre_action_fails(case),
        "stale_verdict": stale,
        "beacon_untrusted": lambda: _beacon_fails(case),
        "anchor_missing": lambda: authenticated and case.get("anchor") is None,
        "anchor_commitment": lambda: authenticated and _anchor_commitment_fails(case),
        "anchor_header_untrusted": lambda: authenticated and _anchor_header_untrusted(case),
        "anchor_after_action": lambda: authenticated and _anchor_late(case),
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (Malformed, KeyError, TypeError, ValueError, AttributeError, AssertionError):
            # A case an earlier check would have refused, reached only because
            # that check was switched off; the tests see it as a different reason.
            return "unreadable_case"
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case: dict[str, Any] = json.loads(case_path.read_text(encoding="utf-8"))
    failure = _first_failure(case, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    anchored = case["relyingParty"].get("trustedHeaders") is not None
    return {"decision": ALLOW, "reason": REASON_ANCHORED if anchored else REASON_ISSUER_CLOCK}


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
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement.
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
