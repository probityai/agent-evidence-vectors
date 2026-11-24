"""Judge a credential status receipt against the agent credential it vouches for.

An authority that keeps the standing of agent credentials signs a status receipt: this
credential is active, from this time, until that one. A relying party that holds the receipt
and the credential decides offline, without calling the authority again. The receipt is only
worth that much if it names the credential by the digest of its bytes. A receipt that names
the credential by identifier alone, or that signs the status and nothing else, vouches for
every credential that carries the identifier: a holder can swap the capability set, swap or
add a public key, sign the result with a key of their own, and present it beside the
authority's genuine receipt. The credential's own signature still verifies, because the key
that made it ships inside the credential.

The corpus this module reads makes that testable. Several rejected cases carry a receipt whose
signature verifies under the authority's key and a credential whose own signature verifies
under a key it lists, and the receipt in some of them is byte for byte the receipt of the
accepted control. Only the binding between the receipt and the credential's bytes refuses
them.

A case is ``case.json`` naming the check time ``now``, the authority's base64 Ed25519 public
key ``authorityKey``, and two DSSE envelopes: the credential and the receipt. The reader
checks in a fixed order and names the first check that fails:

1. the receipt is a DSSE envelope of the receipt payload type with one signature, over a JSON
   object with exactly ``credential``, ``status``, ``issuedAt`` and ``validUntil``, a known
   status and a window whose start is before its end (``receipt_malformed``);
2. the receipt's signature verifies under the authority key (``receipt_signature_invalid``);
3. the receipt names the credential by digest, not only by identifier (``receipt_unbound``);
4. the credential is a DSSE envelope of the credential payload type over a JSON object with
   exactly ``id``, ``name``, ``capabilities`` and ``keys``, a sorted duplicate-free capability
   list and Ed25519 keys with distinct ``kid`` values (``credential_malformed``);
5. every signature on the credential verifies under the key its ``keyid`` names in the
   credential's own ``keys`` (``credential_signature_invalid``);
6. the receipt names the credential's ``id`` (``credential_id_mismatch``);
7. the receipt's digest is the SHA-256 of the credential payload bytes, the bytes that carry
   the capabilities and every key (``credential_digest_mismatch``);
8. the check time is not before ``issuedAt`` (``receipt_not_yet_valid``) and is before
   ``validUntil`` (``receipt_expired``);
9. the status is ``active`` (``credential_not_active``).

A case that passes every check is ``accept`` with reason ``credential_bound``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object carrying ``decision`` and ``reason``, and exits 0 for ``accept`` and 1 for ``reject``.
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
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import strictb64, strictjson

SUITE = "status-receipt-binding/v1"
ACCEPT, REJECT = "accept", "reject"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
CREDENTIAL_TYPE = "application/vnd.agent-evidence.agent-credential+json"
RECEIPT_TYPE = "application/vnd.agent-evidence.credential-status-receipt+json"
STATUSES = ("active", "revoked", "suspended")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "receipt_malformed",
    "receipt_signature_invalid",
    "receipt_unbound",
    "credential_malformed",
    "credential_signature_invalid",
    "credential_id_mismatch",
    "credential_digest_mismatch",
    "receipt_not_yet_valid",
    "receipt_expired",
    "credential_not_active",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-status-receipt-binding" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-status-receipt-binding")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "pae")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to dispatch the
    suite, so a module-level import would be a cycle."""
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
    raise ImportError("the reference rail's Ed25519 and DSSE primitives are unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class _Envelope:
    """A DSSE envelope as read: the payload type, the payload bytes and the signatures, each
    None when that part does not parse."""

    payload_type: str | None
    payload: bytes | None
    signatures: list[tuple[str, bytes]] | None
    body: dict[str, Any] | None


def _signatures(entries: Any) -> list[tuple[str, bytes]] | None:
    """The ``(keyid, sig)`` pairs of a DSSE ``signatures`` member, or None when it is not a
    non-empty list of exactly those two members with a canonical base64 signature."""
    if not isinstance(entries, list) or not entries:
        return None
    out: list[tuple[str, bytes]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"keyid", "sig"}:
            return None
        if not isinstance(entry["keyid"], str):
            return None
        try:
            out.append((entry["keyid"], strictb64.std(entry["sig"])))
        except (ValueError, TypeError):
            return None
    return out


def _object(payload: bytes | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    try:
        parsed = strictjson.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _envelope(path: Path) -> _Envelope:
    try:
        raw = strictjson.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return _Envelope(None, None, None, None)
    if not isinstance(raw, dict) or set(raw) != {"payload", "payloadType", "signatures"}:
        return _Envelope(None, None, None, None)
    payload_type = raw["payloadType"] if isinstance(raw["payloadType"], str) else None
    try:
        payload: bytes | None = strictb64.std(raw["payload"])
    except (ValueError, TypeError):
        payload = None
    return _Envelope(payload_type, payload, _signatures(raw["signatures"]), _object(payload))


@dataclass(frozen=True)
class _Case:
    now: datetime | None
    authority_key: bytes | None
    credential: _Envelope
    receipt: _Envelope


def _load(case_path: Path) -> _Case:
    case = strictjson.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    now = case.get("now")
    try:
        key: bytes | None = strictb64.std(case.get("authorityKey"))
    except (ValueError, TypeError):
        key = None
    return _Case(
        _when(now) if isinstance(now, str) and _TIME.fullmatch(now) else None,
        key if key is not None and len(key) == 32 else None,
        _envelope(base / str(case.get("credential", ""))),
        _envelope(base / str(case.get("receipt", ""))),
    )


def _binding(body: dict[str, Any] | None) -> dict[str, Any] | None:
    credential = body.get("credential") if body else None
    return credential if isinstance(credential, dict) else None


def receipt_well_formed(receipt: _Envelope) -> bool:
    """Whether the receipt has the shape check 1 asks for. A receipt that names the credential
    by identifier only is well formed here: check 3 refuses it by name."""
    body = receipt.body
    if receipt.payload_type != RECEIPT_TYPE or receipt.signatures is None:
        return False
    if len(receipt.signatures) != 1 or body is None:
        return False
    if set(body) != {"credential", "issuedAt", "status", "validUntil"}:
        return False
    binding = _binding(body)
    if binding is None or not set(binding) <= {"digest", "id"} or "id" not in binding:
        return False
    if not isinstance(binding["id"], str) or not binding["id"]:
        return False
    if "digest" in binding:
        digest = binding["digest"]
        if (not isinstance(digest, dict) or set(digest) != {"sha256"}
                or not isinstance(digest["sha256"], str) or not _HEX64.fullmatch(digest["sha256"])):
            return False
    if body["status"] not in STATUSES:
        return False
    times = (body["issuedAt"], body["validUntil"])
    if not all(isinstance(t, str) and _TIME.fullmatch(t) for t in times):
        return False
    return _when(body["issuedAt"]) < _when(body["validUntil"])


@lru_cache(maxsize=1024)
def _ed25519(key: bytes, message: bytes, sig: bytes) -> bool:
    """One Ed25519 verification, remembered: the rail's arithmetic is plain Python and every
    case is read more than once."""
    return bool(_rail().ed25519_verify(key, message, sig))


def _dsse_verifies(key: bytes, envelope: _Envelope, sig: bytes) -> bool:
    if envelope.payload_type is None or envelope.payload is None:
        return False
    return _ed25519(key, _rail().pae(envelope.payload_type, envelope.payload), sig)


def receipt_signature_verifies(c: _Case) -> bool:
    """Whether the receipt's one signature verifies under the authority key."""
    sigs = c.receipt.signatures
    if c.authority_key is None or not sigs or len(sigs) != 1:
        return False
    return _dsse_verifies(c.authority_key, c.receipt, sigs[0][1])


def _key_bytes(jwk: Any) -> bytes | None:
    if not isinstance(jwk, dict) or set(jwk) != {"crv", "kid", "kty", "x"}:
        return None
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519" or not isinstance(jwk["kid"], str):
        return None
    try:
        raw = strictb64.url(jwk["x"])
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def credential_keys(credential: _Envelope) -> dict[str, bytes] | None:
    """The credential's keys by ``kid``, or None when the list is not well formed."""
    keys = credential.body.get("keys") if credential.body else None
    if not isinstance(keys, list) or not keys:
        return None
    found: dict[str, bytes] = {}
    for jwk in keys:
        raw = _key_bytes(jwk)
        if raw is None or not jwk["kid"] or jwk["kid"] in found:
            return None
        found[jwk["kid"]] = raw
    return found


def credential_well_formed(credential: _Envelope) -> bool:
    """Whether the credential has the shape check 4 asks for."""
    body = credential.body
    if credential.payload_type != CREDENTIAL_TYPE or credential.signatures is None:
        return False
    if body is None or set(body) != {"capabilities", "id", "keys", "name"}:
        return False
    if not isinstance(body["id"], str) or not body["id"] or not isinstance(body["name"], str):
        return False
    caps = body["capabilities"]
    if (not isinstance(caps, list) or not caps or not all(isinstance(c, str) and c for c in caps)
            or caps != sorted(set(caps))):
        return False
    return credential_keys(credential) is not None


def credential_signature_verifies(c: _Case) -> bool:
    """Whether every credential signature verifies under the key its keyid names in the
    credential's own key list. This is the holder's proof over the bytes and nothing more:
    whoever writes the key list also holds a key that verifies."""
    keys = credential_keys(c.credential)
    sigs = c.credential.signatures
    if keys is None or not sigs:
        return False
    return all(kid in keys and _dsse_verifies(keys[kid], c.credential, sig) for kid, sig in sigs)


def _id_mismatch(c: _Case) -> bool:
    binding = _binding(c.receipt.body)
    body = c.credential.body
    return binding is None or body is None or binding.get("id") != body.get("id")


def _digest_mismatch(c: _Case) -> bool:
    binding = _binding(c.receipt.body)
    digest = binding.get("digest") if binding else None
    declared = digest.get("sha256") if isinstance(digest, dict) else None
    return c.credential.payload is None or declared != _sha(c.credential.payload)


def _window(c: _Case) -> tuple[datetime, datetime] | None:
    body = c.receipt.body
    if body is None or not all(isinstance(body.get(k), str) and _TIME.fullmatch(body[k])
                               for k in ("issuedAt", "validUntil")):
        return None
    return _when(body["issuedAt"]), _when(body["validUntil"])


def _first_failure(c: _Case, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each check is forced
    by some member and can model a verifier that omits one; a verifier never sets it. Every
    check is total on its own, so switching an earlier one off cannot crash a later one.
    """
    window = _window(c)
    failures: dict[str, Callable[[], bool]] = {
        "receipt_malformed": lambda: not receipt_well_formed(c.receipt),
        "receipt_signature_invalid": lambda: not receipt_signature_verifies(c),
        "receipt_unbound": lambda: "digest" not in (_binding(c.receipt.body) or {}),
        "credential_malformed": lambda: not credential_well_formed(c.credential),
        "credential_signature_invalid": lambda: not credential_signature_verifies(c),
        "credential_id_mismatch": lambda: _id_mismatch(c),
        "credential_digest_mismatch": lambda: _digest_mismatch(c),
        "receipt_not_yet_valid": lambda: window is None or c.now is None or c.now < window[0],
        "receipt_expired": lambda: window is None or c.now is None or c.now >= window[1],
        "credential_not_active": lambda: (c.receipt.body or {}).get("status") != "active",
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    failure = _first_failure(_load(case_path), skip)
    if failure is not None:
        return {"decision": REJECT, "reason": failure}
    return {"decision": ACCEPT, "reason": "credential_bound"}


def signature_properties(case_path: Path) -> dict[str, bool]:
    """Whether the receipt's and the credential's signatures each verify, as a case declares."""
    c = _load(case_path)
    return {"credentialSignatureVerifies": credential_signature_verifies(c),
            "receiptSignatureVerifies": receipt_signature_verifies(c)}


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


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
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
    """Check every case, through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement. A case whose declared
    signature properties do not hold is a corpus error, whichever verifier is under test.
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
        declared = {key: entry[key] for key in ("credentialSignatureVerifies",
                                                 "receiptSignatureVerifies")}
        if signature_properties(case_path) != declared:
            errors.append(f"{name}: declared signature properties do not hold")
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
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
