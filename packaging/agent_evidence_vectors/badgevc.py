"""Judge an agent badge issued as a W3C Verifiable Credential in a compact JWS.

A verifier that accepts such a badge has to decide five separate things, and a
verifier that decides fewer of them accepts a badge it should refuse:

1. the token is a compact JWS whose header names EdDSA and a key identifier of
   the form ``<did>#<fragment>``;
2. the credential inside it names an issuer the verifier trusts, and the key
   identifier belongs to that same issuer: a credential cannot name one issuer
   and be signed under another party's key;
3. the Ed25519 signature is over the exact ASCII bytes ``header.payload`` as
   transmitted, so a payload altered after signing is refused;
4. the credential is inside its validity window at the verification time;
5. the credential is not revoked in the issuer's own status store. The copy of
   the status that the holder presents is the holder's claim; the store the
   issuer holds is the authority, so a credential the issuer has revoked is
   refused even when the token it travels in carries no sign of it.

Each case is one ``case.json``: the compact JWS (``credential``), the
verification time, the key material the verifier resolved for each issuer DID
(``issuers``), the issuers the verifier trusts (``trustedIssuers``) and the
issuer's status store (``status.revoked``, credential identifiers).

The reader checks in a fixed order and names the first check that fails:

1. ``case.json`` carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the badge contract (``contract_id_unknown``);
3. ``case.json`` has the fields and types the contract names
   (``malformed_case``);
4. ``credential`` is three base64url parts, the header is a JSON object with
   ``alg`` EdDSA and a ``kid`` of the form ``<did>#<fragment>``
   (``jws_malformed``);
5. the payload is a JSON object with ``id``, ``type`` containing
   ``VerifiableCredential``, ``issuer``, ``issuanceDate`` and
   ``credentialSubject.id``, and every time is RFC 3339
   (``credential_malformed``);
6. the credential's issuer is a trusted issuer (``issuer_not_trusted``);
7. the key identifier's DID is the credential's issuer and its fragment names
   a key of that issuer (``issuer_key_binding``);
8. the Ed25519 signature verifies over ``header.payload``
   (``signature_invalid``);
9. ``issuanceDate`` is not after the verification time (``not_yet_valid``);
10. ``expirationDate``, when present, is after the verification time
    (``expired``);
11. the credential's ``id`` is not in the issuer's revoked list (``revoked``).

A case that passes all eleven is ``allow`` with reason ``verified``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
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

SUITE = "badge-vc-verify/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/badge-vc-verify/v1"
ALLOW, DENY = "allow", "deny"
PASS_REASON = "verified"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_case",
    "jws_malformed",
    "credential_malformed",
    "issuer_not_trusted",
    "issuer_key_binding",
    "signature_invalid",
    "not_yet_valid",
    "expired",
    "revoked",
)
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_KID = re.compile(r"(did:[a-z0-9]+:[^#\s]+)#([^#\s]+)")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-badge-vc-verify" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-badge-vc-verify")


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
    raise ImportError("the reference rail is not importable, so Ed25519 is unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def b64url_decode(text: str) -> bytes:
    """Strict unpadded base64url: refuses other alphabets and non-canonical text."""
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise Malformed("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(data).decode().rstrip("=") != text:
        raise Malformed("not canonical base64url")
    return data


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Malformed(f"duplicate member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise Malformed(f"{name} is not JSON")


def strict_json(data: bytes) -> Any:
    """Parse UTF-8 JSON with no duplicate member and no NaN or Infinity."""
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=_no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Malformed(str(exc)) from exc


def parse_time(text: Any) -> datetime:
    """An RFC 3339 date-time with a zone, or ``Malformed``."""
    if not (isinstance(text, str) and _RFC3339.fullmatch(text)):
        raise Malformed("not an RFC 3339 date-time")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Malformed(str(exc)) from exc


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _case_malformed(case: dict[str, Any]) -> bool:
    if not (_text(case.get("credential")) and isinstance(case.get("issuers"), dict)):
        return True
    try:
        parse_time(case.get("verificationTime"))
    except Malformed:
        return True
    trusted = case.get("trustedIssuers")
    if not (isinstance(trusted, list) and all(_text(t) for t in trusted)):
        return True
    status = case.get("status")
    if not (isinstance(status, dict) and isinstance(status.get("revoked"), list)
            and all(_text(r) for r in status["revoked"])):
        return True
    for entry in case["issuers"].values():
        keys = entry.get("keys") if isinstance(entry, dict) else None
        if not isinstance(keys, dict):
            return True
        for fragment, key in keys.items():
            if not (_text(fragment) and isinstance(key, str)):
                return True
            try:
                if len(b64url_decode(key)) != 32:
                    return True
            except Malformed:
                return True
    return False


def split_token(token: str) -> tuple[str, str, str]:
    """The three parts of a compact JWS, each unpadded base64url."""
    parts = token.split(".")
    if len(parts) != 3:
        raise Malformed("not three parts")
    for part in parts:
        b64url_decode(part)
    return parts[0], parts[1], parts[2]


def header_of(token: str) -> dict[str, Any]:
    """The JWS header, checked to name EdDSA and a ``<did>#<fragment>`` key id."""
    header_part, _, _ = split_token(token)
    header = strict_json(b64url_decode(header_part))
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        raise Malformed("alg is not EdDSA")
    kid = header.get("kid")
    if not (isinstance(kid, str) and _KID.fullmatch(kid)):
        raise Malformed("kid is not <did>#<fragment>")
    return header


def _jws_malformed(case: dict[str, Any]) -> bool:
    try:
        header_of(case["credential"])
    except Malformed:
        return True
    return False


def payload_of(token: str) -> Any:
    """The credential payload, parsed strictly."""
    _, payload_part, _ = split_token(token)
    return strict_json(b64url_decode(payload_part))


def _credential_malformed(case: dict[str, Any]) -> bool:
    try:
        payload = payload_of(case["credential"])
    except Malformed:
        return True
    if not isinstance(payload, dict):
        return True
    if not (_text(payload.get("id")) and _text(payload.get("issuer"))):
        return True
    kinds = payload.get("type")
    kinds = [kinds] if isinstance(kinds, str) else kinds
    if not (isinstance(kinds, list) and "VerifiableCredential" in kinds):
        return True
    subject = payload.get("credentialSubject")
    if not (isinstance(subject, dict) and _text(subject.get("id"))):
        return True
    try:
        parse_time(payload.get("issuanceDate"))
        if "expirationDate" in payload:
            parse_time(payload["expirationDate"])
    except Malformed:
        return True
    return False


def _kid(case: dict[str, Any]) -> tuple[str, str]:
    match = _KID.fullmatch(header_of(case["credential"])["kid"])
    assert match is not None
    return match.group(1), match.group(2)


def _binding_fails(case: dict[str, Any]) -> bool:
    payload = payload_of(case["credential"])
    did, fragment = _kid(case)
    keys = case["issuers"].get(did, {}).get("keys", {})
    return bool(did != payload["issuer"] or fragment not in keys)


def _signature_fails(case: dict[str, Any]) -> bool:
    did, fragment = _kid(case)
    encoded = case["issuers"].get(did, {}).get("keys", {}).get(fragment)
    if encoded is None:
        return True
    header_part, payload_part, signature_part = split_token(case["credential"])
    message = f"{header_part}.{payload_part}".encode("ascii")
    return not _rail().ed25519_verify(
        b64url_decode(encoded), message, b64url_decode(signature_part))


def _time_after(payload: dict[str, Any], member: str, at: datetime, *, strict: bool) -> bool:
    """Whether the payload's time is after ``at`` (``strict``) or at or before it.

    An unparseable time is the shape check's to refuse; this check passes it.
    """
    try:
        moment = parse_time(payload.get(member))
    except Malformed:
        return False
    return moment > at if strict else moment <= at


def _first_failure(case: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    def at() -> datetime:
        return parse_time(case["verificationTime"])

    def payload() -> dict[str, Any]:
        value = payload_of(case["credential"])
        assert isinstance(value, dict)
        return value

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in case,
        "contract_id_unknown": lambda: case.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_case": lambda: _case_malformed(case),
        "jws_malformed": lambda: _jws_malformed(case),
        "credential_malformed": lambda: _credential_malformed(case),
        "issuer_not_trusted": lambda: payload()["issuer"] not in case["trustedIssuers"],
        "issuer_key_binding": lambda: _binding_fails(case),
        "signature_invalid": lambda: _signature_fails(case),
        "not_yet_valid": lambda: _time_after(payload(), "issuanceDate", at(), strict=True),
        "expired": lambda: ("expirationDate" in payload()
                            and _time_after(payload(), "expirationDate", at(), strict=False)),
        "revoked": lambda: payload()["id"] in case["status"]["revoked"],
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
    return {"decision": ALLOW, "reason": PASS_REASON}


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
