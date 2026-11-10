"""Judge principal-action records: an action bound to the principals an identity provider authenticated.

A gateway, tool server or decision point that validated signed tokens before an
agent acted writes an in-toto Statement v1, serialised as RFC 8785 bytes and
signed in a DSSE envelope, whose subject is the SHA-256 of the RFC 8785 bytes of
the action and whose predicate names up to four principals (``user``,
``agent``, ``sponsor``, ``approver``). Each principal is the audit-record
``principal`` member: issuer, subject, client, audience, the digest of the
credential, the issuer key, its RFC 7638 thumbprint and the digest of the
issuer's key set, with the credential's RFC 8693 ``act`` chain when it had one.
The specification is ``spec/predicates/principal-action.md``.

Each case is ``case.json`` naming the producer's Ed25519 public key, the
verifier's pin set (issuer to accepted key thumbprints) and one envelope. The
reader checks in the order the specification gives and names the first check
that fails; a principal's failure is ``principal_<role>:<code>``. A record that
passes is ``verified`` with reason ``strict`` or ``basic`` and a delegation
grade, ``act-chain`` or ``act-absent``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason`` (and ``delegation``
when verified), and exits 0 for ``verified`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SUITE = "principal-action/v1"
PREDICATE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/principal-action"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
ROLES = ("user", "agent", "sponsor", "approver")
MEMBERS = (
    "issuer",
    "subject",
    "clientId",
    "audience",
    "authMethod",
    "source",
    "tokenDigest",
    "issuedAt",
    "expiresAt",
    "kid",
    "key",
    "keyThumbprint",
    "jwksDigest",
)
OPTIONAL = ("tenant", "identityProvider", "pinnedThumbprint", "act", "idJag")
SOURCES = frozenset({"jwt-access-token", "id-token", "jwt-assertion", "id-jag"})
AUTH_METHODS = frozenset(
    {
        "none",
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    }
)
IDENTITY_PROVIDERS = frozenset({"okta", "entra", "auth0", "keycloak", "self_issued", "other"})
THUMBPRINT_MEMBERS: dict[str, tuple[str, ...]] = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}
PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
# The order is the contract: a reader names the first check that fails.
STATEMENT_CHECKS = (
    "statement_malformed",
    "recorder_signature_invalid",
    "statement_not_canonical",
    "action_malformed",
    "action_digest_mismatch",
    "principals_malformed",
)
PRINCIPAL_CHECKS = (
    "principal_malformed",
    "principal_member_missing",
    "principal_member_unknown",
    "principal_issuer_invalid",
    "principal_key_invalid",
    "principal_thumbprint_mismatch",
    "principal_kid_mismatch",
    "principal_provider_mismatch",
    "principal_pin_mismatch",
    "principal_not_yet_valid",
    "principal_expired",
    "principal_issuer_untrusted",
    "principal_key_not_pinned",
    "principal_act_malformed",
    "principal_idjag_undefined",
)
BLOCK_CHECKS = (
    "principals_need_user_and_agent",
    "principal_act_names_another_agent",
    "principal_approver_not_an_approval_signer",
)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_THUMBPRINT_SHAPE = re.compile(r"[A-Za-z0-9_-]{43}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
_OKTA = (".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com")
_ENTRA_HOSTS = frozenset(
    {"login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn", "sts.windows.net"}
)
_SELF_ISSUED = frozenset({"https://self-issued.me", "https://self-issued.me/v2"})
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-principal-action"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-principal-action"
)
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "pae", "jcs_dumps")


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
    raise ImportError("the reference rail's Ed25519, DSSE and RFC 8785 primitives are unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def canonical(value: object) -> bytes:
    """RFC 8785 bytes, from the rail."""
    return bytes(_rail().jcs_dumps(value))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(key: dict[str, Any]) -> str:
    """The RFC 7638 SHA-256 thumbprint of a public JWK, base64url without padding."""
    members = THUMBPRINT_MEMBERS[key["kty"]]
    return b64url(hashlib.sha256(canonical({m: key[m] for m in members})).digest())


def derived_identity_provider(issuer: str) -> str:
    """The provider an https issuer names by host and path; ``other`` for a custom domain."""
    parts = urlsplit(issuer)
    host = (parts.hostname or "").lower()
    if issuer.rstrip("/") in _SELF_ISSUED:
        return "self_issued"
    if host.endswith(_OKTA):
        return "okta"
    if host in _ENTRA_HOSTS or host.endswith(".ciamlogin.com"):
        return "entra"
    if host.endswith(".auth0.com"):
        return "auth0"
    segments = [s for s in parts.path.split("/") if s]
    if segments[:1] == ["auth"]:
        segments = segments[1:]
    if len(segments) == 2 and segments[0] == "realms":
        return "keycloak"
    return "other"


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise ValueError("not an RFC 3339 UTC time")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _act_subjects(act: Any) -> list[str] | None:
    """The actor subjects of an RFC 8693 ``act`` chain, outermost first; None when malformed."""
    out: list[str] = []
    while act is not None:
        if not isinstance(act, dict) or not _text(act.get("sub")) or set(act) - {"sub", "act"}:
            return None
        out.append(act["sub"])
        act = act.get("act")
    return out


def _approval_ok(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and set(entry) == {"subject", "approvalDigest"}
        and _text(entry["subject"])
        and isinstance(entry["approvalDigest"], str)
        and bool(_HEX64.fullmatch(entry["approvalDigest"]))
    )


def _members_wellformed(p: dict[str, Any]) -> bool:
    issuer = p["issuer"]
    if not all(_text(p[m]) for m in ("subject", "clientId", "kid", "keyThumbprint")):
        return False
    aud = p["audience"]
    if not (isinstance(aud, list) and aud and all(_text(a) for a in aud) and len(set(aud)) == len(aud)):
        return False
    if p["source"] not in SOURCES or p["authMethod"] not in AUTH_METHODS:
        return False
    if not all(isinstance(p[m], str) and _HEX64.fullmatch(p[m]) for m in ("tokenDigest", "jwksDigest")):
        return False
    if "tenant" in p and not _text(p["tenant"]):
        return False
    if "identityProvider" in p and p["identityProvider"] not in IDENTITY_PROVIDERS:
        return False
    if "pinnedThumbprint" in p and not (
        isinstance(p["pinnedThumbprint"], str) and _THUMBPRINT_SHAPE.fullmatch(p["pinnedThumbprint"])
    ):
        return False
    return isinstance(issuer, str)


def _key_ok(key: Any) -> bool:
    if not isinstance(key, dict) or key.get("kty") not in THUMBPRINT_MEMBERS:
        return False
    if set(key) & PRIVATE_MEMBERS:
        return False
    return all(_text(key.get(m)) for m in THUMBPRINT_MEMBERS[key["kty"]])


def check_principal(p: Any, at: datetime, pins: dict[str, list[str]], skip: frozenset[str]) -> str | None:
    """The first check one principal fails, or None."""

    def fails(code: str, failed: bool) -> bool:
        return failed and code not in skip

    if not isinstance(p, dict):
        return None if "principal_malformed" in skip else "principal_malformed"
    if any(m not in p for m in MEMBERS):
        # No later check can read a principal missing a member, so skipping this check passes it.
        return None if "principal_member_missing" in skip else "principal_member_missing"
    if fails("principal_member_unknown", bool(set(p) - set(MEMBERS) - set(OPTIONAL))):
        return "principal_member_unknown"
    issuer = p["issuer"]
    if fails("principal_issuer_invalid", not (isinstance(issuer, str) and issuer.startswith("https://") and len(issuer) > 8)):
        return "principal_issuer_invalid"
    if fails("principal_malformed", not _members_wellformed(p)):
        return "principal_malformed"
    if not _key_ok(p["key"]):
        return None if "principal_key_invalid" in skip else "principal_key_invalid"
    thumb = jwk_thumbprint(p["key"])
    if fails("principal_thumbprint_mismatch", thumb != p["keyThumbprint"]):
        return "principal_thumbprint_mismatch"
    if fails("principal_kid_mismatch", p["key"].get("kid") != p["kid"]):
        return "principal_kid_mismatch"
    declared = p.get("identityProvider")
    if declared is not None and isinstance(issuer, str):
        derived = derived_identity_provider(issuer)
        if fails("principal_provider_mismatch", derived != "other" and declared != derived):
            return "principal_provider_mismatch"
    if fails("principal_pin_mismatch", "pinnedThumbprint" in p and p["pinnedThumbprint"] != p["keyThumbprint"]):
        return "principal_pin_mismatch"
    try:
        issued, expires = _instant(p["issuedAt"]), _instant(p["expiresAt"])
    except ValueError:
        return None if "principal_malformed" in skip else "principal_malformed"
    if fails("principal_malformed", expires <= issued):
        return "principal_malformed"
    if fails("principal_not_yet_valid", at < issued):
        return "principal_not_yet_valid"
    if fails("principal_expired", at >= expires):
        return "principal_expired"
    if fails("principal_issuer_untrusted", issuer not in pins):
        return "principal_issuer_untrusted"
    if fails("principal_key_not_pinned", thumb not in pins.get(issuer, [])):
        return "principal_key_not_pinned"
    if fails("principal_act_malformed", "act" in p and _act_subjects(p["act"]) is None):
        return "principal_act_malformed"
    if fails("principal_idjag_undefined", "idJag" in p):
        return "principal_idjag_undefined"
    return None


class Record:
    """One envelope, decoded as far as it decodes."""

    def __init__(self, envelope: Any) -> None:
        self.envelope = envelope
        self.payload = b""
        self.statement: Any = None
        try:
            self.payload = base64.b64decode(str(envelope["payload"]), validate=True)
            self.statement = json.loads(self.payload)
        except (KeyError, TypeError, ValueError, binascii.Error):
            self.statement = None

    def well_formed(self) -> bool:
        s = self.statement
        if not isinstance(s, dict) or s.get("_type") != STATEMENT_TYPE:
            return False
        if s.get("predicateType") != PREDICATE_TYPE:
            return False
        subject = s.get("subject")
        if not (
            isinstance(subject, list)
            and len(subject) == 1
            and isinstance(subject[0], dict)
            and subject[0].get("name") == "action"
            and isinstance(subject[0].get("digest"), dict)
            and list(subject[0]["digest"]) == ["sha256"]
            and isinstance(subject[0]["digest"]["sha256"], str)
        ):
            return False
        pred = s.get("predicate")
        if not isinstance(pred, dict) or set(pred) - {"action", "principals", "approvals"}:
            return False
        if not isinstance(pred.get("action"), dict) or not isinstance(pred.get("principals"), dict):
            return False
        approvals = pred.get("approvals", [])
        return isinstance(approvals, list) and all(_approval_ok(a) for a in approvals)

    def recorder_signed(self, producer: bytes) -> bool:
        try:
            sigs = self.envelope["signatures"]
            sig = base64.b64decode(str(sigs[0]["sig"]), validate=True)
        except (KeyError, IndexError, TypeError, ValueError, binascii.Error):
            return False
        if len(sigs) != 1 or self.envelope.get("payloadType") != PAYLOAD_TYPE:
            return False
        rail = _rail()
        return bool(rail.ed25519_verify(producer, rail.pae(PAYLOAD_TYPE, self.payload), sig))

    @property
    def predicate(self) -> dict[str, Any]:
        return dict(self.statement["predicate"])

    def action_ok(self) -> bool:
        action = self.predicate["action"]
        if set(action) != {"tool", "argumentsDigest", "at"} or not _text(action["tool"]):
            return False
        if not (isinstance(action["argumentsDigest"], str) and _HEX64.fullmatch(action["argumentsDigest"])):
            return False
        try:
            _instant(action["at"])
        except ValueError:
            return False
        return True


def _decide(producer: bytes, record: Record, pins: dict[str, list[str]], skip: frozenset[str]) -> dict[str, str]:
    def rejected(reason: str) -> dict[str, str]:
        return {"decision": REJECTED, "reason": reason}

    if not record.well_formed():
        if "statement_malformed" in skip:
            return {"decision": VERIFIED, "reason": "basic", "delegation": "act-absent"}
        return rejected("statement_malformed")
    if "recorder_signature_invalid" not in skip and not record.recorder_signed(producer):
        return rejected("recorder_signature_invalid")
    if "statement_not_canonical" not in skip and record.payload != canonical(record.statement):
        return rejected("statement_not_canonical")
    if not record.action_ok():
        if "action_malformed" in skip:
            return {"decision": VERIFIED, "reason": "basic", "delegation": "act-absent"}
        return rejected("action_malformed")
    pred = record.predicate
    action = pred["action"]
    if "action_digest_mismatch" not in skip and (
        record.statement["subject"][0]["digest"]["sha256"] != _sha(canonical(action))
    ):
        return rejected("action_digest_mismatch")
    block = pred["principals"]
    if not block or set(block) - set(ROLES):
        if "principals_malformed" not in skip:
            return rejected("principals_malformed")
    at = _instant(action["at"])
    for role in ROLES:
        if role in block:
            problem = check_principal(block[role], at, pins, skip)
            if problem is not None:
                return rejected(f"principal_{role}:{problem}")
    if "user" not in block or "agent" not in block:
        if "principals_need_user_and_agent" not in skip:
            return rejected("principals_need_user_and_agent")
        return {"decision": VERIFIED, "reason": "basic", "delegation": "act-absent"}
    user, agent = block["user"], block["agent"]
    chain = _act_subjects(user["act"]) if "act" in user else []
    if (
        "principal_act_names_another_agent" not in skip
        and chain
        and chain[0] not in (agent["subject"], agent["clientId"])
    ):
        return rejected("principal_act_names_another_agent")
    signers = {a["subject"] for a in pred.get("approvals", [])}
    if (
        "principal_approver_not_an_approval_signer" not in skip
        and "approver" in block
        and block["approver"]["subject"] not in signers
    ):
        return rejected("principal_approver_not_an_approval_signer")
    delegation = "act-chain" if "act" in user else "act-absent"
    strict = bool(chain) and all(r in block for r in ROLES)
    return {"decision": VERIFIED, "reason": "strict" if strict else "basic", "delegation": delegation}


def _load(case_path: Path) -> tuple[bytes, Record, dict[str, list[str]]]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    producer = base64.b64decode(str(case["producerKey"]), validate=True)
    envelope = json.loads((case_path.parent / case["envelope"]).read_text(encoding="utf-8"))
    pins = {str(k): [str(t) for t in v] for k, v in dict(case.get("pins", {})).items()}
    return producer, Record(envelope), pins


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's answer for one case.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some case; a verifier never sets it.
    """
    producer, record, pins = _load(case_path)
    return _decide(producer, record, pins, skip)


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
    if manifest.get("suite") != SUITE or manifest.get("predicateType") != PREDICATE_TYPE:
        return [], "unexpected suite or predicate type"
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
        result = subprocess.run(
            [*command, str(case_path), "--json"], capture_output=True, text=True, timeout=90, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
        if answer["decision"] == VERIFIED:
            observed["delegation"] = answer["delegation"]
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT, skip: frozenset[str] = frozenset()
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
        "suite": SUITE,
        "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors), "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else " ".join(answer.values()))
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
