"""Judge bindings of an agent to the principal it acts for and the scope it holds.

Every case is one binding written in the native form of one effort that defines
it, and the relying party's request: the agent, principal and scope it is asked
to accept. The reader recomputes the binding from its bytes and refuses when any
one field disagrees. Two native forms are read:

- ``uma-for-agents``: the UMA for Agents terms agreement, a compact JWS (EdDSA)
  the agent signs with the key in its protected header, echoing the template
  the owner's authorization server proffered. The agent is ``iss``, which for a
  pseudonymous agent is ``agent:`` and the first 16 hex digits of the SHA-256 of
  its key; the principal is the owner's authorization server (``aud``); the
  scope is the echoed ``scope``.
- ``hcp-grant``: a Human Context Protocol 2.0 draft 3 grant, inside an envelope
  the Authorization Service signs over the grant's RFC 8785 form. The agent is
  ``client.id``; the principal is ``authorizingPrincipal.id``; the scope is
  ``scopes``.

The reader checks in a fixed order and names the first check that fails:

1. the binding verifies under the key the case trusts for its signer, and for
   UMA for Agents ``iss`` is the identifier of the signing key
   (``signature_invalid``);
2. UMA for Agents: the echo matches the template on template id, terms URI,
   purpose, scope, family and nonce, and ``aud`` is the template's
   ``proffered_by`` (``echo_mismatch``);
3. UMA for Agents: no prohibition is dropped and ``expires_in`` is not extended
   (``terms_weakened``);
4. HCP: the grant's ``status`` is ``active`` (``grant_inactive``);
5. HCP: every scope string is derived from the grant's ``access``, as
   ``hcp:{category}:{action}`` (``scope_not_backed``);
6. the binding's agent is the agent the request names (``agent_mismatch``);
7. the binding's principal is the principal the request names, and an HCP
   grant naming no delegation has the Context Subject as its Authorizing
   Principal (``principal_mismatch``);
8. every scope the request asks for is in the binding's scope
   (``scope_exceeded``).

A binding that passes every check is ``verified`` with ``agent_bound``.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``verified`` and 1 for ``rejected``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

SUITE = "agent-principal-binding/v1"
VERIFIED, REJECTED = "verified", "rejected"
EXIT_FOR = {VERIFIED: 0, REJECTED: 1}
UMA, HCP = "uma-for-agents", "hcp-grant"
ECHOED = ("template_id", "terms_uri", "purpose", "scope", "family", "nonce")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "signature_invalid",
    "echo_mismatch",
    "terms_weakened",
    "grant_inactive",
    "scope_not_backed",
    "agent_mismatch",
    "principal_mismatch",
    "scope_exceeded",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-principal-binding" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-principal-binding")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")


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
    raise ImportError("the reference rail's Ed25519 and RFC 8785 primitives are unavailable")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64u(text: bytes) -> bytes:
    if b"=" in text:
        raise ValueError("padded base64url")
    return base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))


class Binding:
    """One binding read from its native bytes: whether its signature verifies,
    and the agent, principal and scope it states."""

    def __init__(self, case: dict[str, Any], raw: bytes) -> None:
        self.case = case
        self.signed = False
        self.body: dict[str, Any] = {}
        if case["profile"] == UMA:
            self._read_jws(raw.strip())
        elif case["profile"] == HCP:
            self._read_envelope(raw)
        else:
            raise ValueError(f"unknown profile {case['profile']!r}")

    def _read_jws(self, token: bytes) -> None:
        parts = token.split(b".")
        if len(parts) != 3:
            return
        try:
            header = json.loads(_b64u(parts[0]))
            self.body = json.loads(_b64u(parts[1]))
            key = _b64u(str(header["jwk"]["x"]).encode())
            sig = _b64u(parts[2])
        except (ValueError, KeyError, TypeError, binascii.Error):
            self.body = {}
            return
        trusted = bytes.fromhex(self.case["keys"]["agent"])
        self.signed = (
            header.get("alg") == "EdDSA" and key == trusted
            and isinstance(self.body, dict)
            and self.body.get("iss") == "agent:" + _sha(key)[:16]
            and bool(_rail().ed25519_verify(key, parts[0] + b"." + parts[1], sig)))

    def _read_envelope(self, raw: bytes) -> None:
        try:
            envelope = json.loads(raw)
            self.body = envelope["grant"]
            sig = base64.b64decode(str(envelope["sig"]), validate=True)
        except (ValueError, KeyError, TypeError, binascii.Error):
            self.body = {}
            return
        key = bytes.fromhex(self.case["keys"]["authorization-service"])
        rail = _rail()
        self.signed = isinstance(self.body, dict) and bool(
            rail.ed25519_verify(key, rail.jcs_dumps(self.body), sig))

    def agent(self) -> Any:
        if self.case["profile"] == UMA:
            return self.body.get("iss")
        return (self.body.get("client") or {}).get("id")

    def principal(self) -> Any:
        if self.case["profile"] == UMA:
            return self.body.get("aud")
        return (self.body.get("authorizingPrincipal") or {}).get("id")

    def scope(self) -> list[Any]:
        key = "scope" if self.case["profile"] == UMA else "scopes"
        value = self.body.get(key)
        return value if isinstance(value, list) else []


def _strings(value: Any) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _echo_mismatch(case: dict[str, Any], body: dict[str, Any]) -> bool:
    if case["profile"] != UMA:
        return False
    template = case["template"]
    return (any(body.get(field) != template[field] for field in ECHOED)
            or body.get("aud") != template["proffered_by"])


def _terms_weakened(case: dict[str, Any], body: dict[str, Any]) -> bool:
    if case["profile"] != UMA:
        return False
    template = case["template"]
    expires = body.get("expires_in")
    return (not _strings(template["prohibited"]) <= _strings(body.get("prohibited"))
            or type(expires) is not int or expires > template["expires_in"])


def _derived_scopes(body: dict[str, Any]) -> set[str]:
    derived: set[str] = set()
    for detail in body.get("access") or []:
        if isinstance(detail, dict):
            derived |= {f"hcp:{category}:{action}"
                        for category in _strings(detail.get("categories"))
                        for action in _strings(detail.get("actions"))}
    return derived


def _first_failure(case: dict[str, Any], binding: Binding,
                   skip: frozenset[str] = frozenset()) -> str | None:
    """Name the first check in ``CHECKS`` the binding fails, or None.

    ``skip`` switches named checks off. It exists so the corpus's own tests can
    prove that every check is forced by some member; a verifier never sets it.
    """
    body, request, hcp = binding.body, case["request"], case["profile"] == HCP
    principal = binding.principal()
    failures: dict[str, Callable[[], bool]] = {
        "signature_invalid": lambda: not binding.signed,
        "echo_mismatch": lambda: _echo_mismatch(case, body),
        "terms_weakened": lambda: _terms_weakened(case, body),
        "grant_inactive": lambda: hcp and body.get("status") != "active",
        "scope_not_backed": lambda: hcp and not _strings(body.get("scopes")) <= _derived_scopes(
            body),
        "agent_mismatch": lambda: binding.agent() != request["agent"],
        "principal_mismatch": lambda: principal != request["principal"] or (
            hcp and "delegation" not in (body.get("authorizingPrincipal") or {})
            and principal != (body.get("subject") or {}).get("id")),
        "scope_exceeded": lambda: not _strings(request["scope"]) <= _strings(binding.scope()),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def _load(case_path: Path) -> tuple[dict[str, Any], Binding]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    return case, Binding(case, (case_path.parent / case["binding"]).read_bytes())


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case, binding = _load(case_path)
    failure = _first_failure(case, binding, skip)
    if failure is not None:
        return {"decision": REJECTED, "reason": failure}
    return {"decision": VERIFIED, "reason": "agent_bound"}


def signature_verifies(case_path: Path) -> bool:
    """Whether the binding's signature verifies under the key the case trusts."""
    return _load(case_path)[1].signed


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
    ids = {entry["id"] for entry in entries}
    if not entries or len(ids) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if any(entry.get("pairsWith", entry["id"]) not in ids for entry in entries):
        return [], "a case pairs with a case the manifest does not hold"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != ids:
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
        if signature_verifies(case_path) != entry["bindingSignatureVerifies"]:
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
