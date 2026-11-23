"""Agent payment mandate: the reference reader for the `agent-payment-mandate/v1` corpus.

A dispute evidence pack for an agent-initiated payment is judged from its own record: the
mandate the user signed, the credential the agent presented, the charge that ran, and the
receipt that binds them. The reader verifies the issuer's Ed25519 signature on the mandate and
the settlement witness's Ed25519 signature on the receipt, against keys the relying party pinned
in its policy; a key or a policy the record carries for itself is never read. It recomputes the
mandate digest and the execution digest rather than trusting the fields that claim them, and
refuses a charge that leaves the
mandate in amount, currency, merchant, time or token, a single-use token used twice, and an
evidence pack whose post-checkout actions are not all recorded.

Every rule below is a refusal code. A record is accepted only when none of the
rules fires; a rejected record names the first rule that fired, in the order
listed in ``RULES``. The fixtures are synthetic: no real merchant, patient,
account or server appears in any of them.

External-verifier contract: ``<verifier> <case-dir>/case.json --json --policy <policy.json>``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for ``accepted`` and 1
for ``rejected``. The policy is the relying party's trust root (issuer and witness keys); the
corpus publishes the one its synthetic keys need as ``policy.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors.w3cintake import ed25519_verify
from . import strictjson

SUITE = "agent-payment-mandate/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
ACCEPT_REASON = "mandate_chain_holds"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
MANDATE_DOMAIN = b"agent-payment-mandate/v1:mandate:"
RECEIPT_DOMAIN = b"agent-payment-mandate/v1:receipt:"
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-agent-payment-mandate"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-agent-payment-mandate"
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def canon(value: object) -> bytes:
    """The bytes a digest in a record is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_of(value: object) -> str:
    return _sha(canon(value))


def _get(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def default_policy(root: Path | None = None) -> dict[str, Any]:
    """The relying-party policy the corpus publishes for its synthetic keys."""
    return json.loads(((root or ROOT) / "policy.json").read_text(encoding="utf-8"))


def _unsigned(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    sig = _get(r, "mandate.signature")
    return not (
        isinstance(sig, dict)
        and sig.get("key_id")
        and HEX128.match(str(sig.get("value", "")))
    )


def _sig_ok(keys: Any, sig: Any, message: bytes) -> bool:
    """True only when the signature names a key the relying party pinned and verifies under it."""
    if not isinstance(keys, dict) or not isinstance(sig, dict):
        return False
    key_hex, value = keys.get(sig.get("key_id")), str(sig.get("value", ""))
    if not isinstance(key_hex, str) or not HEX64.match(key_hex) or not HEX128.match(value):
        return False
    return ed25519_verify(bytes.fromhex(key_hex), message, bytes.fromhex(value))


def mandate_message(r: dict[str, Any]) -> bytes:
    """What the issuer signs: the mandate digest, domain-separated."""
    return MANDATE_DOMAIN + str(_get(r, "mandate.digest")).encode("ascii", "replace")


def receipt_message(r: dict[str, Any]) -> bytes:
    """What the settlement witness signs: the receipt minus its signature, domain-separated."""
    receipt = _get(r, "receipt")
    body = {k: v for k, v in receipt.items() if k != "signature"} if isinstance(receipt, dict) else {}
    return RECEIPT_DOMAIN + canon(body)


def _mandate_signature_invalid(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    return not _sig_ok(policy.get("issuer_keys"), _get(r, "mandate.signature"), mandate_message(r))


def _receipt_signer_not_witness(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    sig = _get(r, "receipt.signature")
    witnesses = policy.get("witness_keys")
    return not (isinstance(sig, dict) and isinstance(witnesses, dict)
                and sig.get("key_id") in witnesses)


def _receipt_signature_invalid(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    return not _sig_ok(policy.get("witness_keys"), _get(r, "receipt.signature"), receipt_message(r))


def _digest_mismatch(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "mandate.digest") != digest_of(_get(r, "mandate.terms")))


def _not_bound(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "credential.mandate_digest") != _get(r, "mandate.digest"))


def _expired(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return str(_get(r, "execution.executed_at")) > str(_get(r, "mandate.terms.expires_at"))


def _over_limit(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return int(_get(r, "execution.amount_minor")) > int(_get(r, "mandate.terms.max_amount_minor"))


def _currency(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.currency") != _get(r, "mandate.terms.currency"))


def _merchant(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.merchant") != _get(r, "mandate.terms.merchant"))


def _token_mismatch(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.token_id") != _get(r, "credential.token_id"))


def _replayed(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "credential.single_use")) and (
        _get(r, "execution.token_id") in (_get(r, "credential.consumed_token_ids") or [])
    )


def _receipt_unbound(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(
        _get(r, "receipt.mandate_digest") != _get(r, "mandate.digest")
        or _get(r, "receipt.execution_digest") != digest_of(_get(r, "execution"))
    )


def _post_checkout_missing(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    required = set(_get(r, "post_checkout.required") or [])
    return not required <= set(_get(r, "post_checkout.recorded") or [])


def _signing_key(r: dict[str, Any]) -> tuple[str, dict[str, Any] | None] | None:
    """The signing time and the key-history entry for the signing key.

    None when the record states no signing time or carries no key history: the key
    rules then make no statement, so records without key history are judged as before.
    """
    signed_at = _get(r, "mandate.signature.signed_at")
    keys = _get(r, "key_history.keys")
    if not signed_at or not isinstance(keys, list):
        return None
    key_id = _get(r, "mandate.signature.key_id")
    entry = next((k for k in keys if isinstance(k, dict) and k.get("key_id") == key_id), None)
    return str(signed_at), entry


def _key_unknown(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    found = _signing_key(r)
    return found is not None and found[1] is None


def _key_not_yet_valid(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    found = _signing_key(r)
    return found is not None and found[1] is not None and found[0] < str(found[1]["valid_from"])


def _key_rotated_out(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    found = _signing_key(r)
    return (
        found is not None
        and found[1] is not None
        and found[1].get("valid_until") is not None
        and found[0] >= str(found[1]["valid_until"])
    )


def _key_revoked(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    found = _signing_key(r)
    return (
        found is not None
        and found[1] is not None
        and found[1].get("revoked_effective_from") is not None
        and found[0] >= str(found[1]["revoked_effective_from"])
    )


CHECKS: tuple[tuple[str, Callable[[dict[str, Any], dict[str, Any]], bool]], ...] = (
    ("mandate_unsigned", _unsigned),
    ("mandate_digest_mismatch", _digest_mismatch),
    ("credential_not_bound_to_mandate", _not_bound),
    ("mandate_expired", _expired),
    ("amount_over_limit", _over_limit),
    ("currency_mismatch", _currency),
    ("merchant_mismatch", _merchant),
    ("token_not_the_executed_token", _token_mismatch),
    ("single_use_token_replayed", _replayed),
    ("receipt_not_bound_to_execution", _receipt_unbound),
    ("post_checkout_action_missing", _post_checkout_missing),
    ("signing_key_unknown", _key_unknown),
    ("signing_key_not_yet_valid", _key_not_yet_valid),
    ("signing_key_rotated_out", _key_rotated_out),
    ("signing_key_revoked", _key_revoked),
    ("mandate_signature_invalid", _mandate_signature_invalid),
    ("receipt_signer_not_witness", _receipt_signer_not_witness),
    ("receipt_signature_invalid", _receipt_signature_invalid),
)

RULES = tuple(code for code, _ in CHECKS)


def decide(
    record: dict[str, Any],
    skip: frozenset[str] = frozenset(),
    policy: dict[str, Any] | None = None,
) -> dict[str, str]:
    """The reference reader's decision: the first rule that fires, else accepted.

    ``policy`` is the relying party's trust root; when omitted, the corpus's published policy.
    A ``policy`` member inside the record is never read: the producer cannot pick its own keys.
    """
    trusted = default_policy() if policy is None else policy
    for code, fires in CHECKS:
        if code not in skip and fires(record, trusted):
            return {"decision": REJECTED, "reason": code}
    return {"decision": ACCEPTED, "reason": ACCEPT_REASON}


def verify(
    case_path: Path,
    skip: frozenset[str] = frozenset(),
    policy: dict[str, Any] | None = None,
) -> dict[str, str]:
    return decide(strictjson.loads(case_path.read_text(encoding="utf-8")), skip, policy)


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
    ids = {entry["id"] for entry in entries}
    if not entries or len(ids) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != ids:
        return [], "case directories do not match manifest"
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        if entry["expected"]["decision"] != REJECTED:
            continue
        twin = by_id.get(entry.get("twin", ""))
        if twin is None or twin["expected"]["decision"] != ACCEPTED:
            return [], f"{entry['id']}: a rejected member must name an accepted twin"
        if entry["expected"]["reason"] not in RULES:
            return [], f"{entry['id']}: refusal code is not a rule this reader applies"
    return entries, None


def _external_answer(
    command: list[str], case_path: Path, policy_path: Path
) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json", "--policy", str(policy_path)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
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
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader.

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
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "case.json", skip, default_policy(root))
        else:
            ran, observed = _external_answer(command, directory / "case.json", root / "policy.json")
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
        "suite": SUITE,
        "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {
            "vectors": total,
            "conform": total - len(errors),
            "fail": len(errors),
            "suiteRefusals": 0,
        },
        "failures": errors,
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    parser.add_argument(
        "--policy", help="the relying party's trust root (default: the corpus policy.json)"
    )
    args = parser.parse_args(argv)
    if args.case:
        policy = (
            json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
        )
        answer = verify(Path(args.case), policy=policy)
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
