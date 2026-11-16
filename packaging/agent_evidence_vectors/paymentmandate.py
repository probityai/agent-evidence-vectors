"""Agent payment mandate: the reference reader for the `agent-payment-mandate/v1` corpus.

A dispute evidence pack for an agent-initiated payment is judged from its own record: the
mandate the user signed, the credential the agent presented, the charge that ran, and the
receipt that binds them. The reader verifies the issuer's Ed25519 signature on the mandate, the
mandated agent's Ed25519 signature on the charge, and the settlement witness's Ed25519 signature
on the receipt. The issuer and witness keys come from the relying party's pinned policy; the
agent key comes from the issuer-signed terms (the mandate names the one agent it delegates to).
A key or a policy the record carries for itself is never read. It recomputes the mandate digest
and the execution digest rather than trusting the fields that claim them, and refuses a charge
that leaves the mandate in amount, currency, merchant, rail, time or token, a charge run by an
agent the mandate does not name, a single-use mandate settled more than once, and an evidence
pack whose post-checkout actions are not all recorded.

Every limit a holder could loosen lives in the signed terms: whether the mandate is single-use,
which rails it may be spent on, when it was issued and when it expires, which agent may use it,
and which post-checkout actions must be recorded. Unsigned parts of the record may add to them
and never relax them.

A record whose shape could be read two ways is refused before anything else is judged: a
duplicate member, an amount that is not a positive JSON integer, a timestamp that is not an
RFC 3339 date-time with a zone, or a missing limit.

A pack (``agent-payment-mandate-pack/v1``) holds several records. Each is judged alone, and the
pack is refused when one single-use mandate or token settled in more than one of them, which is
how a charge replayed across rails shows: each rail's witness honestly counts its own first use.

Every rule below is a refusal code. A record is accepted only when none of the
rules fires; a rejected record names the first rule that fired, in the order
listed in ``RULES``. A rule that cannot be evaluated fires. The fixtures are
synthetic: no real merchant, patient, account or server appears in any of them.

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
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors.w3cintake import ed25519_verify

SUITE = "agent-payment-mandate/v1"
PACK_SCHEMA = "agent-payment-mandate-pack/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1}
ACCEPT_REASON = "mandate_chain_holds"
MALFORMED = "record_malformed"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
MANDATE_DOMAIN = b"agent-payment-mandate/v1:mandate:"
RECEIPT_DOMAIN = b"agent-payment-mandate/v1:receipt:"
AGENT_DOMAIN = b"agent-payment-mandate/v1:agent:"
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-agent-payment-mandate"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-agent-payment-mandate"
)


class DuplicateMember(ValueError):
    """A JSON object names one member twice; two parsers may read it two ways."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def canon(value: object) -> bytes:
    """The bytes a digest in a record is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_of(value: object) -> str:
    return _sha(canon(value))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise DuplicateMember(key)
        out[key] = value
    return out


def load_record(text: str) -> dict[str, Any]:
    """Parse a case, refusing a duplicate member (``DuplicateMember``)."""
    return json.loads(text, object_pairs_hook=_no_duplicates)


def _get(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _time(value: Any) -> datetime | None:
    """An RFC 3339 date-time with a zone, as an aware datetime; anything else is None."""
    if not isinstance(value, str) or not RFC3339.match(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def default_policy(root: Path | None = None) -> dict[str, Any]:
    """The relying-party policy the corpus publishes for its synthetic keys."""
    return json.loads(((root or ROOT) / "policy.json").read_text(encoding="utf-8"))


def _malformed(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    terms = _get(r, "mandate.terms")
    agent = _get(r, "mandate.terms.agent")
    return not (
        isinstance(terms, dict)
        and _positive_int(terms.get("max_amount_minor"))
        and _positive_int(_get(r, "execution.amount_minor"))
        and _time(terms.get("issued_at")) is not None
        and _time(terms.get("expires_at")) is not None
        and _time(_get(r, "execution.executed_at")) is not None
        and isinstance(agent, dict)
        and isinstance(agent.get("key_id"), str)
        and HEX64.match(str(agent.get("public_key", "")))
        and isinstance(_get(r, "execution.agent_key_id"), str)
        and _str_list(terms.get("rails"))
        and bool(terms.get("rails"))
        and isinstance(_get(r, "execution.rail"), str)
        and isinstance(terms.get("single_use"), bool)
        and _str_list(terms.get("post_checkout_required"))
        and (not terms.get("single_use") or _positive_int(_get(r, "receipt.token_use_seq")))
    )


def _unsigned(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    sig = _get(r, "mandate.signature")
    return not (
        isinstance(sig, dict) and sig.get("key_id") and HEX128.match(str(sig.get("value", "")))
    )


def _verifies(key_hex: Any, sig: Any, message: bytes) -> bool:
    if not isinstance(key_hex, str) or not HEX64.match(key_hex) or not isinstance(sig, dict):
        return False
    value = str(sig.get("value", ""))
    if not HEX128.match(value):
        return False
    return ed25519_verify(bytes.fromhex(key_hex), message, bytes.fromhex(value))


def _sig_ok(keys: Any, sig: Any, message: bytes) -> bool:
    """True only when the signature names a key the relying party pinned and verifies under it."""
    if not isinstance(keys, dict) or not isinstance(sig, dict):
        return False
    return _verifies(keys.get(sig.get("key_id")), sig, message)


def mandate_message(r: dict[str, Any]) -> bytes:
    """What the issuer signs: the mandate digest, domain-separated."""
    return MANDATE_DOMAIN + str(_get(r, "mandate.digest")).encode("ascii", "replace")


def agent_message(r: dict[str, Any]) -> bytes:
    """What the mandated agent signs: the mandate digest and the charge it ran."""
    execution = _get(r, "execution")
    body = (
        {k: v for k, v in execution.items() if k != "agent_signature"}
        if isinstance(execution, dict)
        else {}
    )
    digest = str(_get(r, "mandate.digest")).encode("ascii", "replace")
    return AGENT_DOMAIN + digest + b":" + canon(body)


def receipt_message(r: dict[str, Any]) -> bytes:
    """What the settlement witness signs: the receipt minus its signature, domain-separated."""
    receipt = _get(r, "receipt")
    if not isinstance(receipt, dict):
        return RECEIPT_DOMAIN + canon({})
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return RECEIPT_DOMAIN + canon(body)


def _mandate_signature_invalid(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    return not _sig_ok(policy.get("issuer_keys"), _get(r, "mandate.signature"), mandate_message(r))


def _digest_mismatch(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "mandate.digest") != digest_of(_get(r, "mandate.terms")))


def _not_bound(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "credential.mandate_digest") != _get(r, "mandate.digest"))


def _credential_widens(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    """The unsigned credential may not relax the signed single-use term."""
    return bool(_get(r, "credential.single_use") != _get(r, "mandate.terms.single_use"))


def _other_agent(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    """The charge was run by an agent the mandate does not name; delegation ends there."""
    return bool(_get(r, "execution.agent_key_id") != _get(r, "mandate.terms.agent.key_id"))


def _agent_proof_invalid(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    sig = _get(r, "execution.agent_signature")
    agent = _get(r, "mandate.terms.agent")
    if not isinstance(sig, dict) or not isinstance(agent, dict):
        return True
    if sig.get("key_id") != agent.get("key_id"):
        return True
    return not _verifies(agent.get("public_key"), sig, agent_message(r))


def _before_mandate(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    issued, ran = _time(_get(r, "mandate.terms.issued_at")), _time(_get(r, "execution.executed_at"))
    return issued is None or ran is None or ran < issued


def _expired(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    ran, ends = _time(_get(r, "execution.executed_at")), _time(_get(r, "mandate.terms.expires_at"))
    return ran is None or ends is None or ran > ends


def _over_limit(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    amount, ceiling = _get(r, "execution.amount_minor"), _get(r, "mandate.terms.max_amount_minor")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (amount, ceiling)):
        return True
    return bool(amount > ceiling)


def _currency(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.currency") != _get(r, "mandate.terms.currency"))


def _merchant(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.merchant") != _get(r, "mandate.terms.merchant"))


def _rail(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    rails = _get(r, "mandate.terms.rails")
    return not isinstance(rails, list) or _get(r, "execution.rail") not in rails


def _token_mismatch(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.token_id") != _get(r, "credential.token_id"))


def _replayed(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    """A single-use mandate settles once: token not consumed, and the witness counted use 1."""
    if not _get(r, "mandate.terms.single_use"):
        return False
    consumed = _get(r, "credential.consumed_token_ids") or []
    return _get(r, "execution.token_id") in consumed or _get(r, "receipt.token_use_seq") != 1


def _receipt_unbound(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    return bool(
        _get(r, "receipt.mandate_digest") != _get(r, "mandate.digest")
        or _get(r, "receipt.execution_digest") != digest_of(_get(r, "execution"))
    )


def _receipt_signer_not_witness(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    sig = _get(r, "receipt.signature")
    witnesses = policy.get("witness_keys")
    return not (
        isinstance(sig, dict) and isinstance(witnesses, dict) and sig.get("key_id") in witnesses
    )


def _receipt_signature_invalid(r: dict[str, Any], policy: dict[str, Any]) -> bool:
    return not _sig_ok(policy.get("witness_keys"), _get(r, "receipt.signature"), receipt_message(r))


def _post_checkout_missing(r: dict[str, Any], _policy: dict[str, Any]) -> bool:
    """Required actions are the signed terms' list plus any the record adds; never fewer."""
    signed = _get(r, "mandate.terms.post_checkout_required")
    required = set(signed if isinstance(signed, list) else []) | set(
        _get(r, "post_checkout.required") or []
    )
    return not required <= set(_get(r, "post_checkout.recorded") or [])


CHECKS: tuple[tuple[str, Callable[[dict[str, Any], dict[str, Any]], bool]], ...] = (
    (MALFORMED, _malformed),
    ("mandate_unsigned", _unsigned),
    ("mandate_signature_invalid", _mandate_signature_invalid),
    ("mandate_digest_mismatch", _digest_mismatch),
    ("credential_not_bound_to_mandate", _not_bound),
    ("credential_widens_mandate", _credential_widens),
    ("agent_not_the_mandated_agent", _other_agent),
    ("agent_proof_invalid", _agent_proof_invalid),
    ("charge_before_mandate", _before_mandate),
    ("mandate_expired", _expired),
    ("amount_over_limit", _over_limit),
    ("currency_mismatch", _currency),
    ("merchant_mismatch", _merchant),
    ("rail_not_mandated", _rail),
    ("token_not_the_executed_token", _token_mismatch),
    ("single_use_token_replayed", _replayed),
    ("receipt_not_bound_to_execution", _receipt_unbound),
    ("receipt_signer_not_witness", _receipt_signer_not_witness),
    ("receipt_signature_invalid", _receipt_signature_invalid),
    ("post_checkout_action_missing", _post_checkout_missing),
)


def _spent_twice(records: list[dict[str, Any]]) -> bool:
    """One single-use mandate, or one single-use token, settled in two records of the pack."""
    seen: set[tuple[str, str]] = set()
    for r in records:
        if not _get(r, "mandate.terms.single_use"):
            continue
        for key in (
            ("mandate", str(_get(r, "mandate.digest"))),
            ("token", str(_get(r, "execution.token_id"))),
        ):
            if key in seen:
                return True
            seen.add(key)
    return False


PACK_RULE = "mandate_spent_twice"
RULES = (*(code for code, _ in CHECKS), PACK_RULE)


def _decide_one(record: Any, skip: frozenset[str], trusted: dict[str, Any]) -> dict[str, str]:
    if not isinstance(record, dict):
        return {"decision": REJECTED, "reason": MALFORMED}
    for code, fires in CHECKS:
        if code in skip:
            continue
        try:
            fired = fires(record, trusted)
        except (TypeError, ValueError, AttributeError):
            fired = True
        if fired:
            return {"decision": REJECTED, "reason": code}
    return {"decision": ACCEPTED, "reason": ACCEPT_REASON}


def decide(
    record: dict[str, Any],
    skip: frozenset[str] = frozenset(),
    policy: dict[str, Any] | None = None,
) -> dict[str, str]:
    """The reference reader's decision: the first rule that fires, else accepted.

    ``policy`` is the relying party's trust root; when omitted, the corpus's published policy.
    A ``policy`` member inside the record is never read: the producer cannot pick its own keys.
    A pack is judged member by member, then for a single-use mandate settled twice.
    """
    trusted = default_policy() if policy is None else policy
    if isinstance(record, dict) and record.get("schema") == PACK_SCHEMA:
        members = record.get("records")
        if not isinstance(members, list) or len(members) < 2:
            return {"decision": REJECTED, "reason": MALFORMED}
        for member in members:
            answer = _decide_one(member, skip, trusted)
            if answer["decision"] == REJECTED:
                return answer
        if PACK_RULE not in skip and _spent_twice(members):
            return {"decision": REJECTED, "reason": PACK_RULE}
        return {"decision": ACCEPTED, "reason": ACCEPT_REASON}
    return _decide_one(record, skip, trusted)


def verify(
    case_path: Path,
    skip: frozenset[str] = frozenset(),
    policy: dict[str, Any] | None = None,
) -> dict[str, str]:
    text = case_path.read_text(encoding="utf-8")
    try:
        record = load_record(text)
    except DuplicateMember:
        if MALFORMED not in skip:
            return {"decision": REJECTED, "reason": MALFORMED}
        record = json.loads(text)
    return decide(record, skip, policy)


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
        answer = json.loads(result.stdout)
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
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8")) if args.policy else None
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
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
