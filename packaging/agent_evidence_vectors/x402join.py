"""x402 evidence join: the reference reader for the `x402-evidence-join/v1` corpus.

One x402 evidence package is judged from its own record: the seller key bound to the
resource domain, the signed offer, the payment construction, the facilitator's settlement
response against a ledger read, the delivered body, the receipt that binds them and the
fulfilment evaluation. The reader recomputes the offer digest and the delivery digest
rather than trusting the fields that claim them.

Every rule below has a code. A record is accepted only when none of the rules fires; any
other record names the first rule that fired, in the order listed in ``RULES``. A rule in
``INDETERMINATE_RULES`` fires when the evidence needed to establish the join is absent and
yields ``indeterminate``; every other rule fires when the evidence present contradicts the
join and yields ``rejected``. A fulfilment that was not evaluated is visible in the record
and does not block acceptance. The fixtures are synthetic.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object carrying ``decision`` and ``reason``, and exits 0 for ``accepted``, 1 for
``rejected`` and 2 for ``indeterminate``.
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
from urllib.parse import urlsplit

SUITE = "x402-evidence-join/v1"
ACCEPTED, REJECTED, INDETERMINATE = "accepted", "rejected", "indeterminate"
EXIT_FOR = {ACCEPTED: 0, REJECTED: 1, INDETERMINATE: 2}
ACCEPT_REASON = "join_holds"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-x402-evidence-join"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-x402-evidence-join"
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


def _host(url: object) -> str:
    try:
        return urlsplit(str(url)).hostname or ""
    except ValueError:
        return ""


def _seller_key_unbound(r: dict[str, Any]) -> bool:
    keys = _get(r, "seller.key_ids") or []
    return bool(
        _get(r, "offer.signature.key_id") not in keys
        or _get(r, "receipt.key_id") not in keys
        or not _get(r, "seller.domain")
        or _get(r, "seller.domain") != _host(_get(r, "offer.resource.url"))
    )


def _offer_digest_mismatch(r: dict[str, Any]) -> bool:
    covered = {"accepted": _get(r, "offer.accepted"), "resource": _get(r, "offer.resource")}
    digest = _get(r, "offer.digest")
    return bool(
        digest != digest_of(covered)
        or _get(r, "offer.signature.value_sha256") != _sha(str(digest).encode())
    )


def _payment_not_for_offer(r: dict[str, Any]) -> bool:
    return bool(_get(r, "payment.offer_digest") != _get(r, "offer.digest"))


def _payer_not_signer(r: dict[str, Any]) -> bool:
    payer = _get(r, "payment.authorization.from")
    return bool(
        not payer
        or _get(r, "payment.signature.signer") != payer
        or _get(r, "settlement.facilitator.payer") != payer
    )


def _payee_not_offer_payee(r: dict[str, Any]) -> bool:
    return bool(_get(r, "payment.authorization.to") != _get(r, "offer.accepted.payTo"))


def _amount_not_offer_amount(r: dict[str, Any]) -> bool:
    return bool(_get(r, "payment.authorization.value") != _get(r, "offer.accepted.amount"))


def _receipt_names_other_offer(r: dict[str, Any]) -> bool:
    named = _get(r, "receipt.offer_digest")
    return named is not None and named != _get(r, "offer.digest")


def _receipt_offer_unbound(r: dict[str, Any]) -> bool:
    return _get(r, "receipt.offer_digest") is None


def _settlement_reference_missing(r: dict[str, Any]) -> bool:
    return not _get(r, "receipt.transaction") and _get(r, "settlement.ledger") is None


def _settlement_conflict(r: dict[str, Any]) -> bool:
    facilitator = _get(r, "settlement.facilitator.transaction")
    receipt = _get(r, "receipt.transaction")
    if receipt and receipt != facilitator:
        return True
    if _get(r, "settlement.ledger") is None:
        return False
    return bool(
        (_get(r, "settlement.facilitator.success") is True
         and _get(r, "settlement.ledger.status") != "success")
        or _get(r, "settlement.ledger.transaction") != facilitator
    )  # fmt: skip


def _ledger_not_offer_terms(r: dict[str, Any]) -> bool:
    if _get(r, "settlement.ledger") is None:
        return False
    pairs = (
        ("settlement.ledger.network", "offer.accepted.network"),
        ("settlement.ledger.asset", "offer.accepted.asset"),
        ("settlement.ledger.to", "offer.accepted.payTo"),
        ("settlement.ledger.value", "offer.accepted.amount"),
        ("settlement.ledger.from", "payment.authorization.from"),
    )
    return any(_get(r, a) != _get(r, b) for a, b in pairs)


def _facilitator_only(r: dict[str, Any]) -> bool:
    return _get(r, "settlement.ledger") is None


def _delivery_digest_mismatch(r: dict[str, Any]) -> bool:
    declared = _get(r, "delivery.body_sha256")
    return bool(
        declared != _sha(str(_get(r, "delivery.body")).encode())
        or _get(r, "receipt.delivery_digest") != declared
    )


def _fulfilment_not_met(r: dict[str, Any]) -> bool:
    if _get(r, "fulfilment.evaluated") is not True:
        return False
    return bool(
        not HEX64.match(str(_get(r, "fulfilment.criteria_digest") or ""))
        or _get(r, "fulfilment.outcome") != "met"
    )


CHECKS: tuple[tuple[str, Callable[[dict[str, Any]], bool]], ...] = (
    ("seller_key_not_domain_bound", _seller_key_unbound),
    ("offer_digest_mismatch", _offer_digest_mismatch),
    ("payment_not_for_offer", _payment_not_for_offer),
    ("payer_not_authorization_signer", _payer_not_signer),
    ("payee_not_offer_payee", _payee_not_offer_payee),
    ("amount_not_offer_amount", _amount_not_offer_amount),
    ("receipt_names_other_offer", _receipt_names_other_offer),
    ("receipt_offer_unbound", _receipt_offer_unbound),
    ("settlement_reference_missing", _settlement_reference_missing),
    ("settlement_conflict", _settlement_conflict),
    ("ledger_transfer_not_offer_terms", _ledger_not_offer_terms),
    ("settlement_asserted_by_facilitator_only", _facilitator_only),
    ("delivery_digest_mismatch", _delivery_digest_mismatch),
    ("fulfilment_not_met", _fulfilment_not_met),
)

RULES = tuple(code for code, _ in CHECKS)
INDETERMINATE_RULES = frozenset(
    {
        "receipt_offer_unbound",
        "settlement_reference_missing",
        "settlement_asserted_by_facilitator_only",
    }
)


def decide(record: dict[str, Any], skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision: the first rule that fires, else accepted."""
    for code, fires in CHECKS:
        if code not in skip and fires(record):
            decision = INDETERMINATE if code in INDETERMINATE_RULES else REJECTED
            return {"decision": decision, "reason": code}
    return {"decision": ACCEPTED, "reason": ACCEPT_REASON}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    return decide(json.loads(case_path.read_text(encoding="utf-8")), skip)


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
        decision, reason = entry["expected"]["decision"], entry["expected"]["reason"]
        if decision == ACCEPTED:
            continue
        twin = by_id.get(entry.get("twin", ""))
        if twin is None or twin["expected"]["decision"] != ACCEPTED:
            return [], f"{entry['id']}: a non-accepted member must name an accepted twin"
        if reason not in RULES or (decision == INDETERMINATE) != (reason in INDETERMINATE_RULES):
            return [], f"{entry['id']}: {decision}/{reason} is not a rule this reader applies"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json"],
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
            ran, observed = True, verify(directory / "case.json", skip)
        else:
            ran, observed = _external_answer(command, directory / "case.json")
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
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
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
