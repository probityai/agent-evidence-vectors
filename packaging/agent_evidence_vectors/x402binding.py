"""x402 payment binding: the reference reader for the `x402-payment-binding/v1` corpus.

One x402 evidence record is judged twice. The authorization verdict asks whether the
record identifies one EIP-3009 authorization: network, asset contract, payer and
nonce together. The settlement verdict asks whether a chain read of that contract
on that network identifies the Transfer log that settled the authorization. A record
can identify its authorization while its settlement stays indeterminate (case C), so
one decision with one reason cannot answer a case here.

Each verdict is one of the four states of the Evidence Chain RFP (verified,
contradicted, indeterminate, not_evaluated) with the code of the first rule that
fired in its table, or the accept code when none did. Network identifiers are kept as
served and compared after mapping: a CAIP-2 identifier names itself, an x402 v1 name
maps through the table in the corpus profile, any other identifier is unknown.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object ``{"authorization": {"state", "reason"}, "settlement": {"state", "reason"}}``
and exits 0 when both verdicts are verified, 1 when either is contradicted, and 2
otherwise.
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

from agent_evidence_vectors import strictjson

SUITE = "x402-payment-binding/v1"
VERIFIED, CONTRADICTED = "verified", "contradicted"
INDETERMINATE, NOT_EVALUATED = "indeterminate", "not_evaluated"
STATES = (VERIFIED, CONTRADICTED, INDETERMINATE, NOT_EVALUATED)
AUTH_OK, SETTLE_OK = "authorization_identified", "transfer_identified"
VERDICTS = ("authorization", "settlement")
CAIP2 = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-x402-payment-binding"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-x402-payment-binding"
)

#: x402 v1 network names and their EVM chain ids, at the x402 commit the manifest pins
#: (python/x402/mechanisms/evm/v1/constants.py). The corpus profile carries the same
#: table, and a test holds the two equal.
V1_CHAIN_IDS = {
    "base": 8453,
    "base-sepolia": 84532,
    "ethereum": 1,
    "polygon": 137,
    "polygon-amoy": 80002,
    "avalanche": 43114,
    "avalanche-fuji": 43113,
    "abstract": 2741,
    "abstract-testnet": 11124,
    "iotex": 4689,
    "sei": 1329,
    "sei-testnet": 1328,
    "peaq": 3338,
    "story": 1514,
    "educhain": 41923,
    "skale-base-sepolia": 324705682,
    "megaeth": 4326,
    "monad": 143,
    "monad-testnet": 10143,
    "stable": 988,
    "stable-testnet": 2201,
    "celo": 42220,
    "flare": 14,
    "hemi": 43111,
    "hemi-testnet": 743111,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _get(record: Any, path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def network_id(value: object) -> str | None:
    """The chain a served network identifier names, or None when it names none."""
    if not isinstance(value, str):
        return None
    if CAIP2.match(value):
        return value
    chain = V1_CHAIN_IDS.get(value)
    return None if chain is None else f"eip155:{chain}"


def _same(a: object, b: object) -> bool:
    """Equal, comparing EVM hex strings without regard to letter case."""
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return a == b


def _kind(r: Any) -> Any:
    return _get(r, "binding.kind")


def _bound_network(r: Any) -> Any:
    if _kind(r) == "accepted_option":
        return _get(r, "offer.accepted.network")
    return _get(r, "binding.authorization.network")


def _logs(r: Any) -> list[dict[str, Any]]:
    logs = _get(r, "chain_read.logs")
    return [log for log in logs if isinstance(log, dict)] if isinstance(logs, list) else []


def _asset_logs(r: Any, event: str) -> list[dict[str, Any]]:
    asset = _get(r, "binding.authorization.asset") or _get(r, "offer.accepted.asset")
    return [g for g in _logs(r) if g.get("event") == event and _same(g.get("address"), asset)]


def _fits_option(r: Any, log: dict[str, Any]) -> bool:
    return _same(log.get("to"), _get(r, "offer.accepted.payTo")) and _same(
        log.get("value"), _get(r, "offer.accepted.amount")
    )


def _read_of_bound_network(r: Any) -> bool:
    bound = network_id(_bound_network(r))
    return bound is not None and bound == network_id(_get(r, "chain_read.network"))


def _read_ok(r: Any) -> bool:
    return _get(r, "chain_read.status") == "ok" and _read_of_bound_network(r)


# Authorization rules, in order.


def _scope_incomplete(r: Any) -> bool:
    if _kind(r) == "accepted_option":
        return False
    scope = _get(r, "binding.authorization")
    fields = ("network", "asset", "payer", "nonce")
    return _kind(r) != "authorization" or not all(_get(scope, f) for f in fields)


def _network_unknown(r: Any) -> bool:
    named = [_bound_network(r)]
    if _get(r, "binding.settlement") is not None:
        named.append(_get(r, "binding.settlement.network"))
    return any(network_id(n) is None for n in named)


def _binding_not_record_authorization(r: Any) -> bool:
    if _kind(r) != "authorization":
        return False
    bound = network_id(_get(r, "binding.authorization.network"))
    pairs = [
        (bound, network_id(_get(r, "offer.accepted.network"))),
        (_get(r, "binding.authorization.asset"), _get(r, "offer.accepted.asset")),
    ]
    if _get(r, "payment.authorization") is not None:
        pairs += [
            (_get(r, "binding.authorization.payer"), _get(r, "payment.authorization.from")),
            (_get(r, "binding.authorization.nonce"), _get(r, "payment.authorization.nonce")),
        ]
    if _get(r, "binding.settlement") is not None:
        pairs.append((bound, network_id(_get(r, "binding.settlement.network"))))
    return not all(_same(a, b) for a, b in pairs)


def _option_fits_more_than_one(r: Any) -> bool:
    if _kind(r) != "accepted_option" or not _read_ok(r):
        return False
    return sum(_fits_option(r, g) for g in _asset_logs(r, "Transfer")) > 1


def _option_only(r: Any) -> bool:
    return _kind(r) == "accepted_option"


AUTHORIZATION_CHECKS: tuple[tuple[str, str, Callable[[Any], bool]], ...] = (
    ("authorization_scope_incomplete", INDETERMINATE, _scope_incomplete),
    ("binding_network_unknown", INDETERMINATE, _network_unknown),
    ("binding_not_record_authorization", CONTRADICTED, _binding_not_record_authorization),
    ("option_fits_more_than_one_payment", INDETERMINATE, _option_fits_more_than_one),
    ("bound_by_accepted_option_only", INDETERMINATE, _option_only),
)


# Settlement rules, in order. Each is handed the record and the authorization verdict.


def _event_for(r: Any, event: str) -> dict[str, Any] | None:
    payer, nonce = _get(r, "binding.authorization.payer"), _get(r, "binding.authorization.nonce")
    for log in _asset_logs(r, event):
        if _same(log.get("authorizer"), payer) and _same(log.get("nonce"), nonce):
            return log
    return None


def _state_used(r: Any) -> bool | None:
    """authorizationState(payer, nonce) at the read's head, or None if not read for it."""
    state = _get(r, "chain_read.authorization_state")
    if not isinstance(state, dict):
        return None
    if not (
        _same(state.get("authorizer"), _get(r, "binding.authorization.payer"))
        and _same(state.get("nonce"), _get(r, "binding.authorization.nonce"))
    ):
        return None
    used = state.get("used")
    return used if isinstance(used, bool) else None


def _past_valid_before(r: Any) -> bool:
    before = _get(r, "payment.authorization.validBefore")
    head = _get(r, "chain_read.head.timestamp")
    if not (isinstance(before, str) and before.isdigit()) or type(head) is not int:
        return False
    return _get(r, "chain_read.head.finalized") is True and head >= int(before)


def _identified_transfer(r: Any) -> dict[str, Any] | None:
    used = _event_for(r, "AuthorizationUsed") or {}
    tx = used.get("transaction")
    index = _get(r, "binding.settlement.log_index")
    if index is not None:
        for log in _logs(r):
            if _same(log.get("transaction"), tx) and log.get("log_index") == index:
                return log
        return None
    transfers = [g for g in _asset_logs(r, "Transfer") if _same(g.get("transaction"), tx)]
    return transfers[0] if len(transfers) == 1 else None


def _transfer_count(r: Any) -> int:
    tx = (_event_for(r, "AuthorizationUsed") or {}).get("transaction")
    return sum(_same(g.get("transaction"), tx) for g in _asset_logs(r, "Transfer"))


def _transfer_not_terms(r: Any) -> bool:
    log = _identified_transfer(r)
    if log is None:
        return True
    asset = _get(r, "binding.authorization.asset")
    return not (
        log.get("event") == "Transfer"
        and _same(log.get("address"), asset)
        and _same(log.get("from"), _get(r, "binding.authorization.payer"))
        and _same(log.get("to"), _get(r, "offer.accepted.payTo"))
        and _same(log.get("value"), _get(r, "offer.accepted.amount"))
    )


def _other_transaction(r: Any) -> bool:
    named = _get(r, "binding.settlement.transaction")
    used = _event_for(r, "AuthorizationUsed")
    return used is not None and named is not None and not _same(named, used.get("transaction"))


SETTLEMENT_CHECKS: tuple[tuple[str, str, Callable[[Any, dict[str, str]], bool]], ...] = (
    ("authorization_not_identified", INDETERMINATE, lambda r, a: a["state"] != VERIFIED),
    ("no_chain_read", NOT_EVALUATED, lambda r, a: _get(r, "chain_read") is None),
    ("chain_read_failed", INDETERMINATE, lambda r, a: _get(r, "chain_read.status") != "ok"),
    ("chain_read_not_bound_network", INDETERMINATE,
     lambda r, a: not _read_of_bound_network(r)),
    ("authorization_canceled", CONTRADICTED,
     lambda r, a: _event_for(r, "AuthorizationCanceled") is not None),
    ("authorization_expired_unused", CONTRADICTED,
     lambda r, a: _event_for(r, "AuthorizationUsed") is None and _state_used(r) is False
     and _past_valid_before(r)),
    ("authorization_not_yet_used", INDETERMINATE,
     lambda r, a: _event_for(r, "AuthorizationUsed") is None and _state_used(r) is False),
    ("authorization_use_not_read", INDETERMINATE,
     lambda r, a: _event_for(r, "AuthorizationUsed") is None),
    ("transaction_did_not_use_authorization", CONTRADICTED, lambda r, a: _other_transaction(r)),
    ("transaction_carries_more_than_one_transfer", INDETERMINATE,
     lambda r, a: _get(r, "binding.settlement.log_index") is None and _transfer_count(r) > 1),
    ("transfer_not_authorization_terms", CONTRADICTED, lambda r, a: _transfer_not_terms(r)),
)  # fmt: skip

RULES = tuple(code for code, _, _ in AUTHORIZATION_CHECKS) + tuple(
    code for code, _, _ in SETTLEMENT_CHECKS
)
STATE_OF = {code: state for code, state, _ in (*AUTHORIZATION_CHECKS, *SETTLEMENT_CHECKS)}


def decide(record: Any, skip: frozenset[str] = frozenset()) -> dict[str, dict[str, str]]:
    """Both verdicts: the first rule that fires in each table, else verified."""
    authorization = {"state": VERIFIED, "reason": AUTH_OK}
    for code, state, fires in AUTHORIZATION_CHECKS:
        if code not in skip and fires(record):
            authorization = {"state": state, "reason": code}
            break
    settlement = {"state": VERIFIED, "reason": SETTLE_OK}
    for code, state, fires_after in SETTLEMENT_CHECKS:
        if code not in skip and fires_after(record, authorization):
            settlement = {"state": state, "reason": code}
            break
    return {"authorization": authorization, "settlement": settlement}


def exit_code(answer: dict[str, Any]) -> int:
    """0 when both verdicts are verified, 1 when either is contradicted, else 2."""
    states = [_get(answer, f"{v}.state") for v in VERDICTS]
    if all(s == VERIFIED for s in states):
        return 0
    return 1 if CONTRADICTED in states else 2


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, dict[str, str]]:
    return decide(strictjson.loads(case_path.read_text(encoding="utf-8")), skip)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _verdict_error(entry: dict[str, Any]) -> str | None:
    expected = entry.get("expected")
    if not isinstance(expected, dict) or set(expected) != set(VERDICTS):
        return f"{entry['id']}: expected must carry exactly {list(VERDICTS)}"
    for name, accept in zip(VERDICTS, (AUTH_OK, SETTLE_OK), strict=True):
        state, reason = _get(expected, f"{name}.state"), _get(expected, f"{name}.reason")
        if state == VERIFIED and reason == accept:
            continue
        if STATE_OF.get(str(reason)) != state:
            return f"{entry['id']}: {name} {state}/{reason} is not a rule this reader applies"
    return None


def _accepted(entry: dict[str, Any]) -> bool:
    return all(_get(entry, f"expected.{v}.state") == VERIFIED for v in VERDICTS)


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
        error = _verdict_error(entry)
        if error:
            return [], error
        if _accepted(entry):
            continue
        twin = by_id.get(entry.get("twin", ""))
        if twin is None or not _accepted(twin):
            return [], f"{entry['id']}: a member not verified twice must name an accepted twin"
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
        answer = strictjson.loads(result.stdout)
        observed = {
            v: {"state": answer[v]["state"], "reason": answer[v]["reason"]} for v in VERDICTS
        }
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no two verdicts (exit {result.returncode})"
    if exit_code(observed) != result.returncode:
        return True, f"exit {result.returncode} disagrees with the verdicts {observed}"
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
    parser.add_argument("--json", action="store_true", help="print the verdicts as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        if args.json:
            print(json.dumps(answer, sort_keys=True))
        else:
            for v in VERDICTS:
                print(f"{v} {answer[v]['state']} {answer[v]['reason']}")
        return exit_code(answer)
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
