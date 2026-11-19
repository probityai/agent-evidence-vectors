#!/usr/bin/env python3
"""Write vectors/decision-receipt/manifest.json, the cases the decision_receipt terms are held to.

    python3 scripts/gen_decision_receipt_vectors.py          # write the manifest
    python3 scripts/gen_decision_receipt_vectors.py --check  # fail when it is stale

Each case names a term, the input a verifier is given and what registry.py must derive: a value, or a
refusal with a stable reason. The file is generated; never edit it by hand. Standard library only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors" / "decision-receipt" / "manifest.json"


def _registry():
    spec = importlib.util.spec_from_file_location("vocabulary_registry", ROOT / "registry.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


R = _registry()
H = lambda text: hashlib.sha256(text.encode()).hexdigest()
ZERO = "0" * 64
SIG = "ab" * 64
EMPTY_LIST = H("[]")


def case(cid: str, term: str, polarity: str, inputs: dict, value: str | None, reason: str | None = None) -> dict:
    """One case. ``value`` is the derived value, or None for a refusal, which must give ``reason``."""
    expect = {"refused": value is None, "value": value}
    if reason is not None:
        expect["reason"] = reason
    return {"id": cid, "term": term, "polarity": polarity, "input": inputs, "expect": expect}


def _rec(n: int, previous: str | None) -> dict:
    decision = {"verdict": "allow", "action": f"tool:t{n}", "requestHash": H(f"req{n}")}
    if previous is not None:
        decision["previousReceiptHash"] = previous
    return {"decision": decision}


def _chain(count: int) -> list[dict]:
    records, previous = [], None
    for n in range(count):
        record = _rec(n, previous)
        records.append(record)
        previous = R.receipt_digest(record)
    return records


def _chain_cases() -> list[dict]:
    chain = _chain(4)
    head = {"lastDigest": R.receipt_digest(chain[-1]), "count": 4}
    forked = [*chain[:3], _rec(9, R.receipt_digest(chain[1]))]
    restarted = [*chain[:2], _rec(7, None)]
    return [
        case("chain-intact-with-head-anchor", "receipt_chain_link", "positive", {"records": chain, "anchor": head}, "first"),
        case("chain-intact-no-anchor-end-not-established", "receipt_chain_link", "positive", {"records": chain}, "first"),
        case("chain-starts-mid-chain", "receipt_chain_link", "positive", {"records": chain[1:]}, "linked"),
        case("chain-reset-reads-unchained", "receipt_chain_link", "positive", {"records": restarted}, "unchained"),
        case("chain-duplicate-record", "receipt_chain_link", "negative", {"records": [*chain, chain[3]]}, None, "duplicate-record"),
        case("chain-reordered", "receipt_chain_link", "negative", {"records": [chain[0], chain[2], chain[1], chain[3]]}, None, "chain-order"),
        case("chain-middle-dropped", "receipt_chain_link", "negative", {"records": [chain[0], chain[2], chain[3]]}, None, "chain-link-broken"),
        case("chain-fork", "receipt_chain_link", "negative", {"records": forked}, None, "fork"),
        case("chain-tail-cut-against-anchor", "receipt_chain_link", "negative", {"records": chain[:3], "anchor": head}, None, "head-anchor-mismatch"),
        case("chain-empty-stream", "receipt_chain_link", "negative", {"records": []}, None, "no-decision"),
        case("chain-zero-filled-link", "receipt_chain_link", "negative",
             {"records": [chain[0], {"decision": {**chain[1]["decision"], "previousReceiptHash": ZERO}}]}, None, "previousReceiptHash-zero-filled"),
    ]


def _commitment_cases() -> list[dict]:
    out = []
    for term, key, absent in (("request_commitment", "requestHash", "uncanonicalizable"),
                              ("policy_commitment", "policyDefinitionHash", "not_committed"),
                              ("trust_root_commitment", "trustedRootsHash", "not_committed")):
        out += [
            case(f"{term}-carried", term, "positive", {"decision": {key: H("x")}}, "committed"),
            case(f"{term}-omitted", term, "positive", {"decision": {}}, absent),
            case(f"{term}-zero-filled", term, "negative", {"decision": {key: ZERO}}, None, f"{key}-zero-filled"),
            case(f"{term}-null", term, "negative", {"decision": {key: None}}, None, f"{key}-not-a-sha256"),
            case(f"{term}-empty-string", term, "negative", {"decision": {key: ""}}, None, f"{key}-not-a-sha256"),
            case(f"{term}-matches-held-bytes", term, "positive", {"decision": {key: H("x")}, "bytes": "x"}, "committed"),
            case(f"{term}-differs-from-held-bytes", term, "negative", {"decision": {key: H("x")}, "bytes": "y"}, None, f"{key}-differs-from-the-bytes"),
        ]
    return out


def _revocation_cases() -> list[dict]:
    t = "revocation_list_in_force"
    return [
        case("revocation-versioned", t, "positive", {"decision": {"revocationListHash": H("l"), "revocationListVersion": 7}}, "versioned_list"),
        case("revocation-unversioned", t, "positive", {"decision": {"revocationListHash": H("l")}}, "unversioned_list"),
        case("revocation-no-list-loaded", t, "positive", {"decision": {}}, "no_list_loaded"),
        case("revocation-empty-list-is-not-absent", t, "positive",
             {"decision": {"revocationListHash": EMPTY_LIST, "revocationListVersion": 1}, "bytes": "[]"}, "versioned_list"),
        case("revocation-version-without-digest", t, "negative", {"decision": {"revocationListVersion": 3}}, None, "version-without-digest"),
        case("revocation-zero-filled-digest", t, "negative", {"decision": {"revocationListHash": ZERO}}, None, "revocationListHash-zero-filled"),
        case("revocation-null-digest", t, "negative", {"decision": {"revocationListHash": None}}, None, "revocationListHash-not-a-sha256"),
        case("revocation-null-version", t, "negative", {"decision": {"revocationListHash": H("l"), "revocationListVersion": None}}, None, "revocationListVersion-not-a-count"),
        case("revocation-list-differs-from-published", t, "negative",
             {"decision": {"revocationListHash": H("l")}, "bytes": "other"}, None, "revocationListHash-differs-from-the-bytes"),
    ]


def _possession_cases() -> list[dict]:
    t = "possession_proof"
    return [
        case("possession-allow-bound", t, "positive", {"decision": {"verdict": "allow", "possessionSignature": SIG}}, "bound"),
        case("possession-refusal-without-proof", t, "positive", {"decision": {"verdict": "block"}}, "absent"),
        case("possession-allow-without-proof", t, "negative", {"decision": {"verdict": "allow"}}, None, "allow-without-possession-proof"),
        case("possession-zero-signature", t, "negative", {"decision": {"verdict": "allow", "possessionSignature": "0" * 128}}, None, "possessionSignature-malformed"),
        case("possession-short-signature", t, "negative", {"decision": {"verdict": "allow", "possessionSignature": "ab" * 10}}, None, "possessionSignature-malformed"),
        case("possession-replayed", t, "negative", {"decision": {"verdict": "allow", "possessionSignature": SIG}, "seen": [SIG]}, None, "possession-proof-replayed"),
    ]


def _code_cases() -> list[dict]:
    t = "decision_code"
    return [
        case("code-refusal-canonical", t, "positive", {"decision": {"verdict": "block", "code": "constraint-violation"}}, "constraint-violation"),
        case("code-allow-carries-none", t, "positive", {"decision": {"verdict": "allow"}}, "none"),
        case("code-allow-with-code", t, "negative", {"decision": {"verdict": "allow", "code": "constraint-violation"}}, None, "code-on-allow"),
        case("code-refusal-without-code", t, "negative", {"decision": {"verdict": "halt"}}, None, "refusal-without-code"),
        case("code-free-text", t, "negative", {"decision": {"verdict": "block", "code": "Denied: path /etc/passwd"}}, None, "code-not-canonical"),
        case("code-too-long", t, "negative", {"decision": {"verdict": "block", "code": "a" * 65}}, None, "code-not-canonical"),
        case("code-outside-held-list", t, "negative",
             {"decision": {"verdict": "block", "code": "made-up"}, "known": ["constraint-violation"]}, None, "code-not-in-the-list"),
    ]


def _upstream_cases() -> list[dict]:
    t = "upstream_receipt"
    base = {"provider": "model-router", "generationId": "gen-0001", "recheckUrl": "https://provider.example/generation?id=gen-0001",
            "fact": {"model": "model-a", "status": "completed"}}
    return [
        case("upstream-agrees", t, "positive", {"upstream": base, "fetched": {"model": "model-a", "status": "completed", "extra": 1}}, "agrees"),
        case("upstream-disagrees-on-model", t, "negative", {"upstream": base, "fetched": {"model": "model-b", "status": "completed"}}, "disagrees"),
        case("upstream-disagrees-field-missing", t, "negative", {"upstream": base, "fetched": {"status": "completed"}}, "disagrees"),
        case("upstream-unreachable-no-record", t, "negative", {"upstream": base, "fetched": None}, "unreachable"),
        case("upstream-not-checked", t, "negative", {"upstream": base, "fetched": None, "checked": False}, "not_checked"),
        case("upstream-recheck-url-not-https", t, "negative", {"upstream": {**base, "recheckUrl": "http://provider.example/g"}}, None, "recheckUrl-not-https"),
        case("upstream-generation-id-empty", t, "negative", {"upstream": {**base, "generationId": ""}}, None, "generationId-missing"),
        case("upstream-fact-missing", t, "negative", {"upstream": {k: v for k, v in base.items() if k != "fact"}}, None, "fact-missing"),
    ]


def build() -> dict:
    cases = _commitment_cases() + _revocation_cases() + _chain_cases() + _possession_cases() + _code_cases() + _upstream_cases()
    return {"version": 1, "suite": "decision-receipt", "cases": cases}


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale: run scripts/gen_decision_receipt_vectors.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
