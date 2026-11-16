"""The corpus regenerates byte for byte, every rule is load-bearing, and a verifier
missing any one rule (a mutant) is caught by the corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import paymentmandate  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("paymentmandate_generator", ROOT / "gen_vectors.py")
mutation = _load("paymentmandate_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import paymentmandate as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [
            ROOT / "MANIFEST.json",
            ROOT / "INDEX.md",
            ROOT / "profile.json",
            ROOT / "policy.json",
            *(ROOT / "cases").rglob("*"),
        ]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = paymentmandate.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = paymentmandate.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


@pytest.mark.parametrize("rule", paymentmandate.RULES)
def test_a_mutant_verifier_missing_one_rule_is_caught(tmp_path: Path, rule: str) -> None:
    _, errors = paymentmandate.check(_stub(tmp_path, (rule,)))
    assert errors, f"a verifier without {rule} passed the whole corpus"
    assert any(e.split(":", 1)[0] for e in errors)


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_every_rejected_member_names_an_accepted_twin() -> None:
    entries = json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]
    accepted = {e["id"] for e in entries if e["expected"]["decision"] == "accepted"}
    assert accepted
    for e in entries:
        if e["expected"]["decision"] == "rejected":
            assert e["twin"] in accepted
    assert {
        e["expected"]["reason"] for e in entries if e["expected"]["decision"] == "rejected"
    } == set(paymentmandate.RULES)


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]


def test_a_tampered_case_is_refused(tmp_path: Path) -> None:
    import shutil

    work = tmp_path / "copy"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    target = next((work / "cases").iterdir()) / "case.json"
    target.write_text(target.read_text() + " ", encoding="utf-8")
    _, errors = paymentmandate.check(root=work)
    assert errors


def _case(name: str) -> dict:
    return json.loads((ROOT / "cases" / name / "case.json").read_text())


def test_keyless_holder_cannot_raise_the_ceiling() -> None:
    """Regression for the 15 Nov 2026 counter-example: before the fix this was accepted."""
    r = _case("charge-over-limit")
    r["mandate"]["terms"]["max_amount_minor"] = 10**9
    r["mandate"]["digest"] = paymentmandate.digest_of(r["mandate"]["terms"])
    r["credential"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["mandate_digest"] = r["mandate"]["digest"]
    r["receipt"]["execution_digest"] = paymentmandate.digest_of(r["execution"])
    r["mandate"]["signature"]["value"] = "ab" * 64
    assert paymentmandate.decide(r) == {
        "decision": "rejected",
        "reason": "mandate_signature_invalid",
    }


def test_keyless_holder_cannot_launder_the_charge() -> None:
    """A holder with no agent key breaks the agent's proof over the charge first."""
    r = _case("charge-over-limit")
    r["execution"]["amount_minor"] = r["mandate"]["terms"]["max_amount_minor"]
    r["receipt"]["execution_digest"] = paymentmandate.digest_of(r["execution"])
    assert paymentmandate.decide(r) == {"decision": "rejected", "reason": "agent_proof_invalid"}


def test_the_agent_cannot_launder_the_charge_without_the_witness() -> None:
    """The agent re-signs its own rewritten charge; the witness's receipt no longer verifies."""
    answer = paymentmandate.verify(ROOT / "cases" / "charge-rewritten-after-witness" / "case.json")
    assert answer == {"decision": "rejected", "reason": "receipt_signature_invalid"}


def test_a_policy_the_record_carries_is_never_read() -> None:
    """A producer that ships its own trust root inside the pack is judged on the pinned one."""
    r = _case("mandate-ceiling-raised-without-key")
    r["policy"] = {"issuer_keys": {"issuer-key-1": "00" * 32}, "witness_keys": {}}
    assert paymentmandate.decide(r)["reason"] == "mandate_signature_invalid"
    accepted = _case("authorized-ap2-cart")
    accepted["policy"] = {"issuer_keys": {}, "witness_keys": {}}
    assert paymentmandate.decide(accepted)["decision"] == "accepted"


def test_another_relying_party_policy_refuses_the_corpus_keys() -> None:
    other = {
        "issuer_keys": {"issuer-key-1": "00" * 32},
        "witness_keys": {"witness-key-1": "00" * 32},
    }
    answer = paymentmandate.decide(_case("authorized-ap2-cart"), policy=other)
    assert answer["decision"] == "rejected"


# Forgeries found by the 16 Nov 2026 attack run: the released reader (0.37.0) accepted all of
# them, and the signature fix alone still accepted every one listed here. Each is now a member.
FORGERIES_16_NOV = {
    "mandate-used-by-other-agent": "agent_not_the_mandated_agent",
    "sub-delegation-without-user-link": "agent_not_the_mandated_agent",
    "agent-proof-by-other-key": "agent_proof_invalid",
    "credential-claims-multi-use": "credential_widens_mandate",
    "single-use-token-second-settlement": "single_use_token_replayed",
    "charge-on-unmandated-rail": "rail_not_mandated",
    "single-use-mandate-spent-on-two-rails": "mandate_spent_twice",
    "charge-after-expiry-via-offset": "mandate_expired",
    "executed-at-unix-seconds": "record_malformed",
    "mandate-expiry-missing": "record_malformed",
    "charge-before-mandate-issued": "charge_before_mandate",
    "amount-fractional-minor-units": "record_malformed",
    "amount-negative": "record_malformed",
    "post-checkout-requirement-dropped": "post_checkout_action_missing",
    "duplicate-member-in-record": "record_malformed",
}


@pytest.mark.parametrize("name", sorted(FORGERIES_16_NOV))
def test_every_16_nov_forgery_is_refused(name: str) -> None:
    answer = paymentmandate.verify(ROOT / "cases" / name / "case.json")
    assert answer == {"decision": "rejected", "reason": FORGERIES_16_NOV[name]}


def test_unsigned_parts_never_relax_signed_limits() -> None:
    r = _case("authorized-spt-seller-bound")
    r["credential"]["single_use"] = False
    assert paymentmandate.decide(r)["reason"] == "credential_widens_mandate"
    r = _case("authorized-ap2-cart")
    r["post_checkout"] = {"required": [], "recorded": ["capture"]}
    assert paymentmandate.decide(r)["reason"] == "post_checkout_action_missing"


def test_a_duplicate_member_is_refused_before_it_is_read() -> None:
    raw = (ROOT / "cases" / "duplicate-member-in-record" / "case.json").read_text()
    with pytest.raises(paymentmandate.DuplicateMember):
        paymentmandate.load_record(raw)


def test_time_is_compared_as_time_not_as_text() -> None:
    r = _case("authorized-ap2-cart")
    assert paymentmandate._expired(r, {}) is False
    r["execution"]["executed_at"] = "2026-11-29T23:30:00-05:00"
    assert paymentmandate._expired(r, {}) is True
    r["execution"]["executed_at"] = "2026-11-30T00:30:00+01:00"
    assert paymentmandate._expired(r, {}) is False


def test_an_amount_is_a_positive_integer() -> None:
    for bad in (12500.0, True, "12500", 0, -1):
        r = _case("authorized-ap2-cart")
        r["execution"]["amount_minor"] = bad
        assert paymentmandate._malformed(r, {}), bad


def test_a_pack_of_one_is_malformed() -> None:
    pack = _case("authorized-two-mandates-two-rails")
    pack["records"] = pack["records"][:1]
    assert paymentmandate.decide(pack)["reason"] == "record_malformed"
