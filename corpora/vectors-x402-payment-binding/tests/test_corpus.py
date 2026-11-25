"""The corpus regenerates byte for byte, every rule is load-bearing, a verifier
missing any one rule (a mutant) is caught, and a verifier that answers with one
verdict instead of two is caught."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import x402binding  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("x402binding_generator", ROOT / "gen_vectors.py")
mutation = _load("x402binding_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...], collapse: bool = False) -> str:
    """A verifier built on the reference reader, minus `skip`, optionally single-verdict.

    A collapsed verifier keeps one decision with one reason, as a one-verdict record
    does, and reports it for both the authorization and the settlement.
    """
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import x402binding as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        f"if {collapse!r}:\n"
        "    first = answer['authorization']\n"
        "    worst = answer['settlement'] if first['state'] == 'verified' else first\n"
        "    answer = {'authorization': worst, 'settlement': worst}\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.exit_code(answer))\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text())


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [
            ROOT / "MANIFEST.json",
            ROOT / "INDEX.md",
            ROOT / "profile.json",
            *(ROOT / "cases").rglob("*"),
        ]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = x402binding.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = x402binding.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


@pytest.mark.parametrize("rule", x402binding.RULES)
def test_a_mutant_verifier_missing_one_rule_is_caught(tmp_path: Path, rule: str) -> None:
    _, errors = x402binding.check(_stub(tmp_path, (rule,)))
    assert errors, f"a verifier without {rule} passed the whole corpus"


def test_a_single_verdict_verifier_is_caught(tmp_path: Path) -> None:
    _, errors = x402binding.check(_stub(tmp_path, (), collapse=True))
    failed = {e.split(":", 1)[0] for e in errors}
    assert "c-authorization-not-yet-used" in failed


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_a_and_c_differ_in_the_authorization_verdict() -> None:
    by_id = {e["id"]: e["expected"] for e in _manifest()["vectors"]}
    a, c = by_id["a-option-only-two-payments-fit"], by_id["c-authorization-not-yet-used"]
    assert a["authorization"]["state"] == "indeterminate"
    assert c["authorization"] == {"state": "verified", "reason": "authorization_identified"}
    assert a["settlement"]["state"] == c["settlement"]["state"] == "indeterminate"
    assert a["settlement"]["reason"] != c["settlement"]["reason"]


def test_read_failed_and_not_found_carry_different_reasons() -> None:
    by_id = {e["id"]: e["expected"]["settlement"] for e in _manifest()["vectors"]}
    failed, not_found = by_id["c-chain-read-failed"], by_id["c-authorization-not-yet-used"]
    assert failed["state"] == not_found["state"] == "indeterminate"
    assert failed["reason"] == "chain_read_failed"
    assert not_found["reason"] == "authorization_not_yet_used"


def test_the_network_alias_pair_answers_alike_and_keeps_the_served_form() -> None:
    by_id = {e["id"]: e["expected"] for e in _manifest()["vectors"]}
    assert by_id["c-confirmed-network-served-as-base"] == by_id["c-confirmed-single-transfer"]
    served = json.loads(
        (ROOT / "cases" / "c-confirmed-network-served-as-base" / "case.json").read_text()
    )
    assert served["offer"]["accepted"]["network"] == "base"
    assert served["binding"]["authorization"]["network"] == "base"


def test_the_profile_carries_the_reader_network_table() -> None:
    profile = json.loads((ROOT / "profile.json").read_text())
    table = profile["networkIdentifiers"]["v1"]
    assert table == {k: f"eip155:{v}" for k, v in x402binding.V1_CHAIN_IDS.items()}


def test_every_member_not_verified_twice_names_an_accepted_twin() -> None:
    entries = _manifest()["vectors"]
    accepted = {
        e["id"]
        for e in entries
        if all(e["expected"][v]["state"] == "verified" for v in x402binding.VERDICTS)
    }
    assert accepted
    for e in entries:
        if e["id"] not in accepted:
            assert e["twin"] in accepted
    reasons = {e["expected"][v]["reason"] for e in entries for v in x402binding.VERDICTS}
    assert set(x402binding.RULES) <= reasons


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("b-batch-log-index-names-transfer", 0),
        ("c-valid-before-passed", 1),
        ("c-authorization-not-yet-used", 2),
        ("c-no-chain-read", 2),
    ],
)
def test_single_case_exit_code_follows_the_verdicts(name: str, code: int) -> None:
    assert x402binding.main([str(ROOT / "cases" / name / "case.json"), "--json"]) == code


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = _manifest()
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]


def test_a_tampered_case_is_refused(tmp_path: Path) -> None:
    work = tmp_path / "copy"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    target = next((work / "cases").iterdir()) / "case.json"
    target.write_text(target.read_text() + " ", encoding="utf-8")
    _, errors = x402binding.check(root=work)
    assert errors


def test_a_one_verdict_manifest_row_is_refused(tmp_path: Path) -> None:
    work = tmp_path / "copy"
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    manifest = json.loads((work / "MANIFEST.json").read_text())
    manifest["vectors"][0]["expected"] = {"decision": "accepted", "reason": "join_holds"}
    manifest["corpusDigest"] = x402binding._sha(x402binding._json(manifest["vectors"]))
    (work / "MANIFEST.json").write_text(json.dumps(manifest))
    _, errors = x402binding.check(root=work)
    assert errors and "expected must carry exactly" in errors[0]
