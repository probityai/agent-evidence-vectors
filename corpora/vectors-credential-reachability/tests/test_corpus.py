"""The corpus regenerates byte for byte, every rule is load-bearing, and the external
contract agrees with the reference reader."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors  # noqa: E402, F401  (the reader borrows its Ed25519)
from agent_evidence_vectors import credreach  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("credential_reachability_generator", ROOT / "gen_vectors.py")
mutation = _load("credential_reachability_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "import run_vectors\n"
        "from agent_evidence_vectors import credreach as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _case(name: str) -> tuple[bytes, dict[str, Any]]:
    case = json.loads((ROOT / "cases" / name / "case.json").read_text())
    return (ROOT / "cases" / name / "envelope.json").read_bytes(), case["policy"]


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                 if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = credreach.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = credreach.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_a_verifier_that_trusts_the_agent_key_is_refused(tmp_path: Path) -> None:
    _, errors = credreach.check(_stub(tmp_path, ("agent_key",)))
    assert {e.split(":", 1)[0] for e in errors} == {
        "signed-by-agent-key", "agent-key-names-host-keyid", "agent-cosigned"}


def test_a_verifier_that_copies_class_verdicts_is_refused(tmp_path: Path) -> None:
    _, errors = credreach.check(_stub(tmp_path, ("class_verdict",)))
    assert {e.split(":", 1)[0] for e in errors} >= {
        "found-reported-clean", "not-run-reported-clean", "error-reported-clean"}


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_every_refused_member_names_a_supported_twin() -> None:
    entries = json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]
    by_id = {e["id"]: e for e in entries}
    for e in entries:
        if e["expected"]["decision"] != "supported":
            assert by_id[e["twin"]]["expected"]["decision"] == "supported", e["id"]


def test_every_field_has_a_member() -> None:
    reasons = {e["expected"]["reason"]
               for e in json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]}
    assert {f"predicate_field_invalid:{f}" for f in credreach.FIELDS} <= reasons


def test_a_policy_naming_one_key_as_signer_and_agent_reaches_no_verdict() -> None:
    envelope, policy = _case("contained")
    policy = {**policy, "agent_keys": dict(policy["trusted_signers"])}
    assert credreach.judge(envelope, policy) == {"decision": "no_verdict",
                                                 "reason": "policy_invalid"}


def test_one_changed_payload_byte_is_caught() -> None:
    envelope, policy = _case("contained")
    assert credreach.judge(envelope, policy) == {"decision": "supported",
                                                 "reason": "contained_verified"}
    doc = json.loads(envelope)
    body = bytearray(base64.b64decode(doc["payload"]))
    body[body.index(b"not_reachable")] = ord("N")
    doc["payload"] = base64.b64encode(bytes(body)).decode()
    answer = credreach.judge(json.dumps(doc).encode(), policy)
    assert answer == {"decision": "contradicted", "reason": "signature_invalid"}


def test_no_attempt_in_the_corpus_carries_more_than_a_prefix() -> None:
    for entry in json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]:
        if entry["id"] in ("attempt-carries-value", "attempt-full-digest"):
            continue
        try:
            envelope = json.loads((ROOT / entry["path"] / "envelope.json").read_bytes())
            statement = json.loads(base64.b64decode(envelope["payload"]))
        except (ValueError, KeyError, TypeError):
            continue
        predicate = statement.get("predicate") if isinstance(statement, dict) else None
        if not isinstance(predicate, dict) or not isinstance(predicate.get("classes"), list):
            continue
        for c in predicate["classes"]:
            for a in c.get("attempts", []):
                assert "value" not in a, entry["id"]
                assert len(a.get("digestPrefix", "")) in (0, 12), entry["id"]


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]
