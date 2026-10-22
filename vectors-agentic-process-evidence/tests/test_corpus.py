"""The corpus regenerates byte for byte, every rule is load-bearing, and the
external contract agrees with the reference reader."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

import run_vectors  # noqa: E402, F401  (the reader borrows its Ed25519)
from agent_evidence_vectors import agenticprocess  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("agentic_process_generator", ROOT / "gen_vectors.py")
mutation = _load("agentic_process_mutation", ROOT / "mutation_check.py")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "import run_vectors\n"
        "from agent_evidence_vectors import agenticprocess as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text())


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                 if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = agenticprocess.check()
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_external_contract_agrees(tmp_path: Path) -> None:
    answered, errors = agenticprocess.check(_stub(tmp_path, ()))
    assert errors == []
    assert answered == len(generator.MEMBERS)


def test_a_verifier_trusting_any_signed_key_is_refused(tmp_path: Path) -> None:
    _, errors = agenticprocess.check(_stub(tmp_path, ("pinned_keys_only",)))
    assert {e.split(":", 1)[0] for e in errors} == {"wrong-key"}


def test_a_verifier_reading_only_the_schema_shape_is_refused(tmp_path: Path) -> None:
    """A verifier that never checks the result enum accepts a result the spec does not list."""
    _, errors = agenticprocess.check(_stub(tmp_path, ("field:predicate.result",)))
    assert {e.split(":", 1)[0] for e in errors} == {"result-missing", "result-not-listed"}


def test_every_rule_is_load_bearing() -> None:
    assert mutation.sweep() == []


def test_every_refused_member_names_a_supported_twin() -> None:
    by_id = {e["id"]: e for e in _manifest()["vectors"]}
    for e in by_id.values():
        if e["expected"]["decision"] != "supported":
            assert by_id[e["twin"]]["expected"]["decision"] == "supported", e["id"]


def test_every_field_rule_has_a_member() -> None:
    reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]}
    assert {f"field_invalid:{f}" for f in agenticprocess.FIELDS} <= reasons


def test_the_published_example_is_supported_and_one_byte_breaks_it() -> None:
    case = ROOT / "cases" / "published-example" / "case.json"
    policy = json.loads(case.read_text())["policy"]
    envelope = (case.parent / "envelope.json").read_bytes()
    assert agenticprocess.judge(envelope, policy) == {
        "decision": "supported", "reason": "process_evidence_verified"}
    forged = envelope.replace(b'"payload":"ey', b'"payload":"eX', 1)
    assert forged != envelope
    assert agenticprocess.judge(forged, policy)["decision"] in ("contradicted", "no_verdict")


def test_unsigned_statement_check_reads_the_published_example() -> None:
    statement = generator.statement(generator.PREDICATE_JFROG)
    assert agenticprocess.check_statement(statement, generator.PREDICATE_JFROG) is None
    statement["predicate"]["contextArtifacts"][0]["data"] = "inline"
    assert (agenticprocess.check_statement(statement, generator.PREDICATE_JFROG)
            == "field_invalid:predicate.contextArtifacts")


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = _manifest()
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]
