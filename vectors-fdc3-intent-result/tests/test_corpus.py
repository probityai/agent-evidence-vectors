"""The corpus regenerates, every verdict agrees with jsonschema, and every keyword matters."""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("fdc3_intent_result_corpus", ROOT / "check_vectors.py")
generator = _load("fdc3_intent_result_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import fdc3intentresult as reader  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
SETS = tuple(MANIFEST["schemaSets"])
API = "packages/fdc3-schema/schemas/api"
# The cases issue #2271 is about: refused by the schemas it cites, accepted by
# the proposal.
FIXED_BY_THE_PROPOSAL = {"handler-throws", "handler-returns-rejected-promise",
                         "proxy-reports-handler-error", "agent-forwards-result-error"}


def _cases() -> list[tuple[str, dict[str, Any]]]:
    return [(e["id"], json.loads((ROOT / e["path"] / "case.json").read_text("utf-8")))
            for e in MANIFEST["vectors"]]


@functools.cache
def _validator(set_name: str, message_type: str) -> Draft7Validator:
    """A jsonschema validator over exactly the vendored, pinned files of one set."""
    base = ROOT / "schema-sets" / set_name
    resources = []
    for rel, pin in MANIFEST["schemaSets"][set_name]["files"].items():
        data = (base / rel).read_bytes()
        assert hashlib.sha256(data).hexdigest() == pin["sha256"], rel
        doc = json.loads(data)
        resources.append((doc["$id"], Resource.from_contents(doc, default_specification=DRAFT7)))
    registry: Registry = Registry().with_resources(resources)
    schema = json.loads((base / API / f"{message_type}.schema.json").read_text("utf-8"))
    return Draft7Validator(schema, registry=registry)


@functools.cache
def _verdicts(off: frozenset[str] = frozenset()) -> dict[tuple[str, str], dict[str, Any]]:
    return {(e["id"], s): reader.verify(ROOT / e["path"] / "case.json",
                                        ROOT / "schema-sets" / s, off)
            for e in MANIFEST["vectors"] for s in SETS}


def _stub(tmp_path: Path, body: str) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import fdc3intentresult as m\n"
        f"{body}\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


class TestFdc3IntentResultCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            for name in SETS:
                if name not in generator.GENERATED:
                    shutil.copytree(ROOT / "schema-sets" / name,
                                    tmp_path / "schema-sets" / name)
            generator.generate(tmp_path)
            owned = ["MANIFEST.json", "cases", "schema-sets"]
            committed = {p.relative_to(ROOT): p.read_bytes() for o in owned
                         for p in ([ROOT / o] if (ROOT / o).is_file() else (ROOT / o).rglob("*"))
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes() for o in owned
                           for p in ([tmp_path / o] if (tmp_path / o).is_file()
                                     else (tmp_path / o).rglob("*")) if p.is_file()}
            assert committed == regenerated

        def test_reference_reader_answers_every_case_against_every_set(self) -> None:
            answered, errors = reader.check(None, ROOT)
            assert errors == []
            assert answered == len(MANIFEST["vectors"]) * len(SETS)

        def test_every_message_verdict_agrees_with_jsonschema(self) -> None:
            for case_id, case in _cases():
                for set_name in SETS:
                    expected = next(e for e in MANIFEST["vectors"]
                                    if e["id"] == case_id)["expected"][set_name]
                    rejected = [
                        step["step"] for step in case["sequence"]
                        if not _validator(set_name, step["message"]["type"]).is_valid(
                            step["message"])]
                    assert rejected == expected["rejectedSteps"], (case_id, set_name)
                    assert expected["decision"] == ("rejected" if rejected else "accepted")

        def test_upstream_files_are_pinned_to_a_commit(self) -> None:
            for name, schema_set in MANIFEST["schemaSets"].items():
                if "commit" not in schema_set:
                    assert schema_set["derivedFrom"] in SETS
                    continue
                assert len(schema_set["commit"]) == 40
                for rel, pin in schema_set["files"].items():
                    data = (ROOT / "schema-sets" / name / rel).read_bytes()
                    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324
                    assert pin["gitBlob"] == blob
                    assert pin["url"].endswith(f"/{schema_set['commit']}/{rel}")

        def test_the_proposal_fixes_exactly_the_cases_the_issue_names(self) -> None:
            fixed = {e["id"] for e in MANIFEST["vectors"]
                     if e["expected"]["fdc3-39505b1"]["decision"] == "rejected"
                     and e["expected"]["proposed-oneof"]["decision"] == "accepted"}
            assert fixed == FIXED_BY_THE_PROPOSAL

        def test_only_an_alternative_refuses_a_result_and_an_error_together(self) -> None:
            entry = next(e for e in MANIFEST["vectors"] if e["id"] == "both-result-and-error")
            assert entry["expected"]["optional-error"]["decision"] == "accepted"
            assert entry["expected"]["proposed-oneof"]["decision"] == "rejected"

        def test_reference_reader_runs_as_a_named_verifier(self, tmp_path: Path) -> None:
            verifier = _stub(tmp_path, "answer = m.verify(Path(sys.argv[1]), Path(sys.argv[2]))")
            answered, errors = reader.check(verifier, ROOT)
            assert (answered, errors) == (len(MANIFEST["vectors"]) * len(SETS), [])

        def test_a_checkout_with_the_proposal_passes_the_proposal(self) -> None:
            answered, errors = reader.check(None, ROOT,
                                            checkout=ROOT / "schema-sets" / "proposed-oneof")
            assert (answered, errors) == (len(MANIFEST["vectors"]), [])

    class TestRejectionCases:
        # The keywords these cases force. type and const are judged too, but no
        # rule here turns on them: every message's type names its own schema.
        @pytest.mark.parametrize("keyword", ["required", "properties", "additionalProperties",
                                             "allOf", "oneOf", "not", "enum"])
        def test_switching_a_keyword_off_changes_a_verdict(self, keyword: str) -> None:
            assert _verdicts(frozenset({keyword})) != _verdicts()

        def test_a_checkout_without_the_proposal_fails_the_proposal(self) -> None:
            _, errors = reader.check(None, ROOT, checkout=ROOT / "schema-sets" / "fdc3-39505b1")
            assert {error.split(" ", 1)[0] for error in errors} == FIXED_BY_THE_PROPOSAL

        def test_an_unsupported_keyword_is_an_error_not_a_verdict(self, tmp_path: Path) -> None:
            shutil.copytree(ROOT / "schema-sets" / "proposed-oneof", tmp_path / "set")
            path = tmp_path / "set" / API / "intentResultRequest.schema.json"
            schema = json.loads(path.read_text("utf-8"))
            schema["$defs"]["IntentResultRequestType"]["pattern"] = "^intent"
            path.write_text(json.dumps(schema), encoding="utf-8")
            case = ROOT / "cases" / "handler-throws" / "case.json"
            with pytest.raises(reader.UnsupportedSchema):
                reader.verify(case, tmp_path / "set")

        def test_a_tampered_case_is_a_corpus_error(self, tmp_path: Path) -> None:
            shutil.copytree(ROOT, tmp_path / "corpus", ignore=shutil.ignore_patterns(
                "__pycache__", "tests"))
            case = tmp_path / "corpus" / "cases" / "handler-throws" / "case.json"
            case.write_bytes(case.read_bytes().replace(b"raise-0001", b"raise-0002"))
            _, errors = reader.check(None, tmp_path / "corpus")
            assert errors == ["handler-throws: fixture digest mismatch"]

        def test_a_tampered_schema_is_a_corpus_error(self, tmp_path: Path) -> None:
            shutil.copytree(ROOT, tmp_path / "corpus", ignore=shutil.ignore_patterns(
                "__pycache__", "tests"))
            path = (tmp_path / "corpus" / "schema-sets" / "fdc3-39505b1" / API
                    / "intentResultRequest.schema.json")
            path.write_bytes(path.read_bytes().replace(b'"intentResult"\n', b'"error"\n'))
            _, errors = reader.check(None, tmp_path / "corpus")
            assert len(errors) == 1 and "digest mismatch" in errors[0]

        def test_a_verifier_that_prints_nothing_answers_nothing(self) -> None:
            _, errors = reader.check(f"{sys.executable} -c pass", ROOT)
            assert len(errors) == len(MANIFEST["vectors"]) * len(SETS)
