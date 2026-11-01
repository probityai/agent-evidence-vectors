"""The corpus regenerates, every refusal code is forced, and a reader that echoes is refused."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import skillfrontmatter  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


generator = _load("skill_frontmatter_generator", ROOT / "gen_vectors.py")
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
TOTAL = len(MANIFEST["vectors"])
NEEDS_YAML = sum(bool(v.get("needsYaml")) for v in MANIFEST["vectors"])


def _yaml_check(block: str) -> bool:
    return "[unclosed" not in block and "    a: 1\n  b: 2" not in block


class TestSkillFrontmatterCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            shutil.copy(ROOT / "SPEC.md", tmp_path / "SPEC.md")
            generator.generate(tmp_path)
            committed = {
                p.relative_to(ROOT): p.read_bytes()
                for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                if p.is_file()
            }
            regenerated = {
                p.relative_to(tmp_path): p.read_bytes()
                for p in tmp_path.rglob("*")
                if p.is_file() and p.name != "SPEC.md"
            }
            assert regenerated == committed

        def test_reference_reader_answers_every_case_without_a_yaml_processor(self) -> None:
            answered, not_applicable, errors = skillfrontmatter.check()
            assert (answered, not_applicable, errors) == (TOTAL - NEEDS_YAML, NEEDS_YAML, [])

        def test_reference_reader_answers_every_case_with_a_yaml_processor(self) -> None:
            answered, not_applicable, errors = skillfrontmatter.check(yaml_check=_yaml_check)
            assert (answered, not_applicable, errors) == (TOTAL, 0, [])

        def test_every_refusal_code_is_forced(self) -> None:
            codes = {v["expected"]["code"] for v in MANIFEST["vectors"] if "code" in v["expected"]}
            spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
            named = set(re.findall(r"refuse with `([a-z0-9-]+)`", spec))
            named |= set(re.findall(r"`(document-(?:end|start)-marker)`", spec))
            named.add("yaml-syntax-error")
            assert named <= codes, sorted(named - codes)

        def test_every_step_has_a_case(self) -> None:
            steps = {v["step"] for v in MANIFEST["vectors"]}
            assert {str(n) for n in range(1, 12)} <= steps

        def test_the_limits_are_cases_at_and_over_the_edge(self) -> None:
            by_id = {v["id"]: v for v in MANIFEST["vectors"]}
            assert by_id["file-at-limit"]["expected"]["outcome"] == "ok"
            assert by_id["file-too-large"]["expected"]["code"] == "file-too-large"
            assert by_id["frontmatter-at-limit"]["expected"]["outcome"] == "ok"
            assert by_id["frontmatter-too-large"]["expected"]["code"] == "frontmatter-too-large"

    class TestFailingCases:
        def test_a_split_on_the_first_dashes_reader_is_refused(self, tmp_path: Path) -> None:
            script = tmp_path / "naive.py"
            script.write_text(
                "import json, sys\n"
                "text = open(sys.argv[1], encoding='utf-8', errors='replace').read()\n"
                "parts = text.split('---', 2)\n"
                "print(json.dumps({'outcome': 'ok', 'keys': [], 'body': parts[-1]}))\n",
                encoding="utf-8",
            )
            answered, _, errors = skillfrontmatter.check([sys.executable, str(script)])
            assert answered == TOTAL - NEEDS_YAML
            assert len(errors) > 40

        def test_an_accept_everything_verifier_is_refused(self, tmp_path: Path) -> None:
            script = tmp_path / "accept.py"
            script.write_text(
                'import json\nprint(json.dumps({"outcome": "ok", "keys": [], "body": ""}))\n',
                encoding="utf-8",
            )
            answered, _, errors = skillfrontmatter.check([sys.executable, str(script)])
            accepted = sum(v["expected"]["outcome"] == "ok" for v in MANIFEST["vectors"])
            assert answered == TOTAL - NEEDS_YAML
            assert len(errors) >= TOTAL - NEEDS_YAML - accepted

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, _, errors = skillfrontmatter.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert len(errors) == TOTAL - NEEDS_YAML

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "cases" / "minimal" / "SKILL.md"
            path.write_bytes(path.read_bytes().replace(b"name: a", b"name: b"))
            answered, _, errors = skillfrontmatter.check(root=copied)
            assert any("fixture digest mismatch" in error for error in errors)
            assert answered == TOTAL - NEEDS_YAML - 1

        def test_a_bom_is_refused_by_name_not_read_as_no_frontmatter(self) -> None:
            result = skillfrontmatter.parse(b"\xef\xbb\xbf---\nname: a\n---\n")
            assert result == skillfrontmatter.Refused("byte-order-mark", 1)

        def test_a_dash_run_inside_a_value_does_not_close_the_block(self) -> None:
            result = skillfrontmatter.parse(b"---\nname: a\ndescription: see a---b\n---\nB\n")
            assert isinstance(result, skillfrontmatter.Accepted)
            assert result.keys == ("name", "description")

        def test_unreadable_file_exits_two(self, tmp_path: Path) -> None:
            assert skillfrontmatter.main([str(tmp_path / "absent" / "SKILL.md")]) == 2
