"""Tests for scripts/independent-producibility.py against throwaway corpora and minters.

python -m pytest -q scripts/independent-producibility-test.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "independent_producibility", HERE / "independent-producibility.py"
)
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gate
_spec.loader.exec_module(gate)

MINTER = """
import json, sys
from pathlib import Path
from _helper import body

out = Path(sys.argv[1])
(out / "cases" / "one").mkdir(parents=True)
(out / "cases" / "one" / "case.json").write_bytes(body())
(out / "MANIFEST.json").write_text(json.dumps({"vectors": [{"path": "cases/one"}]}))
"""


def make_corpus(root: Path, case_bytes: bytes = b"{}\n") -> Path:
    corpora = root / "corpora"
    (corpora / "vectors-x" / "cases" / "one").mkdir(parents=True)
    (corpora / "vectors-x" / "cases" / "one" / "case.json").write_bytes(case_bytes)
    (corpora / "vectors-x" / "MANIFEST.json").write_text(
        json.dumps({"vectors": [{"path": "cases/one"}]})
    )
    (corpora / "vectors-y").mkdir()
    (corpora / "vectors-y" / "MANIFEST.json").write_text(json.dumps({"vectors": []}))
    return corpora


def make_minter(
    root: Path, source: str = MINTER, helper: str = "def body():\n    return b'{}\\n'\n"
) -> Path:
    directory = root / "mint"
    directory.mkdir()
    (directory / "_helper.py").write_text(helper)
    (directory / "vectors-x.py").write_text(source)
    return directory / "vectors-x.py"


def test_a_minter_that_writes_the_same_bytes_passes(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    assert gate.check_minter("vectors-x", make_minter(tmp_path), corpora) == []


def test_a_changed_byte_is_named(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path, b"{ }\n")
    assert gate.check_minter("vectors-x", make_minter(tmp_path), corpora) == [
        "vectors-x: bytes differ: cases/one/case.json"
    ]


def test_a_file_the_minter_does_not_write_is_named(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    (corpora / "vectors-x" / "cases" / "one" / "extra.txt").write_bytes(b"x")
    assert gate.check_minter("vectors-x", make_minter(tmp_path), corpora) == [
        "vectors-x: not written by the minter: cases/one/extra.txt"
    ]


def test_a_file_the_corpus_lacks_is_named(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    source = MINTER + '(out / "stray.txt").write_text("x")\n'
    assert gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora) == [
        "vectors-x: written by the minter, absent from the corpus: stray.txt"
    ]


def test_an_import_from_the_repository_is_refused_before_it_runs(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    source = "from agent_evidence_vectors import chunkedexport\n" + MINTER
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert problems == [
        "vectors-x: imports agent_evidence_vectors; a minter may import the standard library "
        "and tools/independent-mint/_*.py only"
    ]


def test_a_helper_cannot_import_a_third_party_package(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    helper = "import cryptography\ndef body():\n    return b'{}\\n'\n"
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, helper=helper), corpora)
    assert problems and "imports cryptography" in problems[0]


def test_the_minter_runs_without_the_repository_on_its_path(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    # importlib reaches a module by a name the import scan cannot see; the isolated run
    # still cannot find the repository's package.
    source = "import importlib\nimportlib.import_module('agent_evidence_vectors')\n" + MINTER
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert len(problems) == 1 and "the minter exited 1" in problems[0]
    assert "ModuleNotFoundError" in problems[0]


COPIER = """
import shutil, sys
from pathlib import Path
src = Path({corpus!r})
out = Path(sys.argv[1])
shutil.copy(src / "MANIFEST.json", out / "MANIFEST.json")
shutil.copytree(src / "cases", out / "cases")
"""


def test_a_minter_that_copies_the_committed_corpus_is_refused(tmp_path: Path) -> None:
    # The break: an absolute path reaches the committed bytes, and a copy matches byte for byte.
    corpora = make_corpus(tmp_path)
    source = COPIER.format(corpus=str(corpora / "vectors-x"))
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert len(problems) == 1 and "the minter exited 1" in problems[0]
    assert "reading" in problems[0] and "refused" in problems[0]


def test_a_minter_cannot_import_the_first_generator_by_path(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    (corpora / "vectors-x" / "gen_vectors.py").write_text("BODY = b'{}\\n'\n")
    source = (
        "import importlib, sys\n"
        f"sys.path.insert(0, {str(corpora / 'vectors-x')!r})\n"
        "importlib.import_module('gen_vectors')\n" + MINTER
    )
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    # The import machinery's directory listing is refused, so the module is not found.
    assert len(problems) == 1 and "No module named 'gen_vectors'" in problems[0], problems


def test_a_minter_cannot_start_a_process(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    source = "import subprocess\nsubprocess.run(['true'])\n" + MINTER
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert len(problems) == 1 and "refused" in problems[0], problems


def test_a_minter_cannot_link_the_committed_file_into_its_output(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    case = corpora / "vectors-x" / "cases" / "one" / "case.json"
    source = MINTER.replace(
        '(out / "cases" / "one" / "case.json").write_bytes(body())',
        f'import os\nos.symlink({str(case)!r}, out / "cases" / "one" / "case.json")',
    )
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert len(problems) == 1 and "os.symlink refused" in problems[0], problems


def test_a_link_left_in_the_output_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "real.json").write_bytes(b"{}")
    (out / "linked.json").symlink_to(out / "real.json")
    assert gate.written_files(out) == ({"real.json": b"{}"}, ["linked.json"])


def test_a_relative_path_is_refused(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    source = "open('../../corpora/vectors-x/MANIFEST.json').read()\n" + MINTER
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert len(problems) == 1 and "relative path refused" in problems[0], problems


def test_the_minter_sees_an_empty_environment(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    # Only what the interpreter sets for itself (PEP 538 locale coercion) may appear.
    source = "import os\nassert set(os.environ) <= {'LC_CTYPE'}, sorted(os.environ)\n" + MINTER
    assert gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora) == []


def test_a_minter_that_is_a_link_is_refused(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    real = make_minter(tmp_path)
    link = real.parent / "vectors-link.py"
    link.symlink_to(real)
    problems = gate.check_minter("vectors-link", link, corpora)
    assert problems == [
        "vectors-link: vectors-link.py is a link; a minter and its helpers are files"
    ]


PASTED = """
def build(rows):
    \"\"\"Doc strings and names do not hide a paste.\"\"\"
    out = []
    for row in rows:
        if row:
            out.append(row * 2)
    return out
"""


def test_a_function_pasted_from_the_first_generator_is_refused(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    (corpora / "vectors-x" / "gen_vectors.py").write_text(PASTED)
    renamed = PASTED.replace("build", "make").replace("rows", "items").replace("row", "item")
    source = renamed.replace("Doc strings and names do not hide a paste.", "Renamed.") + MINTER
    problems = gate.check_minter("vectors-x", make_minter(tmp_path, source), corpora)
    assert problems == [
        "vectors-x: shares code with the first generator: "
        "vectors-x.py make() has the body of gen_vectors.py build()"
    ]


def test_census_counts_the_corpora_with_a_minter(tmp_path: Path) -> None:
    corpora = make_corpus(tmp_path)
    assert gate.census(corpora, ["vectors-x"]) == (1, 2, ["vectors-y"])


def test_every_committed_minter_reproduces_its_corpus() -> None:
    minters = gate.minters()
    assert minters, "no minter under tools/independent-mint"
    for corpus_id, minter in minters.items():
        assert gate.check_minter(corpus_id, minter) == [], corpus_id
