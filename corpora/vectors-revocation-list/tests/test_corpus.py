"""The committed corpus is exactly what its generator writes."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("revocation_gen", ROOT / "gen_vectors.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*.json"))
        if "tests" not in p.relative_to(root).parts
    }


def test_regeneration_is_byte_identical() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        _generator().generate(out)
        assert _tree(out) == _tree(ROOT)


def test_corpus_digest_recomputes_from_the_files() -> None:
    gen = _generator()
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    assert gen.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]


def test_an_edited_list_is_caught() -> None:
    gen = _generator()
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "corpus"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("tests", "__pycache__"))
        target = copy / "cases" / "rl01-empty-first-list" / "list-01.json"
        target.write_bytes(target.read_bytes().replace(b"2026", b"2027", 1))
        manifest = json.loads((copy / "MANIFEST.json").read_text())
        try:
            gen.corpus_digest(manifest, str(copy))
        except ValueError as exc:
            assert "digest mismatch" in str(exc)
        else:
            raise AssertionError("an edited list file passed the digest check")


def test_every_decision_is_stated() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    for row in manifest["vectors"]:
        expected = row["expected"]
        assert expected["decision"] in ("accept", "reject")
        assert (expected["index"] is None) == (expected["decision"] == "accept")
        assert len(expected["listDigests"]) == len(row["lists"])
