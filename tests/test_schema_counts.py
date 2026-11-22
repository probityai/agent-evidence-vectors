"""Every published predicate schema keeps its pinned positive and negative counts."""

import importlib.util
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("schema_counts", ROOT / "scripts" / "schema_counts.py")
schema_counts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(schema_counts)


def test_every_schema_matches_its_pinned_counts():
    assert schema_counts.check() == []


def test_a_loosened_schema_lets_more_mutants_through(tmp_path):
    table = tomllib.loads(schema_counts.COUNTS.read_text(encoding="utf-8"))["schema"]
    entry = next(e for e in table if "joint-authority" in e["schema"])
    loose = json.loads((ROOT / entry["schema"]).read_text(encoding="utf-8"))
    loose["required"] = []
    loose["properties"]["predicate"] = {}
    path = tmp_path / "loose.schema.json"
    path.write_text(json.dumps(loose), encoding="utf-8")
    got = schema_counts.measure(dict(entry, schema=str(path)))
    assert got["mutants_rejected"] < entry["expect"]["mutants_rejected"]


def test_an_unpinned_schema_is_reported(tmp_path, monkeypatch):
    counts = tmp_path / "COUNTS.toml"
    counts.write_text("schema = []\n", encoding="utf-8")
    monkeypatch.setattr(schema_counts, "COUNTS", counts)
    problems = schema_counts.check()
    assert problems and all("no counts are pinned" in line for line in problems)
