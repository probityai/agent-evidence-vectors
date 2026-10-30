"""Tests for scripts/check_uris_resolve.py and scripts/build_vocabulary_pages.py."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


uris = _load("check_uris_resolve")
vocab_pages = _load("build_vocabulary_pages")
INDEX = json.loads((_ROOT / "packages" / "vocabulary" / "registry.json").read_text(encoding="utf-8"))
TABLE = uris.rules((_ROOT / "w3id" / "agent-evidence.htaccess").read_text(encoding="utf-8"))


@pytest.fixture
def pages(tmp_path: Path) -> Path:
    shutil.copytree(_ROOT / "pages", tmp_path / "pages")
    return tmp_path / "pages"


def test_every_identifier_resolves_against_the_built_site() -> None:
    assert uris.check(_ROOT / "pages", INDEX, TABLE) == []


def test_the_vocabulary_pages_are_current() -> None:
    assert vocab_pages.main(["--check"]) == 0


def test_every_term_and_value_is_an_identifier() -> None:
    found = set(uris.identifiers(_ROOT / "pages", INDEX))
    assert "https://w3id.org/agent-evidence/vocab/v1/observation_vantage#substrate" in found
    assert "https://w3id.org/agent-evidence/predicate/v1/done-receipt" in found
    terms = [u for u in found if "/vocab/v1/" in u and "#" not in u and "/registry/" not in u]
    assert len(terms) == len(INDEX["terms"]) + 1
    digest = INDEX["source_sha256"]
    assert f"https://w3id.org/agent-evidence/vocab/v1/registry/sha256-{digest}.yaml" in found


def test_a_missing_term_page_fails(pages: Path) -> None:
    shutil.rmtree(pages / "vocab" / "v1" / "observation_vantage")
    failures = uris.check(pages, INDEX, TABLE)
    assert any(f.startswith("https://w3id.org/agent-evidence/vocab/v1/observation_vantage") for f in failures)


def test_a_missing_value_anchor_fails(pages: Path) -> None:
    page = pages / "vocab" / "v1" / "observation_vantage" / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace('id="substrate"', 'id="x"'), encoding="utf-8")
    assert uris.check(pages, INDEX, TABLE) == [
        ("https://w3id.org/agent-evidence/vocab/v1/observation_vantage#substrate: "
         "pages/vocab/v1/observation_vantage/index.html has no anchor for the fragment")]


def test_an_identifier_with_no_rule_fails() -> None:
    table = [rule for rule in TABLE if "vocab" not in rule[0].pattern]
    failures = uris.check(_ROOT / "pages", INDEX, table)
    vocab = [u for u in uris.identifiers(_ROOT / "pages", INDEX) if "/vocab/v1/" in u]
    assert [f.split(": ", 1)[0] for f in failures] == vocab


def test_the_rules_rewrite_like_w3id() -> None:
    assert uris.rewrite("https://w3id.org/agent-evidence/predicate/v1/done-receipt", TABLE) == \
        "https://probityai.github.io/agent-evidence/predicate/v1/done-receipt/"
    assert uris.rewrite("https://w3id.org/agent-evidence/vocab/v1/result#fail", TABLE) == \
        "https://probityai.github.io/agent-evidence/vocab/v1/result/"
    assert uris.rewrite("https://w3id.org/agent-evidence/other", TABLE) is None


def _jsonld(page: Path) -> dict:
    text = page.read_text(encoding="utf-8")
    start = text.index('<script type="application/ld+json">') + len('<script type="application/ld+json">')
    return json.loads(text[start:text.index("</script>", start)])


def test_every_term_page_carries_absolute_jsonld_for_the_term_and_each_value() -> None:
    for name, term in INDEX["terms"].items():
        data = _jsonld(_ROOT / "pages" / "vocab" / "v1" / name / "index.html")
        ids = {node["@id"] for node in data["@graph"]}
        assert ids == {term["uri"], *(f"{term['uri']}#{v}" for v in term["values"] or [])} | (
            {c["uri"] for c in INDEX["verdict_classes"]["children"].values()}
            if name == INDEX["verdict_classes"]["parent_term"] else set())
        assert all(i.startswith("https://w3id.org/agent-evidence/vocab/v1/") for i in ids)
        assert not any("skos:narrower" in node for node in data["@graph"])


def test_a_term_key_may_not_take_the_reserved_registry_path() -> None:
    index = json.loads(json.dumps(INDEX))
    index["terms"]["registry"] = dict(next(iter(index["terms"].values())), uri=index["term_uri_base"] + "registry")
    assert any("reserved" in f for f in uris.check(_ROOT / "pages", index, TABLE))


def test_a_snapshot_whose_bytes_do_not_match_its_name_fails(pages: Path) -> None:
    snapshot = next((pages / "vocab" / "v1" / "registry").glob("sha256-*.yaml"))
    snapshot.write_bytes(snapshot.read_bytes() + b"\n")
    assert any("does not hash to its name" in f for f in uris.check(pages, INDEX, TABLE))


def test_the_builder_refuses_to_drop_an_issued_term(monkeypatch: pytest.MonkeyPatch, pages: Path) -> None:
    (pages / "vocab" / "v1" / "retired_term").mkdir()
    (pages / "vocab" / "v1" / "retired_term" / "index.html").write_text("issued", encoding="utf-8")
    monkeypatch.setattr(vocab_pages, "OUT", pages / "vocab" / "v1")
    assert vocab_pages.main([]) == 1
    assert (pages / "vocab" / "v1" / "retired_term" / "index.html").is_file()
