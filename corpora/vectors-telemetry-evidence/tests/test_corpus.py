"""The corpus regenerates byte for byte, the reference reader agrees with every case, and a reader
that drops
any one rule is refused by the case that names it."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("telemetry_evidence_corpus", ROOT / "check_vectors.py")
generator = _load("telemetry_evidence_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import telemetryevidence as reader  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(MANIFEST["vectors"])


def test_every_case_names_its_requirement_and_no_vendor() -> None:
    assert {v["draftId"] for v in MANIFEST["vectors"]} == {"OBS-5a", "OBS-5b", "OBS-5c", "OBS-7"}
    text = "".join(p.read_text(encoding="utf-8") for p in ROOT.rglob("*.json"))
    assert "aer_receipt_v1" not in text


def test_the_six_edits_and_the_signed_id_pair_are_present() -> None:
    expected = {
        v["id"]: (v["expected"]["decision"], v["expected"]["reason"]) for v in MANIFEST["vectors"]
    }
    assert (
        sum(1 for v in MANIFEST["vectors"] if v["edit"].startswith("edit ") and "of 6" in v["edit"])
        == 6
    )
    assert expected["signed-id-self-carried-key"] == ("contradicted", "signer_pinned")
    assert expected["signed-id-pinned-key"] == ("agrees", "digests_bind_consumed_copy")


RULES = {
    "pin": (
        "    if hashlib.sha256(key).hexdigest() not in pins:",
        "    if False:",
        "signed-id-self-carried-key",
    ),
    "coverage": (
        "    if any(item not in refs for item in consumed):",
        "    if False:",
        "evidence-ref-zero-of-n",
    ),
    "duplicate": (
        '            raise Refused("no_duplicate_member")\n        out[key] = value',
        "            pass\n        out[key] = value",
        "evidence-ref-duplicate-member",
    ),
    "sequence": (
        '    if any(e["seq"] != first + i for i, e in enumerate(events)):',
        "    if False:",
        "log-drop",
    ),
    "head": (
        '    if head["count"] != len(events) or head["head"] != digests[-1]:',
        "    if False:",
        "log-tail-truncation",
    ),
}


@pytest.mark.parametrize("rule", sorted(RULES))
def test_a_reader_without_the_rule_fails_its_case(rule: str, tmp_path: Path) -> None:
    old, new, case = RULES[rule]
    source = Path(reader.__file__).read_text(encoding="utf-8")
    assert old in source
    mutant = tmp_path / "mutant_reader.py"
    mutant.write_text(source.replace(old, new, 1), encoding="utf-8")
    module = _load(f"mutant_{rule}", mutant)
    record = json.loads((ROOT / "cases" / case / "record.json").read_text(encoding="utf-8"))
    want = next(v["expected"] for v in MANIFEST["vectors"] if v["id"] == case)
    try:
        answer = module.judge(record)
    except (KeyError, ValueError, TypeError):
        answer = None
    assert answer != want
