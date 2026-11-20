"""The DNS-AID RRset corpus regenerates, the oracle holds every member, and the old reading fails.

    uv run --extra dev pytest corpora/vectors-dns-aid-rrset-v01/tests -q
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"rrset_{name}", HERE / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = _load("gen_vectors")
oracle = _load("check_vectors")
MANIFEST = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))


def _tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in (".json", ".md") and "tests" not in p.parts}


def _case(entry: dict) -> dict:
    return json.loads((HERE / entry["file"]).read_text(encoding="utf-8"))


def test_regenerates_byte_for_byte(tmp_path: Path) -> None:
    gen.generate(tmp_path)
    assert _tree(tmp_path) == _tree(HERE)


def test_the_oracle_holds_every_member() -> None:
    for entry in MANIFEST["vectors"]:
        got = oracle.report(_case(entry))
        assert got == {k: entry["expected"][k] for k in ("codes", "verdict")}, entry["id"]


def test_both_drafts_examples_pass() -> None:
    controls = {"draft-02-example-rrset", "draft-newer-00-example-rrset", "two-records-bare-alpn"}
    kinds = {e["id"]: e["kind"] for e in MANIFEST["vectors"]}
    assert all(kinds[c] == "accept" for c in controls)


def test_reading_raw_alpn_as_the_protocol_set_fails_the_controls() -> None:
    """The earlier oracle compared sorted alpn strings with the published protocols."""

    def old(case: dict) -> bool:
        return sorted(r["params"]["alpn"] for r in case["rrset"]) == sorted(case["published"])

    wrong = [e["id"] for e in MANIFEST["vectors"] if old(_case(e)) != (e["kind"] == "accept")]
    assert {"draft-02-example-rrset", "draft-newer-00-example-rrset"} <= set(wrong)
