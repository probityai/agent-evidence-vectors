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


def _case(entry: dict) -> object:
    return oracle.load_case((HERE / entry["file"]).read_bytes())


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

    def readable(case: object) -> bool:
        return isinstance(case, dict) and all(isinstance(r, dict) and isinstance(r["params"].get("alpn"), str)
                                              for r in case["rrset"])

    wrong = [e["id"] for e in MANIFEST["vectors"]
             if readable(c := _case(e)) and old(c) != (e["kind"] == "accept")]
    assert {"draft-02-example-rrset", "draft-newer-00-example-rrset"} <= set(wrong)


def test_every_shape_defect_is_a_verdict_never_a_crash() -> None:
    """The first oracle raised on a record that is not an object and read a string as a set."""
    for case in ({"rrset": ["mcp"]}, {"rrset": [{"params": []}]}, {"rrset": [], "published": "mcp"},
                 {"rrset": [], "published": [1]}, {"rrset": [{"params": {"alpn": {"x": 1}}}]},
                 {"rrset": [{"params": {"proto": None}}]}):
        assert oracle.report(case) == {"codes": ["rrset-malformed"], "verdict": "invalid"}, case
    for raw in (b'{"rrset":[],"rrset":[]}', b'{"rrset":NaN}', b"[" * 100000, b"\xff"):
        assert oracle.report(oracle.load_case(raw))["codes"] == ["rrset-malformed"], raw[:20]


def test_a_present_empty_proto_does_not_fall_back_to_alpn() -> None:
    case = {"published": ["mcp"], "rrset": [{"params": {"alpn": "mcp", "proto": ""}}]}
    assert "record-names-no-protocol" in oracle.report(case)["codes"]


def test_the_member_file_is_read_strictly() -> None:
    raw = (HERE / "cases" / "member-duplicate-alpn.json").read_bytes()
    assert oracle.report(json.loads(raw))["verdict"] == "valid"  # what a last-wins reader concludes
    assert oracle.report(oracle.load_case(raw))["codes"] == ["rrset-malformed"]
