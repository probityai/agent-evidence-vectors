"""The DNS-AID sig corpus regenerates, two independent generators agree, and every check is forced.

    uv run --extra dev pytest corpora/vectors-dns-aid-sig-v01/tests -q
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = _load("gen_vectors")
reader = _load("check_vectors")
MANIFEST = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))


def _tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in (".json", ".md") and "tests" not in p.parts}


def test_regenerates_byte_for_byte(tmp_path: Path) -> None:
    gen.generate(tmp_path)
    assert _tree(tmp_path) == _tree(HERE)


def test_independent_generator_writes_the_same_members(tmp_path: Path) -> None:
    subprocess.run([sys.executable, "-I", str(HERE / "gen_vectors_independent.py"), str(tmp_path)], check=True)
    ours = {k: v for k, v in _tree(HERE).items() if k.startswith("cases/")}
    assert {k: v for k, v in _tree(tmp_path).items() if k.startswith("cases/")} == ours
    assert len(ours) == len(MANIFEST["vectors"])


def test_every_member_behaves_as_declared() -> None:
    assert reader.self_check(HERE) == []


def test_every_code_and_decision_is_exercised() -> None:
    codes = {c for e in MANIFEST["vectors"] for c in e["expected"]["codes"]}
    decisions = {e["expected"]["decision"] for e in MANIFEST["vectors"]}
    assert decisions == {"agrees", "contradicted", "cannot-tell"}
    assert set(gen.CODES) - codes == set()


def test_cli_follows_the_rail_contract() -> None:
    for entry in MANIFEST["vectors"]:
        done = subprocess.run([sys.executable, str(HERE / "check_vectors.py"), str(HERE / entry["file"])],
                              capture_output=True, text=True)
        line = json.loads(done.stdout.strip().splitlines()[-1])
        assert line["verdict"] == entry["expected"]["verdict"], entry["id"]
        assert done.returncode == (0 if line["verdict"] == "valid" else 1), entry["id"]


def test_a_flipped_expectation_turns_the_self_check_red(tmp_path: Path) -> None:
    gen.generate(tmp_path)
    manifest = json.loads((tmp_path / "MANIFEST.json").read_text(encoding="utf-8"))
    manifest["vectors"][0]["expected"]["verdict"] = "invalid"
    (tmp_path / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert reader.self_check(tmp_path)


def _case(name: str) -> dict:
    return json.loads((HERE / "cases" / f"{name}.json").read_text(encoding="utf-8"))


#: Each lenient reading a real reader makes, the member that catches it, and how.
LENIENT = {
    "no key authority": ("foreign-key-no-provenance", lambda c: {**c, "key_authority": {
        "kind": "pin", "jwks_fingerprint": reader.jwks_fingerprint(c["jwks"])}}),
    "crit ignored": ("crit-unknown-extension", None),
    "non-canonical base64url accepted": ("signature-base64url-non-canonical", None),
}


@pytest.mark.parametrize("name", sorted(LENIENT))
def test_a_lenient_reading_is_caught(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    member, rewrite = LENIENT[name]
    case = _case(member)
    assert reader.report(case)["decision"] != "agrees"
    if rewrite is not None:
        assert reader.report(rewrite(copy.deepcopy(case)))["decision"] == "agrees"
    elif name == "crit ignored":
        monkeypatch.setattr(reader, "check_crit", lambda header: None)
        assert reader.report(case)["decision"] == "agrees"
    else:
        original = reader.ub64

        def lax(text: object, what: str) -> bytes:
            try:
                return original(text, what)
            except reader.Finding as finding:
                if finding.code != "base64url-non-canonical":
                    raise
                import base64
                assert isinstance(text, str)
                return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

        monkeypatch.setattr(reader, "ub64", lax)
        assert reader.report(case)["decision"] == "agrees"


def test_the_root_is_no_publishing_zone() -> None:
    assert not reader.within("a.example.com..", ".")
    assert not reader.within("a.example.com", "")
    assert reader.within("A.Example.COM.", "example.com")
