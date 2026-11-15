"""The corpus regenerates, every rule is load-bearing, and lenient checkers are caught."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import resolve_ids  # noqa: E402


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("ave_id_generator", ROOT / "gen_vectors.py")
corpus = _load("ave_id_corpus", ROOT / "check_vectors.py")
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
V120 = MANIFEST["snapshots"]["v1.2.0"]["recordsSha256"]


def _member(entry: dict) -> tuple[object, dict, str]:
    pin = MANIFEST["snapshots"][entry["snapshot"]]["recordsSha256"]
    statuses = resolve_ids.load_snapshot(
        ROOT / "snapshots" / entry["snapshot"] / "ave-records.json", pin
    )
    return json.loads((ROOT / entry["path"]).read_bytes()), statuses, pin


def _stub(tmp_path: Path, body: str) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "import resolve_ids as m\n"
        "output, snapshot, pin = sys.argv[1:4]\n"
        f"{body}\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    for name in ["MANIFEST.json", "INDEX.md"] + [v["path"] for v in MANIFEST["vectors"]]:
        assert (tmp_path / name).read_bytes() == (ROOT / name).read_bytes(), name
    committed = {p.relative_to(ROOT) for p in (ROOT / "cases").rglob("*") if p.is_file()}
    assert committed == {Path(v["path"]) for v in MANIFEST["vectors"]}


def test_reference_checker_answers_every_member() -> None:
    assert corpus.check(None, ROOT) == (len(MANIFEST["vectors"]), [])


def test_reference_checker_runs_as_a_named_verifier(tmp_path: Path) -> None:
    verifier = _stub(
        tmp_path, "sys.exit(m.main([output, '--snapshot', snapshot, '--sha256', pin]))"
    )
    assert corpus.check(verifier, ROOT) == (len(MANIFEST["vectors"]), [])


def test_every_rule_changes_the_answer_of_every_member_that_names_it() -> None:
    for rule in resolve_ids.RULES:
        naming = [v for v in MANIFEST["vectors"] if rule in v["expected"]["codes"]]
        assert naming, rule
        off = tuple(r for r in resolve_ids.RULES if r != rule)
        for entry in naming:
            got = resolve_ids.judge(*_member(entry), off)
            assert (got["verdict"], got["codes"]) != (
                entry["expected"]["verdict"],
                entry["expected"]["codes"],
            )


def test_a_checker_that_ignores_status_is_caught(tmp_path: Path) -> None:
    body = (
        "statuses = {k: 'active' for k in m.load_snapshot(Path(snapshot), pin)}\n"
        "r = m.judge(json.loads(Path(output).read_text()), statuses, pin)\n"
        "print(json.dumps(r))\n"
        "sys.exit(m.EXIT[r['verdict']])"
    )
    _, failures = corpus.check(_stub(tmp_path, body), ROOT)
    assert {f.split(":")[0] for f in failures} == {
        v["id"] for v in MANIFEST["vectors"] if "id-not-active" in v["expected"]["codes"]
    }


def test_a_verifier_whose_exit_or_output_is_wrong_fails(tmp_path: Path) -> None:
    body = "print(json.dumps({'verdict': 'resolves', 'codes': []}))\nsys.exit(1)"
    _, failures = corpus.check(_stub(tmp_path, body), ROOT, decision_only=True)
    assert len(failures) == len(MANIFEST["vectors"])
    _, failures = corpus.check(_stub(tmp_path, "print('not json')"), ROOT)
    assert failures and all("errored" in f for f in failures)


def test_a_status_outside_the_known_list_fails() -> None:
    got = resolve_ids.judge(
        {"findings": [{"ave_id": "AVE-2026-00001"}]}, {"AVE-2026-00001": "withdrawn"}, "0"
    )
    assert got["codes"] == ["id-not-active"]


def test_non_string_and_nested_values_are_malformed() -> None:
    doc = {"runs": [{"results": [{"ruleId": "x", "properties": {"ave_id": 7}}]}]}
    assert resolve_ids.judge(doc, {}, "0")["codes"] == ["id-malformed"]
    assert resolve_ids.judge({"ave_ids": [["a"]]}, {}, "0")["codes"] == ["id-malformed"]
    assert resolve_ids.judge({"ave_ids": [["a"]]}, {}, "0", ("id-unknown",))["codes"] == [
        "id-unknown"
    ]


def test_unreadable_inputs_are_not_judged(tmp_path: Path) -> None:
    records = ROOT / "snapshots" / "v1.2.0" / "ave-records.json"
    output = ROOT / "cases" / "active-resolves-json" / "output.json"
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="ascii")
    listed = tmp_path / "listed.json"
    listed.write_text('{"a": 1}', encoding="ascii")
    cases = [
        (output, records, "0" * 64),
        (bad, records, V120),
        (output, tmp_path / "missing.json", "0" * 64),
        (output, bad, hashlib.sha256(bad.read_bytes()).hexdigest()),
        (output, listed, hashlib.sha256(listed.read_bytes()).hexdigest()),
    ]
    for out, snap, pin in cases:
        assert resolve_ids.main([str(out), "--snapshot", str(snap), "--sha256", pin]) == 2


def test_a_tampered_member_or_snapshot_fails_the_corpus(tmp_path: Path) -> None:
    copy = tmp_path / "corpus"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("__pycache__", "tests"))
    member = copy / MANIFEST["vectors"][0]["path"]
    member.write_bytes(member.read_bytes().replace(b"00002", b"00003"))
    assert corpus.check(None, copy)[1][0].startswith("corpus:")
    sums = copy / "snapshots" / "v1.3.0" / "SHA256SUMS"
    sums.write_bytes(sums.read_bytes() + b"0" * 64 + b"  extra.json\n")
    assert any("SHA256SUMS" in f for f in corpus.check(None, copy)[1])
