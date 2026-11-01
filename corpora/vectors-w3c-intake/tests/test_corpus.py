"""The intake corpus, the checker that judges it, and the records it admits.

Run: uv run --locked --extra dev --extra generators pytest vectors-w3c-intake/tests -q
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "vectors-w3c-intake"
MODULE = REPO / "packaging" / "agent_evidence_vectors" / "w3cintake.py"
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import w3cintake  # noqa: E402

GROUNDS = sorted(w3cintake.G.values())
RECORDS = sorted((REPO / "release" / "intake").glob("*.intake.json"))


def manifest() -> dict[str, Any]:
    loaded = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), "MANIFEST.json is not a JSON object"
    return loaded


def cli(*args: str, cwd: Path = REPO) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agent_evidence_vectors.w3cintake", *args],
        cwd=cwd, capture_output=True, text=True, check=False,
        env={"PYTHONPATH": str(REPO / "packaging"), "PATH": "/usr/bin:/bin"},
    )


def test_the_committed_corpus_is_judged_clean() -> None:
    judged = w3cintake.judge(str(CORPUS))
    assert judged.ok(), w3cintake.render(judged, w3cintake.SUITE)


def test_the_corpus_regenerates_byte_identically() -> None:
    proc = subprocess.run(
        [sys.executable, str(CORPUS / "gen_vectors.py"), "--check"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_ground_is_bound_and_has_both_kinds_of_member() -> None:
    data = manifest()
    assert [row["id"] for row in data["requirements"]] == GROUNDS
    for ground in GROUNDS:
        kinds = {e["kind"] for e in data["vectors"] if ground in e["requirements"]}
        assert kinds == {"accept", "reject"}, ground


def mutant(ground: str, tmp_path: Path) -> ModuleType:
    """The checker with every line that adds this ground deleted from its source."""
    number = int(ground.rsplit("-", 1)[1])
    source = MODULE.read_text(encoding="utf-8")
    pattern = re.compile(rf"f\.add\(G\[{number}\],")
    assert pattern.search(source), f"no check adds {ground}"
    path = tmp_path / f"w3cintake_without_{number}.py"
    path.write_text(pattern.sub("(lambda *_: None)(None,", source), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("ground", GROUNDS)
def test_deleting_a_grounds_check_turns_the_corpus_red(ground: str, tmp_path: Path) -> None:
    judged = mutant(ground, tmp_path).judge(str(CORPUS))
    assert not judged.ok(), f"deleting the check for {ground} left every member passing"
    failing = [mid for mid, _, findings in judged.members if findings]
    expected = [e["id"] for e in manifest()["vectors"] if e["expected"]["rejects"] == [ground]]
    assert set(expected) <= set(failing)


def member_of(ground: str, kind: str, rooted: bool) -> Path:
    for entry in manifest()["vectors"]:
        if entry["requirements"] == [ground] and entry["kind"] == kind and (
            (entry["root"] is not None) == rooted
        ):
            return CORPUS / str(entry["file"])
    raise AssertionError(f"no {kind} member for {ground} with root={rooted}")


def test_the_command_line_refuses_and_names_the_ground() -> None:
    proc = cli("--member", str(member_of("W3C-I-014", "reject", False)))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "REFUSE W3C-I-014" in proc.stdout
    assert "verdict: refused under [W3C-I-014]" in proc.stdout
    assert "bytes on disk: not read (no --root)" in proc.stdout


def test_the_command_line_says_which_checks_read_bytes() -> None:
    proc = cli("--member", str(member_of("W3C-I-003", "reject", True)))
    assert proc.returncode == 1, proc.stdout
    assert "bytes on disk: read under" in proc.stdout
    assert "REFUSE W3C-I-003" in proc.stdout
    admitted = cli("--member", str(member_of("W3C-I-003", "accept", True)))
    assert admitted.returncode == 0, admitted.stdout
    verdict = "verdict: admitted, no intake rejection ground applies"
    assert admitted.stdout.rstrip().endswith(verdict)


def test_a_root_check_does_not_run_without_a_root() -> None:
    """The member-moved tree refuses under W3C-I-003 only when its bytes are read."""
    document = json.loads(member_of("W3C-I-003", "reject", True).read_text(encoding="utf-8"))
    assert w3cintake.rejections(document["record"]) == []


def test_a_walk_never_leaves_the_named_root() -> None:
    """A root such as ".." lists nothing; the corpus's own vectors directory does."""
    assert w3cintake._walk(str(CORPUS), "vectors", ".json", True)
    for rel in ("..", "../corpora", "vectors/..", "/etc", "", "."):
        assert w3cintake._walk(str(CORPUS), rel, "", True) == [], rel


def test_an_unreadable_record_exits_two(tmp_path: Path) -> None:
    broken = tmp_path / "record.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli(str(broken)).returncode == 2


def test_every_published_corpus_has_an_intake_record() -> None:
    listed = [
        line.split()[1].split("/")[0]
        for line in (REPO / "release" / "CORPUS-DIGESTS.txt").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert sorted(f"{d}.intake.json" for d in listed) == sorted(r.name for r in RECORDS)


@pytest.mark.parametrize("record", RECORDS, ids=lambda p: p.name)
def test_every_intake_record_is_admitted_under_the_repository_root(record: Path) -> None:
    proc = cli(str(record.relative_to(REPO)), "--root", ".")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_record_whose_native_output_moved_is_refused(tmp_path: Path) -> None:
    """The records are checked against bytes: a changed native line is caught."""
    record = json.loads((REPO / "release/intake/vectors-grade-floor.intake.json").read_text())
    record["checks"][0]["native"]["reasons"] = ["transcribed after the run"]
    record["checks"][0]["state"] = "fail"
    record["state"] = "fail"
    assert w3cintake.G[19] in w3cintake.rejections(record, str(REPO))


def test_the_scitt_checker_attributes_a_finding_to_its_member(tmp_path: Path) -> None:
    copy = tmp_path / "vectors-scitt-cose"
    shutil.copytree(REPO / "vectors-scitt-cose", copy)
    data = json.loads((copy / "MANIFEST.json").read_text())
    entry = data["vectors"][0]
    target = copy / entry["file"]
    body = bytearray(target.read_bytes())
    body[len(body) // 2] ^= 0x01
    target.write_bytes(bytes(body))
    proc = subprocess.run(
        [sys.executable, str(copy / "check_vectors.py"), "--json"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 1
    result = json.loads(proc.stdout)
    named = {m["id"]: m.get("findings", []) for m in result["members"]}
    assert named[entry["id"]], "the flipped member carries no finding"


def test_the_signature_check_passes_rfc_8032_and_refuses_a_changed_message() -> None:
    """RFC 8032 section 7.1, test 1: the stdlib verifier the signed anchor relies on."""
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
        "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert w3cintake.ed25519_verify(public, b"", signature)
    assert not w3cintake.ed25519_verify(public, b"x", signature)
    assert not w3cintake.ed25519_verify(public, b"", signature[:63] + b"\x00")


def test_the_release_key_is_read_as_an_ed25519_key() -> None:
    key = w3cintake.ed25519_public_key((REPO / "release" / "cosign.pub").read_bytes())
    assert key is not None and len(key) == 32


def generator() -> ModuleType:
    path = REPO / "scripts" / "gen-intake-records.py"
    spec = importlib.util.spec_from_file_location("gen_intake_records", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_digest_routine_that_is_not_here_is_refused(tmp_path: Path) -> None:
    """owner() names the routine a record's anchor cites, and refuses a missing one."""
    module = generator()
    (tmp_path / "vectors-example").mkdir()
    module.__dict__["REPO"] = tmp_path
    with pytest.raises(SystemExit, match="has no digest routine"):
        module.owner("vectors-example")
    (tmp_path / "vectors-example" / "gen_vectors.py").write_text("")
    assert module.owner("vectors-example") == "vectors-example/gen_vectors.py"
