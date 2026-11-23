"""The checker scores a proposed member on what the corpus claims of it, never on
the published reader's verdict, and still fails it on its bytes."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROPOSED = {"revision": "draft-ietf-05", "text": "a record dated at the deadline releases the hold"}
VERDICT = "CS55 cs55-set-zero-settlement-released-at-deadline-proposed: expected set malformed"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # A dataclass resolves its module through sys.modules while the class body
    # runs, so the module is registered before it executes.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


corpus = _load("audit_record_check_vectors", ROOT / "check_vectors.py")
from agent_evidence_vectors import auditrecord  # noqa: E402


def _member(tmp_path: Path, raw: bytes, *, proposed: bool, identifier: str = "") -> dict[str, Any]:
    (tmp_path / "member.json").write_bytes(raw)
    entry: dict[str, Any] = {
        "id": identifier or "v" + hashlib.sha256(raw).hexdigest()[:16],
        "draftId": "CS55",
        "kind": "reject",
        "file": "member.json",
        "expected": {"set": {"verdict": "malformed", "codes": ["consumption-set-release-unshown"]}},
    }
    if proposed:
        entry["proposed"] = PROPOSED
    return entry


def _judged(entry: dict[str, Any], findings: list[str]) -> Any:
    judged = auditrecord.Judged()
    judged.members.append((entry["id"], "reject", findings))
    return judged


def test_proposed_member_verdict_is_a_note_not_a_failure(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(corpus, "HERE", str(tmp_path))
    entry = _member(tmp_path, b'{"set": "cs55"}', proposed=True)
    scored = corpus._score_published_text(_judged(entry, [VERDICT]), {"vectors": [entry]})
    assert scored.members == [(entry["id"], "reject", [])]
    assert scored.ok()
    assert scored.notes == [f"{entry['id']} (proposed text, not scored): {VERDICT}"]


def test_proposed_member_still_fails_on_its_bytes(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(corpus, "HERE", str(tmp_path))
    raw = b'{"set": "cs55"}'
    entry = _member(tmp_path, raw, proposed=True, identifier="vdeadbeefdeadbeef")
    scored = corpus._score_published_text(_judged(entry, [VERDICT]), {"vectors": [entry]})
    recomputed = "v" + hashlib.sha256(raw).hexdigest()[:16]
    assert scored.members == [
        (
            "vdeadbeefdeadbeef",
            "reject",
            [
                f"file bytes hash to {recomputed} and the manifest calls this member "
                "vdeadbeefdeadbeef"
            ],
        )
    ]
    assert not scored.ok()


def test_published_member_verdict_still_fails(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(corpus, "HERE", str(tmp_path))
    entry = _member(tmp_path, b'{"set": "cs54"}', proposed=False)
    judged = _judged(entry, [VERDICT])
    scored = corpus._score_published_text(judged, {"vectors": [entry]})
    assert scored.members == judged.members
    assert scored.notes == []
    assert not scored.ok()


def test_failing_leaves_proposed_members_out_of_the_section_sweep(monkeypatch: Any) -> None:
    monkeypatch.setattr(corpus, "_fails", lambda entry, policy: True)
    manifest = {
        "vectors": [
            {"draftId": "CS54", "expected": {"set": {}}},
            {"draftId": "CS55", "expected": {"set": {}}, "proposed": PROPOSED},
        ]
    }
    assert corpus._failing(manifest) == "CS54"


def test_section_sweep_counts_a_proposed_member_the_reader_already_agrees_with(
    monkeypatch: Any,
) -> None:
    manifest = {
        "vectors": [
            {"draftId": "PR12", "expected": {"verdict": "valid"}, "proposed": PROPOSED},
            {"draftId": "CS55", "expected": {"set": {}}, "proposed": PROPOSED},
        ]
    }
    monkeypatch.setattr(corpus.auditrecord, "policy_for", lambda manifest, entry: None)
    monkeypatch.setattr(corpus, "_fails", lambda entry, policy: entry["draftId"] == "CS55")
    counted = corpus._agreeing_proposed(manifest)
    assert counted == frozenset({"PR12"})
    assert corpus._failing(manifest, counted) == ""
    monkeypatch.setattr(corpus, "_fails", lambda entry, policy: True)
    assert corpus._failing(manifest, counted) == "PR12"
    assert corpus._failing(manifest) == ""
