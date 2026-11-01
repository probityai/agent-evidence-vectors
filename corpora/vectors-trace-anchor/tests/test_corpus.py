"""The corpus regenerates, forces every check, and refuses a receipt-trusting verifier."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("trace_anchor_corpus", ROOT / "check_vectors.py")
generator = _load("trace_anchor_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import traceanchor  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
BY_REASON: dict[str, list[str]] = {}
for _entry in MANIFEST["vectors"]:
    BY_REASON.setdefault(_entry["expected"]["reason"], []).append(_entry["id"])
# A carried root or count that lies while the proof replays to the entry is
# caught by that comparison and nothing else, so switching it off accepts.
CAUGHT_ONLY_BY_ITS_RULE = {"receipt-root-lies", "receipt-count-lies"}


def _stub(tmp_path: Path, body: str) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import traceanchor as m\n"
        "case = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        f"{body}\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestTraceAnchorCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in [tmp_path / "MANIFEST.json", *(tmp_path / "cases").rglob("*")]
                           if p.is_file()}
            assert committed == regenerated

        def test_reference_reader_answers_every_case(self) -> None:
            answered, errors = corpus.check(None, ROOT)
            assert errors == []
            assert answered == len(MANIFEST["vectors"])

        def test_every_check_is_named_by_a_member(self) -> None:
            assert set(BY_REASON) - {traceanchor.LINK_UNCHECKED} == set(traceanchor.CHECKS)

        def test_reference_reader_runs_as_a_named_verifier(self, tmp_path: Path) -> None:
            verifier = _stub(tmp_path, "answer = m.verify(Path(sys.argv[1]))")
            answered, errors = corpus.check(verifier, ROOT)
            assert (answered, errors) == (len(MANIFEST["vectors"]), [])

        def test_both_constructions_agree_on_every_accepted_root(self) -> None:
            for entry in MANIFEST["vectors"]:
                if entry["expected"]["decision"] != traceanchor.ANCHORED:
                    continue
                case = json.loads((ROOT / entry["path"] / "case.json").read_text("utf-8"))
                receipt, claim_entry = case["receipt"], case["entry"]
                assert traceanchor.replays(case["claim"], receipt["leaf_index"],
                                           receipt["audit_path"], claim_entry["leaf_count"],
                                           claim_entry["merkle_root"]), entry["id"]

    class TestRejectionCases:
        @pytest.mark.parametrize("check", traceanchor.CHECKS)
        def test_switching_a_check_off_changes_every_member_naming_it(
                self, check: str) -> None:
            _, errors = corpus.check(None, ROOT, frozenset({check}))
            assert _failed(errors) == set(BY_REASON[check])

        def test_a_lying_carried_field_is_caught_only_by_its_comparison(self) -> None:
            for name in CAUGHT_ONLY_BY_ITS_RULE:
                entry = next(e for e in MANIFEST["vectors"] if e["id"] == name)
                path = ROOT / entry["path"] / "case.json"
                off = frozenset({entry["expected"]["reason"]})
                assert traceanchor.verify(path, off)["decision"] == traceanchor.ANCHORED

        def test_a_verifier_that_trusts_the_receipt_root_is_refused(
                self, tmp_path: Path) -> None:
            # Before trace-spec#533 the suite replayed the proof against the
            # root and count the receipt brought, and took no entry at all.
            body = (
                "r = case.get('receipt')\n"
                "ok = isinstance(r, dict) and 'merkle_root' in r and 'leaf_count' in r and "
                "not m._receipt_malformed(r) and "
                "m.replays(case.get('claim'), r['leaf_index'], r['audit_path'], "
                "r['leaf_count'], r['merkle_root'])\n"
                "answer = {'decision': 'anchored' if ok else 'refused', "
                "'reason': m.LINK_UNCHECKED if ok else 'proof_does_not_replay'}"
            )
            _, errors = corpus.check(_stub(tmp_path, body), ROOT, decision_only=True)
            assert {"entry-absent", "self-anchored-no-entry", "self-anchored-with-real-entry",
                    "receipt-subtree-root", "receipt-count-lies"} <= _failed(errors)

        def test_a_tampered_case_is_a_corpus_error(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            case = tmp_path / "cases" / "anchored-one-leaf" / "case.json"
            case.write_bytes(case.read_bytes().replace(b"b-one", b"b-0ne"))
            _, errors = corpus.check(None, tmp_path)
            assert errors == ["anchored-one-leaf: fixture digest mismatch"]

        def test_a_verifier_that_prints_nothing_answers_nothing(self, tmp_path: Path) -> None:
            _, errors = corpus.check(f"{sys.executable} -c pass", ROOT)
            assert len(errors) == len(MANIFEST["vectors"])
