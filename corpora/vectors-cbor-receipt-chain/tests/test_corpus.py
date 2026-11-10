"""The corpus regenerates, forces every check, and refuses a verifier that skips any of them."""

from __future__ import annotations

import importlib.util
import json
import shutil
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


corpus = _load("cbor_receipt_chain_corpus", ROOT / "check_vectors.py")
generator = _load("cbor_receipt_chain_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import cborreceiptchain  # noqa: E402

# The case that has to turn when each check is the only one switched off.
FORCED_BY = {
    "receipt_shape": {"receipt-malformed"},
    "signature": {"signature-flipped"},
    "signer_pinned": {"embedded-key-unpinned", "foreign-key-extends"},
    "no_duplicate_receipt": {"duplicate-line"},
    "single_use": {"reissued-authorization"},
    "chain_order": {"first-receipt-dropped", "middle-receipt-dropped", "receipts-swapped"},
    "head_anchor": {"cut-tail-anchored", "restart-hides-lost-tail"},
}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import cborreceiptchain as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestCborReceiptChainCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {
                p.relative_to(ROOT): p.read_bytes()
                for p in [ROOT / "MANIFEST.json", ROOT / "profile.json", *(ROOT / "cases").rglob("*")]
                if p.is_file()
            }
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = cborreceiptchain.check()
            assert errors == []
            assert answered == len(generator.CASES) == 18

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = cborreceiptchain.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.CASES)

        def test_every_decision_word_is_present(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            assert manifest["counts"] == {"contradicted": 11, "not_established": 4, "supported": 3}

        def test_no_pinned_head_never_reads_as_supported(self) -> None:
            for name in ("unanchored-intact", "cut-tail-unanchored"):
                answer = cborreceiptchain.verify(ROOT / "cases" / name / "case.json")
                assert answer == {"decision": "not_established", "reason": "head_not_anchored"}

    class TestFailingCases:
        @pytest.mark.parametrize("name", cborreceiptchain.CHECKS)
        def test_every_check_is_forced_by_its_cases(self, name: str) -> None:
            _, errors = cborreceiptchain.check(skip=frozenset({name}))
            assert FORCED_BY[name] <= _failed(errors), f"switching off {name} changed no verdict"

        def test_forced_table_covers_every_check(self) -> None:
            assert set(FORCED_BY) == set(cborreceiptchain.CHECKS)

        def test_signature_only_verifier_is_refused(self, tmp_path: Path) -> None:
            _, errors = cborreceiptchain.check(_stub(tmp_path, cborreceiptchain.CHECKS[2:]))
            assert {"embedded-key-unpinned", "duplicate-line", "reissued-authorization",
                    "receipts-swapped", "cut-tail-anchored"} <= _failed(errors)

        def test_verifier_that_rejects_everything_fails_the_controls(self, tmp_path: Path) -> None:
            script = tmp_path / "reject.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "contradicted", '
                              '"reason": "signature"}))\nsys.exit(1)\n', encoding="ascii")
            _, errors = cborreceiptchain.check(f"{sys.executable} {script}")
            assert {"control-intact-anchored", "control-first-prev-pinned",
                    "control-denied-request-repeats"} <= _failed(errors)

        def test_verifier_that_accepts_everything_fails_every_refusal(self, tmp_path: Path) -> None:
            script = tmp_path / "accept.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "supported", '
                              '"reason": "receipt_chain_holds"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = cborreceiptchain.check(f"{sys.executable} {script}")
            assert len(_failed(errors)) == 15

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = cborreceiptchain.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "control-intact-anchored" / "chain.jsonl").write_bytes(b"\n")
            _, errors = cborreceiptchain.check(root=copied)
            assert "control-intact-anchored: fixture digest mismatch" in errors

        def test_mutated_profile_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            profile = json.loads((copied / "profile.json").read_text())
            profile["allow_outcome"] = "permit"
            (copied / "profile.json").write_text(json.dumps(profile, sort_keys=True, indent=2) + "\n")
            answered, errors = cborreceiptchain.check(root=copied)
            assert answered == 0
            assert errors == ["profile digest mismatch"]

        def test_corpus_digest_matches_the_manifest(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]

    class TestOtherFormatProfiles:
        def _case(self, tmp_path: Path, receipts: list[bytes], key: object) -> Path:
            rb = generator.rb
            (tmp_path / "profile.json").write_text(json.dumps(rb.WRAPPED))
            (tmp_path / "chain.jsonl").write_bytes(rb.stream(rb.WRAPPED, receipts))
            head = cborreceiptchain.hashlib.sha256(receipts[-1]).hexdigest()
            case = {"chain": "chain.jsonl", "profile": "profile.json",
                    "signer_keys": [rb.public_hex(key)], "head": head, "count": len(receipts)}
            (tmp_path / "case.json").write_text(json.dumps(case))
            return tmp_path / "case.json"

        def test_json_line_profile_with_pair_keys_is_judged(self, tmp_path: Path) -> None:
            rb = generator.rb
            key = rb.seed_key("wrapped")
            receipts = rb.chain(rb.WRAPPED, key, 3)
            answer = cborreceiptchain.verify(self._case(tmp_path, receipts, key))
            assert answer == {"decision": "supported", "reason": "receipt_chain_holds"}

        def test_json_line_profile_still_refuses_a_dropped_receipt(self, tmp_path: Path) -> None:
            rb = generator.rb
            key = rb.seed_key("wrapped")
            receipts = rb.chain(rb.WRAPPED, key, 4)
            case = self._case(tmp_path, receipts[:1] + receipts[2:], key)
            assert cborreceiptchain.verify(case)["reason"] == "chain_order"
