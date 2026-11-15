"""The corpus regenerates, forces every check, and refuses a reader that stops at
"the signature is valid and the key is trusted", or that credits the issuer's own clock."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/preaction-verdict/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("preaction_verdict_corpus", ROOT / "check_vectors.py")
generator = _load("preaction_verdict_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import preactionverdict  # noqa: E402

# The checks a reader that stops after the signature and the key set runs.
SIGNATURE_AND_KEY_SET = ("contract_id_missing", "contract_id_unknown", "malformed_case",
                         "event_id", "signature", "key_not_in_set")
# Checks that stand before any record is read, so a case for one cannot be isolated.
UNISOLATED = ("contract_id_missing", "contract_id_unknown", "malformed_case")
# With the key-set check off these still meet the binding check, which names the same record.
OTHER_REFUSAL_WITHOUT = {"wrong-key-names-issuer": "key_binding"}
# With a beacon or an anchor check off, a case written for the other still refuses.
AUTHENTICATED = ("beacon_untrusted", "anchor_missing", "anchor_commitment",
                 "anchor_header_untrusted", "anchor_after_action")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import preactionverdict as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestPreactionVerdictCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_contract_id_is_the_published_one(self) -> None:
            assert preactionverdict.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "deny"}
            assert reasons == set(preactionverdict.CHECKS)

        def test_the_manifest_credits_the_reader_contract_it_follows(self) -> None:
            assert [c["name"] for c in _manifest()["credits"]] == ["babyblueviper1"]

    class TestSignatureArithmetic:
        # The three official BIP-340 vectors 0, 1 and 5 from the BIP's test-vectors.csv.
        VECTORS = (
            ("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
             "0000000000000000000000000000000000000000000000000000000000000000",
             "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
             "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", True),
            ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
             "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
             "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
             "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", True),
            ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
             "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
             "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
             "3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", False),
        )

        @pytest.mark.parametrize(("pubkey", "message", "signature", "expected"), VECTORS)
        def test_official_vectors(self, pubkey: str, message: str, signature: str,
                                  expected: bool) -> None:
            assert preactionverdict.schnorr_verify(
                bytes.fromhex(message), bytes.fromhex(pubkey),
                bytes.fromhex(signature)) is expected

    class TestFailingCases:
        def test_signature_and_key_set_only_reader_is_refused_on_binding_time_and_anchor(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in preactionverdict.CHECKS if c not in SIGNATURE_AND_KEY_SET)
            _, errors = corpus.check(_stub(tmp_path, skip))
            unchecked = set(preactionverdict.CHECKS) - set(SIGNATURE_AND_KEY_SET)
            expected = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["reason"] in unchecked}
            assert _failed(errors) == expected
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["id"] in expected}
            assert reasons == unchecked

        def test_issuer_clock_only_reader_credits_the_unanchored_cases(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, AUTHENTICATED))
            expected = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["reason"] in AUTHENTICATED}
            assert _failed(errors) == expected
            assert len(expected) >= 6

        @pytest.mark.parametrize("name", preactionverdict.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_its_own_check_alone(self) -> None:
            """Switching off the one check a denied case names turns it into an
            allow, so the defect is the only thing between it and its control."""
            for entry in _manifest()["vectors"]:
                reason = entry["expected"]["reason"]
                if entry["expected"]["decision"] != "deny" or reason in UNISOLATED:
                    continue
                answer = preactionverdict.verify(ROOT / entry["path"] / "case.json",
                                                 frozenset({reason}))
                if entry["id"] in OTHER_REFUSAL_WITHOUT:
                    assert answer == {"decision": "deny",
                                      "reason": OTHER_REFUSAL_WITHOUT[entry["id"]]}, entry["id"]
                else:
                    assert answer["decision"] == "allow", entry["id"]

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "signature"}))\nsys.exit(1)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "allow"}
            assert controls and controls <= _failed(errors)

        def test_verifier_that_allows_everything_fails_every_denial(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "allow.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                              '"reason": "verified_issuer_clock"}))\nsys.exit(0)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            denied = {e["id"] for e in _manifest()["vectors"]
                      if e["expected"]["decision"] == "deny"}
            assert denied <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-issuer-clock" / "case.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-issuer-clock: fixture digest mismatch" in errors
