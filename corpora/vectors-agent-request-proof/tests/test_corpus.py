"""The corpus regenerates, forces every check, and refuses a proof-signature-only verifier."""

from __future__ import annotations

import base64
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


corpus = _load("agent_request_proof_corpus", ROOT / "check_vectors.py")
generator = _load("agent_request_proof_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import agentrequestproof  # noqa: E402

# Members whose proof verifies under the JWK the record carries, and which a
# verifier must still reject: the binding of the proof to the recorded request,
# the registered key and the recorder's earlier records decides.
SIGNED_REJECTS = {
    "recorder-signature-invalid",
    "wrong-typ",
    "embedded-jwk",
    "thumbprint-mismatch",
    "principal-mismatch",
    "htm-htu-mismatch",
    "body-digest-mismatch",
    "expired",
    "excessive-lifetime",
    "replayed-jti",
}
CONTROLS = {"request-bound", "upstream-golden", "distinct-jti-sequence"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import agentrequestproof as m\n"
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


class TestAgentRequestProofCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
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

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_controls_are_the_verified_members(self) -> None:
            verified = {
                e["id"] for e in _manifest()["vectors"] if e["expected"]["decision"] == "verified"
            }
            assert verified == CONTROLS

        def test_upstream_golden_is_the_fixture_byte_for_byte(self) -> None:
            envelope = json.loads(
                (ROOT / "cases" / "upstream-golden" / "envelope-1.json").read_text(encoding="utf-8")
            )
            stmt = json.loads(base64.b64decode(envelope["payload"]))
            assert stmt["predicate"]["proof"]["jws"] == generator.UPSTREAM_ASSERTION
            assert stmt["predicate"]["principal"]["jwk"]["n"] == generator.UPSTREAM_N

        def test_payload_is_rfc8785(self) -> None:
            for path in (ROOT / "cases").rglob("envelope-*.json"):
                envelope = json.loads(path.read_text(encoding="utf-8"))
                payload = base64.b64decode(envelope["payload"])
                assert bytes(generator.rail.jcs_dumps(json.loads(payload))) == payload

        def test_signed_rejects_carry_a_proof_that_verifies(self) -> None:
            signed = {
                e["id"]
                for e in _manifest()["vectors"]
                if e["proofSignatureVerifies"] and e["expected"]["decision"] == "rejected"
            }
            assert signed == SIGNED_REJECTS

    class TestFailingCases:
        def test_proof_signature_only_verifier_is_refused_on_every_binding_case(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(
                c
                for c in agentrequestproof.CHECKS
                if c not in {"statement_malformed", "proof_signature_invalid"}
            )
            _, errors = corpus.check(_stub(tmp_path, skip))
            assert SIGNED_REJECTS <= _failed(errors)

        @pytest.mark.parametrize("name", agentrequestproof.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_rejects_everything_fails_the_controls(self, tmp_path: Path) -> None:
            script = tmp_path / "reject.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "rejected", '
                '"reason": "proof_expired"}))\nsys.exit(1)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert CONTROLS <= _failed(errors)

        def test_exit_status_must_agree_with_the_decision(self, tmp_path: Path) -> None:
            script = tmp_path / "liar.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "verified", '
                '"reason": "request_bound"}))\nsys.exit(1)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert any("disagrees with decision" in error for error in errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "request-bound" / "envelope-1.json").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "request-bound: fixture digest mismatch" in errors

        def test_undersized_modulus_is_refused(self) -> None:
            small = {"e": "AQAB", "kty": "RSA", "n": agentrequestproof.b64url(b"\xc1" * 128)}
            assert not agentrequestproof.rs256_verify(small, b"x", b"\x01" * 128)
