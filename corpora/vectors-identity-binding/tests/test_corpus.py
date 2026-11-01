"""The corpus regenerates, forces every check, and refuses a signature-only verifier."""

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


corpus = _load("identity_binding_corpus", ROOT / "check_vectors.py")
generator = _load("identity_binding_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import identitybinding  # noqa: E402

# Members whose DSSE signature verifies under the key the envelope names, and
# which a verifier must still reject: the binding, not the signature, decides.
SIGNED_REJECTS = {"subject-swap", "web-key-rotated-out", "wba-deactivated-before-signing",
                  "wba-fingerprint-mismatch", "key-not-in-authentication"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import identitybinding as m\n"
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


class TestIdentityBindingCorpus:
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

        def test_both_methods_have_a_verified_member(self) -> None:
            verified = [e for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "verified"]
            methods = {e["didMethod"] for e in verified}
            assert methods == {"web", "wba"}

        def test_the_wba_member_carries_its_binding_fingerprint(self) -> None:
            case = ROOT / "cases" / "wba-verified"
            envelope = json.loads((case / "envelope.json").read_text(encoding="utf-8"))
            subject = identitybinding.subject_of(envelope)
            assert subject.startswith("did:wba:") and ":e1_" in subject
            assert identitybinding.well_formed(subject)

        def test_signed_rejects_carry_a_signature_that_verifies(self) -> None:
            signed = {e["id"] for e in _manifest()["vectors"]
                      if e["signatureVerifies"] and e["expected"]["decision"] == "rejected"}
            assert signed == SIGNED_REJECTS

    class TestFailingCases:
        def test_signature_only_verifier_is_refused_on_every_binding_case(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in identitybinding.CHECKS if c != "signature_invalid")
            _, errors = corpus.check(_stub(tmp_path, skip))
            assert SIGNED_REJECTS <= _failed(errors)

        @pytest.mark.parametrize("name", identitybinding.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_rejects_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "reject.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "rejected", '
                              '"reason": "signature_invalid"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {"web-verified", "wba-verified", "web-signed-before-rotation"} <= _failed(
                errors)

        def test_exit_status_must_agree_with_the_decision(self, tmp_path: Path) -> None:
            script = tmp_path / "liar.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "verified", '
                              '"reason": "subject_bound"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert any("disagrees with decision" in error for error in errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "web-verified" / "envelope.json").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "web-verified: fixture digest mismatch" in errors

        @pytest.mark.parametrize("did", [
            "did:wba:agents.example.com/agents/billing",
            "did:wba:192.0.2.7",
            "did:wba:example.com:user:alice:e1_short",
            "did:web:",
            "did:WEB:example.com",
            "did:wba:example.com:3000:user",
        ])
        def test_malformed_did_strings_are_refused(self, did: str) -> None:
            assert not identitybinding.well_formed(did)

        @pytest.mark.parametrize("did", [
            "did:web:agents.example.com",
            "did:web:agents.example.com%3A8443:alice",
            "did:wba:example.com",
            "did:wba:example.com:user:alice:e1_" + "A" * 43,
        ])
        def test_well_formed_did_strings_are_accepted(self, did: str) -> None:
            assert identitybinding.well_formed(did)
