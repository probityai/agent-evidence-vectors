"""The corpus regenerates, forces every check, and refuses a verifier that reads the status only."""

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


corpus = _load("status_receipt_corpus", ROOT / "check_vectors.py")
generator = _load("status_receipt_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import statusreceipt  # noqa: E402

# Members where the authority's receipt and the credential's own signature both verify, the
# identifiers match, the window holds and the status is active, and which a verifier must still
# reject: only the binding between the receipt and the credential's bytes decides them.
UNBOUND = {"capabilities-escalated", "key-swapped", "key-added", "capabilities-and-key-swapped",
           "receipt-status-only", "receipt-status-only-forged-credential",
           "receipt-for-earlier-version"}
# The four that carry the accepted control's receipt, byte for byte.
SAME_RECEIPT = {"capabilities-escalated", "key-swapped", "key-added",
                "capabilities-and-key-swapped"}
CONTROLS = {"accept-bound", "accept-two-keys-second-signs", "accept-at-issued-at"}
# What a verifier that matches the receipt to the credential by identifier alone omits.
BY_IDENTIFIER = ("receipt_unbound", "credential_digest_mismatch")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import statusreceipt as m\n"
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


def _payload(case: str, name: str) -> dict:  # type: ignore[type-arg]
    envelope = json.loads((ROOT / "cases" / case / name).read_text(encoding="utf-8"))
    return statusreceipt.strictjson.loads(statusreceipt.strictb64.std(envelope["payload"]))


class TestStatusReceiptCorpus:
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

        def test_unbound_rejects_carry_two_signatures_that_verify(self) -> None:
            signed = {e["id"] for e in _manifest()["vectors"]
                      if e["receiptSignatureVerifies"] and e["credentialSignatureVerifies"]
                      and e["expected"]["reason"] in BY_IDENTIFIER}
            assert signed == UNBOUND

        def test_swapped_credentials_sit_beside_the_controls_own_receipt(self) -> None:
            rows = {e["id"]: e for e in _manifest()["vectors"]}
            for name in SAME_RECEIPT:
                assert "accept-bound" in rows[name]["sharedReceipt"]
                assert ((ROOT / "cases" / name / "receipt.json").read_bytes()
                        == (ROOT / "cases" / "accept-bound" / "receipt.json").read_bytes())

        def test_swapped_credentials_keep_the_identifier_and_change_the_bytes(self) -> None:
            genuine = _payload("accept-bound", "credential.json")
            for name in SAME_RECEIPT:
                swapped = _payload(name, "credential.json")
                assert swapped["id"] == genuine["id"]
                assert (swapped["capabilities"], swapped["keys"]) != (genuine["capabilities"],
                                                                      genuine["keys"])

        def test_the_status_only_receipt_names_no_digest(self) -> None:
            binding = _payload("receipt-status-only", "receipt.json")["credential"]
            assert binding == {"id": _payload("accept-bound", "credential.json")["id"]}

    class TestFailingCases:
        def test_identifier_only_verifier_accepts_every_unbound_case(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, BY_IDENTIFIER))
            assert _failed(errors) == UNBOUND

        def test_verifier_without_the_holder_check_accepts_an_unlisted_signer(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, ("credential_signature_invalid",)))
            assert "credential-signed-by-unlisted-key" in _failed(errors)

        @pytest.mark.parametrize("name", statusreceipt.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_rejects_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "reject.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "reject", '
                              '"reason": "credential_digest_mismatch"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert CONTROLS <= _failed(errors)

        def test_exit_status_must_agree_with_the_decision(self, tmp_path: Path) -> None:
            script = tmp_path / "liar.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "accept", '
                              '"reason": "credential_bound"}))\nsys.exit(1)\n',
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
            (copied / "cases" / "accept-bound" / "credential.json").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "accept-bound: fixture digest mismatch" in errors

        def test_a_changed_declared_signature_property_is_a_corpus_error(
            self, tmp_path: Path
        ) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            manifest = json.loads((copied / "MANIFEST.json").read_text(encoding="utf-8"))
            manifest["vectors"][0]["receiptSignatureVerifies"] = False
            manifest["corpusDigest"] = statusreceipt._sha(statusreceipt._json(manifest["vectors"]))
            (copied / "MANIFEST.json").write_bytes(statusreceipt._json(manifest))
            _, errors = corpus.check(root=copied)
            assert "accept-bound: declared signature properties do not hold" in errors
