"""The corpus regenerates, forces every check, and refuses a verifier that only
checks that the leaf grant names the tool and has not expired."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/grant-use/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("grant_use_corpus", ROOT / "check_vectors.py")
generator = _load("grant_use_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import grantuse  # noqa: E402

CONTRACT_CHECKS = ("contract_id_missing", "contract_id_unknown", "malformed_record")
# What a capability library ships: the token parses, its leaf names the tool, and
# the leaf has not expired. Nothing else.
NAIVE_CHECKS = (*CONTRACT_CHECKS, "tool_not_granted")
# The denials such a verifier still catches through its own expiry test.
NAIVE_EXPIRY_CATCHES = {"use-at-leaf-expiry"}
# Two denials cannot be isolated, and why. An effect observed before the leaf is
# in force has no permit that could have been minted while it was, so it also
# fails the permit's window. An effect naming a permit nobody minted leaves the
# permit checks after it nothing to read.
NOT_ISOLABLE = {"use-before-not-before", "permit-not-minted"}


def _stub(tmp_path: Path, skip: tuple[str, ...], naive: bool = False) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import grantuse as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        f"if {naive!r} and answer['decision'] == 'allow':\n"
        "    record = json.loads(Path(sys.argv[1]).read_text())\n"
        "    leaf = record['grants'][-1]\n"
        "    if m._when(record['effect']['observedAt']) >= m._when(leaf['expiresAt']):\n"
        "        answer = {'decision': 'deny', 'reason': 'grant_not_in_force'}\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _denied() -> list[dict]:  # type: ignore[type-arg]
    return [e for e in _manifest()["vectors"] if e["expected"]["decision"] == "deny"]


class TestGrantUseCorpus:
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
            assert grantuse.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _denied()}
            assert reasons == set(grantuse.CHECKS)

        def test_every_allow_is_an_authorised_use(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "allow"}
            assert reasons == {grantuse.ALLOW_REASON}

        def test_digest_is_the_canonical_bytes(self) -> None:
            assert grantuse.digest({"b": 1, "a": "x"}) == (
                "sha256:" + __import__("hashlib").sha256(b'{"a":"x","b":1}').hexdigest())

    class TestFailingCases:
        def test_naive_verifier_lets_through_exactly_the_authority_cases(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in grantuse.CHECKS if c not in NAIVE_CHECKS)
            _, errors = corpus.check(_stub(tmp_path, skip, naive=True))
            expected = {e["id"] for e in _denied()
                        if e["expected"]["reason"] not in NAIVE_CHECKS} - NAIVE_EXPIRY_CATCHES
            assert _failed(errors) == expected
            assert "use-before-not-before" in expected

        @pytest.mark.parametrize("name", grantuse.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_its_own_check_alone(self) -> None:
            """Switching off the one check a denied case names turns it into an
            allow, so the defect is the only thing between it and its control."""
            for entry in _denied():
                reason = entry["expected"]["reason"]
                if reason in CONTRACT_CHECKS or entry["id"] in NOT_ISOLABLE:
                    continue
                answer = grantuse.verify(
                    ROOT / entry["path"] / "record.json", frozenset({reason}))
                assert answer == {"decision": "allow", "reason": "authorized_use"}, entry["id"]

        def test_the_cases_that_cannot_be_isolated_are_the_named_ones(self) -> None:
            stuck = set()
            for entry in _denied():
                reason = entry["expected"]["reason"]
                if reason in CONTRACT_CHECKS:
                    continue
                answer = grantuse.verify(ROOT / entry["path"] / "record.json",
                                         frozenset({reason}))
                if answer["decision"] != "allow":
                    stuck.add(entry["id"])
            assert stuck == NOT_ISOLABLE

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "grant_widened"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "allow"}
            assert controls and controls <= _failed(errors)

        def test_verifier_that_allows_everything_fails_every_denial(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "allow.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                              '"reason": "authorized_use"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert _failed(errors) == {e["id"] for e in _denied()}

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-two-hop-attenuated" / "record.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-two-hop-attenuated: fixture digest mismatch" in errors

        def test_a_claimed_digest_is_recomputed(self, tmp_path: Path) -> None:
            """Editing a granted argument constraint without touching any digest
            field breaks the chain, because the reader recomputes the leaf's
            parent digest rather than reading it."""
            body = json.loads((ROOT / "cases" / "allow-two-hop-attenuated" /
                               "record.json").read_text(encoding="utf-8"))
            body["grants"][0]["constraints"]["payments.refund"]["amount"]["range"] = [1, 999]
            path = tmp_path / "record.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            assert grantuse.verify(path) == {"decision": "deny", "reason": "grant_chain_broken"}
