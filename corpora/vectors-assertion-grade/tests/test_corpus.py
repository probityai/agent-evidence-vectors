"""The corpus regenerates, every rule is load-bearing, and a verifier that trusts the claims is
refused."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through it
    spec.loader.exec_module(module)
    return module


corpus = _load("assertion_grade_corpus", ROOT / "check_vectors.py")
generator = _load("assertion_grade_generator", ROOT / "gen_vectors.py")

I_ROUTES = {"I-HOSTED-WITNESS-QUORUM", "I-NOTARY", "I-TEE", "I-COUNTERPARTY"}
W_PLUS_ROUTES = {"W+-HSM-STREAM", "W+-TEE-JOURNAL"}
# The attacks the identity programme's thresholds name, each failing closed.
ATTACKS = {
    "forged-witness-cosignature",
    "swapped-witness-key",
    "expired-checkpoint",
    "wrong-tenant",
    "w-relabelled-i",
    "coverage-overclaimed",
    "mocked-attestation-chain",
    "receipt-without-map-proof",
    "tenant-declared-counterparty",
    "receipt-replayed-second-slot",
    "receipt-window-exceeded",
    "receipt-key-expired-at-inclusion",
    "receipt-without-actor-stamp",
    "rollback",
    "split-view",
    "notary-saw-commitment-only",
    "notary-customer-custody-root",
    "hsm-without-usage-log",
    "hsm-partition-reinit",
    "hsm-hidden-signature",
    "tee-journal-stale-nonce",
    "gateway-mutually-signed-claimed-i",
}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _rows() -> dict[str, dict]:  # type: ignore[type-arg]
    return {e["id"]: e for e in _manifest()["vectors"]}


def _stub(tmp_path: Path, body: str) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import assertiongrade as m\n" + body,
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestAssertionGradeCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {
                p.relative_to(ROOT): p.read_bytes()
                for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                if p.is_file()
            }
            regenerated = {
                p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
            }
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.all_cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            body = (
                "answer = m.verify(Path(sys.argv[1]))\nprint(json.dumps(answer))\n"
                "sys.exit(m.EXIT_FOR[answer['decision']])\n"
            )
            _, errors = corpus.check(_stub(tmp_path, body))
            assert errors == []

        def test_every_route_has_an_honest_fixture_at_its_grade(self) -> None:
            seen: dict[str, set[str]] = {}
            for row in _manifest()["vectors"]:
                if row["expected"]["decision"] != "accepted":
                    continue
                for a in row["expected"]["assertions"]:
                    seen.setdefault(a["grade"], set()).add(a["route"])
            assert I_ROUTES <= seen["I"]
            assert W_PLUS_ROUTES <= seen["W+"]
            assert {"W", "S"} <= set(seen)

        def test_one_bundle_mixes_grades(self) -> None:
            grades = [a["grade"] for a in _rows()["mixed-bundle"]["expected"]["assertions"]]
            assert grades == ["I", "W", "S"]

        def test_every_counterparty_key_binding_reaches_i(self) -> None:
            rows = _rows()
            for case, anchor in (
                ("counterparty-domain-document", "web-root:web-root-1"),
                ("counterparty-naming-log", "naming-log:names.example/log"),
                ("counterparty-rail-operator", "rail:rail.example"),
            ):
                (a,) = rows[case]["expected"]["assertions"]
                assert (a["grade"], a["independentOf"], a["anchors"]) == ("I", ["tenant"], [anchor])

        def test_corpus_attestation_root_never_prints_production(self) -> None:
            for row in _manifest()["vectors"]:
                for a in row["expected"]["assertions"]:
                    if any(x.startswith("attestation-root:") for x in a["anchors"]) and a[
                        "grade"
                    ] in ("I", "W+"):
                        assert a["qualifier"] == "staging-grade"

        def test_every_rejected_member_names_an_accepted_twin(self) -> None:
            rows = _rows()
            for row in rows.values():
                if row["expected"]["decision"] == "rejected":
                    assert rows[row["pairsWith"]]["expected"]["decision"] == "accepted"

        def test_attacks_are_all_present_and_fail_closed(self) -> None:
            rows = _rows()
            assert ATTACKS <= set(rows)
            for name in ATTACKS:
                assert rows[name]["expected"]["decision"] == "rejected", name

    class TestFailingCases:
        def test_a_verifier_that_echoes_the_claims_is_refused_on_every_attack(
            self, tmp_path: Path
        ) -> None:
            body = (
                "doc = json.loads(Path(sys.argv[1]).read_text())\n"
                "answer = m.decide(doc)\n"
                "for out, a in zip(answer['assertions'], doc['bundle']['assertions']):\n"
                "    out['grade'] = a['claim']['grade']\n"
                "answer['decision'], answer['reason'] = 'accepted', 'grades_derived'\n"
                "print(json.dumps(answer))\nsys.exit(0)\n"
            )
            _, errors = corpus.check(_stub(tmp_path, body))
            assert ATTACKS <= _failed(errors)

        def test_a_verifier_that_rejects_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            body = (
                "answer = m.verify(Path(sys.argv[1]))\nanswer['decision'] = 'rejected'\n"
                "print(json.dumps(answer))\nsys.exit(1)\n"
            )
            _, errors = corpus.check(_stub(tmp_path, body))
            accepted = {
                e["id"] for e in _manifest()["vectors"] if e["expected"]["decision"] == "accepted"
            }
            assert accepted <= _failed(errors)

        def test_mutual_signing_never_raises_a_grade(self) -> None:
            (a,) = _rows()["gateway-mutually-signed-claimed-i"]["expected"]["assertions"]
            assert (a["grade"], a["properties"]) == ("W", ["mutually signed"])

        def test_tenant_declared_counterparty_is_w_with_its_label(self) -> None:
            (a,) = _rows()["tenant-declared-counterparty"]["expected"]["assertions"]
            assert (a["grade"], a["label"]) == ("W", "tenant-declared counterparty")

        def test_an_edited_case_is_refused_by_digest(self, tmp_path: Path) -> None:
            import shutil

            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            target = copied / "cases" / "hosted-external-quorum" / "case.json"
            target.write_text(target.read_text().replace('"decided": "allow"', '"decided": "deny"'))
            _, errors = corpus.check(root=copied)
            assert _failed(errors) == {"hosted-external-quorum"}
