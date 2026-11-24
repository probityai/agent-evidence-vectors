"""The corpus regenerates, forces every check, and refuses reading an outage as a removal."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("key_directory_corpus", ROOT / "check_vectors.py")
generator = _load("key_directory_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import keydirectory  # noqa: E402

# Members where the fetch is not evidence: a verifier must keep its cached keys.
KEEPS_CACHE = {"status-404-keeps-cache", "status-503-keeps-cache",
               "transport-failure-keeps-cache", "redirect-not-followed",
               "html-error-page-with-200", "wrong-media-type-at-well-known",
               "refused-with-empty-key-set-keeps-cache", "limit-refused-keeps-cache",
               "no-keys-member-keeps-cache", "empty-body-keeps-cache"}
# The request every broken-read case shares with empty-key-set-evicts: it names the key the
# verifier holds, so a verifier that serves the stale key on a failed load is caught too.
BROKEN_READS = {"refused-with-empty-key-set-keeps-cache", "limit-refused-keeps-cache",
                "no-keys-member-keeps-cache", "empty-body-keeps-cache"}
# Members where the directory resolved without the key: a verifier must evict it.
EVICTS = {"empty-key-set-evicts", "key-removed-other-kept"}


def _script(tmp_path: Path, body: str) -> str:
    script = tmp_path / "verifier.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import keydirectory as m\n"
        "case = json.loads(Path(sys.argv[1]).read_text())\n"
        "answer = m.verify(Path(sys.argv[1]))\n"
        + body +
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestKeyDirectoryCorpus:
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
            answered, errors = corpus.check(_script(tmp_path, ""))
            assert errors == []
            assert answered == len(generator.cases())

        def test_the_drafts_example_kid_is_not_its_thumbprint(self) -> None:
            key = generator.draft_jwk()
            assert keydirectory.jwk_thumbprint(key) == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
            assert generator.DRAFT_WRONG_KID != keydirectory.jwk_thumbprint(key)

        def test_cache_partition_is_declared(self) -> None:
            by_id = {e["id"]: e["expected"]["cache"] for e in _manifest()["vectors"]}
            assert {n for n, c in by_id.items() if c == keydirectory.KEPT} == KEEPS_CACHE
            assert EVICTS <= {n for n, c in by_id.items() if c == keydirectory.REPLACED}

    class TestFailingCases:
        @pytest.mark.parametrize("name", keydirectory.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_reads_any_failure_as_removal_is_refused(
            self, tmp_path: Path
        ) -> None:
            # The outage-revokes mistake: every non-directory answer empties the cache.
            body = ("if answer['cache'] == 'kept':\n"
                    "    answer['cache'] = 'replaced'; answer['cacheAfter'] = []\n")
            _, errors = corpus.check(_script(tmp_path, body))
            assert _failed(errors) == KEEPS_CACHE

        def test_refusal_and_evicting_empty_set_differ_only_in_the_status(self) -> None:
            def load(name: str) -> tuple[dict[str, Any], bytes]:
                directory = ROOT / "cases" / name
                return (json.loads((directory / "case.json").read_text(encoding="utf-8")),
                        (directory / "response.body").read_bytes())

            read, read_body = load("empty-key-set-evicts")
            refused, refused_body = load("refused-with-empty-key-set-keeps-cache")
            assert read_body == refused_body
            assert json.loads(read_body) == {"keys": []}
            assert {k: v for k, v in read["fetch"].items() if k != "status"} == {
                k: v for k, v in refused["fetch"].items() if k != "status"}
            assert (read["fetch"]["status"], refused["fetch"]["status"]) == (200, 403)
            for field in ("cached", "directoryUrl", "keyid"):
                assert read[field] == refused[field]

        @pytest.mark.parametrize("name", sorted(BROKEN_READS))
        def test_every_broken_read_names_the_key_the_verifier_holds(self, name: str) -> None:
            case = json.loads((ROOT / "cases" / name / "case.json").read_text(encoding="utf-8"))
            assert case["keyid"] in case["cached"]

        def test_verifier_that_ignores_the_status_reads_a_refusal_as_a_removal(self) -> None:
            # Judging the bytes and not the status: a 403 carrying an empty key set evicts.
            _, errors = corpus.check(skip=frozenset({"discovery_failed"}))
            refused = [e for e in errors if e.startswith("refused-with-empty-key-set-keeps-cache:")]
            assert len(refused) == 1
            assert "'cache': 'replaced'" in refused[0].split(", got ", 1)[1]

        def test_verifier_that_defaults_a_missing_key_set_to_empty_is_refused(
            self, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            # keys = body.get("keys", []) and an empty body read as an empty key set.
            def lenient(self: keydirectory._Case) -> list[dict[str, Any]] | None:
                if self.body is None:
                    return None
                if not self.body.strip():
                    return []
                try:
                    parsed = json.loads(self.body)
                except ValueError:
                    return None
                found = parsed.get("keys", []) if isinstance(parsed, dict) else []
                return [k for k in found if isinstance(k, dict)]

            monkeypatch.setattr(keydirectory._Case, "keys", lenient)
            _, errors = corpus.check()
            assert _failed(errors) == {"no-keys-member-keeps-cache", "empty-body-keeps-cache"}

        def test_verifier_that_reads_an_unknown_outcome_as_a_removal_is_refused(
            self, tmp_path: Path
        ) -> None:
            body = ("if case['fetch']['outcome'] not in ('response', 'connect_failure'):\n"
                    "    answer = {'decision': 'not_attributed', "
                    "'reason': 'key_absent_from_directory', 'cache': 'replaced', "
                    "'cacheAfter': []}\n")
            _, errors = corpus.check(_script(tmp_path, body))
            assert _failed(errors) == {"limit-refused-keeps-cache"}

        def test_verifier_that_never_evicts_is_refused(self, tmp_path: Path) -> None:
            # The stale-key mistake: a directory that dropped the key leaves the cache alone.
            body = ("if answer['reason'] == 'key_absent_from_directory':\n"
                    "    answer['cache'] = 'kept'; answer['cacheAfter'] = sorted(case['cached'])\n")
            _, errors = corpus.check(_script(tmp_path, body))
            assert _failed(errors) == EVICTS

        def test_exit_status_must_agree_with_the_decision(self, tmp_path: Path) -> None:
            script = tmp_path / "liar.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "attributed", '
                              '"reason": "key_in_directory", "cache": "replaced", '
                              '"cacheAfter": []}))\nsys.exit(1)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert any("disagrees with decision" in error for error in errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "key-listed" / "response.body").write_bytes(b'{"keys": []}\n')
            _, errors = corpus.check(root=copied)
            assert "key-listed: fixture digest mismatch" in errors

        @pytest.mark.parametrize("jwk", [
            {"kty": "OKP", "crv": "X25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"},
            {"kty": "OKP", "crv": "Ed25519", "x": "short"},
            {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
            {"kty": "OKP", "crv": "Ed25519"},
        ])
        def test_non_ed25519_or_malformed_keys_have_no_thumbprint(self, jwk: dict) -> None:  # type: ignore[type-arg]
            assert keydirectory.jwk_thumbprint(jwk) is None

        @pytest.mark.parametrize("url,expected", [
            ("https://a.example/.well-known/http-message-signatures-directory", True),
            ("https://a.example/.well-known/http-message-signatures-directory?v=2", True),
            ("http://a.example/.well-known/http-message-signatures-directory", False),
            ("https://a.example/jwks.json", False),
        ])
        def test_well_known_detection(self, url: str, expected: bool) -> None:
            assert keydirectory.at_well_known(url) is expected
