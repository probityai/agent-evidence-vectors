"""Tests for the artifact-binding tool.

Each test names the property of ``spec/artifact-binding/v1.md`` it holds down.
The three-outcome distinction is tested in both directions on purpose: a
verifier that collapses ``not-established`` into either neighbour passes a
one-directional test and is exactly the defect the contract exists to prevent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import aee_bind  # noqa: E402
import fixture  # noqa: E402
import jcs  # noqa: E402
import manifest as manifest_mod  # noqa: E402
import regrade as regrade_mod  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402

SEED = bytes(range(32))
STAMP = "2026-01-01T00:00:00Z"


@pytest.fixture
def bound(tmp_path: Path) -> dict[str, Path]:
    """A synthetic trial with a built and signed record beside it."""
    trial = fixture.build_trial(tmp_path / "trial")
    verifier = fixture.build_verifier(tmp_path / "verifier")
    facts = manifest_mod.collect_facts(trial, verifier)
    record = manifest_mod.build(
        facts,
        signer_key_id=sign.key_id(sign.public_bytes(SEED)),
        verifier_id="test/v1",
        recorded_at=STAMP,
    )
    manifest_path = trial / "binding" / "manifest.json"
    raw = manifest_mod.write(record, manifest_path)
    signature_path = trial / "binding" / "manifest.sig"
    signature_path.write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    return {
        "trial": trial,
        "verifier": verifier,
        "manifest": manifest_path,
        "signature": signature_path,
    }


def check(bound: dict[str, Path], key: bytes | None = None) -> verify_mod.Outcome:
    return verify_mod.verify(
        bound["trial"],
        bound["manifest"],
        bound["signature"],
        key if key is not None else sign.public_bytes(SEED),
    )


# --- canonical encoding -------------------------------------------------


def test_es6_numbers_follow_the_rfc_not_python() -> None:
    assert jcs.es6_number(1e-6) == "0.000001"
    assert jcs.es6_number(2.0**68) == "295147905179352830000"
    assert jcs.es6_number(-0.0) == "0"
    with pytest.raises(ValueError):
        jcs.es6_number(float("nan"))


def test_member_names_sort_by_utf16_code_unit() -> None:
    assert jcs.canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_is_canonical_rejects_reserialized_bytes() -> None:
    assert jcs.is_canonical(b'{"a":1}')
    assert not jcs.is_canonical(b'{ "a": 1 }')
    assert not jcs.is_canonical(b"not json")


def test_digest_is_over_canonical_bytes() -> None:
    assert jcs.digest({"a": 1, "b": 2}) == jcs.digest({"b": 2, "a": 1})


# --- signing ------------------------------------------------------------


def test_signature_round_trips_and_a_changed_byte_breaks_it() -> None:
    public = sign.public_bytes(SEED)
    signature = sign.sign_bytes(SEED, b"payload")
    assert sign.verify_bytes(public, b"payload", signature)
    assert not sign.verify_bytes(public, b"payloae", signature)
    assert not sign.verify_bytes(public, b"payload", b"short")


def test_seed_is_read_from_a_file_or_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "key"
    path.write_text(SEED.hex(), encoding="utf-8")
    assert sign.load_seed(path) == SEED
    (tmp_path / "raw").write_bytes(SEED)
    assert sign.load_seed(tmp_path / "raw") == SEED
    monkeypatch.setenv("AEE_BIND_KEY", SEED.hex())
    assert sign.load_seed() == SEED
    monkeypatch.delenv("AEE_BIND_KEY")
    with pytest.raises(sign.KeyError_):
        sign.load_seed()


def test_a_short_key_is_refused(tmp_path: Path) -> None:
    (tmp_path / "short").write_bytes(b"\x00" * 8)
    with pytest.raises(sign.KeyError_):
        sign.load_seed(tmp_path / "short")
    with pytest.raises(sign.KeyError_):
        sign.load_public(tmp_path / "short")


def test_public_key_loads_raw_and_hex(tmp_path: Path) -> None:
    public = sign.public_bytes(SEED)
    (tmp_path / "hex").write_text(public.hex(), encoding="utf-8")
    (tmp_path / "raw").write_bytes(public)
    assert sign.load_public(tmp_path / "hex") == public
    assert sign.load_public(tmp_path / "raw") == public


# --- building -----------------------------------------------------------


def test_a_built_record_covers_every_required_role(bound: dict[str, Path]) -> None:
    record = _load(bound["manifest"])
    roles = {entry["role"] for entry in record["artifacts"]}
    roles |= {entry["role"] for entry in record["verification_inputs"]["grading_inputs"]}
    for role in manifest_mod.REQUIRED_ROLES:
        assert role in roles, role


def test_the_stored_manifest_is_canonical(bound: dict[str, Path]) -> None:
    assert jcs.is_canonical(bound["manifest"].read_bytes())


def _load(path: Path) -> dict[str, Any]:
    """A manifest as a plain dictionary, for tests that index into it."""
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def test_a_record_carries_neither_its_own_digest_nor_its_signature(
    bound: dict[str, Path],
) -> None:
    record = _load(bound["manifest"])
    assert "signature" not in record
    assert "manifest_digest" not in record


def test_grading_inputs_are_captured_into_the_archive(bound: dict[str, Path]) -> None:
    record = _load(bound["manifest"])
    for entry in record["verification_inputs"]["grading_inputs"]:
        assert entry["path"].startswith(manifest_mod.GRADING_INPUT_DIR)
        assert (bound["trial"] / entry["path"]).is_file()


def test_archive_digest_ignores_grading_outputs(tmp_path: Path) -> None:
    entries = [
        manifest_mod.Entry("trial_result", "result.json", 1, "a" * 64),
        manifest_mod.Entry("reward", "verifier/reward.txt", 1, "b" * 64),
    ]
    without_reward = [entries[0]]
    assert manifest_mod.archive_digest(entries) == manifest_mod.archive_digest(without_reward)
    _ = tmp_path


def test_a_regrade_record_must_name_its_source(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial")
    facts = manifest_mod.collect_facts(trial, None)
    with pytest.raises(manifest_mod.BindingError):
        manifest_mod.build(facts, operation="regrade", signer_key_id="x")
    with pytest.raises(manifest_mod.BindingError):
        manifest_mod.build(facts, operation="rescore", signer_key_id="x")


def test_a_directory_without_a_result_is_refused(tmp_path: Path) -> None:
    with pytest.raises(manifest_mod.BindingError):
        manifest_mod.collect_facts(tmp_path, None)


def test_an_external_trajectory_reference_is_reported_uncovered(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial", external_subagent=True)
    facts = manifest_mod.collect_facts(trial, None)
    assert facts.uncovered
    record = manifest_mod.build(facts, signer_key_id="x")
    dependencies = record["dependencies"]
    assert isinstance(dependencies, dict)
    assert dependencies["status"] == "incomplete"


def test_reward_is_read_from_json_when_there_is_no_text_file(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial")
    (trial / "verifier" / "reward.txt").unlink()
    (trial / "verifier" / "reward.json").write_text('{"reward": 0.5}', encoding="utf-8")
    reward, path = manifest_mod.read_reward(trial)
    assert reward == 0.5
    assert path == "verifier/reward.json"


def test_a_trial_with_no_reward_file_reports_none(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial")
    (trial / "verifier" / "reward.txt").unlink()
    assert manifest_mod.read_reward(trial) == (None, None)


def test_an_unparseable_reward_reports_no_value(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial")
    (trial / "verifier" / "reward.txt").write_text("not a number", encoding="utf-8")
    reward, path = manifest_mod.read_reward(trial)
    assert reward is None
    assert path == "verifier/reward.txt"


def test_find_atif_skips_non_atif_json(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial")
    (trial / "agent" / "notes.json").write_text('{"schema_version": "other"}', encoding="utf-8")
    found = manifest_mod.find_atif(trial)
    assert found is not None
    assert found.name == "trajectory.json"
    empty = tmp_path / "empty"
    empty.mkdir()
    assert manifest_mod.find_atif(empty) is None


def test_safe_relative_refuses_a_path_outside_the_root(tmp_path: Path) -> None:
    inside = tmp_path / "root" / "file"
    inside.parent.mkdir(parents=True)
    inside.write_text("x", encoding="utf-8")
    assert manifest_mod.safe_relative(tmp_path / "root", inside)
    assert not manifest_mod.safe_relative(tmp_path / "root", tmp_path / "missing")


# --- the four arms ------------------------------------------------------


def test_arm_one_an_intact_archive_verifies(bound: dict[str, Path]) -> None:
    outcome = check(bound)
    assert outcome.verdict == verify_mod.VERIFIED
    assert outcome.exit_code == verify_mod.EXIT_VERIFIED
    assert outcome.report() == "verdict: verified"


def test_arm_two_one_changed_byte_fails_and_names_the_artifact(
    bound: dict[str, Path],
) -> None:
    target = bound["trial"] / "artifacts" / "logs" / "artifacts" / "answer.txt"
    target.write_text("TAMPERED\n", encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert outcome.exit_code == verify_mod.EXIT_FAILED
    assert "artifact-digest-mismatch" in outcome.codes
    assert any("answer.txt" in line for line in outcome.messages)


def test_arm_two_grading_never_runs_over_a_tampered_archive(
    bound: dict[str, Path], tmp_path: Path
) -> None:
    target = bound["trial"] / "artifacts" / "logs" / "artifacts" / "answer.txt"
    target.write_text("TAMPERED\n", encoding="utf-8")
    out = tmp_path / "regraded"
    with pytest.raises(regrade_mod.RegradeRefused):
        regrade_mod.regrade(
            source_dir=bound["trial"],
            source_manifest=bound["manifest"],
            source_signature=bound["signature"],
            public_key=sign.public_bytes(SEED),
            private_seed=SEED,
            verifier_dir=bound["verifier"],
            target_dir=out,
            verifier_id="test/v1",
        )
    assert not (out / "verifier").exists()


def test_arm_three_a_missing_required_artifact_is_not_established(
    bound: dict[str, Path],
) -> None:
    (bound["trial"] / "verifier" / "reward.txt").unlink()
    outcome = check(bound)
    assert outcome.verdict == verify_mod.NOT_ESTABLISHED
    assert outcome.exit_code == verify_mod.EXIT_NOT_ESTABLISHED
    assert "artifact-absent" in outcome.codes


def test_arm_three_is_neither_a_pass_nor_a_plain_failure(bound: dict[str, Path]) -> None:
    (bound["trial"] / "verifier" / "reward.txt").unlink()
    outcome = check(bound)
    assert outcome.verdict != verify_mod.VERIFIED
    assert outcome.verdict != verify_mod.FAILED
    assert outcome.exit_code not in (verify_mod.EXIT_VERIFIED, verify_mod.EXIT_FAILED)


def test_arm_four_a_changed_verifier_preserves_both_outcomes(
    bound: dict[str, Path], tmp_path: Path
) -> None:
    changed = fixture.build_verifier(tmp_path / "verifier-changed", changed=True)
    result = regrade_mod.regrade(
        source_dir=bound["trial"],
        source_manifest=bound["manifest"],
        source_signature=bound["signature"],
        public_key=sign.public_bytes(SEED),
        private_seed=SEED,
        verifier_dir=changed,
        target_dir=tmp_path / "regraded",
        verifier_id="test/v2",
        recorded_at=STAMP,
    )
    second = verify_mod.verify(
        result.trial_dir,
        result.manifest_path,
        result.signature_path,
        sign.public_bytes(SEED),
    )
    assert second.verdict == verify_mod.VERIFIED
    first_record = _load(bound["manifest"])
    second_record = _load(result.manifest_path)
    assert first_record["graded_outcome"]["reward"] == 1.0
    assert second_record["graded_outcome"]["reward"] == 0.0
    assert second_record["operation"] == "regrade"
    assert (
        second_record["source_archive_digest"] == first_record["source_archive_digest"]
    )
    problems = regrade_mod.check_lineage(
        [first_record, second_record],
        [verify_mod.manifest_digest(bound["manifest"]), ""],
    )
    assert problems == []


# --- the other four corpus conditions -----------------------------------


def test_a_wrong_signer_is_refused_by_identity(bound: dict[str, Path]) -> None:
    other = sign.public_bytes(bytes(range(1, 33)))
    outcome = check(bound, key=other)
    assert outcome.verdict == verify_mod.FAILED
    assert "signer-key-mismatch" in outcome.codes


def test_a_valid_signature_over_a_forged_record_still_fails_the_key_pin(
    bound: dict[str, Path],
) -> None:
    other_seed = bytes(range(1, 33))
    record = _load(bound["manifest"])
    record["signer_key_id"] = sign.key_id(sign.public_bytes(other_seed))
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(other_seed, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "signer-key-mismatch" in outcome.codes


def test_a_non_canonical_manifest_fails_before_the_signature_is_believed(
    bound: dict[str, Path],
) -> None:
    record = _load(bound["manifest"])
    raw = json.dumps(record, indent=2).encode("utf-8")
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "manifest-encoding-not-canonical" in outcome.codes


def test_an_incomplete_dependency_set_is_not_established(tmp_path: Path) -> None:
    trial = fixture.build_trial(tmp_path / "trial", external_subagent=True)
    verifier = fixture.build_verifier(tmp_path / "verifier")
    facts = manifest_mod.collect_facts(trial, verifier)
    record = manifest_mod.build(
        facts, signer_key_id=sign.key_id(sign.public_bytes(SEED)), recorded_at=STAMP
    )
    manifest_path = trial / "binding" / "manifest.json"
    raw = manifest_mod.write(record, manifest_path)
    signature_path = trial / "binding" / "manifest.sig"
    signature_path.write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = verify_mod.verify(trial, manifest_path, signature_path, sign.public_bytes(SEED))
    assert outcome.verdict == verify_mod.NOT_ESTABLISHED
    assert "dependencies-incomplete" in outcome.codes


def test_an_atif_pointer_that_disagrees_with_the_document_fails(
    bound: dict[str, Path],
) -> None:
    record = _load(bound["manifest"])
    record["atif"]["document_sha256"] = "0" * 64
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "atif-document-digest-mismatch" in outcome.codes


def test_a_trajectory_id_that_disagrees_fails(bound: dict[str, Path]) -> None:
    record = _load(bound["manifest"])
    record["atif"]["trajectory_id"] = "not-the-document-id"
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert "atif-trajectory-id-mismatch" in outcome.codes


def test_a_declared_outcome_that_contradicts_the_bytes_fails(
    bound: dict[str, Path],
) -> None:
    record = _load(bound["manifest"])
    record["graded_outcome"]["reward"] = 0.0
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "graded-outcome-mismatch" in outcome.codes


def test_a_broken_signature_fails(bound: dict[str, Path]) -> None:
    bound["signature"].write_text("00" * 64, encoding="utf-8")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "signature-invalid" in outcome.codes


def test_an_unsupported_schema_version_fails(bound: dict[str, Path]) -> None:
    record = _load(bound["manifest"])
    record["schema_version"] = "artifact-binding/v99"
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert "schema-version-unsupported" in outcome.codes


def test_an_unparseable_manifest_fails(bound: dict[str, Path]) -> None:
    bound["manifest"].write_bytes(b"not json at all")
    outcome = check(bound)
    assert outcome.verdict == verify_mod.FAILED
    assert "manifest-unparseable" in outcome.codes


def test_an_escaping_path_is_refused(bound: dict[str, Path]) -> None:
    record = _load(bound["manifest"])
    record["artifacts"][0]["path"] = "../escape.txt"
    raw = jcs.canonical_bytes(record)
    bound["manifest"].write_bytes(raw)
    bound["signature"].write_text(sign.sign_bytes(SEED, raw).hex(), encoding="utf-8")
    outcome = check(bound)
    assert "artifact-path-unsafe" in outcome.codes


# --- lineage ------------------------------------------------------------


def test_lineage_refuses_a_chain_over_two_archives() -> None:
    first: dict[str, Any] = {"operation": "execute", "source_archive_digest": "a"}
    second: dict[str, Any] = {
        "operation": "regrade",
        "source_archive_digest": "b",
        "source_record_digest": "d0",
    }
    problems = regrade_mod.check_lineage([first, second], ["d0", ""])
    assert any("one archive" in problem for problem in problems)


def test_lineage_refuses_a_broken_back_reference() -> None:
    first: dict[str, Any] = {"operation": "execute", "source_archive_digest": "a"}
    second: dict[str, Any] = {
        "operation": "regrade",
        "source_archive_digest": "a",
        "source_record_digest": "x",
    }
    problems = regrade_mod.check_lineage([first, second], ["d0", ""])
    assert any("source_record_digest" in problem for problem in problems)


def test_lineage_refuses_an_empty_chain_and_a_wrong_head() -> None:
    assert regrade_mod.check_lineage([], []) == ["the chain is empty"]
    head: dict[str, Any] = {"operation": "regrade", "source_archive_digest": "a"}
    assert regrade_mod.check_lineage([head], [""])


def test_lineage_refuses_a_second_execute_record() -> None:
    first: dict[str, Any] = {"operation": "execute", "source_archive_digest": "a"}
    second: dict[str, Any] = {
        "operation": "execute",
        "source_archive_digest": "a",
        "source_record_digest": "d0",
    }
    problems = regrade_mod.check_lineage([first, second], ["d0", ""])
    assert any("not a regrade" in problem for problem in problems)


def test_a_verifier_directory_with_no_entrypoint_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(regrade_mod.RegradeRefused):
        regrade_mod.run_verifier(empty, tmp_path / "trial")


# --- the command line ---------------------------------------------------


def test_the_cli_runs_all_four_arms(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = tmp_path / "key"
    assert aee_bind.main(["keygen", "--key", str(key), "--pubkey", str(tmp_path / "key.pub")]) == 0
    trial = fixture.build_trial(tmp_path / "trial")
    verifier = fixture.build_verifier(tmp_path / "verifier")
    changed = fixture.build_verifier(tmp_path / "changed", changed=True)
    argv = ["build", str(trial), "--verifier", str(verifier), "--key", str(key)]
    assert aee_bind.main([*argv, "--recorded-at", STAMP]) == 0
    pub = str(tmp_path / "key.pub")
    assert aee_bind.main(["verify", str(trial), "--pubkey", pub]) == verify_mod.EXIT_VERIFIED
    assert (
        aee_bind.main(
            [
                "regrade",
                str(trial),
                "--verifier",
                str(changed),
                "--key",
                str(key),
                "--out",
                str(tmp_path / "regraded"),
                "--recorded-at",
                STAMP,
            ]
        )
        == 0
    )
    assert (
        aee_bind.main(
            [
                "lineage",
                str(trial / "binding" / "manifest.json"),
                str(tmp_path / "regraded" / "binding" / "manifest.json"),
            ]
        )
        == 0
    )
    captured = capsys.readouterr().out
    assert "lineage ok" in captured


def test_the_cli_reports_a_tampered_archive_as_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "key"
    aee_bind.main(["keygen", "--key", str(key), "--pubkey", str(tmp_path / "key.pub")])
    trial = fixture.build_trial(tmp_path / "trial")
    verifier = fixture.build_verifier(tmp_path / "verifier")
    aee_bind.main(["build", str(trial), "--verifier", str(verifier), "--key", str(key)])
    (trial / "verifier" / "reward.txt").write_text("0\n", encoding="utf-8")
    code = aee_bind.main(["verify", str(trial), "--pubkey", str(tmp_path / "key.pub")])
    assert code == verify_mod.EXIT_FAILED
    assert aee_bind.main(
        [
            "regrade",
            str(trial),
            "--verifier",
            str(verifier),
            "--key",
            str(key),
            "--out",
            str(tmp_path / "regraded"),
        ]
    ) == verify_mod.EXIT_FAILED
    assert "nothing was graded" in capsys.readouterr().out


def test_the_cli_reports_a_missing_key_as_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AEE_BIND_KEY", raising=False)
    trial = fixture.build_trial(tmp_path / "trial")
    assert aee_bind.main(["build", str(trial)]) == verify_mod.EXIT_USAGE


def test_the_cli_reports_an_unreadable_lineage_record(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    assert aee_bind.main(["lineage", str(bad)]) == verify_mod.EXIT_USAGE


def test_the_cli_reports_a_broken_lineage(tmp_path: Path) -> None:
    one = tmp_path / "one.json"
    one.write_bytes(jcs.canonical_bytes({"operation": "regrade", "source_archive_digest": "a"}))
    assert aee_bind.main(["lineage", str(one)]) == verify_mod.EXIT_FAILED


# --- the corpus scripts -------------------------------------------------
#
# Run here as well as in CI. Running them is the only way they are covered:
# both are scripts whose whole behaviour is their exit code over the committed
# bytes, and a corpus checker nobody executes is the shape of dead gate this
# repository keeps finding.

CORPUS = TOOLS.parents[1] / "vectors-artifact-binding"
if str(CORPUS) not in sys.path:
    sys.path.insert(0, str(CORPUS))


def test_the_generator_reproduces_the_committed_manifest() -> None:
    import gen_vectors

    committed = _load(CORPUS / "MANIFEST.json")
    rebuilt = gen_vectors.build()
    assert rebuilt["corpusDigest"] == committed["corpusDigest"]
    assert [entry["id"] for entry in rebuilt["vectors"]] == [
        entry["id"] for entry in committed["vectors"]
    ]




# --- the dependency-selection profile ------------------------------------
#
# Section 6.2: the consumer names the profile and the in-force digests; neither
# is read from the record.

DEPSEL = TOOLS.parents[1] / "vectors-dependency-selection"


def _depsel_generator() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("depsel_gen", DEPSEL / "gen_vectors.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_unknown_profile_is_refused_not_judged_against_no_roles(
    bound: dict[str, Path],
) -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        verify_mod.verify(
            bound["trial"],
            bound["manifest"],
            bound["signature"],
            sign.public_bytes(SEED),
            "no-such-profile/v1",
        )


def test_a_harbor_record_is_not_established_under_the_dependency_profile(
    bound: dict[str, Path],
) -> None:
    outcome = verify_mod.verify(
        bound["trial"],
        bound["manifest"],
        bound["signature"],
        sign.public_bytes(SEED),
        manifest_mod.DEPENDENCY_SELECTION_PROFILE,
    )
    assert outcome.verdict == verify_mod.NOT_ESTABLISHED
    assert set(outcome.codes) == {"required-role-absent"}


def test_a_role_pinned_to_other_bytes_fails(bound: dict[str, Path]) -> None:
    outcome = verify_mod.verify(
        bound["trial"],
        bound["manifest"],
        bound["signature"],
        sign.public_bytes(SEED),
        manifest_mod.PROFILE_NAME,
        {"trial_result": "0" * 64},
    )
    assert outcome.verdict == verify_mod.FAILED
    assert outcome.codes == ["role-not-in-force"]


def test_a_role_pinned_to_its_own_bytes_still_verifies(bound: dict[str, Path]) -> None:
    record = json.loads(bound["manifest"].read_text(encoding="utf-8"))
    actual = next(e["sha256"] for e in record["artifacts"] if e["role"] == "trial_result")
    outcome = verify_mod.verify(
        bound["trial"],
        bound["manifest"],
        bound["signature"],
        sign.public_bytes(SEED),
        manifest_mod.PROFILE_NAME,
        {"trial_result": actual},
    )
    assert outcome.verdict == verify_mod.VERIFIED


def test_the_dependency_generator_reproduces_the_committed_manifest() -> None:
    committed = _load(DEPSEL / "MANIFEST.json")
    rebuilt = _depsel_generator().build()
    assert rebuilt["corpusDigest"] == committed["corpusDigest"]
    assert rebuilt["vectors"] == committed["vectors"]


def test_the_checker_judges_the_dependency_corpus(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import runpy

    monkeypatch.setattr(sys, "argv", ["check_vectors.py", str(DEPSEL)])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(CORPUS / "check_vectors.py"), run_name="__main__")
    assert stopped.value.code == 0
    assert "dependency-selection/v1" in capsys.readouterr().out


def test_the_cli_verifies_the_worked_dependency_record(tmp_path: Path) -> None:
    pub = tmp_path / "key.pub"
    pub.write_text(_load(DEPSEL / "MANIFEST.json")["publicKey"], encoding="utf-8")
    pins = _load(DEPSEL / "MANIFEST.json")["inForce"]
    args = ["--pubkey", str(pub), "--profile", manifest_mod.DEPENDENCY_SELECTION_PROFILE]
    for role, digest_hex in pins.items():
        args += ["--in-force", f"{role}={digest_hex}"]
    intact = DEPSEL / "cases" / "intact-selection" / "trial"
    other = DEPSEL / "cases" / "skill-not-in-force" / "trial"
    assert aee_bind.main(["verify", str(intact), *args]) == verify_mod.EXIT_VERIFIED
    assert aee_bind.main(["verify", str(other), *args]) == verify_mod.EXIT_FAILED


@pytest.mark.parametrize(
    "extra",
    [["--profile", "no-such/v1"], ["--in-force", "skill_instructions"]],
)
def test_the_cli_refuses_a_bad_profile_or_pin(tmp_path: Path, extra: list[str]) -> None:
    pub = tmp_path / "key.pub"
    pub.write_text(sign.public_bytes(SEED).hex(), encoding="utf-8")
    intact = DEPSEL / "cases" / "intact-selection" / "trial"
    code = aee_bind.main(["verify", str(intact), "--pubkey", str(pub), *extra])
    assert code == verify_mod.EXIT_USAGE
