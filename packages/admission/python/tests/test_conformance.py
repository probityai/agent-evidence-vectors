"""Conformance result records: the runner, the replay of posted runs, the registry, the CLI."""

import copy
import json
import sys
from pathlib import Path

import pytest
from agent_evidence_admission import conformance_registry as registry
from agent_evidence_admission import conformance_result as cr
from agent_evidence_admission import dsse, ed25519
from agent_evidence_admission.cli import main

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "conformance"
MANIFEST = VECTORS / "manifest.json"
RUNS = json.loads((VECTORS / "posted-runs-excerpt.json").read_text())
SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)
TRUSTED = {dsse.keyid(PUBLIC): PUBLIC}


@pytest.fixture
def seed_file(tmp_path):
    path = tmp_path / "seed.hex"
    path.write_text(SEED.hex() + "\n")
    return path


def signed(statement, seed=SEED):
    return dsse.make_envelope(cr.canonical(statement), seed)


def test_figures_parse_and_refuse():
    assert cr.parse_figure("125/130") == (125, 130)
    for bad in ("5/4", "05/6", "a/b", "5", "-1/3", 5, None):
        with pytest.raises(ValueError):
            cr.parse_figure(bad)


def test_every_posted_row_becomes_a_verifying_record():
    for row in RUNS["runs"]:
        statement = cr.statement_from_row(RUNS["implementation"], row)
        verdict = cr.verify_record(signed(statement), TRUSTED, source=row)
        assert verdict.ok, verdict.reasons
        assert verdict.revision == row["suiteRevision"]
        assert verdict.implementation == RUNS["implementation"]
        assert [s["passed"] for s in statement["predicate"]["scores"]] == [int(f["figure"].split("/")[0]) for f in row["figures"]]


def test_a_record_does_not_verify_against_an_edited_row():
    row = RUNS["runs"][0]
    envelope = signed(cr.statement_from_row(RUNS["implementation"], row))
    edited = copy.deepcopy(row)
    edited["figures"][0]["figure"] = "126/126"
    assert cr.verify_record(envelope, TRUSTED, source=edited).reasons == ["subject-digest-mismatch"]


def test_an_unknown_run_label_is_refused_when_building():
    row = copy.deepcopy(RUNS["runs"][0])
    row["runLabel"] = "friendly"
    with pytest.raises(ValueError, match="runLabel"):
        cr.statement_from_row(RUNS["implementation"], row)


def base_predicate():
    return cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0])["predicate"]


@pytest.mark.parametrize(
    "edit,reason",
    [
        (lambda p: p.update(implementation=""), "field-invalid:implementation"),
        (lambda p: p.update(posting=3), "field-invalid:posting"),
        (lambda p: p.update(suite={"revision": 0, "commit": None}), "field-invalid:suite.revision"),
        (lambda p: p.update(suite={"revision": True, "commit": None}), "field-invalid:suite.revision"),
        (lambda p: p.update(suite="x"), "field-invalid:suite.revision"),
        (lambda p: p.update(suite={"revision": 1, "commit": 5}), "field-invalid:suite.commit"),
        (lambda p: p.update(evidence="vibes"), "field-invalid:evidence"),
        (lambda p: p.update(runner={"kind": "guess"}), "field-invalid:runner.kind"),
        (lambda p: p.update(scores=[]), "field-invalid:scores"),
        (lambda p: p.update(scores=[{"role": "score", "passed": 3, "total": 2}]), "field-invalid:scores"),
        (lambda p: p.update(scores=[{"role": "", "passed": 1, "total": 2}]), "field-invalid:scores"),
        (lambda p: p.update(scores=[{"role": "score", "passed": True, "total": 2}]), "field-invalid:scores"),
        (lambda p: p.update(scores=["x"]), "field-invalid:scores"),
    ],
)
def test_predicate_problems(edit, reason):
    predicate = base_predicate()
    assert cr.validate_predicate(predicate) == []
    edit(predicate)
    assert reason in cr.validate_predicate(predicate)


def test_predicate_must_be_an_object():
    assert cr.validate_predicate([]) == ["predicate-not-object"]


@pytest.mark.parametrize(
    "edit,reason",
    [
        (lambda s: s.update(_type="x"), "statement-type-invalid"),
        (lambda s: s.update(predicateType="https://example.org/other"), "predicate-type-unsupported"),
        (lambda s: s.update(subject=[]), "subject-invalid"),
        (lambda s: s.update(subject=[{"name": "x", "digest": {"sha256": "ZZ"}}]), "subject-invalid"),
        (lambda s: s.update(subject=[{"name": "x", "digest": "d"}]), "subject-invalid"),
        (lambda s: s.update(predicate={}), "field-invalid:implementation"),
    ],
)
def test_statement_refusals(edit, reason):
    statement = cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0])
    edit(statement)
    verdict = cr.verify_record(signed(statement), TRUSTED)
    assert not verdict.ok
    assert reason in verdict.reasons


def test_untrusted_signer_and_non_json_payload():
    statement = cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0])
    stranger = signed(statement, seed=bytes(range(1, 33)))
    assert cr.verify_record(stranger, TRUSTED).reasons[0].startswith("envelope-invalid:")
    garbage = dsse.make_envelope(b"\xff not json", SEED)
    assert cr.verify_record(garbage, TRUSTED).reasons[0].startswith("envelope-invalid:")
    scalar = dsse.make_envelope(b"[1]", SEED)
    assert cr.verify_record(scalar, TRUSTED).reasons == ["statement-type-invalid"]


def test_runner_scores_exit_codes_and_never_reads_an_error_as_a_refusal():
    manifest = json.loads(MANIFEST.read_text())
    results = cr.run_corpus(manifest, [sys.executable, str(VECTORS / "impl.py")], VECTORS)
    assert {r["id"]: r["verdict"] for r in results} == {
        "accepts-one": "accept",
        "accepts-two": "accept",
        "refuses-one": "refuse",
        "refuses-two": "refuse",
        "wrong-on-purpose": "accept",
        "breaks-the-implementation": "errored",
    }
    statement = cr.statement_from_results("toy", manifest, results, "author-produced", "measured")
    assert statement["predicate"]["scores"] == [{"role": "score", "passed": 4, "total": 6}]
    assert statement["subject"][0]["digest"]["sha256"] == cr.digest_of(results)


def test_runner_marks_a_missing_command_and_a_timeout_as_errored():
    manifest = {"suite": {"revision": 1}, "cases": [{"id": "a", "input": "cases/accepts-one.json", "expect": "accept"}]}
    assert cr.run_corpus(manifest, ["/nonexistent/implementation"], VECTORS)[0]["verdict"] == "errored"
    sleeper = [sys.executable, "-c", "import time; time.sleep(5)"]
    assert cr.run_corpus(manifest, sleeper, VECTORS, timeout=0.2)[0]["verdict"] == "errored"


def test_results_statement_refuses_a_bad_label():
    manifest = {"suite": {"revision": 1}}
    with pytest.raises(ValueError, match="runLabel"):
        cr.statement_from_results("toy", manifest, [], "friendly", "measured")


def test_registry_add_dedupe_and_verify(tmp_path):
    root = tmp_path / "registry"
    for row in RUNS["runs"]:
        registry.add_record(root, signed(cr.statement_from_row(RUNS["implementation"], row)), TRUSTED)
    index = json.loads((root / "index.json").read_text())
    assert [e["suiteRevision"] for e in index["entries"]] == [1, 6, 28]
    assert registry.verify_registry(root, TRUSTED) == []
    with pytest.raises(ValueError, match="already registered"):
        registry.add_record(root, signed(cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0])), TRUSTED)
    with pytest.raises(ValueError, match="does not verify"):
        registry.add_record(root, signed(cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0]), bytes(range(1, 33))), TRUSTED)


def test_registry_finds_every_kind_of_tampering(tmp_path):
    root = tmp_path / "registry"
    for row in RUNS["runs"]:
        registry.add_record(root, signed(cr.statement_from_row(RUNS["implementation"], row)), TRUSTED)
    first, second, third = sorted((root / "records").glob("*.dsse.json"))
    envelope = json.loads(first.read_text())
    envelope["payload"] = envelope["payload"][:-4] + "AAAA"
    first.write_text(json.dumps(envelope))
    second.rename(root / "records" / ("0" * 64 + ".dsse.json"))
    third.write_text("{not json")
    (root / "records" / ("1" * 64 + ".dsse.json")).write_text(json.dumps(signed(cr.statement_from_row("x/y", RUNS["runs"][0]))))
    found = {f["file"]: f["reasons"] for f in registry.verify_registry(root, TRUSTED)}
    assert any(r.startswith("envelope-invalid") for r in found[f"records/{first.name}"])
    assert "file-name-not-digest" in found["records/" + "0" * 64 + ".dsse.json"]
    assert found[f"records/{third.name}"][0].startswith("unreadable")
    assert "not-in-index" in found["records/" + "1" * 64 + ".dsse.json"]
    assert found[f"records/{second.name}"] == ["listed-but-missing"]


def test_registry_detects_a_relabelled_index_entry(tmp_path):
    root = tmp_path / "registry"
    registry.add_record(root, signed(cr.statement_from_row(RUNS["implementation"], RUNS["runs"][0])), TRUSTED)
    index = json.loads((root / "index.json").read_text())
    index["entries"][0]["suiteRevision"] = 99
    (root / "index.json").write_text(json.dumps(index))
    assert registry.verify_registry(root, TRUSTED)[0]["reasons"] == ["index-entry-differs"]
    (root / "index.json").write_text(json.dumps({"version": 2, "entries": []}))
    with pytest.raises(ValueError, match="version 1"):
        registry.verify_registry(root, TRUSTED)


def test_cli_replay_then_verify_registry(tmp_path, seed_file, capsys):
    root = tmp_path / "registry"
    code = main(["conformance", "replay", str(VECTORS / "posted-runs-excerpt.json"), "--seed-file", str(seed_file), "--registry", str(root)])
    assert code == 0
    assert "replayed 3 of 3 posted runs" in capsys.readouterr().out
    assert main(["conformance", "verify", str(root), "--trusted-key", PUBLIC.hex()]) == 0
    assert "3 records checked, 0 failing" in capsys.readouterr().out
    assert main(["conformance", "verify", str(root), "--trusted-key", PUBLIC.hex(), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["checked"] == 3
    wrong = ed25519.public_key(bytes(range(1, 33))).hex()
    assert main(["conformance", "verify", str(root), "--trusted-key", wrong]) == 1
    assert "FAIL" in capsys.readouterr().out
    assert main(["conformance", "verify", str(tmp_path / "empty-dir"), "--trusted-key", wrong]) == 2


def test_cli_run_writes_a_record_that_verifies_against_its_results(tmp_path, seed_file, capsys):
    record, results, root = tmp_path / "record.json", tmp_path / "results.json", tmp_path / "registry"
    argv = [
        "conformance", "run", str(MANIFEST), "--implementation", "toy", "--run-label", "author-produced", "--evidence", "measured",
        "--seed-file", str(seed_file), "--out", str(record), "--results-out", str(results), "--registry", str(root),
        "--", sys.executable, str(VECTORS / "impl.py"),
    ]  # fmt: skip
    assert main(argv) == 0
    assert "toy scored 4/6 on suite revision 7 (1 errored)" in capsys.readouterr().out
    assert main(["conformance", "verify", str(record), "--trusted-key", PUBLIC.hex(), "--source", str(results)]) == 0
    assert "PASS" in capsys.readouterr().out
    edited = json.loads(results.read_text())
    edited[0]["verdict"] = "refuse"
    results.write_text(json.dumps(edited))
    assert main(["conformance", "verify", str(record), "--trusted-key", PUBLIC.hex(), "--source", str(results), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["reasons"] == ["subject-digest-mismatch"]
    assert main(["conformance", "verify", str(root), "--trusted-key", PUBLIC.hex()]) == 0


def test_cli_exit_2_is_for_things_that_could_not_run(tmp_path, seed_file, capsys):
    base = ["--implementation", "toy", "--run-label", "independent", "--evidence", "blind", "--seed-file", str(seed_file)]
    assert main(["conformance", "run", str(MANIFEST), *base]) == 2
    assert "no implementation command" in capsys.readouterr().err
    assert main(["conformance", "run", str(tmp_path / "missing.json"), *base, "--", "true"]) == 2
    bad_seed = tmp_path / "bad.hex"
    bad_seed.write_text("abcd")
    assert main(["conformance", "replay", str(VECTORS / "posted-runs-excerpt.json"), "--seed-file", str(bad_seed)]) == 2
    assert main(["conformance", "verify", str(tmp_path / "nope.json"), "--trusted-key", PUBLIC.hex()]) == 2
    capsys.readouterr()


def test_cli_replay_prints_without_a_registry(seed_file, capsys):
    assert main(["conformance", "replay", str(VECTORS / "posted-runs-excerpt.json"), "--seed-file", str(seed_file)]) == 0
    assert capsys.readouterr().out.strip() == "replayed 3 of 3 posted runs"


def test_cli_keygen_never_overwrites_and_public_key_matches(tmp_path, capsys):
    seed = tmp_path / "new.hex"
    assert main(["conformance", "keygen", "--seed-file", str(seed)]) == 0
    printed = capsys.readouterr().out.splitlines()
    assert printed[0] == f"wrote {seed}"
    assert oct(seed.stat().st_mode & 0o777) == "0o600"
    assert main(["conformance", "public-key", "--seed-file", str(seed)]) == 0
    assert printed[1] == f"public key {capsys.readouterr().out.strip()}"
    assert main(["conformance", "keygen", "--seed-file", str(seed)]) == 2
    assert "FileExistsError" in capsys.readouterr().err
