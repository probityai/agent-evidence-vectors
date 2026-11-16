"""Tests for the rule sets: every vector, every check needed, and the command line."""

import json
import random
import subprocess
import sys
from pathlib import Path

import pytest
from agent_evidence_admission import canonical, freshness, rules, strict_json
from agent_evidence_admission.cli import main
from agent_evidence_admission.strict_json import Refusal

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "rules"
MANIFESTS = sorted(VECTORS.glob("*/manifest.json"))
CASES = [(m, row["id"]) for m in MANIFESTS for row in json.loads(m.read_text())["cases"]]


def test_every_rule_set_has_vectors():
    named = {json.loads(m.read_text())["ruleSet"] for m in MANIFESTS}
    assert named == {r.name for r in rules.all_rule_sets()}


@pytest.mark.parametrize(("manifest", "case_id"), CASES, ids=[f"{m.parent.name}:{c}" for m, c in CASES])
def test_vector(manifest, case_id):
    rule_set, cases = rules.load_cases(manifest)
    (case,) = [c for c in cases if c.id == case_id]
    verdict = rules.run(rule_set, case.raw, case.options, case.files, warn=case.warn)
    assert case.judged(verdict), verdict.as_dict()


@pytest.mark.parametrize("manifest", MANIFESTS, ids=[m.parent.name for m in MANIFESTS])
def test_every_check_is_needed_and_the_set_is_sufficient(manifest):
    rule_set, cases = rules.load_cases(manifest)
    result = rules.ablate(rule_set, cases)
    assert result.sufficient, result.failing_with_all
    assert result.monotone
    assert not result.unexercised, f"checks no vector needs: {result.unexercised}"


def test_vectors_are_what_the_generator_writes():
    run = subprocess.run([sys.executable, "-I", str(VECTORS / "generate.py"), "--check"], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr


def test_ablation_lattice_for_the_parse_is_every_check():
    rule_set, cases = rules.load_cases(VECTORS / "ijson" / "manifest.json")
    result = rules.ablate(rule_set, cases, exhaustive=True)
    assert result.minimal_sets == (rule_set.check_names(),)
    assert result.as_dict()["minimalSufficientSets"] == [list(rule_set.check_names())]


def test_ablation_names_a_dead_check():
    rule_set, cases = rules.load_cases(VECTORS / "co-signed-receipt" / "manifest.json")
    kept = [c for c in cases if c.expect_code != "latency-out-of-range"]
    result = rules.ablate(rule_set, kept)
    assert result.unexercised == ("latency",)


def test_ablation_reports_a_case_the_full_set_gets_wrong():
    rule_set, cases = rules.load_cases(VECTORS / "co-signed-receipt" / "manifest.json")
    wrong = rules.Case("wrong", cases[0].raw, False, "member-missing")
    result = rules.ablate(rule_set, [wrong])
    assert not result.sufficient
    assert result.failing_with_all == ("wrong",)


def test_unknown_rule_set_and_check_are_refused():
    with pytest.raises(ValueError, match="unknown rule set"):
        rules.get("nope")
    with pytest.raises(ValueError, match="has no checks named"):
        rules.run(rules.get("ijson"), b"{}", enabled=["nope"])


def test_register_refuses_a_second_rule_set_of_one_name():
    with pytest.raises(AssertionError):
        rules.register(rules.get("ijson"))


def test_a_check_that_crashes_is_a_refusal_not_a_pass():
    def boom(context):
        raise KeyError("x")

    rule_set = rules.RuleSet("crashing", "test", (rules.Check("boom", "crashes", boom),))
    verdict = rules.run(rule_set, b"{}")
    assert not verdict.admitted
    assert verdict.code == "shape-unreadable"


def test_statement_payload_must_be_base64():
    verdict = rules.run(rules.get("audit-freshness"), b'{"payloadType":"x","payload":"%%%","signatures":[]}')
    assert verdict.code == "payload-not-base64"


def test_statement_payload_must_be_an_object_string():
    verdict = rules.run(rules.get("audit-freshness"), b'{"payloadType":"x","payload":1,"signatures":[]}')
    assert verdict.code == "shape-unreadable"


# ---------------------------------------------------------------- strict_json


def test_refusal_names_the_pointer():
    with pytest.raises(Refusal) as caught:
        strict_json.loads(b'{"a/b":[{"x~":{"k":1,"k":2}}]}')
    assert caught.value.code == "duplicate-member"
    assert caught.value.at == "/a~1b/0/x~0/k"


def test_a_check_left_out_reads_as_a_lenient_decoder_does():
    everything_but = [c for c in strict_json.CHECKS if c not in ("duplicate-member", "lone-surrogate")]
    assert strict_json.loads(b'{"a":1,"a":2}', checks=everything_but) == {"a": 2}
    assert strict_json.loads(b'{"a":"\\ud800"}', checks=everything_but) == {"a": "�"}
    assert strict_json.loads(b'\xef\xbb\xbf{"a":"\xff"}', checks=[]) == {"a": "�"}


def test_profile_and_check_names_are_checked():
    with pytest.raises(ValueError, match="unknown profile"):
        strict_json.loads(b"1", profile="lax")
    with pytest.raises(ValueError, match="unknown checks"):
        strict_json.loads(b"1", checks=["nope"])


@pytest.mark.parametrize(
    "text",
    ['{"a" 1}', '{"a":1', "[1,2", '"abc', '"\\x"', '"\\u12"', '"a\nb"', "tru", "01", "1.", "1e", "-", "{1:2}", ""],
)
def test_not_json_is_not_parseable(text):
    with pytest.raises(Refusal) as caught:
        strict_json.loads(text)
    assert caught.value.code == "not-parseable"


def test_escapes_decode():
    assert strict_json.loads('"\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9"') == '"\\/\b\f\n\r\té'
    assert strict_json.loads(' [ ] ') == []
    assert strict_json.loads('{ }') == {}


def test_deep_nesting_past_the_interpreter_is_refused():
    with pytest.raises(Refusal) as caught:
        strict_json.loads("[" * 100000 + "]" * 100000, max_depth=10**9)
    assert caught.value.code == "nesting-too-deep"


# ---------------------------------------------------------------- canonical


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (0.0, "0"),
        (1.0, "1"),
        (-0.5, "-0.5"),
        (123.456, "123.456"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (4.5e-7, "4.5e-7"),
        (12, "12"),
    ],
)
def test_numbers_follow_ecmascript(value, text):
    assert canonical.number(value) == text


def test_canonical_bytes_sort_by_utf16_and_keep_literals():
    value = {"\U0001f600": 1, "דּ": 2, "a": [None, True, False, "é"]}
    assert canonical.canonical_bytes(value) == '{"a":[null,true,false,"é"],"\U0001f600":1,"דּ":2}'.encode()


def test_canonical_refuses_what_is_not_json():
    with pytest.raises(TypeError):
        canonical.number(True)
    with pytest.raises(TypeError):
        canonical.encode(object())


# ---------------------------------------------------------------- freshness

S = 1_000_000


def test_age_equal_to_the_window_is_fresh_and_one_second_more_is_stale():
    assert freshness.judge(0, 3600 * S, 3600)
    assert not freshness.judge(0, 3601 * S, 3600)


def test_the_future_bound_takes_the_skew_only():
    assert freshness.judge(300 * S, 0, 86400, skew=300)
    with pytest.raises(Refusal) as caught:
        freshness.judge(301 * S, 0, 86400, skew=300, uncertainty=600)
    assert caught.value.code == "result-after-reference"


def test_uncertainty_widens_the_past_bound_and_is_capped():
    assert freshness.judge(0, 3700 * S, 3600, uncertainty=100)
    assert not freshness.judge(0, 3701 * S, 3600, uncertainty=100)
    with pytest.raises(Refusal) as caught:
        freshness.judge(0, 0, 3600, uncertainty=3601, max_uncertainty=3600)
    assert caught.value.code == "uncertainty-over-cap"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"max_age": -1}, "time-member-malformed"),
        ({"max_age": True}, "time-member-malformed"),
        ({"max_age": 1.5}, "time-member-malformed"),
        ({"max_age": 2**53}, "time-member-out-of-range"),
        ({"max_age": 1, "skew": 2**64 - 1}, "time-member-out-of-range"),
        ({"max_age": 1, "uncertainty": -5}, "time-member-malformed"),
    ],
)
def test_time_members_are_range_checked_before_arithmetic(kwargs, code):
    with pytest.raises(Refusal) as caught:
        freshness.judge(0, 0, **kwargs)
    assert caught.value.code == code


def test_judge_equals_the_rule_on_random_inputs():
    rng = random.Random(20261115)
    for _ in range(5000):
        produced = rng.randrange(-(10**15), 10**15)
        reference = produced + rng.randrange(-(10**10), 10**10)
        window, skew, spread = rng.randrange(0, 10**6), rng.randrange(0, 1000), rng.randrange(0, 3601)
        if produced - reference > skew * S:
            with pytest.raises(Refusal):
                freshness.judge(produced, reference, window, skew, spread)
        else:
            assert freshness.judge(produced, reference, window, skew, spread) == (reference - produced <= (window + spread) * S)


def test_each_bound_has_its_own_allowance():
    start, within = 0, 600
    # The late bound on an OpenTimestamps anchor takes the block-time allowance: the last admitted
    # second and the first refused one.
    assert not freshness.late(start, (within + freshness.OTS_TOLERANCE_SECONDS) * S, within, freshness.OTS_TOLERANCE_SECONDS)
    assert freshness.late(start, (within + freshness.OTS_TOLERANCE_SECONDS + 1) * S, within, freshness.OTS_TOLERANCE_SECONDS)
    # A clock reading takes the skew tolerance on the same bound.
    assert freshness.late(start, (within + freshness.SKEW_TOLERANCE_SECONDS + 1) * S, within, freshness.SKEW_TOLERANCE_SECONDS)


@pytest.mark.parametrize(
    "text", ["2026-09-19 11:04:02Z", "2026-09-19T11:04:02", "2026-13-19T11:04:02Z", "2026-09-19T11:04:02Z\n", 5, "2026-09-19T11:04:0٢Z"]
)
def test_instants_are_strict(text):
    with pytest.raises(Refusal) as caught:
        freshness.instant(text, "/t")
    assert caught.value.code == "instant-malformed"


def test_instants_with_offsets_and_fractions():
    assert freshness.instant("1970-01-01T01:00:00+01:00", "") == 0
    assert freshness.instant("1970-01-01T00:00:00.5Z", "") == 500_000


# ---------------------------------------------------------------- command line


def write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def case_bytes(rule_set: str, case_id: str) -> rules.Case:
    _, cases = rules.load_cases(VECTORS / rule_set / "manifest.json")
    return next(c for c in cases if c.id == case_id)


def test_cli_admits_and_refuses(tmp_path, capsys):
    good = write(tmp_path, "good.json", case_bytes("co-signed-receipt", "valid").raw)
    bad = write(tmp_path, "bad.json", case_bytes("co-signed-receipt", "uppercase-hash").raw)
    assert main(["admit", "co-signed-receipt", good]) == 0
    assert "ADMIT" in capsys.readouterr().out
    assert main(["admit", "co-signed-receipt", bad, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "hash-not-lowercase-hex64"


def test_cli_options_files_and_warnings(tmp_path, capsys):
    case = case_bytes("mcp-authz", "valid")
    options = write(tmp_path, "options.json", json.dumps({k: v for k, v in case.options.items() if k != "now"}).encode())
    record = write(tmp_path, "token.json", case.raw)
    assert main(["admit", "mcp-authz", record, "--options", options, "--option", f"now={case.options['now']}"]) == 0
    transplant = case_bytes("catalog-attestations", "transplanted-attestation")
    catalog = write(tmp_path, "catalog.json", transplant.raw)
    ((uri, data),) = transplant.files.items()
    scan = write(tmp_path, "scan.sarif", data)
    capsys.readouterr()
    code = main(["admit", "catalog-attestations", catalog, "--file", f"{uri}={scan}", "--warn", "entry_digest_missing_for_url"])
    out = capsys.readouterr().out
    assert code == 1
    assert "WARN entry_digest_missing_for_url" in out
    assert "REFUSE attestation_unsigned" in out


@pytest.mark.parametrize(
    "extra",
    [["--option", "novalue"], ["--file", "=x"], ["--options", "missing.json"]],
)
def test_cli_unreadable_input_is_exit_2(tmp_path, extra):
    record = write(tmp_path, "r.json", b"{}")
    assert main(["admit", "co-signed-receipt", record, *extra]) == 2


def test_cli_options_must_be_an_object(tmp_path):
    record = write(tmp_path, "r.json", b"{}")
    options = write(tmp_path, "o.json", b"[]")
    assert main(["admit", "co-signed-receipt", record, "--options", options]) == 2
    assert main(["admit", "nope", record]) == 2


def test_cli_lists_rule_sets(capsys):
    assert main(["rule-sets"]) == 0
    out = capsys.readouterr().out
    for rule_set in rules.all_rule_sets():
        assert f"{rule_set.name}:" in out
    assert "option resource:" in out


def test_cli_ablate(tmp_path, capsys):
    assert main(["ablate", str(VECTORS / "ijson" / "manifest.json"), "--exhaustive"]) == 0
    assert "minimal set:" in capsys.readouterr().out
    assert main(["ablate", str(VECTORS / "mcp-authz" / "manifest.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["sufficient"] is True
    manifest = json.loads((VECTORS / "co-signed-receipt" / "manifest.json").read_text())
    manifest["cases"] = [c for c in manifest["cases"] if c["expect"].get("code") != "latency-out-of-range"]
    manifest["cases"].append({"id": "wrong", "text": "{}", "expect": {"verdict": "admit"}})
    trimmed = tmp_path / "manifest.json"
    trimmed.write_text(json.dumps(manifest))
    assert main(["ablate", str(trimmed)]) == 1
    out = capsys.readouterr().out
    assert "UNEXERCISED" in out
    assert "FAILS WITH EVERY CHECK ON: wrong" in out
    assert main(["ablate", str(tmp_path / "missing.json")]) == 2


def test_manifest_rows_may_name_files(tmp_path):
    (tmp_path / "doc.json").write_bytes(b'{"a":1}')
    (tmp_path / "manifest.json").write_text(
        json.dumps({"ruleSet": "ijson", "cases": [{"id": "f", "file": "doc.json", "expect": {"verdict": "admit"}}]})
    )
    rule_set, cases = rules.load_cases(tmp_path / "manifest.json")
    assert rules.run(rule_set, cases[0].raw).admitted
