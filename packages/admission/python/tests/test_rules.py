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
    run = subprocess.run(
        [sys.executable, "-I", str(VECTORS / "generate.py"), "--check"], capture_output=True, text=True, check=False
    )
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
    assert result.unexercised == tuple(c.name for c in rule_set.checks)


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


@pytest.mark.parametrize("text", ["1e-400", "-1e-400", "0.5e-400", "1E-9999"])
def test_a_nonzero_number_that_underflows_is_refused(text):
    with pytest.raises(Refusal) as caught:
        strict_json.loads(text)
    assert caught.value.code == "value-not-representable"


@pytest.mark.parametrize("text", ["0e-400", "0.000e5", "0E-9999", "5e-324"])
def test_zero_written_with_an_exponent_and_the_smallest_double_are_admitted(text):
    assert strict_json.loads(text) == float(text)


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

S = 1_000_000_000


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


def test_bounds_are_held_to_the_nanosecond():
    # 300.000000001 s after the reference under a 300 s skew is refused, as Go's time refuses it.
    assert freshness.judge(300 * S, 0, 86400, skew=300)
    with pytest.raises(Refusal):
        freshness.judge(300 * S + 1, 0, 86400, skew=300)
    assert freshness.judge(0, 3600 * S, 3600)
    assert not freshness.judge(0, 3600 * S + 1, 3600)
    late = "1970-01-01T00:05:00.000000001Z"
    assert freshness.instant(late, "") - freshness.instant("1970-01-01T00:00:00Z", "") == 300 * S + 1


def test_each_bound_has_its_own_allowance():
    start, within = 0, 600
    # The late bound on an OpenTimestamps anchor takes the block-time allowance: the last admitted
    # second and the first refused one.
    assert not freshness.late(start, (within + freshness.OTS_TOLERANCE_SECONDS) * S, within, freshness.OTS_TOLERANCE_SECONDS)
    assert freshness.late(start, (within + freshness.OTS_TOLERANCE_SECONDS + 1) * S, within, freshness.OTS_TOLERANCE_SECONDS)
    # A clock reading takes the skew tolerance on the same bound.
    assert freshness.late(start, (within + freshness.SKEW_TOLERANCE_SECONDS + 1) * S, within, freshness.SKEW_TOLERANCE_SECONDS)


@pytest.mark.parametrize(
    "text",
    [
        "2026-09-19 11:04:02Z",
        "2026-09-19T11:04:02",
        "2026-13-19T11:04:02Z",
        "2026-09-19T11:04:02Z\n",
        5,
        "2026-09-19T11:04:0٢Z",
        "2026-09-19T11:04:02+00:60",
        "2026-09-19T11:04:02+24:00",
        "2026-09-19T11:04:02.1234567890Z",
    ],
)
def test_instants_are_strict(text):
    with pytest.raises(Refusal) as caught:
        freshness.instant(text, "/t")
    assert caught.value.code == "instant-malformed"


def test_instants_with_offsets_and_fractions():
    assert freshness.instant("1970-01-01T01:00:00+01:00", "") == 0
    assert freshness.instant("1970-01-01T00:00:00.5Z", "") == 500_000_000
    assert freshness.instant("1970-01-01T00:00:00.000000001Z", "") == 1
    assert freshness.instant("1969-12-31T23:59:59.999999999Z", "") == -1


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


def test_an_option_the_rule_set_does_not_define_is_refused(tmp_path):
    case = case_bytes("mcp-authz", "valid")
    with pytest.raises(ValueError, match="no options named skwe"):
        rules.run(rules.get("mcp-authz"), case.raw, {**case.options, "skwe": 0})
    record = write(tmp_path, "token.json", case.raw)
    options = write(tmp_path, "options.json", json.dumps(case.options).encode())
    assert main(["admit", "mcp-authz", record, "--options", options, "--option", "skwe=0"]) == 2
    with pytest.raises(ValueError, match="takes: none"):
        rules.run(rules.get("ijson"), b"{}", {"skew": 1})


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
    assert "latency: UNEXERCISED" in out
    assert "FAILS WITH EVERY CHECK ON: wrong" in out
    # A case that fails with every check on is reported once, never as a need of each check.
    assert out.count("wrong") == 1
    assert main(["ablate", str(tmp_path / "missing.json")]) == 2


def test_manifest_rows_may_name_files(tmp_path):
    (tmp_path / "doc.json").write_bytes(b'{"a":1}')
    (tmp_path / "manifest.json").write_text(
        json.dumps({"ruleSet": "ijson", "cases": [{"id": "f", "file": "doc.json", "expect": {"verdict": "admit"}}]})
    )
    rule_set, cases = rules.load_cases(tmp_path / "manifest.json")
    assert rules.run(rule_set, cases[0].raw).admitted


# ---------------------------------------------------------------- the audit-record corpus

AUDIT_CORPUS = Path(__file__).resolve().parents[4] / "corpora" / "vectors-agent-audit-record"
#: The corpus codes the audit-freshness rule set decides; a member refused for any other code is
#: outside its scope (a closed vocabulary, a signature) and is not compared.
FRESHNESS_CODES = {
    "evaluation-result-after-decision",
    "evaluation-inconsistent",
    "evaluation-input-repeated",
    "evaluation-entry-malformed",
    "unsafe-integer",
    "member-missing",
}


def test_audit_freshness_agrees_with_the_audit_record_corpus():
    """Every FR member of the signed corpus: a valid one is admitted, and one refused for a code this
    rule set decides is refused for the same code."""
    manifest = json.loads((AUDIT_CORPUS / "MANIFEST.json").read_text())
    rule_set = rules.get("audit-freshness")
    compared = []
    for member in manifest["vectors"]:
        if not str(member.get("draftId", "")).startswith("FR"):
            continue
        expected = member["expected"]
        codes = expected.get("codes", [])
        if expected["verdict"] != "valid" and (not codes or codes[0] not in FRESHNESS_CODES):
            continue
        verdict = rules.run(rule_set, (AUDIT_CORPUS / member["file"]).read_bytes())
        got = (verdict.admitted, verdict.code)
        want = (True, None) if expected["verdict"] == "valid" else (False, codes[0])
        compared.append((member["draftId"], got == want, got, want))
    assert len(compared) >= 20
    assert [c for c in compared if not c[1]] == []


def test_every_valid_single_record_of_the_corpus_is_admitted():
    """Admission refuses only what a verifier would: every record the corpus calls valid, revision 01's
    consumption entries among them, is admitted. Bundles (retention, record series) are other shapes."""
    manifest = json.loads((AUDIT_CORPUS / "MANIFEST.json").read_text())
    rule_set = rules.get("audit-freshness")
    checked, refused = 0, []
    for member in manifest["vectors"]:
        if member.get("expected", {}).get("verdict") != "valid":
            continue
        raw = (AUDIT_CORPUS / member["file"]).read_bytes()
        document = json.loads(raw)
        if "envelope" in document or "records" in document:
            continue
        checked += 1
        verdict = rules.run(rule_set, raw)
        if not verdict.admitted:
            refused.append((member.get("draftId"), verdict.code))
    assert checked >= 50
    assert refused == []


# ---------------------------------------------------------------- shapes and options the vectors do not reach


@pytest.mark.parametrize(
    ("catalog", "code"),
    [
        ({"entries": [{"url": "https://x.example/a", "trustManifest": []}]}, "trust_manifest_malformed"),
        ({"entries": [{"url": "https://x.example/a", "trustManifests": [5]}]}, "trust_manifest_malformed"),
        ({"entries": [{"url": "https://x.example/a", "trustManifest": {"attestations": {}}}]}, "attestation_malformed"),
        ({"entries": [5]}, "entry_malformed"),
        ({"entries": [{"data": {"entries": {}}}]}, "entry_malformed"),
        ({}, "entry_malformed"),
    ],
)
def test_catalog_members_of_the_wrong_type_are_refused(catalog, code):
    verdict = rules.run(rules.get("catalog-attestations"), json.dumps(catalog).encode())
    assert code in [r.code for r in verdict.refusals]


@pytest.mark.parametrize("sig", ["", "!!!", "AA==", "AB==", "-_8=", "+_8=", None, 7])
def test_a_signature_counts_only_when_it_is_non_empty_canonical_base64(sig):
    from agent_evidence_admission import catalog_rules

    present = catalog_rules._signature_present({"sig": sig})
    assert present is (sig in ("AA==", "-_8="))


@pytest.mark.parametrize(
    ("text", "data"),
    [("+/8=", b"\xfb\xff"), ("-_8=", b"\xfb\xff"), ("QQ==", b"A")],
)
def test_dsse_base64_reads_both_alphabets(text, data):
    from agent_evidence_admission.dsse import decode_base64

    assert decode_base64(text) == data


@pytest.mark.parametrize("text", ["+_8=", "QR==", "QQ", "Q Q==", 7])
def test_dsse_base64_refuses_a_mixed_alphabet_and_a_second_spelling(text):
    from agent_evidence_admission.dsse import EnvelopeError, decode_base64

    with pytest.raises(EnvelopeError):
        decode_base64(text)


def test_a_url_safe_envelope_opens():
    import base64

    from agent_evidence_admission import dsse

    seed = bytes(range(32))
    for n in range(64):
        payload = b"?" * n + b">"
        if any(c in base64.b64encode(payload).decode() for c in "+/"):
            break
    envelope = dsse.make_envelope(payload, seed)
    envelope["payload"] = base64.urlsafe_b64encode(payload).decode()
    trusted = {envelope["signatures"][0]["keyid"]: dsse.ed25519.public_key(seed)}
    assert dsse.open_envelope(envelope, trusted).payload == payload


@pytest.mark.parametrize("code", sorted(rules.UNWARNABLE))
def test_a_code_that_means_nothing_was_read_cannot_be_warned(code):
    with pytest.raises(ValueError, match="cannot be a warning"):
        rules.run(rules.get("ijson"), b"{", warn=[code])


def test_a_warned_parse_code_reads_on_and_every_rule_still_runs():
    raw = case_bytes("audit-freshness", "duplicate-in-payload").raw
    verdict = rules.run(rules.get("audit-freshness"), raw, warn=["duplicate-member"])
    assert [w.code for w in verdict.warnings] == ["duplicate-member"]
    assert verdict.code == "evaluation-inconsistent"
    catalog = b'{"entries":[{"url":"https://x.example/a","trustManifest":{"attestations":[]}}],"entries":[{"url":7}]}'
    verdict = rules.run(rules.get("catalog-attestations"), catalog, warn=["duplicate-member"])
    assert verdict.code == "entry_malformed"


def test_an_integer_past_the_interpreter_digit_limit_is_a_refusal_with_the_length_bound_off():
    checks = [c for c in strict_json.CHECKS if c != "number-token-too-long"]
    with pytest.raises(Refusal) as caught:
        strict_json.loads(b"[1" + b"0" * 5000 + b"]", checks=checks)
    assert caught.value.code == "value-not-representable"


@pytest.mark.parametrize(
    ("text", "holds"),
    [("0.1", True), ("1e5", True), ("1.50", True), ("5e-324", True), ("1.5e10", True), ("2.5e-7", True),
     ("0.1000000000000000055511151231257827021181583404541015625", True),
     ("3.141592653589793238462643383279", False), ("0.30000000000000000001", False), ("2.4703282292062328e-324", False)],
)
def test_a_fraction_is_admitted_only_when_its_double_holds_it(text, holds):
    if holds:
        assert strict_json.loads(f'{{"n":{text}}}'.encode())["n"] == float(text)
    else:
        with pytest.raises(Refusal) as caught:
            strict_json.loads(f'{{"n":{text}}}'.encode())
        assert caught.value.code == "value-not-representable"


def test_cli_file_uri_may_carry_a_query(tmp_path, capsys):
    transplant = case_bytes("catalog-attestations", "control-bound")
    uri = "https://tools.example.com/mcp/invoice-reader.json?v=1"
    raw = transplant.raw.replace(b"invoice-reader.json", b"invoice-reader.json?v=1")
    catalog = write(tmp_path, "catalog.json", raw)
    paths = []
    for name, data in transplant.files.items():
        target = uri if name.endswith("invoice-reader.json") else name
        paths += ["--file", f"{target}={write(tmp_path, str(len(paths)) + '.bin', data)}"]
    assert main(["admit", "catalog-attestations", catalog, *paths]) == 0, capsys.readouterr()


def test_an_entry_digest_under_an_unknown_algorithm_binds_nothing():
    from agent_evidence_admission import catalog_rules

    statement = {"subject": [{"digest": {"md5": "0" * 32}}]}
    assert not catalog_rules._binding_sets(statement, {"digest": "md5:" + "0" * 32})
    assert not catalog_rules._binding_sets(statement, {"url": "https://x.example/a"})
    assert catalog_rules._binding_sets({"subject": [{"digest": {"sha3_256": "ab"}}]}, {"digest": "sha3-256:ab"})


@pytest.mark.parametrize(
    "options",
    [
        {"tokenEndpoints": "https://as.example.com/token"},
        {"skew": -1},
        {"skew": True},
        {"resource": ""},
        {"issuers": ["https://as.example.com", 5]},
    ],
)
def test_options_of_the_wrong_type_are_refused(options):
    case = case_bytes("mcp-authz", "valid")
    verdict = rules.run(rules.get("mcp-authz"), case.raw, {**case.options, **options})
    assert "option-malformed" in [r.code for r in verdict.refusals]
