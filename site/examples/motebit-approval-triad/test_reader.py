"""Independent controls for signatures, complete source and exact claim comparison."""

import base64
import copy
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("triad_reader", ROOT / "reader.py")
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def signed(record, seed=bytes(range(33, 65))):
    body = {key: value for key, value in record.items() if key != "signature"}
    raw = Ed25519PrivateKey.from_private_bytes(seed).sign(rfc8785.dumps(body))
    return {**body, "signature": base64.urlsafe_b64encode(raw).decode().rstrip("=")}


def test_exact_native_outputs():
    expected = reader.read_object(ROOT / "retained" / "expected.json")
    result = reader.compare(ROOT, expected)
    assert result["differences"] == []
    assert len(result["rows"]) == 7
    assert result["rows"][0]["unjoined"]["deny-receipt.json"]["signature_receipt"] == "pass"
    assert all(row["claims"]["binding"] == "not_evaluated" for row in result["rows"])


@pytest.mark.parametrize("protected", [False, True])
def test_git_checkout_preserves_producer_bytes(tmp_path, protected):
    source, exported = tmp_path / "source", tmp_path / "exported"
    source.mkdir()
    exported.mkdir()
    shutil.copytree(ROOT / "retained", source / "retained")
    shutil.copyfile(ROOT / "SOURCE.json", source / "SOURCE.json")
    if protected:
        shutil.copyfile(ROOT / ".gitattributes", source / ".gitattributes")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "core.autocrlf=false", "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "core.autocrlf=true",
                    "checkout-index", "--all", "--prefix=" + exported.as_posix() + "/"], check=True)
    if protected:
        expected = reader.read_object(exported / "retained" / "expected.json")
        assert reader.compare(exported, expected)["differences"] == []
    else:
        with pytest.raises(ValueError, match="retained source bytes differ"):
            reader.check_source(exported)


def test_all_producer_oracle_mutation_categories():
    expected = reader.read_object(ROOT / "retained" / "expected.json")
    total = 0
    for name in reader.CASES:
        original = expected["cases"][name]
        replacements = {
            "verdict": "MATCH" if original["verdict"] != "MATCH" else "MISMATCH",
            "codes": original["codes"] + ["run"], "decisive": "binding",
            "files": {**original["files"], next(iter(original["files"])): "0" * 64},
        }
        for key, value in replacements.items():
            changed = copy.deepcopy(expected)
            changed["cases"][name][key] = value
            assert reader.compare(ROOT, changed)["differences"], (name, key)
            total += 1
        changed = copy.deepcopy(expected)
        del changed["cases"][name]
        assert reader.compare(ROOT, changed)["differences"]
        total += 1
        # The producer separately tests binding=pass and every claim flip.
        for claim in ["binding", *expected["claims"]]:
            changed = copy.deepcopy(expected)
            current = original["claims"][claim]
            value = "pass" if claim == "binding" or current == "fail" else "fail"
            changed["cases"][name]["claims"][claim] = value
            assert reader.compare(ROOT, changed)["differences"], (name, claim)
            total += 1
    changed = copy.deepcopy(expected)
    changed["cases"]["control"]["unjoined"]["deny-receipt.json"]["signature_receipt"] = "fail"
    assert reader.compare(ROOT, changed)["differences"]
    changed = copy.deepcopy(expected)
    changed["pinned_keys"]["approver"] = changed["pinned_keys"]["agent"]
    assert reader.compare(ROOT, changed)["differences"]
    assert total + 2 == 114


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '[]'])
def test_ambiguous_json_refused(tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        reader.read_object(path)


@pytest.mark.parametrize("change", ["missing", "suite", "base64", "padding", "wrong-key", "non-finite"])
def test_signature_refusals(change):
    record = reader.read_object(ROOT / "retained/cases/control/approval.json")
    if change == "missing":
        record.pop("signature")
    elif change == "suite":
        record["suite"] = "unknown"
    elif change == "base64":
        record["signature"] = "!"
    elif change == "padding":
        record["signature"] += "=="
    elif change == "wrong-key":
        record["public_key"] = reader.KEYS["agent"]
        record = signed(record, bytes(range(1, 33)))
    else:
        record["risk_level"] = float("nan")
    assert reader.signature(record, "approver") == "fail"


def test_full_jcs_preimage_accepts_signed_extensions():
    record = reader.read_object(ROOT / "retained/cases/control/approval.json")
    record.update({"\U0001f600": 1.25, "\ufb33": -0.0})
    assert reader.signature(signed(record), "approver") == "pass"


@pytest.mark.parametrize("field", ["approval_id", "resolved_at"])
def test_signed_malformed_native_fields_are_setup_errors(field):
    approval = reader.read_object(ROOT / "retained/cases/control/approval.json")
    invocation = reader.read_object(ROOT / "retained/cases/control/invocation.json")
    receipt = reader.read_object(ROOT / "retained/cases/control/receipt.json")
    approval.pop(field)
    with pytest.raises(ValueError):
        reader.relations(signed(approval), invocation, receipt)


def test_boolean_timestamp_is_not_integer_time():
    approval = reader.read_object(ROOT / "retained/cases/control/approval.json")
    invocation = reader.read_object(ROOT / "retained/cases/control/invocation.json")
    receipt = reader.read_object(ROOT / "retained/cases/control/receipt.json")
    approval["resolved_at"] = True
    with pytest.raises(ValueError):
        reader.relations(approval, invocation, receipt)


@pytest.mark.parametrize("mode", ["extra", "changed", "missing", "symlink", "duplicate"])
def test_source_refusals(tmp_path, mode):
    shutil.copytree(ROOT / "retained", tmp_path / "retained")
    shutil.copyfile(ROOT / "SOURCE.json", tmp_path / "SOURCE.json")
    path = tmp_path / "retained/cases/control/approval.json"
    if mode == "duplicate":
        source = reader.read_object(tmp_path / "SOURCE.json")
        source["files"].append(copy.deepcopy(source["files"][0]))
        (tmp_path / "SOURCE.json").write_text(json.dumps(source))
    elif mode == "extra":
        (tmp_path / "retained/extra.json").write_text("{}")
    elif mode == "changed":
        path.write_bytes(path.read_bytes() + b"\n")
    elif mode == "missing":
        path.unlink()
    else:
        original = tmp_path / "original.json"
        path.rename(original)
        path.symlink_to(original)
    with pytest.raises(ValueError):
        reader.check_source(tmp_path)


def test_comparison_preserves_null_missing_and_boolean_number_disagreements():
    expected = reader.read_object(ROOT / "retained/expected.json")
    expected["cases"]["control"]["extra"] = None
    expected["cases"]["control"]["claims"]["binding"] = True
    expected["claims"] = []
    result = reader.compare(ROOT, expected)
    assert {x["field"] for x in result["differences"]} == {"claims", "extra"}
    assert result["rows"][0]["claims"]["binding"] == "not_evaluated"


def test_cli_distinguishes_agreement_disagreement_and_setup(tmp_path, capsys):
    assert reader.main([]) == 0
    assert json.loads(capsys.readouterr().out)["differences"] == []
    expected = reader.read_object(ROOT / "retained/expected.json")
    expected["cases"]["control"]["verdict"] = "MISMATCH"
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(expected))
    assert reader.main(["--expected", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["differences"]
    assert reader.main(["--root", str(tmp_path)]) == 2
    assert "setup_error" in json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("cases", [[], None, {"control": "bad"}, {"control": None}])
def test_cli_refuses_malformed_oracle_containers(tmp_path, capsys, cases):
    expected = reader.read_object(ROOT / "retained/expected.json")
    expected["cases"] = cases
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(expected))
    assert reader.main(["--expected", str(path)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert "setup_error" in result
    assert "differences" not in result
