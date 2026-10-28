"""Tests for the ot-federation reader: every frozen answer, the refusals, and corpus adequacy.

The adequacy test seeds one fault into the reader at a time (drop or bend one check)
and requires the corpus to catch it: at least one case must then disagree with its
frozen answer. A seeded fault the corpus does not catch means a verifier missing that
check would still agree with every case, so the corpus does not exercise the check.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.ot_federation import run as runner  # noqa: E402
from agent_evidence_vectors.ot_federation.reader import (  # noqa: E402
    MalformedCase,
    evaluate,
    load_case,
)

READER = PACKAGING / "agent_evidence_vectors/ot_federation/reader.py"
CORPUS = PACKAGING / "agent_evidence_vectors/ot_federation/corpus"
CASES = load_case((CORPUS / "cases.json").read_bytes())["cases"]


def _answer(module: types.ModuleType, case: dict) -> dict:
    got = module.evaluate(copy.deepcopy(case))
    return {"verdict": got["verdict"], "claims": got["claims"]}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_frozen_answer(case: dict) -> None:
    got = evaluate(copy.deepcopy(case["case"]))
    assert {"verdict": got["verdict"], "claims": got["claims"]} == case["expected"]


def test_every_negative_names_a_claim_and_positives_have_none() -> None:
    for case in CASES:
        got = evaluate(copy.deepcopy(case["case"]))
        assert (got["claim_id"] is None) == (
            got["verdict"] == "ESTABLISHED" or got["claims"] is None
        )


def test_corpus_is_what_the_builder_writes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts/ot-federation-build.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_changed_member_is_refused(tmp_path: Path) -> None:
    for name in ("cases.json", "manifest.json"):
        (tmp_path / name).write_bytes((CORPUS / name).read_bytes())
    (tmp_path / "cases.json").write_bytes(
        (CORPUS / "cases.json").read_bytes().replace(b"ZONE-03", b"ZONE-04", 1)
    )
    with pytest.raises(MalformedCase):
        runner.load_corpus(tmp_path)


def test_duplicate_member_and_non_finite_are_refused() -> None:
    with pytest.raises(MalformedCase):
        load_case(b'{"a": 1, "a": 2}')
    with pytest.raises(MalformedCase):
        load_case(b'{"a": NaN}')


def test_reader_never_raises_on_odd_input() -> None:
    for odd in (None, [], "x", {"schema": "ot-federation-case/v1"}, {"schema": 1}):
        assert evaluate(odd)["verdict"] == "NOT_ESTABLISHED"


def test_strict_vantage_never_establishes_a_same_deployment_observation() -> None:
    clean = next(c for c in CASES if c["id"] == "clean_verify")["case"]
    got = evaluate(copy.deepcopy(clean), strict_vantage=True)
    assert got["claims"]["declared_effect_observed"] == "NOT_ESTABLISHED"
    separate = copy.deepcopy(clean)
    separate["remora_envelope"]["effect"]["ledger_entry"]["effect_vantage"] = "separate_deployment"
    assert evaluate(separate, strict_vantage=True)["verdict"] == "ESTABLISHED"


def test_emitted_fixture_set_reads_back_identically(tmp_path: Path) -> None:
    manifest = runner.emit_fixtures(CORPUS, tmp_path / "set")
    expected = {c["id"]: c["expected"]["verdict"] for c in CASES}
    assert {c["case_id"]: c["expected_verdict"] for c in manifest["cases"]} == expected
    for entry in manifest["files"]:
        case = load_case((tmp_path / "set" / entry["path"]).read_bytes())
        assert evaluate(case)["verdict"] == expected[case["case_id"]]
    raw = (tmp_path / "set/cases/evidence_keys_unsorted.json").read_text("utf-8")
    assert raw.index('"proposal"') < raw.index('"effect_verification"'), (
        "evidence keys must stay unsorted on disk"
    )
    assert "Zürich" in (tmp_path / "set/cases/evidence_non_ascii.json").read_text("utf-8")


# One seeded fault each: (name, exact text in reader.py, replacement). Each must be caught.
MUTANTS = [
    ("ignore decision.approved", 'if decision["approved"] is not True:', "if False:"),
    ("ignore unknown decision kinds", "if kind not in APPROVING:", "if False:"),
    ("ignore the reviewer's answer", 'if reviewer["approved"] is not True:', "if False:"),
    (
        "a missing reviewer counts as approval",
        'if not isinstance(reviewer, dict) or "approved" not in reviewer:\n'
        "            return NOT_ESTABLISHED",
        "if False:\n            return NOT_ESTABLISHED",
    ),
    (
        "ask a reviewer of ACCEPT too",
        'NEEDS_REVIEWER = frozenset({"verify", "escalate"})',
        'NEEDS_REVIEWER = frozenset({"verify", "escalate", "accept"})',
    ),
    ("ignore the envelope binding", "if env_id is not None and env_id != pid:", "if False:"),
    ("ignore the evidence binding", "if ev_id is not None and ev_id != pid:", "if False:"),
    ("an unbound decision counts as bound", "if env_id is None and ev_id is None:", "if False:"),
    (
        "require both binding sources",
        "if env_id is None and ev_id is None:",
        "if env_id is None or ev_id is None:",
    ),
    (
        "not executed but applied is only unestablished",
        '                CONTRADICTED,\n                "nothing executed, yet',
        '                NOT_ESTABLISHED,\n                "nothing executed, yet',
    ),
    ("ignore an observation when nothing executed", "or obs is not None:", ":"),
    (
        "assume one execution when absent",
        'return NOT_ESTABLISHED, "execution.executions absent"',
        'return ESTABLISHED, "execution.executions absent"',
    ),
    ("accept any execution count", 'if execution["executions"] != 1:', "if False:"),
    (
        "ignore the twin's operation id",
        'if twin["operation_id"] != claim["proposal_id"]:',
        "if False:",
    ),
    (
        "ignore the twin's requested value",
        'if "requested_setpoint_c" in twin and '
        'twin["requested_setpoint_c"] != claim["setpoint_c"]:',
        "if False:",
    ),
    ("ignore the twin's status", 'if twin["status"] != "APPLIED":', "if False:"),
    ("ignore the twin's zone", 'if twin["zone_id"] != claim["zone_id"]:', "if False:"),
    (
        "ignore the twin's applied value (observation only)",
        'if twin["new_setpoint_c"] != claim["setpoint_c"]:',
        "if False:",
    ),
    (
        "a missing applied value counts as applied",
        'if not _is_num(twin.get("new_setpoint_c")):',
        "if False:",
    ),
    (
        "ignore the observed value (twin only)",
        'if obs["observed_setpoint_c"] != claim["setpoint_c"]:',
        "if False:",
    ),
    (
        "no observation counts as observed",
        'if obs is None or "observed_setpoint_c" not in obs:\n'
        '        return NOT_ESTABLISHED, "no observed value"',
        'if False:\n        return NOT_ESTABLISHED, "no observed value"',
    ),
    (
        "assume a dispatch time",
        "if dispatched is None:\n        return NOT_ESTABLISHED",
        "if False:\n        return NOT_ESTABLISHED",
    ),
    (
        "assume an observation time",
        'if obs is None or "observed_at_sim_s" not in obs:\n'
        '        return NOT_ESTABLISHED, "observation time absent"',
        'if obs is not None and "observed_at_sim_s" not in obs:\n'
        '        return ESTABLISHED, "assumed"\n'
        '    if obs is None:\n        return NOT_ESTABLISHED, "observation time absent"',
    ),
    (
        "strictly after the dispatch",
        'if obs["observed_at_sim_s"] < dispatched:',
        'if obs["observed_at_sim_s"] <= dispatched:',
    ),
    (
        "ignore the evidence digest",
        'if canonical_sha256(case["remora_evidence"]) != want:',
        "if False:",
    ),
    (
        "digest with ensure_ascii=True",
        "ensure_ascii=False)\n    return hashlib",
        "ensure_ascii=True)\n    return hashlib",
    ),
    ("digest without sort_keys", "sort_keys=True, separators", "sort_keys=False, separators"),
    (
        "digest with default separators",
        'json.dumps(value, sort_keys=True, separators=(",", ":"), ',
        "json.dumps(value, sort_keys=True, ",
    ),
    ("accept a digest that is not hex", "if not HEX64.fullmatch(want):", "if False:"),
    (
        "a malformed case is established",
        '"verdict": NOT_ESTABLISHED,\n            "claim_id": None,\n'
        '            "reason": f"malformed',
        '"verdict": ESTABLISHED,\n            "claim_id": None,\n'
        '            "reason": f"malformed',
    ),
    ("skip the shape check", "        _check_shape(case)\n", "        pass\n"),
    ("accept any schema name", 'case.get("schema") != SCHEMA', "False"),
    (
        "accept a boolean execution count",
        'if "executions" in execution and not _is_int(execution["executions"]):',
        "if False:",
    ),
]


def _mutant(name: str, old: str, new: str) -> types.ModuleType:
    source = READER.read_text("utf-8")
    assert source.count(old) == 1, f"{name}: the anchor occurs {source.count(old)} times"
    module = types.ModuleType(f"mutant_{abs(hash(name))}")
    exec(compile(source.replace(old, new), name, "exec"), module.__dict__)  # noqa: S102
    return module


@pytest.mark.parametrize("name,old,new", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_corpus_catches_seeded_fault(name: str, old: str, new: str) -> None:
    module = _mutant(name, old, new)
    caught = [c["id"] for c in CASES if _answer(module, c["case"]) != c["expected"]]
    assert caught, f"no case catches the seeded fault: {name}"


def test_unmutated_reader_agrees_through_the_same_loader() -> None:
    spec = importlib.util.spec_from_file_location("plain_reader", READER)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    assert all(_answer(module, c["case"]) == c["expected"] for c in CASES)


def test_report_records_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.main(["--output", "out", "--implementation-revision", "0" * 40]) == 0
    report = json.loads((tmp_path / "out/report.json").read_text("utf-8"))
    assert report["failures"] == [] and len(report["results"]) == len(CASES)
