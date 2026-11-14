"""Strictest-wins verdict resolution: the conflict vectors, order independence and the vocabulary's list."""

import itertools
import json
from pathlib import Path

import pytest
from agent_evidence_admission import verdict_precedence as vp
from agent_evidence_admission.cli import main

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "precedence" / "manifest.json"
MANIFEST = json.loads(VECTORS.read_text())
CASES = MANIFEST["cases"]
REGISTRY = Path(__file__).resolve().parents[3] / "vocabulary" / "registry.json"


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_vector(case):
    if "error" in case["expect"]:
        with pytest.raises(vp.PrecedenceInputError) as caught:
            vp.resolve(case["answers"])
        assert str(caught.value) == case["expect"]["error"]
        return
    resolution = vp.resolve(case["answers"])
    assert resolution.as_dict() == case["expect"]


def test_the_manifest_states_the_order_the_module_uses():
    assert tuple(MANIFEST["order"]) == vp.ORDER


def test_the_vocabulary_registry_lists_the_same_order():
    if not REGISTRY.exists():  # the wheel is tested away from the monorepo
        pytest.skip("the vocabulary registry is not beside this package")
    assert tuple(json.loads(REGISTRY.read_text())["terms"]["decision_verdict"]["values"]) == vp.ORDER


@pytest.mark.parametrize("case", [c for c in CASES if "error" not in c["expect"]], ids=lambda c: c["id"])
def test_the_answer_does_not_depend_on_the_order_policies_answered_in(case):
    for permutation in itertools.permutations(case["answers"]):
        assert vp.resolve(list(permutation)).as_dict() == case["expect"]


def test_every_verdict_pair_resolves_to_the_stricter():
    for low, high in itertools.combinations(vp.ORDER, 2):
        answers = [{"policy": "a", "verdict": low, "constraint": "c"}, {"policy": "b", "verdict": high, "constraint": "c"}]
        assert vp.resolve(answers).verdict == high


def test_the_manifest_holds_both_polarities_and_every_verdict_as_a_winner():
    assert {c["polarity"] for c in CASES} == {"positive", "negative"}
    assert {c["expect"]["verdict"] for c in CASES if "verdict" in c["expect"]} == set(vp.ORDER)


def test_the_command_prints_the_resolution_and_refuses_an_empty_set(tmp_path, capsys):
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps({"answers": [{"policy": "p1", "verdict": "allow"}, {"policy": "p2", "verdict": "halt"}]}))
    assert main(["resolve-verdicts", str(answers), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "halt"
    answers.write_text("[]")
    assert main(["resolve-verdicts", str(answers)]) == 2
    assert "no-decision" in capsys.readouterr().err
