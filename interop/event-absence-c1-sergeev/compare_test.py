"""A flip on either side fails the comparison. Pure, no verifier or checker needed.

    python interop/event-absence-c1-sergeev/compare_test.py
"""

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = ["C1-01-covered-empty", "C1-02-event-with-gap", "C1-03-empty-with-gap"]
MAP = json.load(open(os.path.join(HERE, "PAIRING.json")))["verdict_to_decision"]
C_EXP = {
    c: {
        "status": "ok",
        "result": {"verdict": e["verdict"], "compatible_histories": e["compatible_histories"]},
    }
    for c, e in compare.checker_expectations().items()
}
C_WANT = compare.checker_expectations()
P_EXP = json.load(open(os.path.join(HERE, "EXPECTED.json")))["cases"]
P_PEER = {c: P_EXP[c]["PEER"] for c in CASES}


def run(c_out, p_out):
    return compare.compare(CASES, c_out, p_out, C_WANT, P_EXP, MAP)


def main() -> int:
    assert run(copy.deepcopy(C_EXP), copy.deepcopy(P_PEER)) == [], "pinned answers must pass"
    for case in CASES:
        for verdict in ("TRUE", "FALSE", "UNRESOLVED"):
            if verdict == C_EXP[case]["result"]["verdict"]:
                continue
            c = copy.deepcopy(C_EXP)
            c[case]["result"]["verdict"] = verdict
            bad = run(c, copy.deepcopy(P_PEER))
            assert any("checker side moved" in b for b in bad), (case, verdict, bad)
            assert any("disagree" in b for b in bad), (case, verdict, bad)
        for decision in ("supported", "contradicted", "not_established"):
            if decision == P_PEER[case]["decision"]:
                continue
            p = copy.deepcopy(P_PEER)
            p[case] = {"decision": decision, "reason": P_PEER[case]["reason"]}
            bad = run(copy.deepcopy(C_EXP), p)
            assert any("event_absence/v2 side moved" in b for b in bad), (case, decision, bad)
            assert any("disagree" in b for b in bad), (case, decision, bad)
        p = copy.deepcopy(P_PEER)
        p[case] = {"decision": P_PEER[case]["decision"], "reason": "other_reason"}
        assert any("event_absence/v2 side moved" in b for b in run(copy.deepcopy(C_EXP), p)), case
    for case in CASES:
        c = copy.deepcopy(C_EXP)
        c[case]["result"]["compatible_histories"] = ["N", "W99"]
        assert any("checker side moved" in b for b in run(c, copy.deepcopy(P_PEER))), case
        c = copy.deepcopy(C_EXP)
        c[case]["status"] = "error"
        assert any("checker side moved" in b for b in run(c, copy.deepcopy(P_PEER))), case
    both = copy.deepcopy(C_EXP)
    both[CASES[0]]["result"]["verdict"] = "FALSE"
    p = copy.deepcopy(P_PEER)
    p[CASES[0]] = {"decision": "contradicted", "reason": "event_observed"}
    assert any("checker side moved" in b for b in run(both, p)), "agreeing flips still fail"
    print("compare_test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
