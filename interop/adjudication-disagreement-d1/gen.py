"""Write the inputs, pins and expectations of the D1 and L1 adjudication cases.

    python3 interop/adjudication-disagreement-d1/gen.py          # write
    python3 interop/adjudication-disagreement-d1/gen.py --check  # fail if a file differs

Each case is one set of records read by two methods: ``event_absence/v2`` in
agent-evidence-verify, and the standalone finite checker published in
Witnessability/witnessability-research (Mikhail Sergeev). The probity-side records
and the checker-side model of one case describe the same synthetic run. The checker
model is where the case's binding and failure-domain assumptions are written down;
the probity record format has no field for either, which is what these cases measure.

The expectations below were written from the two methods' published rules before
either method was run on these inputs. ``run.py`` and ``run_checker.py`` compare the
run results with them.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

CHECKER = {
    "repository": "Witnessability/witnessability-research",
    "commit": "719b243b6c8b1bcd4429cab6347bb3e77ead6a5e",
    "files": {
        "standalone/src/witnessability_checker/__init__.py": "29173d924f69319bceed4ae09511ffc467b38f92d3e288113ad727fc89d5044a",
        "standalone/src/witnessability_checker/__main__.py": "935a1c1166b0c1ea35a82256345000bf2c73ded718d77773bc27a71ecce28f7d",
        "standalone/src/witnessability_checker/analysis.py": "bebc7340f1e13b2a3e8ea92dbe30ff425f63c6599bcc82177d28d3c795cba0d7",
        "standalone/src/witnessability_checker/capability_command.py": "72206f435e86d066cafe9c4c721dcb5ed78ec07f1bd4a2be8aa3e7cc078c3fb0",
        "standalone/src/witnessability_checker/cli.py": "fa90888f5ae5dd2b3f770884c1a277c80edfc7fd6af1ab2eeee931c47c3ff3f9",
        "standalone/src/witnessability_checker/common.py": "0754a2ec68284b4b8c2411356f79dec35887140c18888ad19c5d275da0f61a92",
        "standalone/src/witnessability_checker/context.py": "7f551fd06f8d123b4191924ab4676264e11b8ad0a0383fa6a9610a3d9469e668",
        "standalone/src/witnessability_checker/legacy.py": "b749d73065d0373a7377ff4d1bac1a89f4d7c19aaef5f0da18454c5f8090db78",
        "standalone/src/witnessability_checker/model.py": "e4fc3704c13b6da816b43b5f5a445a79bd2a9c00ff2e0727ce3ba51e09fff4ad",
        "standalone/src/witnessability_checker/validation.py": "caa71617c6a1ba9ef6859e6aae1808fb98e98e9a67a479595af20282d2bfc611",
        "standalone/src/witnessability_checker/verify.py": "f2fb2cfb8b34d050bfe3238b11e6a516afc46b4f5b2bcf603c6415569ec8bb0e",
    },
}
VERIFIER = "agent-evidence-verify==0.5.1"

INVOCATION = "d1-call-1"
PARTY = "agent-d1"
SCOPE = {"id": "d1-window", "start": "2026-11-19T09:00:00Z", "end": "2026-11-19T09:01:00Z"}
CHECKER_POLICY = {"acknowledged_assumptions": True, "id": "declared-model", "version": "1"}
SYNTHETIC = "Synthetic D1 consumer-selected premise; not authenticated"

COVERED = ["covered_empty", "covered_event"]


def observation(producer: str, events: list[dict]) -> dict:
    return {"schema_version": "probity-observation/v1", "claim_id": "d1-absence",
            "invocation_id": INVOCATION, "producer": producer, "scope": SCOPE,
            "coverage": "complete", "vantage": "independent", "events": events}


def capability(producer: str, visible: list[str]) -> dict:
    return {"schema_version": "probity-capabilities/v1", "claim_id": "d1-absence",
            "invocation_id": INVOCATION, "producer": producer, "visible_event_types": visible}


def model(name: str, claim: str, histories: dict[str, bool], domains: list[str],
          alphabets: list[list[str]], joint: dict[str, list[list[str]]],
          faults: list[list[str]]) -> dict:
    return {"schema_version": "wresearch-checker-input-1",
            "semantics_version": "finite-joint-identity-1",
            "model": {"name": name, "claim": claim, "binding": "identity",
                      "histories": list(histories), "truth": histories, "domains": domains,
                      "alphabets": alphabets, "joint": joint,
                      "faults": [sorted(f) for f in faults]}}


ABSENCE = f"No write event by {PARTY} for invocation {INVOCATION} in d1-window."
EXECUTED_A = (f"The write {PARTY} executed for invocation {INVOCATION} in d1-window, after permission "
              "for write A, was write A (premise: exactly one write followed the permission).")
WRITE_10 = {"id": "e1", "type": "write", "time": "2026-11-19T09:00:10Z"}

# Each case: the records our reader reads, the checker model and record, and the expected
# outputs of both methods. "authority" texts state the premise each record rests on; the
# reader carries them through unread, as it does for every policy witness.
CASES = {
    "D1-01-binding-uncertain": {
        "shape": "uncertain binding",
        "event_type": "write",
        "observations": {"observation": ("observer-d1", [WRITE_10],
                                         "Observer attributes each write to an invocation through "
                                         "the session id, which a concurrent call d1-call-2 shares")},
        "capability": ("observer-d1", ["write"]),
        "model": model(
            "D1-01-binding-uncertain", ABSENCE,
            {"N": True, "W10": False, "X10": True}, ["admitted_observation"], [COVERED],
            {"N": [["covered_empty"]], "W10": [["covered_event"]],
             # X10: the write at 09:00:10 was d1-call-2's; the observer's session-id
             # attribution records it as d1-call-1's, so it yields the same atom as W10.
             "X10": [["covered_event"]]},
            [[]]),
        "record": ["covered_event"],
        "expected": {
            "probity": {"PEER": ("contradicted", "event_observed"),
                        "EXTERNAL": ("contradicted", "event_observed")},
            "checker": {"verdict": "UNRESOLVED", "compatible_histories": ["W10", "X10"]},
        },
    },
    "D1-02-shared-failure-domain": {
        "shape": "shared failure",
        "event_type": "write",
        "observations": {
            "observation": ("observer-d1-a", [],
                            "Observer A; runs on capture host H, the same host as observer B"),
            "observation-b": ("observer-d1-b", [],
                              "Observer B; runs on capture host H, the same host as observer A"),
        },
        "capability": ("observer-d1-a", ["write"]),
        "model": model(
            "D1-02-shared-failure-domain", ABSENCE,
            {"N": True, "W30": False}, ["observer_a", "observer_b"], [COVERED, COVERED],
            {"N": [["covered_empty", "covered_empty"]],
             "W30": [["covered_event", "covered_event"]]},
            # One failure domain: host H can corrupt both observers together.
            [[], ["observer_a"], ["observer_b"], ["observer_a", "observer_b"]]),
        "record": ["covered_empty", "covered_empty"],
        "expected": {
            "probity": {"PEER": ("supported", "absence_within_covered_scope"),
                        "EXTERNAL": ("not_established", "witness_scope_below_required")},
            "checker": {"verdict": "UNRESOLVED", "compatible_histories": ["N", "W30"]},
        },
    },
    "D1-03-separate-failure-domains": {
        "shape": "shared failure (control)",
        "event_type": "write",
        "observations": {
            "observation": ("observer-d1-a", [],
                            "Observer A; runs on capture host H1, separate from observer B"),
            "observation-b": ("observer-d1-b", [],
                              "Observer B; runs on capture host H2, separate from observer A"),
        },
        "capability": ("observer-d1-a", ["write"]),
        "model": model(
            "D1-03-separate-failure-domains", ABSENCE,
            {"N": True, "W30": False}, ["observer_a", "observer_b"], [COVERED, COVERED],
            {"N": [["covered_empty", "covered_empty"]],
             "W30": [["covered_event", "covered_event"]]},
            # Two failure domains: at most one observer fails.
            [[], ["observer_a"], ["observer_b"]]),
        "record": ["covered_empty", "covered_empty"],
        "expected": {
            "probity": {"PEER": ("supported", "absence_within_covered_scope"),
                        "EXTERNAL": ("not_established", "witness_scope_below_required")},
            "checker": {"verdict": "TRUE", "compatible_histories": ["N"]},
        },
    },
    "L1-01-lost-binding": {
        "shape": "lost binding",
        "event_type": "write:B",
        "observations": {"observation": ("observer-d1", [WRITE_10],
                                         "Observer sees that a write completed; the write's "
                                         "binding to the permitted action is not recorded")},
        "capability": ("observer-d1", ["write"]),
        "permission": {"schema_version": "d1-permission/v1", "invocation_id": INVOCATION,
                       "permits": "write:A"},
        "model": model(
            "L1-01-lost-binding", EXECUTED_A,
            {"EA": True, "EB": False}, ["permission", "result"],
            [["perm_A"], ["result_unbound", "result_A", "result_B"]],
            # Both histories produce the same record once the result names no action.
            {"EA": [["perm_A", "result_unbound"]], "EB": [["perm_A", "result_unbound"]]},
            [[]]),
        "record": ["perm_A", "result_unbound"],
        "expected": {
            "probity": {"PEER": ("not_established", "field_visibility_unestablished"),
                        "EXTERNAL": ("not_established", "field_visibility_unestablished")},
            "checker": {"verdict": "UNRESOLVED", "compatible_histories": ["EA", "EB"]},
        },
    },
    "L1-02-binding-restored": {
        "shape": "lost binding (control)",
        "event_type": "write:B",
        "observations": {"observation": ("observer-d1",
                                         [{"id": "e1", "type": "write:A",
                                           "time": "2026-11-19T09:00:10Z"}],
                                         "Observer records each completed write with the action "
                                         "it executed")},
        "capability": ("observer-d1", ["write:A", "write:B"]),
        "permission": {"schema_version": "d1-permission/v1", "invocation_id": INVOCATION,
                       "permits": "write:A"},
        "model": model(
            "L1-02-binding-restored", EXECUTED_A,
            {"EA": True, "EB": False}, ["permission", "result"],
            [["perm_A"], ["result_unbound", "result_A", "result_B"]],
            {"EA": [["perm_A", "result_A"]], "EB": [["perm_A", "result_B"]]},
            [[]]),
        "record": ["perm_A", "result_A"],
        "expected": {
            "probity": {"PEER": ("supported", "absence_within_covered_scope"),
                        "EXTERNAL": ("not_established", "witness_scope_below_required")},
            "checker": {"verdict": "TRUE", "compatible_histories": ["EA"]},
        },
    },
}


def dump(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def canonical_sha(value: object) -> str:
    """The checker's pin: SHA-256 of its canonical encoding (standalone/CONTRACT.md)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def checker_pins(document: dict, record: list[str]) -> dict:
    m = document["model"]
    pins = {"model": canonical_sha(m),
            "claim": canonical_sha({"claim": m["claim"], "truth": m["truth"]}),
            "policy": canonical_sha(CHECKER_POLICY),
            "record": canonical_sha(record)}
    pins["context"] = canonical_sha({"schema_version": document["schema_version"],
                                     "semantics_version": document["semantics_version"],
                                     "model": pins["model"], "claim": pins["claim"],
                                     "policy": pins["policy"]})
    return pins


def probity_files(name: str, spec: dict) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    producer, visible = spec["capability"]
    files["capability.json"] = dump(capability(producer, visible))
    witnesses = {"capability": {"artifact": "capability", "authority": SYNTHETIC}}
    for witness, (obs_producer, events, premise) in spec["observations"].items():
        files[f"{witness}.json"] = dump(observation(obs_producer, events))
        witnesses[witness] = {"artifact": witness, "authority": f"{SYNTHETIC}. {premise}",
                              "producer": obs_producer, "vantage": "independent"}
    if "permission" in spec:
        files["permission.json"] = dump(spec["permission"])
    artifacts = {}
    for filename, body in files.items():
        artifact = filename[:-len(".json")]
        digest = hashlib.sha256(body).hexdigest()
        artifacts[artifact] = {"path": filename, "sha256": digest, "length": len(body)}
        if artifact in witnesses:
            witnesses[artifact]["sha256"] = digest
    files["case.json"] = dump({"schema_version": "probity-case/v1", "case_id": "d1-absence",
                               "artifacts": artifacts})
    policy = {"schema_version": "probity-policy/v1",
              "witnesses": {k: dict(sorted(v.items())) for k, v in witnesses.items()},
              "assessments": {"d1-absence": {
                  "claim_type": "event_absence/v2", "event_type": spec["event_type"],
                  "invocation_id": INVOCATION, "scope": SCOPE,
                  "capability_witness": "capability", "observation_witness": "observation",
                  "observed_party": PARTY}}}
    files["policy.json"] = dump(policy)
    return {f"inputs/probity/{name}/{k}": v for k, v in sorted(files.items())}


def build() -> dict[str, bytes]:
    out: dict[str, bytes] = {"inputs/checker/checker-policy.json": dump(CHECKER_POLICY)}
    expected: dict = {}
    for name, spec in CASES.items():
        out.update(probity_files(name, spec))
        out[f"inputs/checker/models/{name}.json"] = dump(spec["model"])
        out[f"inputs/checker/records/{name}.json"] = dump(spec["record"])
        out[f"inputs/checker/expected-pins/{name}.json"] = dump(
            checker_pins(spec["model"], spec["record"]))
        exp = spec["expected"]
        expected[name] = {
            "shape": spec["shape"],
            "probity": {scope: {"decision": d, "reason": r} for scope, (d, r) in exp["probity"].items()},
            "checker": exp["checker"],
        }
    manifest = {"files": {path: {"length": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                          for path, body in sorted(out.items())},
                "source": "interop/adjudication-disagreement-d1/gen.py",
                "verifier": VERIFIER,
                "checker": {"repository": CHECKER["repository"], "commit": CHECKER["commit"]}}
    out["MANIFEST.json"] = dump(manifest)
    out["EXPECTED.json"] = dump({
        "note": ("Expected outputs written from each method's published rules before either "
                 "method ran on these inputs. run.py and run_checker.py compare runs with them."),
        "verifier": VERIFIER, "checker_commit": CHECKER["commit"], "cases": expected})
    out["CHECKER-PIN.json"] = dump({"repository": CHECKER["repository"], "commit": CHECKER["commit"],
                                    "files": [{"path": p, "sha256": s}
                                              for p, s in sorted(CHECKER["files"].items())]})
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for rel, body in build().items():
        path = os.path.join(HERE, rel)
        current = open(path, "rb").read() if os.path.exists(path) else None
        if current == body:
            continue
        if check:
            stale.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
    for rel in stale:
        print("stale:", rel)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
