"""Generate deterministic signed controls from explicit expected truth values."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from agent_evidence_vectors import run_vectors as rail

from authority_effect.reader import PROFILE, SIGNATURE_DOMAIN, commitment

ROOT = Path(__file__).resolve().parents[1] / "authority_effect" / "fixtures"
SEED = hashlib.sha256(b"public authority-effect test seed; never use in production").digest()
EFFECT = hashlib.sha256(b"synthetic effect version 1").hexdigest()
OTHER = hashlib.sha256(b"synthetic effect version 2").hexdigest()
TARGET_A = "https://fixture.example/a"
TARGET_B = "https://fixture.example/b"


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def signed(intent: dict) -> dict:
    digest = commitment(intent)
    return {
        "intent": intent,
        "commitment": digest,
        "signature": rail.ed25519_sign(SEED, SIGNATURE_DOMAIN + bytes.fromhex(digest)).hex(),
    }


def baseline() -> tuple[dict, dict, dict]:
    envelope = {
        "operation": "operation-1",
        "chainId": 8453,
        "target": TARGET_A,
        "calldataHash": "5a" * 32,
        "value": "1000",
    }
    intent = envelope | {"effectSha256": EFFECT, "validFrom": 1000, "validUntil": 2000}
    case = {
        "profile": PROFILE,
        "caseId": "matching-supplied-records",
        "authorization": signed(intent),
        "runtime": envelope | {"submittedAt": 1100},
        "report": envelope | {"completed": True},
        "observation": envelope
        | {"effectSha256": EFFECT, "observedAt": 1110, "operator": "synthetic-observer-label"},
        "scan": {
            "scanned": ["unit-a", "unit-b", "unit-c"],
            "skipped": [],
            "findings": [],
            "exitCode": 0,
            "stdout": "unit-a\nunit-b\nunit-c\nno credential-shaped values found\n",
        },
    }
    policy = {
        "profile": "probity.authority-effect-policy/v1",
        "principalPublicKey": rail.ed25519_public_key(SEED).hex(),
        "referenceTime": 1120,
        "maxObservationAge": 60,
        "scanUnits": ["unit-a", "unit-b", "unit-c"],
    }
    expected = {
        "commitmentRecomputed": True,
        "signatureUnderSelectedKey": True,
        "authorizationTimeAtUse": True,
        "destinationAuthorized": True,
        "callEnvelopeAuthorized": True,
        "reportedTargetMatchesRuntime": True,
        "historicalCompletionReported": True,
        "reportedDispatchMatchesObservation": True,
        "observationFresh": True,
        "suppliedCurrentEffectMatches": True,
        "observationProvenanceAuthenticated": None,
        "coverageComplete": True,
        "noFindingReported": True,
        "processExitMatchesCoverage": True,
        "truncationNoticePresent": None,
    }
    return case, policy, expected


def cases() -> dict[str, bytes]:
    case, policy, expected = baseline()
    files = {"policy.json": encoded(policy)}
    entries = []

    def add(name: str, updates: dict | None = None, mutate=None, selected_policy=None):
        value = copy.deepcopy(case)
        value["caseId"] = name
        if mutate:
            mutate(value)
        selected = copy.deepcopy(selected_policy or policy)
        exp = expected | (updates or {})
        payload = encoded(value)
        files[f"cases/{name}.json"] = payload
        policy_payload = encoded(selected)
        files[f"policies/{name}.json"] = policy_payload
        entries.append(
            {
                "id": name,
                "path": f"cases/{name}.json",
                "policy": f"policies/{name}.json",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "policySha256": hashlib.sha256(policy_payload).hexdigest(),
                "expected": exp,
            }
        )

    add("matching-supplied-records")
    add(
        "tampered-intent-retains-hash-and-signature",
        {
            "commitmentRecomputed": False,
            "destinationAuthorized": None,
            "callEnvelopeAuthorized": None,
        },
        lambda c: c["authorization"]["intent"].update(target=TARGET_B),
    )
    add(
        "authorized-a-runtime-b",
        {
            "destinationAuthorized": False,
            "callEnvelopeAuthorized": False,
            "reportedTargetMatchesRuntime": False,
            "reportedDispatchMatchesObservation": False,
            "suppliedCurrentEffectMatches": None,
        },
        lambda c: c["runtime"].update(target=TARGET_B),
    )
    add(
        "runtime-a-observation-b",
        {"reportedDispatchMatchesObservation": False, "suppliedCurrentEffectMatches": None},
        lambda c: c["observation"].update(target=TARGET_B),
    )
    add(
        "reported-b-runtime-a",
        {"reportedTargetMatchesRuntime": False},
        lambda c: c["report"].update(target=TARGET_B),
    )
    add(
        "reported-failure-current-effect-matches",
        {"historicalCompletionReported": False},
        lambda c: c["report"].update(completed=False),
    )
    add(
        "reported-success-current-state-differs",
        {"suppliedCurrentEffectMatches": False},
        lambda c: c["observation"].update(effectSha256=OTHER),
    )
    add(
        "stale-observation",
        {"observationFresh": False, "suppliedCurrentEffectMatches": None},
        lambda c: c["observation"].update(observedAt=1000),
    )
    add(
        "future-observation",
        {"observationFresh": False, "suppliedCurrentEffectMatches": None},
        lambda c: c["observation"].update(observedAt=1121),
    )
    add(
        "missing-observation",
        {
            "reportedDispatchMatchesObservation": None,
            "observationFresh": None,
            "suppliedCurrentEffectMatches": None,
        },
        lambda c: c.update(observation=None),
    )
    add(
        "missing-report",
        {"reportedTargetMatchesRuntime": None, "historicalCompletionReported": None},
        lambda c: c.update(report=None),
    )
    add(
        "wrong-selected-principal-key",
        {
            "signatureUnderSelectedKey": False,
            "destinationAuthorized": None,
            "callEnvelopeAuthorized": None,
        },
        selected_policy=policy
        | {"principalPublicKey": rail.ed25519_public_key(b"\x7f" * 32).hex()},
    )
    add(
        "changed-signature",
        {
            "signatureUnderSelectedKey": False,
            "destinationAuthorized": None,
            "callEnvelopeAuthorized": None,
        },
        lambda c: c["authorization"].update(signature="00" * 64),
    )
    add(
        "authorization-expired-at-use",
        {
            "authorizationTimeAtUse": False,
            "destinationAuthorized": None,
            "callEnvelopeAuthorized": None,
        },
        lambda c: c["authorization"].update(
            signed(c["authorization"]["intent"] | {"validUntil": 1099})
        ),
    )
    add(
        "authorization-not-yet-valid",
        {
            "authorizationTimeAtUse": False,
            "destinationAuthorized": None,
            "callEnvelopeAuthorized": None,
        },
        lambda c: c["authorization"].update(
            signed(c["authorization"]["intent"] | {"validFrom": 1101})
        ),
    )
    for field, value in [("operation", "operation-2"), ("chainId", 1)]:
        add(
            f"runtime-{field.lower()}-differs",
            {
                "destinationAuthorized": False,
                "callEnvelopeAuthorized": False,
                "reportedTargetMatchesRuntime": False,
                "reportedDispatchMatchesObservation": False,
                "suppliedCurrentEffectMatches": None,
            },
            lambda c, field=field, value=value: c["runtime"].update({field: value}),
        )
    for field, value in [("calldataHash", "6b" * 32), ("value", "1001")]:
        add(
            f"runtime-{field.lower()}-differs",
            {
                "callEnvelopeAuthorized": False,
                "reportedDispatchMatchesObservation": False,
                "suppliedCurrentEffectMatches": None,
            },
            lambda c, field=field, value=value: c["runtime"].update({field: value}),
        )
    add(
        "target-trailing-slash",
        {
            "destinationAuthorized": False,
            "callEnvelopeAuthorized": False,
            "reportedTargetMatchesRuntime": False,
            "reportedDispatchMatchesObservation": False,
            "suppliedCurrentEffectMatches": None,
        },
        lambda c: c["runtime"].update(target=TARGET_A + "/"),
    )
    for name, exit_code, stdout, notice, correct in [
        (
            "truncation-notice-exit-zero",
            0,
            "unit-a\ntruncated: 2 unit(s)\nno findings\n",
            True,
            False,
        ),
        (
            "truncation-notice-exit-one",
            1,
            "unit-a\ntruncated: 2 unit(s)\npartial scan refused\n",
            True,
            True,
        ),
        ("silent-truncation-exit-zero", 0, "unit-a\nno findings\n", False, False),
    ]:
        add(
            name,
            {
                "coverageComplete": False,
                "processExitMatchesCoverage": correct,
                "truncationNoticePresent": notice,
            },
            lambda c, e=exit_code, s=stdout: c["scan"].update(
                scanned=["unit-a"], skipped=["unit-b", "unit-c"], exitCode=e, stdout=s
            ),
        )
    add(
        "complete-scan-with-finding",
        {"noFindingReported": False},
        lambda c: c["scan"].update(findings=["synthetic-credential-shape"], exitCode=1),
    )
    add(
        "no-units-scanned",
        {"coverageComplete": False, "truncationNoticePresent": True},
        lambda c: c["scan"].update(
            scanned=[],
            skipped=policy["scanUnits"],
            exitCode=1,
            stdout="truncated: 3 unit(s)\npartial scan refused\n",
        ),
    )
    add(
        "missing-scan",
        {
            name: None
            for name in (
                "coverageComplete",
                "noFindingReported",
                "processExitMatchesCoverage",
                "truncationNoticePresent",
            )
        },
        lambda c: c.update(scan=None),
    )
    add(
        "empty-consumer-inventory",
        {"coverageComplete": False},
        lambda c: c["scan"].update(scanned=[], exitCode=1),
        selected_policy=policy | {"scanUnits": []},
    )
    files["manifest.json"] = encoded(
        {
            "profile": PROFILE,
            "testKey": "Public deterministic test key",
            "baselinePolicySha256": hashlib.sha256(files["policy.json"]).hexdigest(),
            "cases": entries,
            "total": len(entries),
        }
    )
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = cases()
    if args.check:
        actual = {str(p.relative_to(ROOT)): p.read_bytes() for p in ROOT.rglob("*.json")}
        if actual != outputs:
            raise SystemExit("fixture regeneration differs")
    else:
        for name, data in outputs.items():
            path = ROOT / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print(f"generated bytes match: {len(outputs)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
