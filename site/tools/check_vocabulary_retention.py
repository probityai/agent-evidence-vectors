"""Bind the authored vocabulary result to original provider and selected reader bytes.

This is an offline retention gate. It never imports packet source, installs a
candidate wheel, loads a model, or grants effect authority from schema success.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

if __package__:
    from .check_lab import artifact_path, require
else:
    from check_lab import artifact_path, require

IDENTITY = "model-vocabulary-cpu-2026-10-03"
SOURCE = "62f5d0c6fbd785259db2d5c8076dd844b53a0593"
READER = "ff556045011010025cc95b7572bffb0dbe0dc0d6"
BASELINE = "806abee71076def61e6a6d4f91e166d75f926459"
RETENTION = "e1122b6c08915207921ca575d98115cea4790062"
HASHES = {
    "original-artifact.zip": "eef05226335f9e2de6783ee797d891cbd1fe47058264e2d57eb41f1ec39131d8",
    "installed-capsule.zip": "93a86439639978dc35af686b46b7b51c202a44e868d8c759a75e08cb5cd79ca9",
    "provider-inventory.json": "e50753f843e5d42facb65ef9e20b5f5c3ff9a2e7abc98d63a7cb75577dd86339",
    "source-contract.json": "4a3a47b14308f726af505ac489c9cb4c482cd48c09eacd3881c2fafe44f14ff7",
    "native-report.json": "4b9638a73ce0fc8e7273fc8969cfc92467b5779903e47a501b3989b357b4d9b0",
    "installed-replay.json": "1cde7314140f7bb9d8aad9cca1ece0cc5fee3f32c8bb0e7dcb65628a5a11fb97",
    "provenance.json": "fefb96f1cac94f9cffbcdfd90d5434ba3dd4e2c993bf4c69c4a9d39e921d4e8f",
    "report.json": "b921ec50bb757e06f738bdec620f3a68051e3d6ce7630460116e782e99dd2dd2",
}
UNMEASURED = (
    "outside-producer-acceptance", "external-host-recurring-adoption",
    "independent-effect-custody", "model-action-acceptance",
    "general-benchmark-performance", "independent-transfer-or-inference-witness",
)


def encode(value: Any) -> bytes:
    """Compare JSON with exact types and without nonfinite numeric values."""
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def claim_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Bind observations and failed quality gates separately from unmeasured claims."""
    claims = []
    def measured(name: str, result: str, pointer: str, value: Any) -> None:
        claims.append({"claim": name, "result": result, "recordedField": pointer,
                       "expectedValue": value})
    native, installed = report["native"], report["installed"]
    measured("complete-native-population", "pass", "/native/population", native["population"])
    measured("complete-evidence-within-declared-budget", "pass", "/native/evidence", native["evidence"])
    for mode in ("control", "vocabulary"):
        measured(mode + "-complete-policy-correctness", "fail", "/comparison/" + mode,
                 report["comparison"][mode])
    for index, row in enumerate(native["quality"]):
        identity = "--".join(row[key] for key in ("model", "configuration", "family"))
        measured("default-quality--" + identity, "fail", "/native/quality/" + str(index), row)
    for field in ("elapsed_ns", "process_cpu_ns", "nativeTokens", "preparation"):
        measured("native-resource--" + field, "pass", "/native/" + field, native[field])
    for field in ("evidenceDecision", "stdoutReplayExact", "structuredReplayExact",
                  "evidenceOnlyStillQualityHold", "mutations", "cumulativeSixPreparationsResponseBodyBytes"):
        measured("installed-replay--" + field, "pass", "/installed/" + field, installed[field])
    measured("installed-default-quality", "fail", "/installed/consumerDecision", installed["consumerDecision"])
    claims.extend({"claim": name, "result": "not-exercised"} for name in UNMEASURED)
    return claims


def _members(bundle: zipfile.ZipFile, members: list[dict[str, Any]]) -> None:
    """Authenticate every member against a previously source-bound inventory."""
    names = bundle.namelist()
    require(len(names) == len(set(names)) and set(names) == {m["path"] for m in members},
            "vocabulary archive member population changed")
    for member in members:
        name = member["path"]
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "vocabulary archive member path is unsafe")
        raw = bundle.read(name)
        require(len(raw) == member["bytes"] and hashlib.sha256(raw).hexdigest() == member["sha256"],
                "vocabulary original member bytes changed")


def _validate(record: dict[str, Any], root: Path) -> None:
    """Refuse changed evidence even when its outer artifact digest is reselected."""
    prefix = "../experiments/" + IDENTITY + "/"
    expected_refs = {prefix + name: digest for name, digest in HASHES.items()}
    require({a["path"]: a["sha256"] for a in record["artifacts"]} == expected_refs,
            "vocabulary source-bound artifact selection changed")
    raw = {}
    for name, digest in HASHES.items():
        raw[name] = artifact_path(root, prefix + name).read_bytes()
        require(hashlib.sha256(raw[name]).hexdigest() == digest,
                "vocabulary retained original bytes changed")
    report = json.loads(raw["report.json"])
    provenance = json.loads(raw["provenance.json"])
    native = json.loads(raw["native-report.json"])
    installed = json.loads(raw["installed-replay.json"])
    require(encode(report["native"]) == encode(native) and encode(report["installed"]) == encode(installed),
            "vocabulary report differs from original receipts")
    metadata = {
        "id": IDENTITY, "atlasRevision": BASELINE, "sourceRevision": SOURCE,
        "readerRevision": READER, "report": prefix + "report.json",
        "provenance": prefix + "provenance.json",
        "contract": "https://github.com/probityai/agent-evidence-observer/tree/" + READER + "/interop/local-model-vocabulary-2026-10-02",
        "reviewState": "author-retained-measured-record",
        "evidenceClaim": "authored-native-action-vocabulary-and-installed-quality-hold",
        "roles": provenance["roles"], "answerExposure": provenance["answerExposure"],
        "comparisonOrder": "Native inference follows frozen protocol, source-bound controls and protected merge; Atlas raw retention precedes indexing at " + RETENTION + ". Same-operator replay does not establish independent custody.",
        "limits": provenance["limits"],
    }
    require(set(record) == set(metadata) | {"artifacts", "claimResults"} and
            all(encode(record.get(key)) == encode(value) for key, value in metadata.items()),
            "vocabulary scope, ownership or source metadata changed")
    require(encode(record["claimResults"]) == encode(claim_results(report)),
            "vocabulary measured or unexercised claims changed")
    inventory = json.loads(raw["provider-inventory.json"])
    full, provider_native, provider_installed = inventory["artifacts"]
    require(inventory["head"] == SOURCE and inventory["runId"] == 37094901561 and
            inventory["nativePacketExactSubsetOfFullPreparation"] is True,
            "vocabulary provider selection changed")
    with zipfile.ZipFile(io.BytesIO(raw["original-artifact.zip"])) as original:
        _members(original, provider_native["members"])
        require(original.read("report.json") == raw["native-report.json"],
                "vocabulary native report is not the provider original")
        for pin in installed["hostPins"].values():
            require(hashlib.sha256(original.read(pin["path"])).hexdigest() == pin["sha256"],
                    "vocabulary independent host pin changed")
        protocol = json.loads(original.read("protocol.json"))
        cases = {case["id"]: case for case in protocol["cases"]}
        require(len(cases) == 32 and len(native["attempts"]) == 128 and len(native["quality"]) == 8,
                "vocabulary native population changed")
        seen = set()
        for attempt in native["attempts"]:
            key = tuple(attempt[k] for k in ("model", "configuration", "decoder"))
            case_id = attempt["id"].removeprefix("--".join(key) + "--")
            require((key, case_id) not in seen and case_id in cases,
                    "vocabulary native attempt identity changed")
            seen.add((key, case_id))
            case = cases[case_id]
            response = json.loads(attempt["output"])
            require(set(response) == {"decision"} and isinstance(response["decision"], str),
                    "vocabulary native schema observation changed")
            require(attempt["correct"] is (response == case["target"]),
                    "vocabulary semantic score differs from original response")
        for mode in ("control", "vocabulary"):
            rows = [row for row in native["quality"] if row["family"] == "policy-" + mode]
            comparison = {key: sum(row[key] for row in rows)
                          for key in ("correct", "planned", "fullyCorrectPairs", "plannedPairs")}
            require(encode(comparison) == encode(report["comparison"][mode]),
                    "vocabulary aggregate changed")
    with zipfile.ZipFile(io.BytesIO(raw["installed-capsule.zip"])) as capsule:
        _members(capsule, provenance["installedCapsule"]["members"])
        contract = json.loads(raw["source-contract.json"])
        wheel_name = "installed-original/wheel/" + installed["wheel"]["name"]
        wheel_raw = capsule.read(wheel_name)
        require(hashlib.sha256(wheel_raw).hexdigest() == installed["wheel"]["sha256"],
                "vocabulary installed wheel changed")
        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as wheel:
            for name, source in contract["files"].items():
                if name not in ("LICENSE", "pyproject.toml"):
                    require(hashlib.sha256(wheel.read(name)).hexdigest() == source["sha256"],
                            "vocabulary installed package differs from host source contract")
        actual = json.loads(capsule.read("actual-replay/actual.stdout.json"))
        require(encode(actual["report"]) == encode(native) and
                actual["evidenceDecision"] == "accept-scoped-evidence" and
                actual["consumerDecision"] == "hold-quality" and len(actual["qualityFailures"]) == 8,
                "vocabulary installed quality hold changed")
        require(capsule.read("actual-replay/actual.stdout.json") == capsule.read("actual-replay/actual-repeat.stdout.json"),
                "vocabulary installed repeated stdout changed")
    for mapping, provider in ((provenance["fullPreparationMemberMapping"], full),
                              (provenance["installedMemberMapping"], provider_installed)):
        require(len(mapping) == len(provider["members"]) and
                {m["path"]: {key: m[key] for key in ("path", "bytes", "sha256")} for m in mapping}
                == {m["path"]: m for m in provider["members"]},
                "vocabulary full omitted-member accounting changed")
    full_members = {m["path"]: m for m in full["members"]}
    require(all(full_members["run/" + m["path"]]["sha256"] == m["sha256"] for m in provider_native["members"]),
            "vocabulary native packet is not an exact full preparation subset")


def check_selected_vocabulary(register: dict[str, Any], root: Path) -> None:
    """Validate this additive profile when present, without changing older profiles."""
    for record in register["records"]:
        if record.get("id") == IDENTITY:
            try:
                _validate(record, root)
            except (KeyError, TypeError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
                raise ValueError("vocabulary original receipt structure is invalid") from exc
