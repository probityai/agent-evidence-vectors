#!/usr/bin/env python3
"""Derive the APS comparison from both original native archives."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
APS = "646490a834e1eca4aad230033502b73f3b5cd9d1"
CORPUS = "ecc8b5ef4b380a2fe38e5079d128307a1c702717"
ADAPTER = "fa3e6705746e0131a7884591a86e5c05b6c050ab"


def require(condition: bool, message: str) -> None:
    """Refuse an altered retained population or projection."""
    if not condition:
        raise ValueError(message)


def sha256(raw: bytes) -> str:
    """Hash original bytes without decoding or normalizing them."""
    return hashlib.sha256(raw).hexdigest()


def machine(value: dict[str, Any]) -> dict[str, Any]:
    """Keep outcome fields, excluding only runtime diagnostic prose."""
    return {key: item for key, item in value.items() if key != "error"}


def check_archive(name: str, source: dict[str, Any]) -> dict[str, Any]:
    """Authenticate every original member before reading its comparison."""
    raw = (HERE / name).read_bytes()
    require(len(raw) == source["archive_bytes"] and sha256(raw) == source["archive_sha256"], "APS original archive differs")
    with zipfile.ZipFile(HERE / name) as packet:
        names = [item.filename for item in packet.infolist() if not item.is_dir()]
        members = source["members"]
        require(len(names) == len(set(names)) == len(members) == 9, "APS original member population differs")
        require(set(names) == {member["path"] for member in members}, "APS original members differ")
        for member in members:
            value = packet.read(member["path"])
            require(len(value) == member["bytes"] and sha256(value) == member["sha256"], "APS original member bytes differ")
        return json.loads(packet.read("comparison.json"))


def check_source() -> None:
    """Verify selected licensed source bytes and all source-lock members."""
    manifest = json.loads((HERE / "source-manifest.json").read_bytes())
    archive = (HERE / "selected-source.zip").read_bytes()
    require(len(archive) == manifest["archive"]["bytes"] and sha256(archive) == manifest["archive"]["sha256"], "APS selected source archive differs")
    require(manifest["adapter_commit"] == ADAPTER, "APS adapter selection differs")
    with zipfile.ZipFile(HERE / "selected-source.zip") as packet:
        members = manifest["members"]
        names = [item.filename for item in packet.infolist() if not item.is_dir()]
        require(len(names) == len(set(names)) == len(members) + 1 == 722, "APS source population differs")
        require(set(names) == {item["member"] for item in members} | {"SOURCE-MANIFEST.json"}, "APS selected source members differ")
        require(json.loads(packet.read("SOURCE-MANIFEST.json"))["members"] == members, "APS source manifests differ")
        for member in members:
            raw = packet.read(member["member"])
            git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            require(len(raw) == member["bytes"] and sha256(raw) == member["sha256"] and git_blob == member["git_blob_sha"], "APS selected Git source bytes differ")
        lock = json.loads((HERE / "source-lock.json").read_bytes())
        for group, prefix, pin in [("aps", "aps/", APS), ("jcs_admit", "jcs-admit/", CORPUS)]:
            require(lock[group]["commit"] == pin, "APS selected source pin differs")
            for item in lock[group]["files"]:
                raw = packet.read(prefix + item["path"])
                require(len(raw) == item["bytes"] and sha256(raw) == item["sha256"], "APS locked source member differs")


def project(native: dict[str, Any]) -> dict[str, Any]:
    """Count the native rows without conflating serializer and raw admission."""
    require(native["aps_commit"] == APS and native["corpus_commit"] == CORPUS and native["executed_head"] == ADAPTER, "APS executed pins differ")
    require(native["native_admission_executed"] is True and native["execution"] == "author-operated", "APS execution scope differs")
    require(native["source_lock_sha256"] == sha256((HERE / "source-lock.json").read_bytes()), "APS source-lock binding differs")
    rows = native["rows"]
    require(len(rows) == len({row["name"] for row in rows}) == 1223, "APS frozen case identities differ")
    for row in rows:
        expected, actual = row["expected"], row["native_admission"]
        require(actual["status"] == expected["status"], "APS native admission outcome differs")
        if expected["status"] == "accepted":
            require(actual["canonical_hex"] == expected["canonical_hex"], "APS native canonical bytes differ")
        elif "error_class" in expected:
            require(actual["error_class"] == expected["error_class"], "APS declared native refusal class differs")
    summary = {
        "corpus_cases": len(rows),
        "expected_accepted": sum(row["expected"]["status"] == "accepted" for row in rows),
        "aps_raw_accepted": sum(row["aps_raw_parser"]["status"] == "accepted" for row in rows),
        "parsed_refusal_bypasses": sum(row["expected"]["status"] == "refused" and row["aps_parsed_serializer"]["status"] == "accepted" for row in rows),
        "raw_policy_differences": sum(row["expected"]["status"] != row["aps_raw_parser"]["status"] for row in rows),
        "signed_receipt_controls": len(native["receipts"]),
    }
    require(summary == native["summary"], "APS native summary does not count its rows")
    receipts = {row["name"]: row for row in native["receipts"]}
    require(len(receipts) == 5 and set(receipts) == {"clean", "duplicate-issuer", "escaped-duplicate-issuer", "wrong-key", "resource-depth"}, "APS receipt controls differ")
    require(receipts["clean"]["serialized_verifier"]["valid"] is True, "APS clean receipt did not verify")
    for name in ["duplicate-issuer", "escaped-duplicate-issuer"]:
        result = receipts[name]["serialized_verifier"]
        require(result["valid"] is False and result["signature_results"] == [] and result["receipt_id_valid"] == "not_checked", "APS duplicate receipt did not stop before signature checks")
        require(receipts[name]["parse_first_verifier"]["valid"] is True, "APS parse-first duplicate control differs")
    wrong = receipts["wrong-key"]["serialized_verifier"]
    require(wrong["valid"] is False and len(wrong["signature_results"]) == 1 and wrong["signature_results"][0]["valid"] is False, "APS wrong-key control differs")
    depth = receipts["resource-depth"]["serialized_verifier"]
    require(depth["valid"] is False and depth["status"] == "indeterminate" and depth["signature_results"] == [], "APS receipt resource control differs")
    return {"node": native["node_version"], "workflowRun": native["workflow_run_id"], "executedHead": native["executed_head"], "summary": summary, "rawRefusals": len(rows) - summary["expected_accepted"], "receipts": native["receipts"]}


def derive_report() -> dict[str, Any]:
    """Reconstruct the two-runtime report from authenticated native output."""
    check_source()
    sources = json.loads((HERE / "native-manifest.json").read_bytes())
    require(len(sources) == 2, "APS runtime population differs")
    native = [check_archive(name, source) for name, source in zip(["original-node20.zip", "original-node22.zip"], sources, strict=True)]
    runs = [project(value) for value in native]
    require([row["node"] for row in runs] == ["v20.20.2", "v22.23.3"], "APS native runtimes differ")
    diagnostics = []
    for left, right in zip(native[0]["rows"], native[1]["rows"], strict=True):
        require({k: v for k, v in left.items() if k not in {"aps_raw_parser", "aps_parsed_serializer"}} == {k: v for k, v in right.items() if k not in {"aps_raw_parser", "aps_parsed_serializer"}}, "APS case identity or admission differs between runtimes")
        for key in ["aps_parsed_serializer", "aps_raw_parser"]:
            require(machine(left[key]) == machine(right[key]), "APS machine outcome differs between runtimes")
        if left["aps_parsed_serializer"] != right["aps_parsed_serializer"]:
            diagnostics.append({"name": left["name"], "node20": left["aps_parsed_serializer"], "node22": right["aps_parsed_serializer"]})
    require(native[0]["receipts"] == native[1]["receipts"], "APS signed receipt outcomes differ between runtimes")
    runtime = json.loads((HERE / "runtime-comparison.json").read_bytes())
    require(diagnostics == runtime["diagnostics"] and len(diagnostics) == runtime["diagnostic_only_differences"] == 88, "APS diagnostic-only comparison differs")
    require(runtime["machine_outcomes_equal"] is True and runtime["signed_receipt_outcomes_byte_equal"] is True, "APS runtime comparison labels differ")
    return {"schema": "probity.lab.aps-jcs.v1", "apsRevision": APS, "admissionRevision": CORPUS, "adapterRevision": ADAPTER, "operator": "author-operated", "runs": runs, "machineOutcomesAgree": True, "receiptOutcomesAgree": True, "diagnosticProseDifferences": len(diagnostics), "firstPartySourceMembers": 721}


def validate() -> None:
    """Bind the displayed projection to both original native archives."""
    require(derive_report() == json.loads((HERE / "report.json").read_bytes()), "APS Lab projection differs")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-report"]:
        (HERE / "report.json").write_text(json.dumps(derive_report(), indent=2) + "\n")
    else:
        require(not sys.argv[1:], "unsupported arguments")
        validate()
    print("Both APS native archives, 721 selected source members and the separate runtime outcomes match")
