#!/usr/bin/env python3
"""Bind ADK routing, callbacks and separate Verify decisions to originals."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ADK = "86a47f6974bae349a5c9ea15a74a4b450614ae42"
VERIFY = "e835ce2bd6a960e7a1cc2fa6522f16d55dce728a"
CASES = ["approval-granted", "approval-denied", "long-running-completed"]


def require(condition: bool, message: str) -> None:
    """Refuse altered native evidence or a changed report projection."""
    if not condition:
        raise ValueError(message)


def sha256(raw: bytes) -> str:
    """Hash original bytes without normalizing their JSON."""
    return hashlib.sha256(raw).hexdigest()


def read_json(packet: zipfile.ZipFile, name: str) -> Any:
    """Read one authenticated original JSON member."""
    return json.loads(packet.read(name))


def unbox(value: dict[str, Any]) -> dict[str, Any]:
    """Check that a native value retains its exact serialized source bytes."""
    require(json.loads(bytes.fromhex(value["jsonHex"])) == value["value"], "ADK native wrapper differs from its serialized bytes")
    return value["value"]


def check_wrappers(value: Any) -> None:
    """Check serialized wrappers nested inside callback-native structures."""
    if isinstance(value, dict):
        if "jsonHex" in value and "value" in value:
            unbox(value)
        for item in value.values():
            check_wrappers(item)
    elif isinstance(value, list):
        for item in value:
            check_wrappers(item)


def check_git_sources(packet: zipfile.ZipFile, pins: dict[str, str], prefix: str) -> None:
    """Compare retained source files to their selected Git blobs."""
    for name, expected in pins.items():
        raw = packet.read(prefix + name)
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(actual == expected, "ADK or Verify selected Git source differs")


def check_archive(source: dict[str, Any]) -> None:
    """Authenticate every member of each failure, correction and passing run."""
    raw = (HERE / source["archive"]).read_bytes()
    require(len(raw) == source["bytes"] and sha256(raw) == source["sha256"], "ADK original archive differs")
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        names = [item.filename for item in packet.infolist() if not item.is_dir()]
        members = source["members"]
        require(len(names) == len(set(names)) == len(members), "ADK original member population differs")
        require(set(names) == {member["path"] for member in members}, "ADK original members differ")
        for member in members:
            raw = packet.read(member["path"])
            require(len(raw) == member["bytes"] and sha256(raw) == member["sha256"], "ADK original member bytes differ")


def check_case(packet: zipfile.ZipFile, row: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the issuing call, later root turn and selected effect join."""
    name = row["case"]
    prefix = f"packet/cases/{name}/"
    turns = [[unbox(event) for event in turn] for turn in read_json(packet, prefix + "turns.json")]
    require(len(turns) == 3, "ADK turn population differs")
    require(list(dict.fromkeys(event["author"] for event in turns[1])) == row["nativeResponseAuthors"], "ADK response author projection differs")
    require([event["author"] for event in turns[2]] == row["nativeLaterTextAuthors"] == ["root"], "ADK later plain text did not return to root")
    require(all(event["author"] == "issuer" for event in turns[1]), "ADK response did not reach the issuing agent")
    calls = [(event["author"], part["function_call"]) for event in turns[0] for part in (event.get("content") or {}).get("parts", []) if part.get("function_call")]
    tool = "pending_work" if name == "long-running-completed" else "approved_write"
    selected = [call for author, call in calls if author == "issuer" and call["name"] == tool]
    require(len(selected) == 1, "ADK original issuing call differs")
    original = selected[0]
    response = unbox(read_json(packet, prefix + "supplied-user-response.json"))["parts"][0]["function_response"]
    if name == "long-running-completed":
        require(response["id"] == original["id"] and response["name"] == original["name"], "ADK long-running response call differs")
    else:
        confirmations = [call for author, call in calls if author == "issuer" and call["name"] == "adk_request_confirmation"]
        require(len(confirmations) == 1, "ADK confirmation population differs")
        confirmation = confirmations[0]
        require(confirmation["args"]["originalFunctionCall"] == {key: original[key] for key in ["args", "id", "name"]}, "ADK confirmation did not bind its original call")
        require(response["id"] == confirmation["id"] and response["name"] == confirmation["name"], "ADK confirmation response call differs")
        require(response["response"]["confirmed"] is (name == "approval-granted"), "ADK grant or denial changed")
    callbacks = read_json(packet, prefix + "callbacks.json")
    require(callbacks["closed"] is True and callbacks["failures"] == 0 and callbacks["capturePayloads"] is True, "ADK callback capture is incomplete")
    for record in callbacks["records"]:
        if "native" in record:
            check_wrappers(record["native"])
    observer = read_json(packet, prefix + "observer-packet.json")
    writes = observer["claim"]["writes"]
    require(observer["claim"]["witnessScope"] == "PEER" and len(writes) == row["observedWrites"], "ADK signed effect projection differs")
    require(all(write["requestId"] == original["id"] for write in writes), "ADK selected write did not bind its issuing call")
    bodies = read_json(packet, prefix + "tool-bodies.json")
    require(len(bodies) == row["toolBodyCalls"], "ADK native tool-body count differs")
    completions = read_json(packet, prefix + "operator-effects.json") if name == "long-running-completed" else []
    require(len(completions) == (1 if name == "long-running-completed" else 0), "ADK host completion population differs")
    require(all(effect["functionCallId"] == original["id"] and effect["effectOperator"] == "same-author-host-completion" for effect in completions), "ADK host completion call or operator differs")
    return {**row, "originalTool": tool, "originalCallId": original["id"], "suppliedResponseId": response["id"], "suppliedResponseName": response["name"], "callbacks": len(callbacks["records"]), "callbackFailures": callbacks["failures"], "callbackClosed": callbacks["closed"], "hostCompletionCalls": len(completions)}


def check_verify(packet: zipfile.ZipFile) -> dict[str, Any]:
    """Verify both original outputs of each actual Verify CLI invocation."""
    receipt = read_json(packet, "verify-consumer/verify-consumer-receipt.json")
    selection = read_json(packet, "verify-consumer/verify-source-selection.json")
    require(selection["revision"] == receipt["verifyRevision"] == VERIFY and len(selection["pythonGitBlobs"]) == 11, "Verify source selection differs")
    check_git_sources(packet, selection["pythonGitBlobs"], "verify-consumer/verify-source/src/probity_verify/")
    require(len(receipt["rows"]) == 6 and len({row["case"] for row in receipt["rows"]}) == 6, "Verify finite case population differs")
    for row in receipt["rows"]:
        prefix = "verify-consumer/cases/" + row["case"] + "/"
        first, second = packet.read(prefix + "verify-1.stdout"), packet.read(prefix + "verify-2.stdout")
        require(first == second and sha256(first) == row["decisionSHA256"] and row["literalRepeat"] is True, "Verify repeated original decision bytes differ")
        actual = json.loads(first)
        require(actual["decision"] == row["decision"] == "supported" and actual["claim_type"] == row["claimType"] == "event_absence/v1", "Verify claim or decision differs")
        for attempt in [1, 2]:
            require(read_json(packet, prefix + f"verify-{attempt}.status.json") == {"returncode": 0, "timeout": False}, "Verify invocation did not complete")
    require(len(receipt["controls"]) == 3, "Verify boundary control population differs")
    for name, decision in [("event-present", "contradicted"), ("coverage-unknown", "not_established")]:
        prefix = f"verify-consumer/controls/{name}/"
        require(read_json(packet, prefix + "verify.stdout")["decision"] == decision, "Verify boundary control differs")
    prefix = "verify-consumer/controls/malformed-duplicate/"
    require(read_json(packet, prefix + "verify.status.json")["returncode"] == 2 and packet.read(prefix + "verify.stdout") == b"", "Verify malformed input produced a verdict")
    require(receipt["outsideOperator"] is False and receipt["witnessScope"] == "PEER", "Verify custody scope differs")
    return receipt


def project(source: dict[str, Any]) -> dict[str, Any]:
    """Project a passing original without running tools or changing targets."""
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        require(read_json(packet, "native-production.status.json") == {"returncode": 0, "timeout": False}, "ADK native production did not complete")
        selection = read_json(packet, "native-source-selection.json")
        require(selection["revision"] == ADK and len(selection["pythonGitBlobs"]) == 778, "ADK native source population differs")
        check_git_sources(packet, selection["pythonGitBlobs"], "native-source/src/google/adk/")
        plan = read_json(packet, "host-plan-before-run.json")
        require(plan["resumability"] is False, "ADK resumability scope differs")
        first, second = packet.read("decision-1.json"), packet.read("decision-2.json")
        require(first == second, "ADK installed reader decision bytes differ")
        decision = json.loads(first)
        require(decision["status"] == "verified" and decision["sourceRevision"] == ADK, "ADK reader did not qualify the selected source")
        require(decision["outsideOperator"] is False and decision["witnessScope"] == "PEER" and decision["prospectiveEightTaskRun"] == "not-started", "ADK reader scope differs")
        require([row["case"] for row in decision["rows"]] == CASES, "ADK case ordering differs")
        controls = packet.read("reader-controls.log").decode()
        require(re.search(r"Ran 19 tests in [0-9.]+s\s+OK\s*$", controls) is not None, "ADK semantic controls did not pass")
        native = read_json(packet, "packet/native-result.json")
        require(native["rows"] == decision["rows"] and native["providerRequests"] == 0 and native["prospectiveEightTaskRun"] == "not-started", "ADK native and reader projections differ")
        return {"archive": source["archive"], "workflowRun": source["run"], "executedHead": source["executedHead"], "routingDecision": decision, "routingDecisionSha256": sha256(first), "routingRepeatedByteExact": True, "rows": [check_case(packet, row) for row in decision["rows"]], "semanticControls": 19, "providerRequests": native["providerRequests"], "nativeSourcePythonFiles": 778, "hostPlan": plan, "hostPolicySha256": sha256(packet.read("host-policy.json")), "verify": check_verify(packet)}


def derive_report() -> dict[str, Any]:
    """Retain all attempts and derive only the two fully qualified outputs."""
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    sources = provenance["archives"]
    require([len(source["members"]) for source in sources] == [850, 857, 960, 960], "ADK attempt populations differ")
    require([source["archive"] for source in sources] == ["first-failed-artifact.zip", "label-correction-artifact.zip", "original-artifact.zip", "main-artifact.zip"], "ADK attempt selection differs")
    for source in sources:
        check_archive(source)
    return {"schema": "probity.lab.adk-responses.v1", "adkRevision": ADK, "verifyRevision": VERIFY, "operator": "author-operated", "witnessScope": "PEER", "attempts": [{key: value for key, value in source.items() if key != "members"} for source in sources], "qualifiedRuns": [project(source) for source in sources[2:]], "historicalComparisonRows": 16, "prospectiveEightTaskRun": "not-started"}


def validate() -> None:
    """Bind the Lab projection to authenticated native archives."""
    require(derive_report() == json.loads((HERE / "report.json").read_bytes()), "ADK Lab projection differs")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-report"]:
        (HERE / "report.json").write_text(json.dumps(derive_report(), indent=2) + "\n")
    else:
        require(not sys.argv[1:], "unsupported arguments")
        validate()
    print("Four ADK originals, two qualified routing runs and separate actual Verify decisions match")
