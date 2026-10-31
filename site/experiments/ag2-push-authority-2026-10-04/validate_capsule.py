#!/usr/bin/env python3
"""Bind AG2 task, URL, callback and effect projections to retained originals."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

HERE = Path(__file__).resolve().parent
AG2 = "fd789e3ca8a77d14c8e3e89923665fe62c00cb9a"
A2A = "e649325e041e44c0b0fe57e3eef0699cad164a1e"
VARIANTS = ["accepted", "registration-denied", "dispatch-denied", "target-denied", "legacy-config-only", "sdk-policy-denied"]
CASES = [f"{transport}/{variant}" for transport in ["jsonrpc", "rest", "grpc"] for variant in VARIANTS]


def require(value, reason):
    """Refuse altered retained inputs or projections."""
    if not value:
        raise ValueError(reason)


def sha(raw):
    """Hash the original bytes."""
    return hashlib.sha256(raw).hexdigest()


def get(packet, name):
    """Read one authenticated native JSON member."""
    return json.loads(packet.read(name))


def archive_check(source):
    """Check every original archive member before reading outcomes."""
    path = HERE / source["archive"]
    raw = path.read_bytes()
    require(len(raw) == source["bytes"] and sha(raw) == source["sha256"], "original archive differs")
    with zipfile.ZipFile(path) as packet:
        names = [i.filename for i in packet.infolist() if not i.is_dir()]
        require(len(names) == len(set(names)) == len(source["members"]), "original member population differs")
        require(set(names) == {m["path"] for m in source["members"]}, "original members differ")
        for member in source["members"]:
            raw = packet.read(member["path"])
            require(len(raw) == member["bytes"] and sha(raw) == member["sha256"], "original member bytes differ")


def task_json(value):
    """Read captured protobuf JSON while retaining wire bytes separately."""
    require(set(value) == {"protobufJSONHex", "protobufHex", "protobufType"}, "native protobuf wrapper differs")
    bytes.fromhex(value["protobufHex"])
    return json.loads(bytes.fromhex(value["protobufJSONHex"]))


def case_projection(packet, row):
    """Keep stored configuration, sender dispatch, target and effect distinct."""
    prefix = "actual-run/packet/cases/" + row["case"] + "/"
    native_task = get(packet, prefix + "native-task.json")
    require(bool(bytes.fromhex(native_task["protobufHex"])), "native task wire data missing")
    task = task_json(native_task)
    require(task["status"]["state"] == "TASK_STATE_COMPLETED", "native task did not complete")
    capture = get(packet, prefix + "native-callbacks.json")
    require(capture["closed"] is True and capture["failures"] == 0 and capture["mutatesRequests"] is False, "native callback capture incomplete")
    require([r["sequence"] for r in capture["records"]] == list(range(len(capture["records"]))), "callback sequence differs")
    for record in capture["records"]:
        task_json(record["native"])
    agent = get(packet, prefix + "native-agent.json")
    require(agent["nativeModelCalls"] == 1 and agent["providerRequests"] == 0 and agent["toolBodyEffects"] == 0 and agent["agentTaskCompletedBeforeRegistration"] is True, "native task or model scope differs")
    stored = get(packet, prefix + "stored-configs.json")
    callbacks = get(packet, prefix + "target-callbacks.json")
    writes = get(packet, prefix + "observer-packet.json")["claim"]["writes"]
    effects = get(packet, prefix + "target-effects.json")
    expected = {"accepted": (1, 1, 1), "registration-denied": (0, 0, 0), "dispatch-denied": (1, 0, 0), "target-denied": (1, 1, 0), "legacy-config-only": (1, 0, 0), "sdk-policy-denied": (0, 0, 0)}[row["case"].split("/")[1]]
    require((len(stored), len(callbacks), len(writes)) == expected, "configuration/callback/effect distinction differs")
    require(len(effects) == len(writes), "target effect population differs")
    require(row["storedConfigs"] == len(stored) and row["targetCallbacks"] == len(callbacks) and row["observedWrites"] == len(writes), "reported native counts differ")
    for callback in callbacks:
        body = bytes.fromhex(callback["bodyJSONHex"])
        require(sha(body) == callback["bodySHA256"] and json.loads(body)["task"]["id"] == task["id"], "target body did not bind the native task")
        require(callback["responseStatus"] == (200 if writes else 403), "target refusal differs")
    for write, effect in zip(writes, effects):
        require(write["requestId"] == effect["requestId"] == task["id"] and effect["operator"] == "same-author-callback-target", "native task/effect/operator join differs")
        require(sha(packet.read(prefix + "workspace/result.txt")) == write["contentDigest"], "retained target file differs")
    dispatch = get(packet, prefix + "dispatch.json")
    require(dispatch["explicitHostCall"] is row["explicitDispatch"] and dispatch["automaticTaskDispatch"] is False and dispatch["returnValue"] is None, "explicit dispatch scope differs")
    require(get(packet, prefix + "effect-before-dispatch.json") == {"files": [], "targetCallbacks": 0}, "configuration produced an early effect")
    return {**row, "taskId": task["id"], "nativeCallbacks": len(capture["records"]), "callbackFailures": 0, "dispatchOperator": dispatch["operator"], "automaticTaskDispatch": False}


def project(source):
    """Derive one qualified execution from its original native packet."""
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        prefix = "actual-run/"
        require(get(packet, prefix + "native-production.status.json") == {"returncode": 0, "timeout": False}, "native producer did not complete")
        selection = get(packet, prefix + "native-source-selection.json")
        for component, revision, count in [("ag2", AG2, 453), ("a2a", A2A, 127)]:
            selected = selection[component]
            require(selected["revision"] == revision and len(selected["pythonGitBlobs"]) == count, "selected source population differs")
            for name, expected in selected["pythonGitBlobs"].items():
                raw = packet.read(prefix + "native-source/" + component + "/" + selected["prefix"] + name)
                require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected, "publisher source differs")
        first, second = packet.read(prefix + "decision-1.json"), packet.read(prefix + "decision-2.json")
        require(first == second, "installed reader repeat differs")
        decision = json.loads(first)
        require(decision["status"] == "verified" and decision["ag2Revision"] == AG2 and decision["a2aSDKRevision"] == A2A, "reader source or verdict differs")
        require(decision["outsideOperator"] is False and decision["witnessScope"] == "PEER" and decision["prospectiveEightTaskRun"] == "not-started" and decision["older16Rows"] == "unchanged", "executed scope differs")
        require([row["case"] for row in decision["rows"]] == CASES, "finite case population differs")
        native = get(packet, prefix + "packet/native-result.json")
        require(native["rows"] == [{**row, "publicationDecision": None} for row in decision["rows"]] and native["publicationDecision"] is None, "producer assumed publication authority")
        require(re.search(r"Ran 16 tests in [0-9.]+s\s+OK\s*$", packet.read(prefix + "reader-controls.log").decode()) is not None, "semantic controls did not pass")
        for role in ["producer", "reader"]:
            require(get(packet, prefix + role + "-installation.status.json") == {"returncode": 0, "timeout": False}, "installed source probe failed")
        rows = [case_projection(packet, row) for row in decision["rows"]]
        return {"archive": source["archive"], "workflowRun": source["run"], "executedHead": source["executedHead"], "decision": decision, "decisionSHA256": sha(first), "readerRepeatedByteExact": True, "rows": rows, "nativeTasks": len(rows), "targetCallbacks": sum(row["targetCallbacks"] for row in rows), "observedWrites": sum(row["observedWrites"] for row in rows), "semanticControls": 16, "nativeSourcePythonFiles": {"ag2": 453, "a2a": 127}, "hostPlan": get(packet, prefix + "host-plan-before-run.json"), "hostPolicySHA256": sha(packet.read(prefix + "host-policy.json"))}


def derive():
    """Keep setup/local failures and both qualified runs separately retained."""
    provenance = json.loads((HERE / "provenance.json").read_bytes())
    sources = provenance["archives"]
    require([s["archive"] for s in sources] == ["first-local-original.zip", "original-artifact.zip", "main-artifact.zip"], "attempt selection differs")
    for source in sources:
        archive_check(source)
    for record in provenance["failedCI"]["records"]:
        raw = (HERE / record["path"]).read_bytes()
        require(len(raw) == record["bytes"] and sha(raw) == record["sha256"], "first failed CI evidence differs")
    require(provenance["failedCI"]["nativeExecuted"] is False and provenance["failedCI"]["artifactProduced"] is False, "setup failure scope differs")
    return {"schema": "probity.lab.ag2-push-authority.v1", "ag2Revision": AG2, "a2aSDKRevision": A2A, "operator": "author-operated", "witnessScope": "PEER", "attempts": [{k: v for k, v in s.items() if k != "members"} for s in sources], "firstCINativeExecuted": False, "qualifiedRuns": [project(s) for s in sources[1:]], "historicalComparisonRows": 16, "prospectiveEightTaskRun": "not-started"}


def validate():
    """Bind the Lab report to both qualified originals and failure provenance."""
    require(derive() == json.loads((HERE / "report.json").read_bytes()), "Lab projection differs")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-report"]:
        (HERE / "report.json").write_text(json.dumps(derive(), indent=2) + "\n")
    else:
        require(not sys.argv[1:], "unsupported arguments")
        validate()
    print("AG2 originals, two qualified 18-case runs and all 16 native reader controls match")
