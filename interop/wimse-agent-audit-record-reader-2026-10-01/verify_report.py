#!/usr/bin/env python3
"""Check the pinned inputs and the external reader's per-member output."""

import hashlib
import importlib.metadata
import json
import sys
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load(path):
    return json.loads(path.read_text())


def index(rows):
    by_id = {row["draftId"]: row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("duplicate draftId in reader output")
    return by_id


def build(corpus, compare=True):
    pins = load(HERE / "INPUTS.json")
    if sys.version.split()[0] != pins["runtime"]["python"]:
        raise ValueError("Python version changed")
    if importlib.metadata.version("cryptography") != pins["runtime"]["cryptography"]:
        raise ValueError("cryptography version changed")
    for path, want in pins["corpus"]["sha256"].items():
        actual = hashlib.sha256((corpus / path).read_bytes()).hexdigest()
        if actual != want:
            raise ValueError(f"input changed: {path}")

    manifest = load(corpus / "MANIFEST.json")
    if manifest["corpusDigest"] != pins["corpus"]["corpusDigest"]:
        raise ValueError("corpus digest changed")
    outputs = {
        name: index(load(corpus / f"{name}_results.json"))
        for name in ("envelope", "stage2", "stage34")
    }
    ids = {v["draftId"] for v in manifest["vectors"]}
    if len(ids) != len(manifest["vectors"]) or any(set(rows) != ids for rows in outputs.values()):
        raise ValueError("reader output does not cover the manifest exactly")

    rows = []
    counts = Counter()
    for vector in manifest["vectors"]:
        draft_id = vector["draftId"]
        envelope = outputs["envelope"][draft_id]
        members = outputs["stage2"][draft_id]
        recompute = outputs["stage34"][draft_id]
        for result in (envelope, members, recompute):
            if result["kind"] != vector["kind"] or result["row"] != vector["row"]:
                raise ValueError(f"reader row changed: {draft_id}")
        stage1 = envelope["verdict"]
        stage2 = members["stage2"]
        stage34 = recompute["stage34"]
        if stage1 != members["stage1"] or stage1 != recompute["stage1"]:
            raise ValueError(f"reader stages disagree: {draft_id}")
        observed = "malformed" if "refuse" in (stage1, stage2, stage34) else "valid"
        allowed = ([r["verdict"] for r in vector["readings"]]
                   if vector["kind"] == "indeterminate"
                   else [vector["expected"]["verdict"]])
        row = {
            "draftId": draft_id,
            "id": vector["id"],
            "kind": vector["kind"],
            "allowed": allowed,
            "observed": observed,
            "conform": observed in allowed,
            "stage1": stage1,
            "stage1Code": envelope.get("code", ""),
            "stage2": stage2,
            "stage2Findings": members["findings"],
            "stage34": stage34,
            "stage34Findings": recompute["findings"],
        }
        rows.append(row)
        counts[(vector["kind"], observed)] += 1

    source = {
        "readerRepo": pins["reader"]["repo"],
        "readerCommit": pins["reader"]["commit"],
        "corpusRepo": pins["corpus"]["repo"],
        "corpusCommit": pins["corpus"]["commit"],
        "corpusDigest": pins["corpus"]["corpusDigest"],
        "runtime": pins["runtime"],
    }
    report = {"source": source, "summary": {
        "vectors": len(rows),
        "conform": sum(row["conform"] for row in rows),
        "acceptValid": counts["accept", "valid"],
        "rejectMalformed": counts["reject", "malformed"],
        "indeterminateValid": counts["indeterminate", "valid"],
    }, "results": rows}
    if compare:
        if report != load(HERE / "RESULTS.json"):
            raise ValueError("rerun differs from RESULTS.json")
        summary = report["summary"]
        print(f"{summary['conform']}/{summary['vectors']} conform: "
              f"{summary['acceptValid']} accept valid, "
              f"{summary['rejectMalformed']} reject malformed, "
              "N1/N2 valid")
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python verify_report.py <fetched-corpus-dir>")
    build(Path(sys.argv[1]))
