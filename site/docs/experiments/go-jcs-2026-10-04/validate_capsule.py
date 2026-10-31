#!/usr/bin/env python3
"""Verify retained Go comparison archives and their data-only projection."""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_members(packet: zipfile.ZipFile, source: dict[str, Any]) -> None:
    names = [i.filename for i in packet.infolist() if not i.is_dir()]
    require(len(names) == len(set(names)) == len(source["members"]) == 119, "original member population differs")
    require(set(names) == {m["member"] for m in source["members"]}, "original members differ")
    for member in source["members"]:
        raw = packet.read(member["member"])
        require(len(raw) == member["bytes"] and digest(raw) == member["sha256"], "original member bytes differ")


def check_projection(native: dict[str, Any], row: dict[str, Any], source: dict[str, Any]) -> None:
    require(native["summary"] == row["summary"], "summary projection differs")
    require(native["runtime"] == row["runtime"], "runtime projection differs")
    require(native["qualified_checkout"] == row["qualifiedCheckout"] == source["actualCheckout"], "checkout differs")
    require(native["worktree_status"] == row["worktreeStatus"] == [], "native worktree differs")
    require(native["workflow_run_id"] == str(row["runId"]) == str(source["runId"]), "native run differs")
    controls = [r for r in native["records"] if r["name"].startswith("controls/")]
    require(controls == row["controls"], "control projection differs")


def count_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    statuses = Counter(r["consumer"]["status"] for r in records)
    stages = Counter(r["consumer"]["stage"] for r in records)
    return {
        "cases": len(records),
        "consumer_exact_byte_matches": statuses["accepted"],
        "raw_admission_refusals": stages["raw-admission"],
        "scalar_domain_refusals": stages["go-root-domain"],
        "bare_go_observations": len(records),
    }


def check_records(native: dict[str, Any], row: dict[str, Any]) -> None:
    records = native["records"]
    require(len(records) == len({r["name"] for r in records}) == 1263, "case identities differ")
    require(count_summary(records) == native["summary"], "native summary does not count its records")
    bare = Counter(r["bare_go"]["status"] for r in records)
    require(bare["accepted"] == row["bareGoAccepted"], "bare Go projection differs")
    for result in records:
        if result["consumer"]["status"] == "accepted":
            require(result["consumer"]["canonical_hex"] == result["bare_go"]["canonical_hex"], "accepted byte agreement differs")


def check_entries(packet: zipfile.ZipFile, entries: list[dict[str, Any]], prefix: str) -> None:
    for item in entries:
        raw = packet.read(prefix + item["path"])
        require(len(raw) == item["bytes"] and digest(raw) == item["sha256"], "source or corpus bytes differ")


def check_sources(packet: zipfile.ZipFile, native: dict[str, Any], projection: dict[str, Any]) -> None:
    raw = packet.read("interop/go-jcs/MANIFEST.json")
    require(raw == (HERE / "source-pins.json").read_bytes(), "source manifest copy differs")
    require(digest(raw) == native["manifest_sha256"] == projection["source"]["manifestSha256"], "manifest binding differs")
    pins = json.loads(raw)
    check_entries(packet, pins["corpus"]["files"], "")
    check_entries(packet, pins["go_source"]["files"], "interop/go-jcs/upstream/")
    for name in ["jsoncanonicalizer.go", "es6numfmt.go"]:
        require(packet.read("interop/go-jcs/source/jsoncanonicalizer/" + name) == packet.read("interop/go-jcs/upstream/go/src/webpki.org/jsoncanonicalizer/" + name), "compiled Go source differs")
    require(packet.read("interop/go-jcs/source/LICENSE") == packet.read("interop/go-jcs/upstream/LICENSE"), "Go license differs")


def check_archive(source: dict[str, Any], row: dict[str, Any], projection: dict[str, Any]) -> None:
    archive = (HERE / source["archive"]).read_bytes()
    require(digest(archive) == source["originalArtifactSha256"] == source["retainedArchiveSha256"], "original archive differs")
    require(len(archive) == source["originalArtifactBytes"] == source["retainedArchiveBytes"], "archive length differs")
    with zipfile.ZipFile(HERE / source["archive"]) as packet:
        check_members(packet, source)
        raw = packet.read(source["reportMember"])
        require(raw == (HERE / source["reportFile"]).read_bytes(), "native report copy differs")
        require(digest(raw) == source["reportSha256"] == row["nativeReportSha256"], "native report pin differs")
        native = json.loads(raw)
        check_projection(native, row, source)
        check_records(native, row)
        check_sources(packet, native, projection)


def validate() -> None:
    provenance = json.loads((HERE / "provenance.json").read_text())
    projection = json.loads((HERE / "report.json").read_text())
    require(len(provenance["archives"]) == len(projection["runs"]) == 6, "six original runs are required")
    for source, row in zip(provenance["archives"], projection["runs"], strict=True):
        check_archive(source, row, projection)


if __name__ == "__main__":
    validate()
    print("Six exact archives, all 714 members, six native reports and source/runtime/control projections match")
