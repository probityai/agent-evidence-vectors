"""Preserve the original native Atomic local-delegation run and claim ceiling.

This gate checks retained bytes and report bindings. It never executes a binary
from a candidate capsule and cannot establish who operated the measured run.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

if __package__:
    from .check_lab import artifact_path, require
else:
    from check_lab import artifact_path, require

IDENTITY = "atomic-delegation-2026-10-02"
SOURCE = "80be8dae6feb8b9106181b78fba2c7c6a7c8f4d8"
ARCHIVE_SHA256 = "ba31071e1f0a60644117e3f4c300b16b07bc75c58caf3a5259047054132c3719"
REPORT_SHA256 = "92b6cd64f85e7a87e8aee04bff128195e578acfd969170c231bbb1ac55f5f7c1"
CASE_NAMES = (
    "exact_retry_and_process_restart_preserve_a_narrow_grant",
    "revocation_survives_restart_and_does_not_revoke_a_distinct_renewal",
    "expired_and_corrupt_grants_stay_inactive_after_restart",
    "local_selection_does_not_establish_external_issuer_authority",
)
UNMEASURED = {
    "upstream-maintainer-acceptance", "outside-recurring-host-use",
    "independent-effect-custody", "server-permission-enforcement",
    "remote-revocation", "crash-mid-write",
}


def check_selected_atomic_register(register: dict[str, Any], root: Path) -> None:
    """Refuse changed original evidence or promoted unmeasured Atomic claims.

    The general register gate has already checked artifact digests and exact
    measured JSON pointers. This selected gate additionally fixes the original
    capsule, its complete member inventory and the local-operation claim limit.
    """
    records = [r for r in register["records"] if r["id"] == IDENTITY]
    if not records:
        return
    record = records[0]
    base = f"../experiments/{IDENTITY}/"
    archive_bytes = artifact_path(root, base + "native-run-capsule.zip").read_bytes()
    require(hashlib.sha256(archive_bytes).hexdigest() == ARCHIVE_SHA256,
            "Atomic original capsule differs from its immutable retention pin")
    report_bytes = artifact_path(root, record["report"]).read_bytes()
    require(hashlib.sha256(report_bytes).hexdigest() == REPORT_SHA256,
            "Atomic report differs from the original native report")
    provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
    report = json.loads(report_bytes)
    require(report["source"]["commit"] == SOURCE and report["source"]["status"] == "",
            "Atomic native source pin or clean-state claim changed")
    require(record["readerRevision"] == SOURCE and provenance["sourceCommit"] == SOURCE,
            "Atomic retained source revision changed")
    require(provenance["retainedArchiveSha256"] == ARCHIVE_SHA256
            and provenance["retainedArchiveBytes"] == len(archive_bytes),
            "Atomic capsule provenance differs from retained bytes")
    with zipfile.ZipFile(artifact_path(root, base + "native-run-capsule.zip")) as archive:
        names = archive.namelist()
        inventory = provenance["members"]
        require(len(names) == len(set(names)) == len(inventory)
                and set(names) == {item["member"] for item in inventory},
                "Atomic capsule inventory is incomplete or repeated")
        for item in inventory:
            content = archive.read(item["member"])
            require(item["selected"] is True and item["bytes"] == len(content)
                    and item["sha256"] == hashlib.sha256(content).hexdigest(),
                    "Atomic capsule member provenance differs from original bytes")
        require(archive.read("report.json") == report_bytes,
                "Atomic selected report differs from original capsule member")
        require(set(names) == set(report["artifacts"]) | {"report.json"},
                "Atomic native run file coverage changed")
        for name, pin in report["artifacts"].items():
            content = archive.read(name)
            require(len(content) == pin["bytes"] and hashlib.sha256(content).hexdigest() == pin["sha256"],
                    "Atomic native file differs from original report manifest")
        require(hashlib.sha256(archive.read(report["binary"]["filename"])).hexdigest()
                == report["binary"]["sha256"], "Atomic exact executable pin changed")
    require(report["declared_cases"] == list(CASE_NAMES)
            and [r["case"] for r in report["results"]] == list(CASE_NAMES),
            "Atomic declared native population changed")
    require([len(r["observations"]) for r in report["results"]] == [2, 4, 4, 2]
            and provenance["observationCounts"] == [2, 4, 4, 2],
            "Atomic local reader-process population changed")
    pids = {item["pid"] for result in report["results"] for item in result["observations"]}
    require(len(pids) == 12 and provenance["distinctLookupProcesses"] == 12,
            "Atomic distinct reader-process claim changed")
    claims = {c["claim"]: c for c in record["claimResults"]}
    require(UNMEASURED <= claims.keys()
            and all(claims[name]["result"] == "not-exercised" for name in UNMEASURED),
            "Atomic unmeasured boundary was promoted or removed")
    for roles in (record["roles"], provenance["roles"]):
        require(all(roles[name] == "not-established" for name in
                    ("independentOperation", "independentEffectCustody", "outsideRecurringUse")),
                "Atomic local-operation claim ceiling changed")
    require(all(value == "not-established" for value in provenance["publicationAxes"].values()),
            "Atomic outside acceptance or custody was promoted")
