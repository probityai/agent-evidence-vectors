"""Check the selected paired-format retention without promoting schema validity."""

from __future__ import annotations

import hashlib
import json
import zipfile
from itertools import product
from pathlib import Path

if __package__:
    from .check_lab import artifact_path, check_claim, require
else:
    from check_lab import artifact_path, check_claim, require

IDENTITY = "model-format-cpu-2026-10-02"


def validate_format_retention(record: dict, report: dict, provenance: dict) -> None:
    """Require all selected quality rows, literal compact/full mapping and budgets.

    This validation checks retained indexing, not native inference, acquisition
    or independent custody. Inputs must first pass the register artifact hashes.
    """
    rows = report["quality"]
    dimensions = ("model", "configuration", "decoder", "family")
    expected = set(product(("smol135-q4", "smol360-q4"), ("short24", "long96"),
                           ("unconstrained", "schema"),
                           ("structured-extraction", "arithmetic", "policy-decision",
                            "grounded-abstention")))
    require(len(rows) == 32 and {tuple(r[k] for k in dimensions) for r in rows} == expected,
            "format retention must preserve all32 separate rows")
    quality_claims = [c for c in record["claimResults"]
                      if c.get("recordedField", "").startswith("/quality/")]
    require(len(quality_claims) == len(rows), "format retention quality bindings incomplete")
    require({c["recordedField"] for c in quality_claims} ==
            {f"/quality/{i}" for i in range(len(rows))}, "format retention row bindings duplicate")
    for i, row in enumerate(rows):
        require(row["scored"] == row["planned"] == 6,
                "format retention selected row population changed")
        for key in ("correct", "formatValid", "schemaValid"):
            require(type(row[key]) is int and 0 <= row[key] <= row["scored"],
                    "format retention quality count invalid")
        claim = next(c for c in quality_claims if c["recordedField"] == f"/quality/{i}")
        check_claim(claim, report)
        require(claim["claim"] == "-".join(row[k] for k in dimensions) + "-all-six-strict-targets",
                "format retention quality label changed")
        require(claim["result"] == ("pass" if row["correct"] == row["planned"] else "fail"),
                "schema validity cannot substitute for target correctness")
    _mapping(provenance)
    history = provenance["preparationHistory"]
    require(history["currentResponseBodyBytes"] == report["preparation"]["selectedPayloadBytes"],
            "current preparation must bind to retained report")
    subtotal = (history["comparisonPriorInitialFailureBytes"] +
                history["comparisonPriorSuccessBytes"] + history["currentResponseBodyBytes"])
    require(history["comparisonAndFormatCumulativeBytes"] == subtotal,
            "prior/current preparation subtotal changed")
    require(history["allFourPreparationAttemptsBodyBytes"] == subtotal + history["original48RunBytes"],
            "four preparation envelopes cannot be reported as one")
    require(history["allFourPreparationAttemptsBodyBytes"] > 512 * 1024 * 1024,
            "cumulative preparation must remain separate from one envelope")
    require(provenance["protocolPreregistration"]["publishedBeforeInference"] is True,
            "protocol preregistration missing")
    require(provenance["roles"]["independentEffectCustody"] == "not-established",
            "retention cannot invent independent custody")


def _mapping(provenance: dict) -> None:
    """Require every original compact member and every explicit full-only omission."""
    compact = {m["member"]: m for m in provenance["members"]}
    full = provenance["fullPreparationMembers"]
    summary = provenance["fullPreparationArchive"]
    require(len(compact) == len(provenance["members"]) == 463, "compact member count changed")
    require(len({m["member"] for m in full}) == len(full) == summary["memberCount"] == 493,
            "full preparation manifest changed")
    selected = [m for m in full if m["retainedInCompact"]]
    omitted = [m for m in full if not m["retainedInCompact"]]
    require(len(selected) == summary["publiclyRetainedNativeMembers"] == 463 and
            len(omitted) == summary["omittedPreparationMembers"] == 30,
            "full preparation omissions hidden")
    require({m["compactMember"] for m in selected} == set(compact), "compact mapping incomplete")
    for member in selected:
        pin = compact[member["compactMember"]]
        require(member["member"] == "run/" + member["compactMember"] and
                (member["sha256"], member["bytes"]) == (pin["sha256"], pin["bytes"]),
                "compact mapping rebinds native bytes")
    require(all(m["compactMember"] is None for m in omitted), "omission carries invented mapping")
    require({"smol135-q4.gguf", "smol360-q4.gguf"} <= {m["member"] for m in omitted},
            "omitted model weights must stay disclosed")


def check_selected_register(register: dict, root: Path) -> None:
    """Check the additive profile after generic artifact/typed-field admission."""
    for record in register["records"]:
        if record["id"] != IDENTITY:
            continue
        report = json.loads(artifact_path(root, record["report"]).read_bytes())
        provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
        validate_format_retention(record, report, provenance)
        archive = artifact_path(root, next(a["path"] for a in record["artifacts"]
                                         if a["path"].endswith("original-artifact.zip")))
        with zipfile.ZipFile(archive) as bundle:
            pins = {m["member"]: m for m in provenance["members"]}
            require(len(bundle.namelist()) == len(pins) and set(bundle.namelist()) == set(pins),
                    "original compact manifest names differ")
            for name, pin in pins.items():
                raw = bundle.read(name)
                require((len(raw), hashlib.sha256(raw).hexdigest()) == (pin["bytes"], pin["sha256"]),
                        "original compact member differs")
            require(bundle.read(provenance["reportMember"]) ==
                    artifact_path(root, record["report"]).read_bytes(), "original report member changed")
            protocol_bytes = bundle.read("protocol.json")
            require(hashlib.sha256(protocol_bytes).hexdigest() ==
                    provenance["protocolPreregistration"]["sha256"], "frozen protocol rebound")
            protocol = json.loads(protocol_bytes)
            contracts = protocol["formatControl"]["taskContracts"]
            require(provenance["protocolPreregistration"]["grammarManifest"] ==
                    {name: item["grammarSHA256"] for name, item in contracts.items()},
                    "frozen grammar mapping rebound")
            for item in contracts.values():
                require(hashlib.sha256(bundle.read("sources/" + item["grammarPath"])).hexdigest() ==
                        item["grammarSHA256"], "native grammar source differs from protocol")
            compiler = hashlib.sha256(bundle.read("sources/selected-grammar-compiler.py")).hexdigest()
            require(compiler == provenance["protocolPreregistration"]["compiler"]["sourceSHA256"] ==
                    protocol["formatControl"]["compiler"]["sourceSHA256"], "frozen compiler rebound")
