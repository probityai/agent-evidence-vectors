"""Validate the frozen 384-call boundary study without promoting its claims.

This selected profile is additive to the general register protocol. It checks
the authenticated original archive, all semantic rows and pair/resource axes.
It neither reruns inference nor establishes outside operation or custody.
"""

from __future__ import annotations

import hashlib
import json
import logging
import zipfile
from collections import defaultdict
from itertools import product
from pathlib import Path
from typing import Any

if __package__:
    from .check_lab import artifact_path, check_claim, require
else:
    from check_lab import artifact_path, check_claim, require

IDENTITY = "model-boundary-cpu-2026-10-02"
DIMENSIONS = ("model", "configuration", "decoder", "family")
FAMILIES = ("typed-boundary", "policy-boundary", "grounded-boundary")
PROTOCOL_SHA256 = "78ee69f5c5a8cc51095e960939ca42497d6f48f2bb6aad54deff098a5faf2ea2"
PROTOCOL_COMMIT = "f63ff5a7c236c8f0122dec71fbaabde8c2feb6a3"
SOURCE_COMMIT = "6cfd28dc61aa0ae43be5da8382fe959c94235997"
READER_COMMIT = "fdda91d18aa4cca5eeb51b0b8d5de8232abb9110"
MERGE_COMMIT = "4080bcc1425457221fa49d43ccac60ecfa485ab7"
READER_SHA256 = "52a6000faae93178ce9e5acbf0e19c246fde69ee57055eb28cca8bddcc8f99b3"
ARCHIVE_SHA256 = "d8ff26e82aca136daf734da65ede259b2bfaed9dd547ba25b92d65bdeeef019f"
FULL_SHA256 = "a8036f8cc32d7452be17e1f848d0c4c2d482815817ab51087fda8673bd92d91b"
FULL_MAPPING_SHA256 = "2f236dd05eedbc043c97bac2f14d3d237db3d2944ba2beb7131346d021eb0995"
REPORT_SHA256 = "fa7b0e39b69bcd42f82fc93096e071b534557c34cf0e03e73e1bac56dcdd72af"
LOGGER = logging.getLogger("atlas.boundary_retention")


def _row_key(row: dict[str, Any]) -> tuple[str, ...]:
    """Return the four selected dimensions without pooling models or families."""
    return tuple(row[key] for key in DIMENSIONS)


def _integer(value: Any, maximum: int, message: str) -> None:
    """Require a bounded integer; Python Boolean equality is insufficient."""
    require(type(value) is int and 0 <= value <= maximum, message)


def _quality_rows(record: dict[str, Any], report: dict[str, Any]) -> None:
    """Bind each complete semantic row to its independent register claim.

    Parameters
    ----------
    record : dict of str to Any
        Selected register entry already admitted by the general claim gate.
    report : dict of str to Any
        Original report containing twenty-four unpooled quality rows.

    Raises
    ------
    ValueError
        If a row is missing, duplicated, relabelled or promoted using schema
        validity. A passing semantic row requires both sixteen correct cases
        and eight fully correct pairs; format alone cannot satisfy either.
    """
    rows = report["quality"]
    expected = set(product(("smol135-q4", "smol360-q4"), ("short24", "long96"),
                           ("unconstrained", "schema"), FAMILIES))
    require(len(rows) == 24 and {_row_key(row) for row in rows} == expected,
            "boundary retention must preserve all24 separate rows")
    claims = [claim for claim in record["claimResults"]
              if claim.get("recordedField", "").startswith("/quality/")]
    require(len(claims) == 24 and {claim["recordedField"] for claim in claims} ==
            {f"/quality/{index}" for index in range(24)},
            "boundary retention requires24 unique row bindings")
    by_pointer = {claim["recordedField"]: claim for claim in claims}
    for index, row in enumerate(rows):
        _quality_row(row, by_pointer[f"/quality/{index}"], report)


def _quality_row(row: dict[str, Any], claim: dict[str, Any], report: dict[str, Any]) -> None:
    """Keep the population, strict case/pair counts and resource scope intact."""
    for field, expected in (("planned", 16), ("scored", 16), ("plannedPairs", 8)):
        require(type(row[field]) is int and row[field] == expected,
                "boundary selected row population changed")
    for field in ("correct", "formatValid", "schemaValid"):
        _integer(row[field], 16, "boundary selected quality count must be a bounded integer")
    _integer(row["fullyCorrectPairs"], 8, "boundary selected pair count must be a bounded integer")
    require(row["resourceScope"] ==
            "returned calls only; CPU is whole-process delta, RSS is lifetime peak, not task allocation",
            "boundary shared resource scope changed")
    check_claim(claim, report)
    require(claim["claim"] == "-".join(_row_key(row)) + "-all-sixteen-targets-and-eight-pairs",
            "boundary selected quality label changed")
    passed = row["correct"] == 16 and row["fullyCorrectPairs"] == 8
    require(claim["result"] == ("pass" if passed else "fail"),
            "boundary schema validity cannot promote semantic case or pair failure")


def _aggregate_row(row: dict[str, Any], attempts: list[dict[str, Any]]) -> None:
    """Rederive row counts/resources from retained attempts without rescoring.

    ``correct`` remains the published typed-exact rubric result. This function
    checks aggregation only. The immutable archive binding in
    :func:`check_selected_boundary_register` preserves the underlying outputs,
    targets, resources and original scores.
    """
    selected = [attempt for attempt in attempts if _row_key(attempt) == _row_key(row)]
    require(len(selected) == 16, "boundary row must retain sixteen original attempts")
    for field in ("correct", "formatValid", "schemaValid"):
        require(all(type(attempt[field]) is bool for attempt in selected),
                "boundary original verdict must remain Boolean")
        require(row[field] == sum(attempt[field] for attempt in selected),
                "boundary row count differs from retained attempts")
    pairs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for attempt in selected:
        pairs[attempt["pair"]].append(attempt)
    require(len(pairs) == 8 and all(len(pair) == 2 and
            {attempt["pairRole"] for attempt in pair} == {"a", "b"} for pair in pairs.values()),
            "boundary original pair identities incomplete")
    require(row["fullyCorrectPairs"] == sum(all(attempt["correct"] for attempt in pair)
            for pair in pairs.values()), "boundary pair count differs from retained attempts")
    _aggregate_resources(row, selected)


def _aggregate_resources(row: dict[str, Any], attempts: list[dict[str, Any]]) -> None:
    """Keep returned-call resource sums separate from total process CPU/RSS."""
    mappings = (("callElapsedNs", "resources", "elapsed_ns"),
                ("processCpuNs", "resources", "process_cpu_ns"),
                ("promptTokens", "tokens", "prompt_tokens"),
                ("completionTokens", "tokens", "completion_tokens"))
    for field, parent, child in mappings:
        _integer(row[field], 2**63 - 1, "boundary row resource must remain a nonnegative integer")
        require(row[field] == sum(attempt[parent][child] for attempt in attempts),
                "boundary row resource differs from retained attempts")
    require(type(row["processLifetimePeakRssKiB"]) is int and
            row["processLifetimePeakRssKiB"] ==
            max(attempt["resources"]["process_maxrss_kib"] for attempt in attempts),
            "boundary RSS must remain a shared lifetime maximum")


def _preparation_history(report: dict[str, Any], provenance: dict[str, Any]) -> None:
    """Preserve five separate acquisition attempts and the original run total."""
    history = provenance["preparationHistory"]
    fields = ("original48RunBytes", "comparisonInitialFailureBytes",
              "comparisonSuccessfulBytes", "formatControlBytes", "currentBoundaryBytes")
    expected = (278149773, 472190754, 472221945, 472221945, 472221945)
    require(all(type(history[field]) is int and history[field] == value
                for field, value in zip(fields, expected)), "boundary preparation history changed")
    require(history["allFiveAttemptsBodyBytes"] == sum(history[field] for field in fields),
            "boundary five preparation envelopes cannot be reported as one")
    require(history["currentBoundaryBytes"] == report["preparation"]["selectedPayloadBytes"],
            "boundary current preparation differs from original report")
    require(type(report["process_cpu_ns"]) is int and
            report["process_cpu_ns"] >= sum(row["processCpuNs"] for row in report["quality"]),
            "boundary total process CPU cannot be replaced by call CPU")


def _unmeasured_claims(record: dict[str, Any]) -> None:
    """Prevent unrelated truthful fields from promoting unexercised claim axes.

    The generic register gate checks a measured pointer's literal value. That
    does not make ``effects == 'not executed'`` evidence for independent custody
    or outside adoption. These selected claims retain their explicit limits.
    """
    claims = {claim["claim"]: claim for claim in record["claimResults"]}
    expected = {"independent-effect-custody": "not-exercised",
                "outside-recurring-host-use": "not-exercised",
                "representative-benchmark-performance": "out-of-scope"}
    for name, result in expected.items():
        require(name in claims and claims[name]["result"] == result and
                "recordedField" not in claims[name] and "expectedValue" not in claims[name],
                "boundary unexercised claim cannot borrow unrelated measured evidence")


def _full_mapping(provenance: dict[str, Any]) -> None:
    """Require every actual compact member and all thirty explicit omissions.

    The complete-original digest describes a separately archived private ZIP.
    Its hashes disclose omitted bytes; they do not make the public compact ZIP
    sufficient to reconstruct weights, acquisition or a new inference run.
    """
    compact = {member["member"]: member for member in provenance["members"]}
    full = provenance["fullPreparationMembers"]
    summary = provenance["fullPreparationArchive"]
    require(len(compact) == len(provenance["members"]) == 871,
            "boundary compact member population changed")
    require(len({member["member"] for member in full}) == len(full) == summary["memberCount"] == 901,
            "boundary full preparation member population changed")
    selected = [member for member in full if member["retainedInCompact"] is True]
    omitted = [member for member in full if member["retainedInCompact"] is False]
    require(len(selected) == summary["publiclyRetainedNativeMembers"] == 871 and
            len(omitted) == summary["omittedPreparationMembers"] == 30,
            "boundary full preparation omissions hidden")
    require({member["compactMember"] for member in selected} == set(compact),
            "boundary compact mapping incomplete")
    for member in selected:
        pin = compact[member["compactMember"]]
        require(member["member"] == "run/" + member["compactMember"] and
                (member["sha256"], member["bytes"]) == (pin["sha256"], pin["bytes"]),
                "boundary compact mapping rebinds native bytes")
    require(all(member["compactMember"] is None for member in omitted),
            "boundary omission carries invented compact mapping")
    require({"smol135-q4.gguf", "smol360-q4.gguf"} <= {member["member"] for member in omitted},
            "boundary omitted model weights must remain disclosed")
    require((summary["sha256"], summary["bytes"]) == (FULL_SHA256, 466005528),
            "boundary complete original archive rebound")
    require(summary["independentCustody"] == "not-established" and
            summary["privateRetentionHolder"] == provenance["roles"]["retentionHolder"] == "Probity",
            "boundary private complete retention cannot invent custody or holder")
    encoded = (json.dumps(full, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    require(hashlib.sha256(encoded).hexdigest() == FULL_MAPPING_SHA256,
            "boundary authenticated full-member inventory rebound")


def validate_boundary_retention(record: dict[str, Any], report: dict[str, Any],
                                provenance: dict[str, Any]) -> None:
    """Validate selected boundary indexing after generic SHA/claim admission.

    Parameters
    ----------
    record, report, provenance : dict of str to Any
        Selected register entry, unmodified native report and original-byte
        provenance. :func:`check_selected_boundary_register` authenticates the
        actual files before calling this selected semantic gate.

    Raises
    ------
    ValueError
        For missing rows, population/pair/resource changes, promoted outcomes,
        hidden omissions, source substitution or invented operation/custody.
    """
    try:
        _validate_boundary_retention(record, report, provenance)
    except ValueError as exc:
        LOGGER.error("boundary retention refused: %s", exc)
        raise


def _validate_boundary_retention(record: dict[str, Any], report: dict[str, Any],
                                 provenance: dict[str, Any]) -> None:
    """Apply selected semantic checks behind the bounded logged public API."""
    require(report["profile"] == "probity-local-cpu-boundary-tasks-v1",
            "boundary native profile changed")
    require(record["sourceRevision"] == provenance["sourceCommit"] == SOURCE_COMMIT and
            record["readerRevision"] == provenance["readerCommit"] == READER_COMMIT and
            provenance["reviewedHead"] == READER_COMMIT and provenance["mergedHead"] == MERGE_COMMIT,
            "boundary source revisions rebound")
    require(provenance["newInferenceExecuted"] is False,
            "boundary original retention cannot claim new inference")
    require(record["roles"] == provenance["roles"] and all(
            provenance["roles"][role] == "not-established" for role in
            ("independentOperation", "independentEffectCustody", "outsideRecurringUse")),
            "boundary retention cannot invent operation adoption or custody")
    require(report["effects"] == "not executed", "boundary retention cannot invent protected effects")
    expected_population = {"planned": 384, "started": 384, "scored": 384,
                           "error": 0, "incomplete": 0, "unknown-start": 0, "unsupported": 0}
    require(report["population"] == expected_population and
            all(type(value) is int for value in report["population"].values()),
            "boundary original population changed")
    attempts = report["attempts"]
    require(len(attempts) == len({attempt["id"] for attempt in attempts}) == 384 and
            all(attempt["outcome"] == "scored" for attempt in attempts),
            "boundary must retain all384 original scored attempts")
    _quality_rows(record, report)
    _unmeasured_claims(record)
    for row in report["quality"]:
        _aggregate_row(row, attempts)
    _preparation_history(report, provenance)
    _full_mapping(provenance)


def _frozen_sources(bundle: zipfile.ZipFile, provenance: dict[str, Any]) -> None:
    """Authenticate frozen protocol/reader/compiler/grammars and case identities."""
    preregistration = provenance["protocolPreregistration"]
    require(preregistration["commit"] == PROTOCOL_COMMIT and
            preregistration["sha256"] == PROTOCOL_SHA256 and
            preregistration["publishedBeforeInference"] is True,
            "boundary protocol preregistration rebound")
    require(hashlib.sha256(bundle.read("protocol.json")).hexdigest() == PROTOCOL_SHA256 and
            hashlib.sha256(bundle.read("sources/task_matrix.py")).hexdigest() ==
            provenance["readerSourceSHA256"] == READER_SHA256, "boundary frozen source bytes rebound")
    protocol = json.loads(bundle.read("protocol.json"))
    _case_identities(protocol, preregistration)
    contracts = protocol["formatControl"]["taskContracts"]
    require(preregistration["grammarManifest"] ==
            {identity: item["grammarSHA256"] for identity, item in contracts.items()},
            "boundary frozen grammar mapping rebound")
    for item in contracts.values():
        require(hashlib.sha256(bundle.read("sources/" + item["grammarPath"])).hexdigest() ==
                item["grammarSHA256"], "boundary native grammar source changed")
    compiler = hashlib.sha256(bundle.read("sources/selected-grammar-compiler.py")).hexdigest()
    require(compiler == preregistration["compiler"]["sourceSHA256"] ==
            protocol["formatControl"]["compiler"]["sourceSHA256"], "boundary frozen compiler rebound")


def _case_identities(protocol: dict[str, Any], preregistration: dict[str, Any]) -> None:
    """Keep forty-eight identities distinct from forty-six literal inputs."""
    cases = protocol["cases"]
    require(len(cases) == len({case["id"] for case in cases}) ==
            preregistration["authoredCaseIdentities"] == 48,
            "boundary authored case population changed")
    require(len({case["input"] for case in cases}) == preregistration["uniqueLiteralInputs"] == 46,
            "boundary literal input count cannot be described as48 unique tasks")
    require(set(protocol["order"]["attemptIds"]) == {
            "--".join((model, configuration, decoder, case["id"]))
            for model, configuration, decoder, case in product(
                ("smol135-q4", "smol360-q4"), ("short24", "long96"),
                ("unconstrained", "schema"), cases)}, "boundary declared attempt identities changed")


def _archive_members(bundle: zipfile.ZipFile, provenance: dict[str, Any]) -> None:
    """Check unique safe names and every original ZIP member digest/length."""
    pins = {member["member"]: member for member in provenance["members"]}
    names = bundle.namelist()
    require(len(names) == len(set(names)) == len(pins) and set(names) == set(pins),
            "boundary original compact manifest names differ")
    for name, pin in pins.items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "boundary original member path is unsafe")
        raw = bundle.read(name)
        require((len(raw), hashlib.sha256(raw).hexdigest()) == (pin["bytes"], pin["sha256"]),
                "boundary original compact member changed")


def check_selected_boundary_register(register: dict[str, Any], root: Path) -> None:
    """Authenticate selected archive/source bytes and then check bounded claims.

    Parameters
    ----------
    register : dict of str to Any
        General register already admitted by ``check_lab.validate_register``.
    root : Path
        Repository root containing retained artifacts. No network is used.

    Raises
    ------
    ValueError
        If an original provider/archive/report/source pin differs or selected
        indexing is malformed. Malformed input gets a bounded refusal so the
        general gate logs a reason without disclosing candidate contents.
    """
    for record in register["records"]:
        if record["id"] != IDENTITY:
            continue
        try:
            _selected_record(record, root)
        except (KeyError, TypeError, StopIteration, zipfile.BadZipFile) as exc:
            raise ValueError("boundary selected retention structure is malformed") from exc


def _selected_record(record: dict[str, Any], root: Path) -> None:
    """Bind the selected report to original provider bytes before interpretation."""
    raw_report = artifact_path(root, record["report"]).read_bytes()
    report = json.loads(raw_report)
    provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
    archive = artifact_path(root, next(artifact["path"] for artifact in record["artifacts"]
                                      if artifact["path"].endswith("original-artifact.zip")))
    require((hashlib.sha256(archive.read_bytes()).hexdigest(), archive.stat().st_size) ==
            (provenance["originalArtifactSha256"], provenance["originalArtifactBytes"]) ==
            (provenance["retainedArchiveSha256"], provenance["retainedArchiveBytes"]) ==
            (ARCHIVE_SHA256, 2745888), "boundary original provider archive rebound")
    require(hashlib.sha256(raw_report).hexdigest() == provenance["reportSha256"] == REPORT_SHA256,
            "boundary original native report rebound")
    with zipfile.ZipFile(archive) as bundle:
        _archive_members(bundle, provenance)
        require(bundle.read(provenance["reportMember"]) == raw_report,
                "boundary report differs from original archive member")
        _frozen_sources(bundle, provenance)
        protocol = json.loads(bundle.read("protocol.json"))
    validate_boundary_retention(record, report, provenance)
    require(record["derivedFindings"] in {artifact["path"] for artifact in record["artifacts"]},
            "boundary finite findings must be a retained artifact")
    if __package__:
        from .derive_boundary_findings import derive_findings, encode
    else:
        from derive_boundary_findings import derive_findings, encode
    require(artifact_path(root, record["derivedFindings"]).read_bytes() ==
            encode(derive_findings(report, protocol, REPORT_SHA256)),
            "boundary finite findings differ from original-byte rederivation")
