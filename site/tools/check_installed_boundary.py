"""Bind the installed .4 publication/quality gate to its actual original CI bytes.

The native fifteen-record retention remains separate. This selected profile
preserves all twenty-four native rows and sixteen quality-policy failures;
complete evidence publication never grants model-action or custody claims.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

if __package__:
    from .check_boundary_retention import DIMENSIONS, REPORT_SHA256
    from .check_lab import artifact_path, require
else:
    from check_boundary_retention import DIMENSIONS, REPORT_SHA256
    from check_lab import artifact_path, require

IDENTITY = "installed-boundary-policy-2026-10-02"
PREFIX = "_temp/model-boundary-upgrade-result/"
SOURCE = "72fc276003232e3b34aed057adc9a76db4f147e3"
REVIEW = "39f6654e752384e5e95542ffaf8a366a0145081a"
CAPSULE_SHA256 = "e1b29236fd546fe4fc5b0cc3a602893a08b89549c8bc393041d04d09f6f9367d"
ORIGINAL_SHA256 = "997e4bd63e4748ea7dcdc9ec567fd7f33433badbfaea29eacc08e491a0823079"
INVENTORY_SHA256 = "6db774ed1990a2742c9504c3e9a41dc153d6a4d86055b359656a29da5bdd49db"
UPGRADE_SHA256 = "a0cdd464446090dfca2580bfbdf1c9c1fd646eb057311a6239a232152f1831e9"
STDOUT_SHA256 = "9b9f2d5012a66ebd1ccb7a308ab859f0fed1da948fccc3915ae40ea79e9578c0"
CONTRACT_SHA256 = "7f838482ac352411d389a88f550c642a82d065f8a3cac9c7dbf2976afc3c1f31"
UNMEASURED = (
    "external-host-recurring-adoption",
    "independent-effect-custody",
    "model-action-acceptance",
    "new-model-inference",
    "general-benchmark-performance",
)


def encode(value: Any) -> bytes:
    """Use deterministic type-sensitive JSON for original-value comparisons."""
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def _read_original(bundle: zipfile.ZipFile, name: str, expected: str) -> Any:
    """Authenticate a selected original member before decoding its JSON."""
    raw = bundle.read(name)
    require(
        hashlib.sha256(raw).hexdigest() == expected,
        "installed boundary original selected member changed",
    )
    return json.loads(raw)


def _selected(name: str) -> bool:
    """Reproduce the disclosed finite capsule selection without candidate paths."""
    boundary = name.startswith(PREFIX) and not any(
        part.endswith("-packet") for part in name.split("/")
    )
    wheels = name.startswith(
        ("_temp/model-reader-wheels/", "_temp/boundary-baseline-wheels/")
    )
    return (
        boundary
        or wheels
        or name
        == "agent-evidence-observer/agent-evidence-observer/model-consumer-tests.xml"
    )


def _metadata(record: dict[str, Any], provenance: dict[str, Any]) -> None:
    """Freeze actual CI source/review/merge, no-rerun and author-retention roles."""
    require(
        record["sourceRevision"] == SOURCE and record["readerRevision"] == SOURCE,
        "installed boundary reviewed source binding changed",
    )
    require(
        record.get("atlasRevision") == "1bdfce81e3afff4ec1c18afdfe3c7d423b693198"
        and record.get("reviewState") == "author-retained-measured-record"
        and record.get("evidenceClaim")
        == "author-operated-installed-reader-publication-and-quality-policy-result",
        "installed boundary selected record scope changed",
    )
    expected = {
        "sourceRepository": "probityai/agent-evidence-observer",
        "retention": "selected-capsule-with-complete-original-omission-map",
        "sourceCommit": SOURCE,
        "readerCommit": SOURCE,
        "mergedHead": SOURCE,
        "reviewedHead": REVIEW,
        "run": 37068022147,
        "artifactId": 11252549725,
        "originalArtifactSha256": ORIGINAL_SHA256,
        "originalArtifactBytes": 30137726,
        "retainedArchiveSha256": CAPSULE_SHA256,
        "retainedArchiveBytes": 283043,
        "sourceContractSha256": CONTRACT_SHA256,
    }
    require(
        all(
            type(provenance.get(key)) is type(value) and provenance[key] == value
            for key, value in expected.items()
        ),
        "installed boundary original provenance binding changed",
    )
    require(
        provenance.get("newInferenceExecuted") is False,
        "installed boundary retention cannot invent inference",
    )
    require(
        encode(provenance.get("nativeOriginal"))
        == encode(
            {
                "record": "model-boundary-cpu-2026-10-02",
                "artifactSha256": "d8ff26e82aca136daf734da65ede259b2bfaed9dd547ba25b92d65bdeeef019f",
                "reportSha256": REPORT_SHA256,
                "all871ProviderBoundaryPacketMembersEqualOriginal": True,
            }
        ),
        "installed boundary native original binding changed",
    )
    _custody(record, provenance)


def _custody(record: dict[str, Any], provenance: dict[str, Any]) -> None:
    """Keep author-operated custody/adoption distinct from gate publication."""
    expected = {
        "producer": "Probity-owned workflow",
        "readerAuthor": "Probity",
        "atlasOperator": "Probity",
        "retentionHolder": "Probity",
        "independentOperation": "not-established",
        "independentEffectCustody": "not-established",
        "outsideRecurringUse": "not-established",
    }
    require(
        record.get("roles") == expected and provenance.get("roles") == expected,
        "installed boundary author-operated role scope changed",
    )
    retained = provenance["fullOriginalRetention"]
    require(
        retained.get("holder") == "Probity"
        and retained.get("completeOriginalRetained") is True
        and retained.get("independentCustody") == "not-established",
        "installed boundary full original custody changed",
    )


def _inventory(provenance: dict[str, Any], bundle: zipfile.ZipFile) -> None:
    """Authenticate the complete original mapping and every explicit omission."""
    members = provenance["members"]
    original = [
        {key: member[key] for key in ("member", "bytes", "sha256")}
        for member in members
    ]
    canonical = (
        json.dumps(original, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    require(
        len(members) == 4964
        and hashlib.sha256(canonical).hexdigest() == INVENTORY_SHA256
        and provenance.get("fullMemberInventorySha256") == INVENTORY_SHA256,
        "installed boundary complete original inventory changed",
    )
    for member in members:
        _member(member, bundle)
    retained = {member["member"] for member in members if member["selected"]}
    require(
        len(retained) == 101
        and len(bundle.namelist()) == 101
        and set(bundle.namelist()) == retained,
        "installed boundary selected original coverage changed",
    )
    require(
        (
            provenance.get("fullMemberCount"),
            provenance.get("selectedMemberCount"),
            provenance.get("omittedMemberCount"),
        )
        == (4964, 101, 4863),
        "installed boundary retained and omitted counts changed",
    )


def _member(member: dict[str, Any], bundle: zipfile.ZipFile) -> None:
    """Refuse hidden omissions or substitutions even after generic SHA reselection."""
    selected = _selected(member["member"])
    require(
        member.get("selected") is selected,
        "installed boundary omission disposition changed",
    )
    reason = (
        "byte-exact selected original member"
        if selected
        else "omitted from selected installed capsule; complete provider original retained separately"
    )
    require(
        member.get("reason") == reason, "installed boundary omission disclosure changed"
    )
    if selected:
        raw = bundle.read(member["member"])
        require(
            len(raw) == member["bytes"]
            and hashlib.sha256(raw).hexdigest() == member["sha256"],
            "installed boundary selected original bytes changed",
        )


def _wheel(bundle: zipfile.ZipFile, contract: dict[str, Any]) -> None:
    """Bind the actual installed .4 wheel, original build record and source pins."""
    root = "_temp/model-reader-wheels/"
    build = json.loads(bundle.read(root + "build-record.json"))
    require(
        build["sourceContractSha256"] == CONTRACT_SHA256
        and contract["version"] == "0.0.4",
        "installed boundary source contract changed",
    )
    require(
        build["sources"]
        == {key: value["sha256"] for key, value in contract["files"].items()},
        "installed boundary packaged source selection changed",
    )
    raw = bundle.read(root + build["wheel"]["name"])
    require(
        hashlib.sha256(raw).hexdigest()
        == "031cb5fe13d446cac7d5ae4e2150f7e447bb4794457c64917dcf54fcdba50a49",
        "installed boundary actual CI wheel changed",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        for name, source in contract["files"].items():
            _wheel_member(wheel, name, source["sha256"])


def _wheel_member(wheel: zipfile.ZipFile, name: str, expected: str) -> None:
    """Require packaged Python/license bytes; build metadata separately pins TOML."""
    if name == "pyproject.toml":
        return
    path = (
        "probity_model_task_reader-0.0.4.dist-info/licenses/LICENSE"
        if name == "LICENSE"
        else name
    )
    require(
        hashlib.sha256(wheel.read(path)).hexdigest() == expected,
        "installed boundary wheel member differs from source pin",
    )


def _failure_row(row: dict[str, Any], rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep correctness and fully-correct pairs as separate finite thresholds."""
    thresholds = (
        ("correct", "minCorrect"),
        ("formatValid", "minFormatValid"),
        ("schemaValid", "minSchemaValid"),
        ("fullyCorrectPairs", "minFullyCorrectPairs"),
    )
    dimensions = {key: row[key] for key in DIMENSIONS}
    return [
        {
            "row": dimensions,
            "field": field,
            "minimum": rule[limit],
            "measured": row[field],
        }
        for field, limit in thresholds
        if row[field] < rule[limit]
    ]


def _quality_policy(
    native: dict[str, Any], upgrade: dict[str, Any], bundle: zipfile.ZipFile
) -> None:
    """Rederive all sixteen quality refusals from the unchanged twenty-four rows."""
    policy = json.loads(bundle.read(PREFIX + "candidate-boundary-quality/policy.json"))
    rows = {tuple(row[key] for key in DIMENSIONS): row for row in native["quality"]}
    failures = [
        failure
        for rule in policy["rows"]
        for failure in _failure_row(rows[tuple(rule[key] for key in DIMENSIONS)], rule)
    ]
    gate = upgrade["candidate-boundary-quality"]["gate"]
    require(
        len(rows) == 24
        and len(failures) == 16
        and encode(gate["policyFailures"]) == encode(failures),
        "installed boundary semantic pair refusals changed",
    )
    require(
        gate["evidenceDecision"] == "verified"
        and gate["publicationDecision"] == "hold-selected-score-or-resource",
        "installed boundary quality hold cannot become acceptance",
    )


def claim_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Build exact measured claims with separate native and selected-policy axes.

    Parameters
    ----------
    report : dict of str to Any
        Values from the authenticated original CI upgrade and installed reader.

    Returns
    -------
    list of dict
        Twenty-four native strict case/pair rows, sixteen independent selected
        threshold failures and five explicitly unmeasured adoption/action axes.
    """
    gates = (
        (
            "ordinary-installed-0.0.3-to0.0.4-upgrade",
            "pass",
            "/upgrade/candidate-installation",
            report["upgrade"]["candidate-installation"],
        ),
        (
            "baseline-boundary-refuses-before-reader-launch",
            "pass",
            "/upgrade/baseline-boundary/gate",
            report["upgrade"]["baseline-boundary"]["gate"],
        ),
        (
            "complete-evidence-publication",
            "pass",
            "/upgrade/candidate-boundary/gate",
            report["upgrade"]["candidate-boundary"]["gate"],
        ),
        (
            "selected-quality-policy-acceptance",
            "fail",
            "/upgrade/candidate-boundary-quality/gate",
            report["upgrade"]["candidate-boundary-quality"]["gate"],
        ),
    )
    claims = [
        {
            "claim": name,
            "result": result,
            "recordedField": pointer,
            "expectedValue": value,
        }
        for name, result, pointer, value in gates
    ]
    claims.extend(
        _native_claim(index, row)
        for index, row in enumerate(report["native"]["quality"])
    )
    failures = report["upgrade"]["candidate-boundary-quality"]["gate"]["policyFailures"]
    claims.extend(
        {
            "claim": "selected-quality-"
            + "-".join(failure["row"][key] for key in DIMENSIONS)
            + "-"
            + failure["field"],
            "result": "fail",
            "recordedField": f"/upgrade/candidate-boundary-quality/gate/policyFailures/{index}",
            "expectedValue": failure,
        }
        for index, failure in enumerate(failures)
    )
    claims.extend({"claim": name, "result": "not-exercised"} for name in UNMEASURED)
    return claims


def _native_claim(index: int, row: dict[str, Any]) -> dict[str, Any]:
    """Require every strict case and both members of every original native pair."""
    return {
        "claim": "installed-"
        + "-".join(row[key] for key in DIMENSIONS)
        + "-all-sixteen-targets-and-eight-pairs",
        "result": "pass"
        if row["correct"] == 16 and row["fullyCorrectPairs"] == 8
        else "fail",
        "recordedField": f"/native/quality/{index}",
        "expectedValue": row,
    }


def check_selected_installed_boundary(register: dict[str, Any], root: Path) -> None:
    """Authenticate the selected installed record after the general claim gate.

    Parameters
    ----------
    register : dict of str to Any
        Protocol0.1 register; historical/native records remain additive.
    root : Path
        Local retained artifact root. No network, inference or effects run.

    Raises
    ------
    ValueError
        For source, original-member, semantic, omission or custody substitutions.
    """
    selected = [record for record in register["records"] if record["id"] == IDENTITY]
    for record in selected:
        _validate_record(record, root)


def _validate_record(record: dict[str, Any], root: Path) -> None:
    """Compare the readout to both original provider JSON members byte for value."""
    report = json.loads(artifact_path(root, record["report"]).read_bytes())
    provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
    _metadata(record, provenance)
    archive = root / "experiments" / IDENTITY / "selected-capsule.zip"
    require(
        hashlib.sha256(archive.read_bytes()).hexdigest() == CAPSULE_SHA256,
        "installed boundary selected original capsule changed",
    )
    with zipfile.ZipFile(archive) as bundle:
        _inventory(provenance, bundle)
        upgrade = _read_original(bundle, PREFIX + "upgrade-result.json", UPGRADE_SHA256)
        native = _read_original(
            bundle, PREFIX + "candidate-boundary/reader.stdout", STDOUT_SHA256
        )
        expected = {
            "schema": "probity-atlas-installed-boundary-report-v1",
            "upgrade": upgrade,
            "native": native,
        }
        require(
            encode(report) == encode(expected),
            "installed boundary report differs from original CI values",
        )
        contract_raw = (
            root / "experiments" / IDENTITY / "source-contract.json"
        ).read_bytes()
        require(
            hashlib.sha256(contract_raw).hexdigest() == CONTRACT_SHA256,
            "installed boundary source contract changed",
        )
        _wheel(bundle, json.loads(contract_raw))
        _quality_policy(native, upgrade, bundle)
    original = (
        root / "experiments/model-boundary-cpu-2026-10-02/report.json"
    ).read_bytes()
    require(
        hashlib.sha256(original).hexdigest() == REPORT_SHA256
        and encode(native) == encode(json.loads(original)),
        "installed boundary original twenty-four rows or resources changed",
    )
    require(
        encode(record["claimResults"]) == encode(claim_results(report)),
        "installed boundary measurement cannot promote quality action adoption or custody",
    )
