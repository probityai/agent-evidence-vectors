"""Re-derive authored tool-argument scores from frozen original native bytes.

This retention checker is model-free. It reads the original provider ZIP and
selected source contract without importing packet code, loading weights, or
turning grammar validity into authority to execute an effect.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
from pathlib import Path
import stat
from typing import Any
import zipfile

if __package__:
    from .check_lab import _same_json_value as same_value
    from .check_lab import artifact_path, require
else:
    from check_lab import _same_json_value as same_value
    from check_lab import artifact_path, require

IDENTITY = "model-tool-arguments-cpu-2026-10-03"
BASELINE = "91632533e3834ebefb7e96a25d2d7ca6fe9e7499"
EXECUTION = "51e0c12551339cce5898d3bfae2ba9ef3d9607f5"
SOURCE = "884814fe8cbc2e3b21d267fbaf86726c37892b14"
REGISTRATION = "db429775f139396df4028a9f4367e9bdfaa4ba17"
PROTOCOL = "f62ded1a32862839da80a80f8e871ef6cda4acc8c30363367cccf6bec9e92c97"
HASHES: dict[str, str] = {
    'original-artifact.zip': '67ef1e638e814c71bbf354fe9895ea0faf5d9ef11eae2ff76b10b065bd7a7e54',
    'native-report.json': '92b0a21e5fe5efc682e7b6c287a850e28847f33b4515b1a02155ad706bb673ba',
    'provenance.json': '158c40fb504e0e44b3dc49e5539483b03aedceb92008c5c63d05340da68ffab7',
    'source-contract.json': '1cf2a5f3527f72db90ad0881c5dd360bb0775f005cd4cc8971e287015fe400d4',
    'README.md': '3b22b8f171370927c15ea5b2e0b98df0019a08f21e00e997ca957433842fbfb2',
}
UNMEASURED = ("outside-producer-acceptance", "external-host-recurring-adoption",
              "independent-effect-custody", "independent-inference-witness",
              "model-action-acceptance", "general-benchmark-performance")
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def digest(raw: bytes) -> str:
    """Commit to a complete unmodified original buffer using SHA-256."""
    return hashlib.sha256(raw).hexdigest()


def encode(value: Any) -> bytes:
    """Encode exact finite JSON values deterministically for metadata comparison."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate JSON members rather than replacing their observations."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "tool-argument original JSON repeats a member")
        value[key] = item
    return value


def invalid_constant(_: str) -> None:
    """Refuse nonfinite original values using a stable retention error."""
    raise ValueError("tool-argument original JSON is nonfinite")


def strict_json(raw: bytes | str) -> Any:
    """Parse duplicate-free finite JSON with bounded depth and value population.

    Parameters
    ----------
    raw : bytes or str
        Previously bounded selected original bytes or a native response text.

    Returns
    -------
    object
        Exact JSON values; Boolean and integer types remain distinct.

    Raises
    ------
    ValueError
        For duplicate, nonfinite, excessively deep or overpopulated originals.
    """
    result = json.loads(raw, object_pairs_hook=unique_members, parse_constant=invalid_constant)
    pending, count = [(result, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(depth <= 32 and count <= 50000, "tool-argument original JSON exceeds population limits")
        require(not isinstance(item, float) or math.isfinite(item), "tool-argument original JSON is nonfinite")
        if isinstance(item, (dict, list)):
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1) for child in children)
    return result


def claim_results(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep measured population/resource passes, quality failures and unknown axes.

    Every measured claim refers to the exact native report. Source custody and
    outside acceptance are separate; neither is inferred from a valid schema.
    """
    bindings = [("complete-native-population", "pass", "/population", report["population"]),
                ("complete-evidence-within-run-budget", "pass", "/evidence", report["evidence"]),
                ("scoped-evidence-publication", "pass", "/publicationDecision", report["publicationDecision"]),
                ("strict-tool-quality", "fail", "/qualityDecision", report["qualityDecision"])]
    bindings.extend(("strict-quality-row--" + str(index), "fail", "/quality/" + str(index), row)
                    for index, row in enumerate(report["quality"]))
    bindings.extend(("native--" + field, "pass", "/" + field, report[field])
                    for field in ("nativeTokens", "resources", "preparationReuse", "effectsExecuted", "providerCalls", "providerDollars"))
    claims = [{"claim": name, "result": result, "recordedField": pointer, "expectedValue": value}
              for name, result, pointer, value in bindings]
    return claims + [{"claim": name, "result": "not-exercised"} for name in UNMEASURED]


def source_record(provenance: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    """Build the exact additive record from frozen retention metadata and report."""
    prefix = "../experiments/" + IDENTITY + "/"
    return {"id": IDENTITY, "atlasRevision": BASELINE, "sourceRevision": EXECUTION,
            "readerRevision": SOURCE, "report": prefix + "native-report.json",
            "provenance": prefix + "provenance.json",
            "contract": "https://github.com/probityai/agent-evidence-observer/tree/" + SOURCE + "/interop/local-model-tool-arguments-2026-10-03",
            "reviewState": "author-retained-measured-record",
            "evidenceClaim": "authored-native-tool-arguments-with-strict-quality-hold",
            "roles": provenance["roles"], "answerExposure": provenance["answerExposure"],
            "comparisonOrder": provenance["comparisonOrder"], "limits": provenance["limits"],
            "artifacts": [{"path": prefix + name, "sha256": value} for name, value in HASHES.items()],
            "claimResults": claim_results(report)}


def selected_bytes(record: dict[str, Any], root: Path) -> dict[str, bytes]:
    """Authenticate frozen artifacts even after a candidate reselects outer hashes."""
    prefix = "../experiments/" + IDENTITY + "/"
    expected = {prefix + name: value for name, value in HASHES.items()}
    actual = {item["path"]: item["sha256"] for item in record["artifacts"]}
    require(actual == expected and len(record["artifacts"]) == len(expected),
            "tool-argument source-bound artifact selection changed")
    result = {name: artifact_path(root, prefix + name).read_bytes() for name in HASHES}
    require(all(digest(raw) == HASHES[name] for name, raw in result.items()),
            "tool-argument retained original bytes changed")
    return result


def archive_members(bundle: zipfile.ZipFile, provenance: dict[str, Any]) -> dict[str, bytes]:
    """Read the exact regular member population under a finite native packet limit."""
    rows = provenance["nativeArchive"]["members"]
    expected = {row["path"]: row for row in rows}
    infos = bundle.infolist()
    require(len(infos) == len(expected) == len(rows) and {info.filename for info in infos} == set(expected),
            "tool-argument original member population changed")
    require(sum(info.file_size for info in infos) <= MAX_ARCHIVE_BYTES,
            "tool-argument original packet exceeds byte selection")
    return {info.filename: read_member(bundle, info, expected[info.filename]) for info in infos}


def read_member(bundle: zipfile.ZipFile, info: zipfile.ZipInfo, selected: dict[str, Any]) -> bytes:
    """Require one safe regular ZIP member and its exact selected length/digest."""
    path = Path(info.filename)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in info.filename,
            "tool-argument original member path is unsafe")
    require(not info.is_dir() and stat.S_IFMT(info.external_attr >> 16) in {0, stat.S_IFREG}
            and info.file_size <= MAX_MEMBER_BYTES, "tool-argument original member is not bounded regular data")
    raw = bundle.read(info)
    require(len(raw) == selected["bytes"] and digest(raw) == selected["sha256"],
            "tool-argument original member bytes changed")
    return raw


def verify_source_closure(members: dict[str, bytes], protocol: dict[str, Any], contract: dict[str, Any]) -> None:
    """Bind the registered protocol and retained source without executing it."""
    require(digest(members["protocol.json"]) == PROTOCOL and contract["sourceCommit"] == SOURCE,
            "tool-argument prospective protocol or source changed")
    for name, selected in protocol["sourceClosure"].items():
        require(contract["files"][name] == selected and digest(members["sources/" + name]) == selected,
                "tool-argument retained source differs from source contract")
    for mode, selection in protocol["schemas"].items():
        require(digest(members["sources/grammars/" + mode + ".gbnf"]) == selection["grammarSHA256"],
                "tool-argument generic grammar differs from registration")
        require(digest(encode(selection["schema"])) == selection["schemaSHA256"],
                "tool-argument generic schema differs from registration")
    require(digest(members["sources/task_matrix.py"]) == contract["files"]["task_matrix.py"],
            "tool-argument retained entrypoint differs from selected source")


def schema_accepts(value: Any, schema: dict[str, Any]) -> bool:
    """Assess the selected generic schema subset, preserving exact JSON types."""
    kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
    if not any(type_accepts(value, kind) for kind in kinds):
        return False
    if "enum" in schema and not any(same_value(value, item) for item in schema["enum"]):
        return False
    return not isinstance(value, dict) or object_accepts(value, schema)


def type_accepts(value: Any, kind: str) -> bool:
    """Keep Boolean values separate from integer/number arguments."""
    kinds = {"string": str, "integer": int, "boolean": bool, "null": type(None),
             "array": list, "object": dict}
    return type(value) in {int, float} if kind == "number" else type(value) is kinds[kind]


def object_accepts(value: dict[str, Any], schema: dict[str, Any]) -> bool:
    """Require the selected closed shape while allowing generic control values."""
    properties = schema.get("properties")
    if properties is None:
        return True
    return set(value) == set(schema["required"]) and all(schema_accepts(value[key], child) for key, child in properties.items())


def expected_scores(text: str, target: dict[str, Any], schema: dict[str, Any], finish: str) -> dict[str, bool]:
    """Re-derive the frozen typed rubric; length-finished correctness stays false."""
    try:
        value = strict_json(text)
    except (ValueError, TypeError, RecursionError):
        return {"formatValid": False, "schemaValid": False, "correct": False}
    return {"formatValid": isinstance(value, dict), "schemaValid": schema_accepts(value, schema),
            "correct": finish != "length" and same_value(value, target)}


def verify_attempts(members: dict[str, bytes], report: dict[str, Any], protocol: dict[str, Any]) -> None:
    """Retain the entire serial denominator and derive every raw-response verdict."""
    order = protocol["order"]["attemptIds"]
    rows = report["attempts"]
    require(len(order) == len(rows) == 128 and [row["id"] for row in rows] == order
            and len(set(order)) == 128, "tool-argument complete native denominator changed")
    cases = {case["id"]: case for case in protocol["cases"]}
    expected_calls = {"calls/" + ident + suffix for ident in order for suffix in ("-started.json", "-returned.json")}
    require({name for name in members if name.startswith("calls/")} == expected_calls,
            "tool-argument native started/returned population changed")
    for row in rows:
        verify_attempt(row, members, cases, protocol)


def verify_attempt(row: dict[str, Any], members: dict[str, bytes], cases: dict[str, Any], protocol: dict[str, Any]) -> None:
    """Bind one original response to selected identity, typed score and actual usage."""
    ident = row["id"]
    model, cap, mode, case_id = ident.split("--")
    case = cases[case_id]
    start = strict_json(members["calls/" + ident + "-started.json"])
    returned = strict_json(members["calls/" + ident + "-returned.json"])
    require(start["id"] == returned["id"] == ident and row["outcome"] == "scored",
            "tool-argument native attempt binding changed")
    require((row["model"], row["configuration"], row["mode"]) == (model, cap, mode)
            and same_value(row["originalIdentity"], case["originalIdentity"]),
            "tool-argument case identity changed")
    require(same_value([row["pair"], row["pairRole"], row["family"], row["targetAbstention"]],
                       [case["pair"], case["role"], case["family"], case["target"]["abstain"]]),
            "tool-argument pair or abstention identity changed")
    verify_response_scores(row, returned, case, protocol)


def verify_response_scores(row: dict[str, Any], returned: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any]) -> None:
    """Recompute raw text format/schema/correctness and preserve resource originals."""
    choice = returned["response"]["choices"][0]
    scores = expected_scores(choice["text"], case["target"], protocol["schemas"][case["mode"]]["schema"], choice["finish_reason"])
    require(all(row[key] is value for key, value in scores.items())
            and row["truncated"] is (choice["finish_reason"] == "length")
            and row["finishReason"] == choice["finish_reason"],
            "tool-argument semantic scores differ from original response")
    require(same_value(row["usage"], returned["response"]["usage"])
            and same_value(row["resources"], returned["resources"]),
            "tool-argument usage or resources differ from original response")


def quality_from_attempts(rows: list[dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    """Re-derive all sixteen cases, eight pairs and abstention/truncation counts."""
    selected = [item for item in rows if (item["model"], item["configuration"], item["mode"])
                == (row["model"], row["configuration"], row["mode"])]
    pairs = {item["pair"] for item in selected}
    values = {field: sum(item[field] for item in selected) for field in ("formatValid", "schemaValid", "correct")}
    values.update(planned=16, plannedPairs=8, scored=len(selected),
                  fullyCorrectPairs=sum(all(item["correct"] for item in selected if item["pair"] == pair) for pair in pairs),
                  truncatedReturns=sum(item["truncated"] for item in selected),
                  plannedAbstentions=sum(item["targetAbstention"] for item in selected),
                  correctAbstentions=sum(item["correct"] and item["targetAbstention"] for item in selected))
    return dict(row, **values)


def verify_quality(report: dict[str, Any]) -> None:
    """Preserve every quality row and refuse promotion from valid schema to effects."""
    verify_quality_population(report)
    require(len(report["quality"]) == 8 and all(same_value(row, quality_from_attempts(report["attempts"], row)) for row in report["quality"]),
            "tool-argument quality rows differ from complete original attempts")
    require(report["publicationDecision"] == "publish-scoped-report"
            and report["qualityDecision"] == "hold-tool-decision-quality",
            "tool-argument evidence and strict quality decisions changed")
    require(all(row["fullyCorrectPairs"] == row["correctAbstentions"] == 0 for row in report["quality"]),
            "tool-argument pair or abstention result changed")
    require(report["effectsExecuted"] == report["providerCalls"] == report["providerDollars"] == 0,
            "tool-argument zero provider/effect scope changed")


def verify_quality_population(report: dict[str, Any]) -> None:
    """Require all eight distinct cells, sixteen unique cases and both pair roles."""
    expected = {(model, cap, mode) for model in ("smol135-q4", "smol360-q4")
                for cap in ("short24", "long96") for mode in ("control", "tool-schema")}
    cells = [(row["model"], row["configuration"], row["mode"]) for row in report["quality"]]
    require(len(cells) == len(set(cells)) == 8 and set(cells) == expected,
            "tool-argument complete distinct quality cell population changed")
    for cell in cells:
        selected = [row for row in report["attempts"]
                    if (row["model"], row["configuration"], row["mode"]) == cell]
        verify_quality_members(selected)


def verify_quality_members(selected: list[dict[str, Any]]) -> None:
    """Refuse duplicate case identities and absent contrast roles in a cell."""
    pairs = {row["pair"] for row in selected}
    require(len(selected) == len({row["originalIdentity"]["id"] for row in selected}) == 16
            and len(pairs) == 8, "tool-argument unique quality case population changed")
    require(all(sorted(row["pairRole"] for row in selected if row["pair"] == pair) == ["a", "b"]
                for pair in pairs), "tool-argument complete quality pair roles changed")


def verify_terminal(members: dict[str, bytes], report: dict[str, Any]) -> None:
    """Keep external whole-child measurements distinct from original child totals."""
    terminal = strict_json(members["terminal.json"])
    child = strict_json(members["inference-terminal.json"])
    require(terminal["status"] == child["status"] == "complete" and terminal["returnCode"] == 0
            and terminal["wallGuardTerminated"] is False, "tool-argument complete native child status changed")
    require(all(report["resources"][key] == terminal[key] and terminal[key] >= child[key]
                for key in ("elapsed_ns", "process_cpu_ns", "process_maxrss_kib")),
            "tool-argument whole-child resource boundary changed")
    tokens = {kind: sum(row["usage"][kind + "_tokens"] for row in report["attempts"])
              for kind in ("prompt", "completion")}
    require(same_value(tokens, report["nativeTokens"]), "tool-argument full population token total changed")


def validate_record(record: dict[str, Any], root: Path) -> None:
    """Authenticate this frozen original, rederive scores and bind exact metadata.

    Parameters
    ----------
    record : dict
        Additive Lab record whose artifact hashes are independently source-bound.
    root : pathlib.Path
        Atlas repository or a test fixture containing the selected retained files.

    Raises
    ------
    ValueError
        For changed artifacts, source pins, metadata, omitted rows, promoted
        quality or any discrepancy between original responses and their scores.
    """
    raw = selected_bytes(record, root)
    report = strict_json(raw["native-report.json"])
    provenance = strict_json(raw["provenance.json"])
    require(same_value(record, source_record(provenance, report)),
            "tool-argument scope, ownership or measured claims changed")
    contract = strict_json(raw["source-contract.json"])
    with zipfile.ZipFile(io.BytesIO(raw["original-artifact.zip"])) as bundle:
        members = archive_members(bundle, provenance)
    require(members["report.json"] == raw["native-report.json"],
            "tool-argument native report is not the original provider member")
    protocol = strict_json(members["protocol.json"])
    verify_source_closure(members, protocol, contract)
    verify_attempts(members, report, protocol)
    verify_quality(report)
    verify_terminal(members, report)


def check_selected_tool_arguments(register: dict[str, Any], root: Path) -> None:
    """Apply this additive source-bound gate while leaving older profiles intact."""
    for record in register["records"]:
        if record.get("id") == IDENTITY:
            validate_record(record, root)
