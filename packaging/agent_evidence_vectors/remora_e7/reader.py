"""Evaluate REMORA E7 fixture premises without importing producer code."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
CONTRACT = "runtime-surface-e7-v0.1"
REVISION = "e4fe474f488c3047b346abb01cbfd77ab447ad69"
PACKAGE_DIGEST = "sha256:01dfdb7885bdbb18c025bc013edc28b482b0631ae282aca877bd0953b865e4bf"
PACKAGE_PATH = Path("artifacts/interop") / CONTRACT
SURFACE_CLAIM = "bounded_observed_surface_matches_governed_set"
GLOBAL_PROPERTY = {"id": "runtime_capability_surface_completeness", "status": "NOT_ESTABLISHED"}


def unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Parse object members, refusing an ambiguous duplicate key."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def load_object(raw: bytes) -> dict[str, Any]:
    """Decode a UTF-8 JSON object without accepting duplicate members."""
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_members)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def sha256(raw: bytes) -> str:
    """Return the hexadecimal SHA-256 of the delivered byte stream."""
    return hashlib.sha256(raw).hexdigest()


def checked_path(root: Path, relative: str) -> Path:
    """Resolve a package member beneath its root, refusing links and traversal."""
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe package path: {relative}")
    candidate = root / path
    for parent in [candidate, *candidate.parents]:
        if parent == root.parent:
            break
        if parent.is_symlink():
            raise ValueError(f"symlink in package path: {relative}")
    return candidate


def verify_package(root: Path) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    """Check every producer package byte against the externally selected digest.

    Parameters
    ----------
    root : Path
        Retained producer tree containing the frozen package paths.

    Returns
    -------
    tuple
        The verified fixture object, claim packet, and actual input digests.

    Raises
    ------
    ValueError
        If the manifest identity, member set, path or delivered bytes disagree.
    """
    manifest = load_object(checked_path(root, str(PACKAGE_PATH / "manifest.json")).read_bytes())
    entries = manifest["package_files"]
    required = {
        str(PACKAGE_PATH / name)
        for name in (
            "README.md",
            "claim-packet.json",
            "fixtures.json",
            "reference_verifier.py",
            "verifier-request.json",
        )
    }
    if {item["path"] for item in entries} != required or len(entries) != len(required):
        raise ValueError("producer package member set differs from the frozen contract")
    preimage = "".join(
        f"{item['path']} {item['sha256']}\n"
        for item in sorted(entries, key=lambda item: item["path"])
    )
    actual = "sha256:" + sha256(preimage.encode())
    if actual != PACKAGE_DIGEST or manifest["package_digest"] != PACKAGE_DIGEST:
        raise ValueError("producer package digest differs from the selected pin")
    snapshots = _read_members(root, entries)
    fixtures = load_object(snapshots[str(PACKAGE_PATH / "fixtures.json")])
    claim = load_object(snapshots[str(PACKAGE_PATH / "claim-packet.json")])
    LOGGER.info("Verified %s package members against %s", len(entries), PACKAGE_DIGEST)
    return fixtures, claim, entries


def _read_members(root: Path, entries: list[dict[str, str]]) -> dict[str, bytes]:
    """Read each member once and refuse any mismatch before JSON evaluation."""
    snapshots = {}
    for entry in entries:
        path = checked_path(root, entry["path"])
        if path.name == "reference_verifier.py" and not path.exists():
            path = checked_path(root, entry["path"] + ".source")
        raw = path.read_bytes()
        if sha256(raw) != entry["sha256"]:
            raise ValueError(f"producer input digest mismatch: {entry['path']}")
        snapshots[entry["path"]] = raw
    return snapshots


def _coverage_gaps(case: dict[str, Any]) -> list[str]:
    """Name missing bounded observation premises without inferring completeness."""
    conditions = [
        (
            case.get("runtime_identity") != case.get("expected_runtime_identity"),
            "runtime_identity_mismatch",
        ),
        (
            not isinstance(case.get("runtime_identity"), str) or not case.get("runtime_identity"),
            "runtime_identity_missing",
        ),
        (case.get("observation_source") != "agent-runtime", "observation_source_not_agent_runtime"),
        (case.get("complete") is not True, "surface_incomplete"),
    ]
    return [reason for failed, reason in conditions if failed]


def _tool_errors(tools: Any) -> list[str]:
    """Refuse missing tool evidence and duplicate tool identities."""
    if not isinstance(tools, list):
        return ["invalid_tool_inventory"]
    if any(not _valid_tool(tool) for tool in tools):
        return ["invalid_tool_evidence"]
    names = [tool["tool_id"] for tool in tools]
    return ["duplicate_tool_identity"] if len(names) != len(set(names)) else []


def _valid_tool(tool: Any) -> bool:
    """Require explicit tool identity, reachability flags and definition evidence."""
    if not isinstance(tool, dict):
        return False
    text = all(isinstance(tool.get(key), str) and tool[key] for key in ("tool_id", "source"))
    flags = all(
        type(tool.get(key)) is bool
        for key in (
            "registered",
            "offered_to_agent",
            "callable_at_dispatch",
        )
    )
    digest = tool.get("toolspec_hash")
    return bool(text and flags and (digest is None or isinstance(digest, str)))


def surface_result(case: dict[str, Any]) -> dict[str, Any]:
    """Compare a complete fixture's reachable tools to its governed definitions.

    Offered or dispatch-callable tools are the bounded observed surface. Registry
    presence alone does not prove agent reachability. Unknown premises return
    NOT_ESTABLISHED; a complete surface with conflicting identities contradicts
    the claim. These are local interpretations outside the five pinned examples.
    """
    gaps = _coverage_gaps(case) + _tool_errors(case.get("tools"))
    governed = case.get("governed_tools")
    if not isinstance(governed, dict):
        gaps.append("invalid_governed_set")
    if gaps:
        return {
            "surface_verdict": "NOT_ESTABLISHED",
            "claim_result": "NOT_ESTABLISHED",
            "reasons": gaps,
        }
    observed = {
        tool["tool_id"]: tool["toolspec_hash"]
        for tool in case["tools"]
        if tool["offered_to_agent"] or tool["callable_at_dispatch"]
    }
    assert isinstance(governed, dict)
    return _surface_comparison(observed, governed)


def _surface_comparison(observed: dict[str, Any], governed: dict[str, Any]) -> dict[str, Any]:
    """Report set and definition disagreements without discarding missing tools."""
    unexpected = sorted(observed.keys() - governed.keys())
    missing = sorted(governed.keys() - observed.keys())
    changed = sorted(
        key for key in observed.keys() & governed.keys() if observed[key] != governed[key]
    )
    mismatch = bool(unexpected or missing or changed)
    result: dict[str, Any] = {
        "surface_verdict": "MISMATCH" if mismatch else "MATCHED_OBSERVATION",
        "claim_result": "CONTRADICTED" if mismatch else "ESTABLISHED",
    }
    for key, values in (
        ("unexpected_tools", unexpected),
        ("missing_tools", missing),
        ("changed_definitions", changed),
    ):
        if values:
            result[key] = values
    return result


def effect_path_result(case: dict[str, Any]) -> dict[str, Any]:
    """Distinguish a witnessed alternative from unproved absence of alternatives."""
    paths = case.get("alternative_effect_paths")
    if not isinstance(paths, list):
        return {
            "claim_id": "exclusive_effect_path",
            "claim_result": "NOT_ESTABLISHED",
            "reason": "effect_path_inventory_missing",
        }
    if paths:
        return {
            "claim_id": "exclusive_effect_path",
            "claim_result": "CONTRADICTED",
            "reason": "alternative_effect_path_observed",
        }
    complete = case.get("path_inventory_complete") is True
    return {
        "claim_id": "exclusive_effect_path",
        "claim_result": "ESTABLISHED" if complete else "NOT_ESTABLISHED",
        "reason": "complete_path_inventory" if complete else "path_inventory_incomplete",
    }


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate actual case fields; the expected-answer member is never read."""
    handlers = {"surface": surface_result, "effect_path": effect_path_result}
    if case.get("kind") not in handlers:
        raise ValueError(f"unsupported fixture kind: {case.get('kind')}")
    result = handlers[case["kind"]](case)
    return {"case_id": case["id"], "claim_id": result.get("claim_id", SURFACE_CLAIM), **result}


def run_package(root: Path) -> dict[str, Any]:
    """Save actual results before comparing them with the exposed fixture answer."""
    fixtures, claim, digests = verify_package(root)
    cases = fixtures["cases"]
    if len(cases) != 5 or len({case["id"] for case in cases}) != 5:
        raise ValueError("frozen E7 population must contain five unique cases")
    actual = [evaluate_case(case) for case in cases]
    failures = [_compare(case, result) for case, result in zip(cases, actual, strict=True)]
    return {
        "contract_id": CONTRACT,
        "consumed_revision": REVISION,
        "package_digest": PACKAGE_DIGEST,
        "input_digests": digests,
        "results": actual,
        "failures": [item for item in failures if item],
        "global_property": GLOBAL_PROPERTY,
        "claims": claim["claims"],
        "assumptions": claim["assumptions"],
        "explicit_non_claims": claim["explicit_non_claims"],
        "temporal_scope": claim["temporal_scope"],
        "answer_exposure": "Published expectations read before implementation; not blind.",
    }


def _compare(case: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Compare required expected fields without influencing the calculation."""
    differences = {
        key: {"expected": value, "actual": actual.get(key)}
        for key, value in case["expected"].items()
        if actual.get(key) != value
    }
    return {"case_id": case["id"], "differences": differences} if differences else {}
