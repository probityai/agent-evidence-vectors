"""Read saved Harness Watch rows without installing or running a harness."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Any

MAX_BYTES = 4 * 1024 * 1024
MAX_POPULATION = 128
ARMS = ("a", "b", "c", "d")
SYMLINK_ARMS = ("e", "f")


class InputError(ValueError):
    """The supplied bytes cannot establish a well-formed pinned import."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    """Stable output serialization; this function is not a JCS implementation."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise InputError("duplicate JSON key")
        out[key] = value
    return out


def _constant(_: str) -> None:
    raise InputError("non-JSON number")


def _bounded(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise InputError("JSON depth limit exceeded")
    if isinstance(value, str):
        if len(value) > MAX_BYTES or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise InputError("non-scalar or oversized JSON string")
    elif isinstance(value, dict):
        for key, item in value.items():
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise InputError("non-finite JSON number")


def strict_json(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise InputError("JSON byte limit exceeded")
    try:
        out = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
        _bounded(out)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError("invalid UTF-8 JSON") from exc
    if not isinstance(out, dict):
        raise InputError("expected JSON object")
    return out


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise InputError(f"{label}: expected nonempty bounded string")
    return value


def _count(value: Any, label: str, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise InputError(f"{label}: expected bounded nonnegative integer")
    return value


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected object")
    return value


def _row(value: Any) -> dict:
    row = _object(value, "row")
    if set(row) - {"arms", "sym", "tools", "bytes_b", "s004"}:
        raise InputError("row: unsupported field")
    arms = _object(row.get("arms"), "row.arms")
    if set(arms) != set(ARMS):
        raise InputError("row.arms: incomplete or changed arm population")
    for arm, tokens in arms.items():
        if not isinstance(tokens, list) or len(tokens) > 4096:
            raise InputError("row.arms: expected bounded token list")
        for token in tokens:
            _text(token, f"arm {arm} token")
    sym = _object(row.get("sym"), "row.sym")
    if set(sym) - set(SYMLINK_ARMS):
        raise InputError("row.sym: unsupported arm")
    for arm, counts in sym.items():
        for token, count in _object(counts, f"sym {arm}").items():
            _text(token, "symlink token")
            _count(count, "symlink count")
    _count(row.get("tools"), "row.tools", optional=True)
    _count(row.get("bytes_b"), "row.bytes_b", optional=True)
    split = row.get("s004")
    if split is not None:
        split = _object(split, "row.s004")
        if set(split) - {"total", "tools", "system"}:
            raise InputError("row.s004: unsupported field")
        for name in ("total", "tools", "system"):
            _count(split.get(name), f"s004.{name}", optional=True)
    return row


def pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _js_items(value: dict) -> list[tuple[str, int]]:
    """JSON.stringify orders array-index property keys before other keys."""
    indices = [key for key in value if key.isascii() and key.isdigit() and str(int(key)) == key and int(key) < 2**32 - 1]
    return [(key, value[key]) for key in sorted(indices, key=int) + [key for key in value if key not in indices]]


def _symlinks(before: dict, after: dict) -> tuple[list[dict], list[str], list[str], bool]:
    differences, order_only, unavailable = [], [], []
    native_changed = False
    for arm in SYMLINK_ARMS:
        old, new = before.get(arm), after.get(arm)
        # A missing baseline is not an observed empty object. The publisher
        # skips it; the importer carries the comparison gap explicitly.
        if old is not None and (new is None or _js_items(old) != _js_items(new)):
            native_changed = True
        if old is None or new is None:
            unavailable.append(f"sym/{arm}")
        elif old != new:
            differences.append({"field": f"sym/{arm}", "kind": "occurrence-count", "before": old, "after": new})
        elif list(old.items()) != list(new.items()):
            order_only.append(f"sym/{arm}")
    return differences, order_only, unavailable, native_changed


def compare_rows(before: dict, after: dict) -> dict:
    """Keep membership, occurrence counts, order and token arithmetic distinct."""
    _row(before)
    _row(after)
    differences: list[dict] = []
    order_only: list[str] = []
    native_changed = False
    for arm in ARMS:
        old, new = before["arms"][arm], after["arms"][arm]
        added, removed = sorted(set(new) - set(old)), sorted(set(old) - set(new))
        if added or removed:
            native_changed = True
            differences.append({"field": f"arms/{arm}", "kind": "membership", "added": added, "removed": removed})
        elif old != new:
            order_only.append(f"arms/{arm}")
    sym_differences, sym_order, unavailable, sym_native = _symlinks(before["sym"], after["sym"])
    differences.extend(sym_differences)
    order_only.extend(sym_order)
    native_changed = native_changed or sym_native
    old_total = (before.get("s004") or {}).get("total")
    new_total = (after.get("s004") or {}).get("total")
    token = {"before": old_total, "after": new_total, "delta": None, "comparison": "not_established"}
    if old_total is not None and new_total is not None:
        delta = new_total - old_total
        token["delta"] = delta
        # Exact integer arithmetic avoids turning the strict boundary into an
        # accidental float tolerance. A zero baseline has no relative change.
        if old_total > 0 and new_total > 0:
            significant = abs(delta) * 100 > old_total * 10
            token["comparison"] = "significant" if significant else "within-threshold"
            if significant:
                differences.append({"field": "s004/total", "kind": "relative-token-shift", "delta": delta})
            native_changed = native_changed or abs((new_total - old_total) / old_total * 100) > 10
    return {
        "method": "watch-set-and-counts/v1",
        "changed": bool(differences),
        "differences": differences,
        "order_only": order_only,
        "tokens": token,
        "tools": {"before": before.get("tools"), "after": after.get("tools")},
        "unavailable_fields": unavailable,
        "outcome": "changed"
        if differences
        else "not_established"
        if unavailable or token["comparison"] == "not_established"
        else "unchanged",
        "upstream_method": "pinned-watch.ts-json-stringify/v1",
        "upstream_recomputed_changed": native_changed,
        "token_threshold": {"percent": 10, "operator": "strictly-greater"},
    }


def _safe_file(root: Path, relative: str) -> Path:
    path = PurePosixPath(_text(relative, "retainedPath"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or "\\" in relative or ":" in relative:
        raise InputError("unsafe source path")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise InputError("symlink source path")
    if not current.resolve().is_relative_to(root.resolve()):
        raise InputError("source path leaves input root")
    return current


def _profile_population(manifest: dict) -> list[str]:
    if manifest.get("schema") != "probity.watch-sources/v1":
        raise InputError("unsupported source manifest")
    population = manifest.get("population")
    if (
        not isinstance(population, list)
        or not 1 <= len(population) <= MAX_POPULATION
        or not all(isinstance(name, str) and re.fullmatch(r"[a-z0-9_-]{1,64}", name) for name in population)
        or len(set(population)) != len(population)
    ):
        raise InputError("invalid frozen population")
    comparison = _object(manifest.get("comparison"), "comparison profile")
    if (
        comparison.get("version") != "watch-set-and-counts/v1"
        or comparison.get("tokenShiftPercent", 10) != 10
        or comparison.get("tokenShiftOperator", "strictly-greater") != "strictly-greater"
    ):
        raise InputError("unsupported comparison profile")
    for field in ("sourceRevision", "baselineRevision"):
        if not re.fullmatch(r"[0-9a-f]{40}", _text(manifest.get(field), field)):
            raise InputError("invalid source revision")
    _text(manifest.get("repository"), "source repository")
    return population


def load_sources(root: Path, manifest: dict) -> tuple[dict[str, bytes], dict[str, dict]]:
    population = _profile_population(manifest)
    repository = manifest["repository"]
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 128:
        raise InputError("invalid source file population")
    raw: dict[str, bytes] = {}
    bindings: dict[str, dict] = {}
    paths: set[str] = set()
    for item in files:
        item = _object(item, "source pin")
        role = _text(item.get("role"), "source role")
        expected_revision = manifest["baselineRevision"] if role == "baseline_state" else manifest["sourceRevision"]
        if item.get("repository") != repository or item.get("revision") != expected_revision:
            raise InputError("source revision or repository differs from selected profile")
        _text(item.get("path"), "source repository path")
        if role in raw or item.get("retainedPath") in paths:
            raise InputError("duplicate source role or path")
        path = _safe_file(root, item.get("retainedPath"))
        size = _count(item.get("bytes"), "source byte length")
        if size > MAX_BYTES or path.stat().st_size != size:
            raise InputError("source length mismatch")
        data = path.read_bytes()
        sha = _text(item.get("sha256"), "source digest")
        git = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or len(data) != size or digest(data) != sha or git != item.get("gitBlob"):
            raise InputError("source pin mismatch")
        raw[role] = data
        paths.add(item["retainedPath"])
        bindings[role] = {key: item[key] for key in ("repository", "revision", "path", "retainedPath", "bytes", "sha256", "gitBlob")}
    required = {"baseline_state", "current_state", "registry", "comparison_source", "upstream_workflow", "tokenizer"}
    required.update("run/" + name for name in population)
    if not required <= raw.keys():
        raise InputError("missing source role")
    return raw, bindings


def _state(data: bytes, population: list[str]) -> dict:
    state = strict_json(data)
    rows = _object(state.get("harnesses"), "state.harnesses")
    if set(rows) != set(population):
        raise InputError("state population differs from frozen source population")
    for name, entry in rows.items():
        entry = _object(entry, f"state {name}")
        for field in ("version", "measured", "where"):
            _text(entry.get(field), f"state {name}.{field}")
        _row(entry.get("row"))
    return rows


def _record(data: bytes, name: str, before: dict, after: dict) -> dict:
    record = strict_json(data)
    if record.get("harness") != name:
        raise InputError("run identity differs from pinned role")
    for field in ("label", "version", "previous_version", "previous_measured", "date", "where", "run", "note"):
        _text(record.get(field), f"run.{field}")
    for field in ("forced", "changed"):
        if type(record.get(field)) is not bool:
            raise InputError(f"run.{field}: expected boolean")
    for field in ("changes", "minor"):
        if not isinstance(record.get(field), list):
            raise InputError(f"run.{field}: expected list")
        for item in record[field]:
            _text(item, f"run.{field} item")
    if record["previous_version"] != before["version"] or record["previous_measured"] != before["measured"]:
        raise InputError("run does not bind the selected baseline identity")
    for run_field, state_field in (("version", "version"), ("date", "measured"), ("where", "where"), ("row", "row")):
        if record.get(run_field) != after[state_field]:
            raise InputError("run does not bind the selected current state")
    return record


def import_watch(root: Path, manifest: dict) -> tuple[dict, dict[str, bytes]]:
    """Consumer-held source pins select raw inputs; they do not authenticate a publisher."""
    raw, bindings = load_sources(root, manifest)
    population = manifest["population"]
    before, after = _state(raw["baseline_state"], population), _state(raw["current_state"], population)
    rows: list[dict] = []
    for name in population:
        run = _record(raw["run/" + name], name, before[name], after[name])
        comparison = compare_rows(before[name]["row"], run["row"])
        declared_match = run["changed"] == comparison["upstream_recomputed_changed"]
        rows.append(
            {
                "harness": name,
                "before": before[name],
                "after": after[name],
                "publisher_record": run,
                "comparison": comparison,
                "publisher_claim_match": declared_match,
                "adapter_agrees_with_publisher": run["changed"] == comparison["changed"],
                "lineage": {
                    "before": {
                        "artifact": "baseline_state",
                        "sha256": bindings["baseline_state"]["sha256"],
                        "pointer": "/harnesses/" + pointer(name) + "/row",
                    },
                    "after": {"artifact": "run/" + name, "sha256": bindings["run/" + name]["sha256"], "pointer": "/row"},
                    "current_state": {
                        "artifact": "current_state",
                        "sha256": bindings["current_state"]["sha256"],
                        "pointer": "/harnesses/" + pointer(name) + "/row",
                    },
                },
                "verdict": "consistent" if declared_match else "contradicted",
            }
        )
    return {
        "schema": "probity.watch-import/v1",
        "source_revision": manifest["sourceRevision"],
        "baseline_revision": manifest["baselineRevision"],
        "source_manifest_sha256": digest(canonical(manifest)),
        "population": population,
        "bindings": bindings,
        "rows": rows,
        "summary": {
            "rows": len(rows),
            "consistent_publisher_claims": sum(row["publisher_claim_match"] for row in rows),
            "adapter_changed": sum(row["comparison"]["changed"] for row in rows),
        },
        "runtime_evidence": manifest.get("runtimeEvidence", {}),
        "scope": {
            "operation": "import-and-recompute-saved-publisher-rows",
            "source_operator": "publisher-reported",
            "source_operator_authenticated": False,
            "harnesses_executed": False,
            "raw_model_requests_observed": False,
            "target_effects_observed": False,
            "host_required_check_adopted": False,
            "relative_change": "A zero or missing token baseline is not_established.",
            "ordering": "Raw input order is preserved; stable semantic comparison and publisher symlink ordering are separate.",
            "missing_baseline": "Missing symlink fields are not observed empty fields and cannot establish an unchanged result.",
        },
    }, raw
