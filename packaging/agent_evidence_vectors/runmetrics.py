"""A validator for the Run object of draft-arsentev-agent-run-metrics-00.

The draft is an individual Internet-Draft (Informational, 10 September 2026)
defining a JSON interchange format for resource accounting of language-model
agent runs. Its text is vendored beside the corpus that cites it and pinned by
digest; each rule here is bound to one sentence of that text by a requirement
identifier the corpus mints (``ARM-R-nnn``), and ``rejections(document)``
returns the identifiers a Run object is rejected under. Only the sentences a
validator can read off one document are carried: the HTTP binding, the
privacy and security guidance, and the Collector-side behaviours are not
properties of a Report and are not rows.

``corpora/runmetrics.go`` is the same statement in Go and the parity test diffs
the two.
"""

from __future__ import annotations

import re
from typing import Any

STATUSES = ("running", "completed", "failed", "aborted")
ENDED = ("completed", "failed", "aborted")
STEP_KINDS = ("model_invocation", "tool_call")
RUN_MEMBERS = (
    "version", "run_id", "parent_run_id", "root_run_id", "start", "end", "status",
    "termination_reason", "agent", "models", "step_count", "steps", "totals",
    "subtree_totals", "cost", "labels", "errors", "revision", "trace_id",
)
USAGE_MEMBERS = (
    "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
    "reasoning_tokens", "billable_input_tokens", "billable_output_tokens", "cache_writes",
)
IDENTIFIERS = ("run_id", "parent_run_id", "root_run_id")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$")
AMOUNT = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")

R = {n: f"ARM-R-{n:03d}" for n in range(1, 23)}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_obj(value: Any) -> bool:
    return isinstance(value, dict)


def _get(obj: dict[str, Any], key: str) -> Any:
    return obj.get(key)


def shape_errors(document: Any) -> list[str]:
    """Every way the document fails to be a Run object at all."""
    if not _is_obj(document):
        return ["the document is not a JSON object"]
    out: list[str] = []
    for member in ("version", "run_id", "start", "status", "step_count", "totals"):
        if member not in document:
            out.append(f"the Run carries no {member} member")
    if "step_count" in document and not _is_int(document["step_count"]):
        out.append("step_count is not an integer")
    _shape_steps(document, out)
    for key in ("totals", "subtree_totals"):
        _shape_ledger(document.get(key), key, out)
    for i, step in enumerate(document.get("steps") or []):
        if _is_obj(step):
            _shape_ledger(step.get("usage"), f"steps[{i}].usage", out)
    return out


def _shape_steps(document: dict[str, Any], out: list[str]) -> None:
    if "steps" in document and not isinstance(document["steps"], list):
        out.append("steps is present and is not an array")
    for i, step in enumerate(document.get("steps") or []):
        if not _is_obj(step):
            out.append(f"steps[{i}] is not an object")
        elif not _is_int(step.get("index")) or not _is_str(step.get("kind")):
            out.append(f"steps[{i}] carries no integer index or no string kind")


def _shape_ledger(usage: Any, where: str, out: list[str]) -> None:
    """A Usage object's cache_writes, when present, is an array of objects (section 3.5)."""
    if not _is_obj(usage) or "cache_writes" not in usage:
        return
    writes = usage["cache_writes"]
    if not isinstance(writes, list):
        out.append(f"{where}.cache_writes is not an array")
        return
    for i, write in enumerate(writes):
        if not _is_obj(write):
            out.append(f"{where}.cache_writes[{i}] is not an object")


def _rows_run_status(run: dict[str, Any], out: set[str]) -> None:
    if run["version"] != "1":
        out.add(R[1])
    status = run["status"]
    if status not in STATUSES:
        out.add(R[4])
    elif (status in ENDED) != ("end" in run):
        out.add(R[2])
    start, end = _get(run, "start"), _get(run, "end")
    if _is_str(start) and _is_str(end) and TIMESTAMP.match(start) and TIMESTAMP.match(end):
        if end < start:
            out.add(R[3])
    steps: Any = run.get("steps")
    if isinstance(steps, list) and _is_int(run["step_count"]) and run["step_count"] < len(steps):
        out.add(R[5])


def _rows_run_members(run: dict[str, Any], out: set[str]) -> None:
    if "root_run_id" in run and "parent_run_id" not in run and run["root_run_id"] != run["run_id"]:
        out.add(R[16])
    if any(m not in RUN_MEMBERS and not m.startswith("x-") for m in run):
        out.add(R[21])
    labels = _get(run, "labels")
    if labels is not None and (not _is_obj(labels) or not all(_is_str(v) for v in labels.values())):
        out.add(R[18])
    cost = _get(run, "cost")
    if _is_obj(cost) and not (_is_str(cost.get("amount")) and AMOUNT.match(cost["amount"])):
        out.add(R[17])


def _rows_timestamps_and_identifiers(run: dict[str, Any], out: set[str]) -> None:
    stamps = [run.get("start"), run.get("end")]
    for step in run.get("steps") or []:
        stamps.append(step.get("start"))
        stamps.append(step.get("end"))
    if any(s is not None and not (_is_str(s) and TIMESTAMP.match(s)) for s in stamps):
        out.add(R[19])
    names = [run.get(k) for k in IDENTIFIERS if k in run]
    for step in run.get("steps") or []:
        if "invocation_id" in step:
            names.append(step["invocation_id"])
        if _is_obj(step.get("tool")) and "name" in step["tool"]:
            names.append(step["tool"]["name"])
    if any(not (_is_str(n) and 0 < len(str(n)) <= 128) for n in names):
        out.add(R[20])


def _rows_usage(usage: Any, out: set[str]) -> None:
    if not _is_obj(usage):
        return
    counters = {k: v for k, v in usage.items() if k != "cache_writes"}
    if any(not _is_int(v) or v < 0 for v in counters.values()):
        out.add(R[9])
        return
    read = counters.get("cache_read_tokens", 0)
    write = counters.get("cache_write_tokens", 0)
    if "input_tokens" in counters:
        if read > counters["input_tokens"]:
            out.add(R[10])
        elif read + write > counters["input_tokens"]:
            out.add(R[11])
    reasoning = counters.get("reasoning_tokens", 0)
    if "output_tokens" in counters and reasoning > counters["output_tokens"]:
        out.add(R[22])
    writes: list[dict[str, Any]] = usage.get("cache_writes", [])
    if "cache_writes" not in usage:
        return
    lifetimes = [w.get("lifetime") for w in writes]
    if len(set(lifetimes)) != len(lifetimes):
        out.add(R[13])
    # A tokens member that is not a non-negative integer is not a count, so the
    # sum the sentence equates with cache_write_tokens does not exist.
    tokens: list[Any] = [w.get("tokens") for w in writes]
    if not all(_is_int(t) and t >= 0 for t in tokens) or sum(tokens) != write:
        out.add(R[14])


def _rows_steps(run: dict[str, Any], out: set[str]) -> None:
    steps = run.get("steps") or []
    indexes = [s["index"] for s in steps]
    starts = [s.get("start") for s in steps]
    pairs = list(zip(starts, starts[1:], strict=False))
    ordered = all(_is_str(a) and _is_str(b) and a <= b for a, b in pairs)
    if len(set(indexes)) != len(indexes) or indexes != sorted(indexes) or not ordered:
        out.add(R[6])
    invocations: list[str] = []
    for step in steps:
        kind = step["kind"]
        if kind == "model_invocation":
            if not (_is_obj(step.get("usage")) and _is_obj(step.get("model"))):
                out.add(R[7])
            if _is_str(step.get("invocation_id")):
                invocations.append(step["invocation_id"])
        elif kind == "tool_call" and (not _is_obj(step.get("tool")) or "usage" in step):
            out.add(R[8])
        _rows_usage(step.get("usage"), out)
    if len(set(invocations)) != len(invocations):
        out.add(R[15])


def _rows_totals(run: dict[str, Any], out: set[str]) -> None:
    totals = run["totals"]
    _rows_usage(totals, out)
    steps = run.get("steps")
    if not isinstance(steps, list) or not _is_obj(totals) or run["step_count"] != len(steps):
        return
    usages = [s["usage"] for s in steps if _is_obj(s.get("usage"))]
    if any(not _is_int(v) for u in usages for k, v in u.items() if k != "cache_writes"):
        return
    members = {k for u in usages for k in u if k != "cache_writes"} | {
        k for k in totals if k != "cache_writes"
    }
    for member in members:
        expected = sum(u.get(member, 0) for u in usages)
        if totals.get(member) != expected:
            out.add(R[12])
            return


def rejections(document: dict[str, Any]) -> list[str]:
    """The requirement identifiers this Run object is rejected under, sorted."""
    out: set[str] = set()
    _rows_run_status(document, out)
    _rows_run_members(document, out)
    _rows_timestamps_and_identifiers(document, out)
    _rows_steps(document, out)
    _rows_totals(document, out)
    return sorted(out)
