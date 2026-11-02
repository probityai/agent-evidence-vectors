"""Turn a generic agent run log into a W3C Agent Conformance v0.1 report.

One command: read the log, write the report, then hand it to the package's
reference reader and print its verdict. A log line that cannot be mapped to
the v0.1 record is refused with its line number; nothing is guessed.

    python from_log.py run.jsonl -o report.json

The mapping is in README.md. The only code outside the standard library is
the package's own ``w3creport`` module, used for the check-set digest and for
the reader, so the digest and the verdict are the reference ones.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from agent_evidence_vectors import w3creport
except ImportError:  # pragma: no cover - the message is the behaviour
    sys.exit("needs agent-evidence-vectors>=0.31.1 (run it with `uv run --no-project --with ...`)")

# Outcome in the log -> v0.1 state. ``error`` and ``timeout`` are harness words
# for a check that started and reached no conclusion, which is v0.1 inconclusive.
STATE_OF = {
    "pass": "pass",
    "fail": "fail",
    "inconclusive": "inconclusive",
    "error": "inconclusive",
    "timeout": "inconclusive",
    "skipped": "not-exercised",
    "not-exercised": "not-exercised",
    "void": "void",
}
# The causes v0.1 section 1.2 admits under each non-verdict state. A reason
# outside the set is refused: free text is not a cause.
CAUSES_FOR = {
    "inconclusive": (
        "failed", "unavailable", "resource_exhausted", "unsupported_input", "availability-failure",
    ),
    "not-exercised": (
        "not_applicable", "disabled_by_policy", "unsupported_input", "out_of_scope",
        "withheld", "unavailable", "precondition-unsatisfiable",
    ),
    "void": ("evidence-does-not-hold", "integrity-failure", "confinement-failed-during-check"),
}
# The only outcomes that carry a stated default: a timeout is resource
# exhaustion, and a void is evidence that does not hold.
DEFAULT_REASON = {"timeout": "resource_exhausted", "void": "evidence-does-not-hold"}
CONTROL_OUTCOMES = ("pass", "fail", "inconclusive", "error", "timeout", "skipped", "void")
LINE_KEYS = {"check", "outcome", "reason", "detail", "control"}
RUN_KEYS = {"checker", "constraint_set", "domain"}

CROSSWALK = {
    "pass/fail": "outcome pass or fail; no cause",
    "inconclusive": "outcome inconclusive, error or timeout; the reason is the cause",
    "not-exercised": "outcome skipped; the reason is the cause",
    "void": "outcome void; cause evidence-does-not-hold unless the reason names another",
    "negative-capable": "control-failed when a control run under the same checker failed, "
    "else shown-by-run when a declared check failed, else nothing",
}

Rows = list[tuple[str, dict[str, Any]]]


class Refused(Exception):
    """A log (or one line of it) that cannot be mapped to the v0.1 record."""


def _text(value: Any, where: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Refused(f"{where}: {field} must be a non-empty string")
    return value


def read_header(obj: Any, where: str) -> dict[str, str]:
    if not isinstance(obj, dict) or set(obj) != {"run"} or not isinstance(obj["run"], dict):
        raise Refused(f'{where}: the first line must be {{"run": {{...}}}}')
    run = obj["run"]
    extra = set(run) - RUN_KEYS
    if extra:
        raise Refused(f"{where}: unknown run key {sorted(extra)}")
    return {
        "checker": _text(run.get("checker"), where, "run.checker"),
        "constraint_set": _text(run.get("constraint_set"), where, "run.constraint_set"),
        "domain": _text(run.get("domain", "the checks of this run"), where, "run.domain"),
    }


def read_jsonl(text: str) -> tuple[dict[str, str], Rows]:
    lines = [(n, raw) for n, raw in enumerate(text.splitlines(), 1) if raw.strip()]
    if not lines:
        raise Refused("the log is empty")
    objects = []
    for n, raw in lines:
        try:
            objects.append((f"line {n}", json.loads(raw)))
        except ValueError as exc:
            raise Refused(f"line {n}: not JSON ({exc})") from None
    return read_header(objects[0][1], objects[0][0]), objects[1:]


def _inspect_names(sample: dict[str, Any], doc: dict[str, Any]) -> list[str]:
    scores = sample.get("scores")
    if isinstance(scores, dict) and scores:
        return list(scores)
    named = [s.get("name") for s in doc["eval"].get("scorers") or [] if isinstance(s, dict)]
    return [n for n in named if isinstance(n, str)]


def _inspect_value(value: Any) -> str | None:
    if isinstance(value, bool):
        return "pass" if value else "fail"
    if value in ("C", 1, 1.0):
        return "pass"
    if value in ("I", 0, 0.0):
        return "fail"
    return None


def _inspect_row(sample: dict[str, Any], name: str, where: str) -> dict[str, Any]:
    row: dict[str, Any] = {"check": f"{sample.get('id')}:{sample.get('epoch', 1)}:{name}"}
    error, limit = sample.get("error"), sample.get("limit")
    score = (sample.get("scores") or {}).get(name)
    if error:
        message = str(error.get("message", "")) if isinstance(error, dict) else str(error)
        row.update(outcome="error", reason="failed", detail=message.splitlines()[0] if message else "error")
    elif limit and not score:
        kind = limit.get("type") if isinstance(limit, dict) else limit
        row.update(outcome="timeout", detail=f"sample limit: {kind}")
    else:
        outcome = _inspect_value(score.get("value") if isinstance(score, dict) else None)
        if outcome is None:
            raise Refused(f"{where}: scorer {name!r} value {score!r} is neither correct nor incorrect")
        row["outcome"] = outcome
    return row


def read_inspect(doc: dict[str, Any]) -> tuple[dict[str, str], Rows]:
    meta = doc["eval"]
    task = _text(meta.get("task"), "eval", "task")
    config = {"task_args": meta.get("task_args"), "scorers": meta.get("scorers")}
    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    dataset = meta.get("dataset") if isinstance(meta.get("dataset"), dict) else {}
    header = {
        "checker": f"inspect:{task}@{meta.get('task_version', 0)}",
        "constraint_set": f"sha256:{digest}",
        "domain": f"samples of {dataset.get('name') or task}",
    }
    rows: Rows = []
    for index, sample in enumerate(doc.get("samples") or []):
        where = f"samples[{index}]"
        names = _inspect_names(sample, doc)
        if not names:
            raise Refused(f"{where}: no scorer name to build a check identity from")
        rows.extend((where, _inspect_row(sample, name, where)) for name in names)
    return header, rows


def read_log(text: str) -> tuple[dict[str, str], Rows]:
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None  # several lines: a JSONL log
    if isinstance(doc, dict) and isinstance(doc.get("eval"), dict) and "samples" in doc:
        return read_inspect(doc)
    return read_jsonl(text)


def record_of(where: str, row: dict[str, Any]) -> dict[str, Any]:
    """The v0.1 per-check record for one line, or a refusal naming the line."""
    if not isinstance(row, dict):
        raise Refused(f"{where}: a check line must be a JSON object")
    if set(row) - LINE_KEYS:
        raise Refused(f"{where}: unknown field {sorted(set(row) - LINE_KEYS)}")
    outcome = row.get("outcome")
    if outcome not in STATE_OF:
        raise Refused(f"{where}: outcome {outcome!r} is not one of {sorted(STATE_OF)}")
    state = STATE_OF[outcome]
    record: dict[str, Any] = {"check": _text(row.get("check"), where, "check"), "state": state}
    if state in w3creport.VERDICT_STATES:
        if "reason" in row or "detail" in row:
            raise Refused(f"{where}: {outcome} is a verdict and carries no reason (row 7)")
        return record
    reason = row.get("reason", DEFAULT_REASON.get(outcome))
    if reason not in CAUSES_FOR[state]:
        raise Refused(f"{where}: {outcome} needs a reason from {list(CAUSES_FOR[state])}, got {reason!r}")
    record["cause"] = {"code": reason}
    if row.get("detail"):
        record["cause"]["detail"] = _text(row["detail"], where, "detail")
    return record


def control_of(where: str, row: dict[str, Any]) -> str | None:
    control = row.get("control")
    if control is not None and control not in CONTROL_OUTCOMES:
        raise Refused(f"{where}: control {control!r} is not one of {list(CONTROL_OUTCOMES)}")
    return control


def negative_capable(
    checks: list[dict[str, Any]], failed_controls: list[str], fixed: dict[str, str]
) -> dict[str, Any]:
    """Section 5.4: say what the producer has that shows the checks can fail."""
    if failed_controls:
        control = {"checks": failed_controls, "state": "fail", "fixed": dict(fixed)}
        return {"kind": "control-failed", "control": control}
    if any(c["state"] == "fail" for c in checks):
        return {"kind": "shown-by-run"}
    return {"kind": "nothing"}


def records_of(rows: Rows) -> tuple[list[dict[str, Any]], list[str]]:
    """Every record, and the ids of the checks whose control run failed."""
    refusals: list[str] = []
    checks: list[dict[str, Any]] = []
    failed_controls: list[str] = []
    for where, row in rows:
        try:
            checks.append(record_of(where, row))
            if control_of(where, row) == "fail":
                failed_controls.append(checks[-1]["check"])
        except Refused as exc:
            refusals.append(str(exc))
    ids = [c["check"] for c in checks]
    refusals += [f"two lines carry the check {i!r}" for i in sorted(set(ids)) if ids.count(i) > 1]
    if not checks and not refusals:
        refusals.append("the log declares no checks")
    if refusals:
        raise Refused("\n".join(refusals))
    return checks, failed_controls


def build(header: dict[str, str], rows: Rows, source: dict[str, str]) -> dict[str, Any]:
    checks, failed_controls = records_of(rows)
    fixed = {"checker": header["checker"], "constraint-set": header["constraint_set"]}
    counts = {"declared": len(checks), "exercised": sum(c["state"] != "not-exercised" for c in checks)}
    counts.update({s: sum(c["state"] == s for c in checks) for s in w3creport.STATES})
    rollup: dict[str, Any] = dict(counts, carried=0, referenced=0)
    rollup["negative-capable"] = negative_capable(checks, failed_controls, fixed)
    return {
        "format": w3creport.FORMAT,
        "source": source,
        "crosswalk": CROSSWALK,
        "domain": {"id": "d-run", "description": header["domain"]},
        "fixed": fixed,
        "checks": checks,
        "evidence": [],
        "roll-up": rollup,
        "check-set": {
            "sha256": w3creport.check_set_root(checks, "flat"),
            "leaf-count": len(checks),
            "tree-shape": "flat",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run log -> v0.1 report, then the reference reader")
    parser.add_argument("log", help="a JSONL run log, or an Inspect eval log converted to JSON")
    parser.add_argument("-o", "--out", required=True, help="where to write the v0.1 report")
    args = parser.parse_args(argv)
    raw = Path(args.log).read_bytes()
    source = {
        "producer": "second-producer/from_log.py",
        "log": Path(args.log).name,
        "log-sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        header, rows = read_log(raw.decode("utf-8"))
        report = build(header, rows, source)
    except (Refused, UnicodeDecodeError) as exc:
        print(f"refused, no report written:\n{exc}", file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)
    return w3creport.read(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
