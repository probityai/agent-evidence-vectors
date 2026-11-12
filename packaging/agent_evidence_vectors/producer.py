"""Producer mode: check the records a project emits, not a verifier it ships.

The corpus modes of this package test a READER: every member is a record the
reader must accept or reject under the right row. A project that only WRITES
records (an emitter, an exporter, a harness that saves a run record) has no
reader to hand over, so those modes have nothing to run. This module checks
the producer's output instead:

1. Each record the producer wrote is read by the pinned reader for its record
   class, the same reader the corpus judge holds to the published vectors. For
   a v0.1 per-check report that is the reading table and the rejection rows in
   ``w3creport``; for a run record it is the interoperability-evidence
   criterion in ``corpora/vectors-mcp-record-contract/check_run_record.py``.
2. When the producer pins its output, each record is held to those pins:
   SHA-256 and size of the file, and for a v0.1 report the check count and the
   declared check-set root. A pinned record that was not produced, and a
   produced record that was not pinned, are mismatches, never skips.
3. A receipt is written that names every record with its digest and verdict,
   and carries ``reference.verifier.id``: the identifier of the reader that
   judged, inside the bytes the producer's pipeline uploads.

Exit 0 when at least one record was read, every record conforms and every pin
holds; 1 when any record does not conform or any pin does not hold; 2 when
there is no verdict (no record matched, a class this module has no reader for,
a file that cannot be read, a pins file that cannot be read, a reader crash).
A run that checked nothing is never a pass.

Stdlib only, like ``w3creport``: a relying party runs it with nothing else
installed.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_evidence_vectors import w3creport  # noqa: E402

RECEIPT_FORMAT = "agent-evidence-vectors/producer-receipt/v1"
PASS, FAIL, NO_VERDICT = 0, 1, 2
CONFORMS, DOES_NOT_CONFORM, NO_VERDICT_STATE = "conforms", "does-not-conform", "no-verdict"

#: A reader takes the record's raw bytes and returns its finding lines; an
#: empty list is a conforming record. It raises on bytes it cannot read.
Reader = Callable[[bytes], list[str]]

RUN_RECORD_CHECKER = ("corpora", "vectors-mcp-record-contract", "check_run_record.py")


def package_version() -> str:
    """The installed version of this package, or ``unreleased`` from a checkout."""
    try:
        return metadata.version("agent-evidence-vectors")
    except metadata.PackageNotFoundError:
        return "unreleased"


def reader_id(record_class: str, version: str | None = None) -> str:
    """The identifier of the reader that judges ``record_class`` at a release.

    A package URL, so it names the exact release on PyPI without a page that
    has to stay up: ``pkg:pypi/agent-evidence-vectors@0.37.0#reader/w3c-report``.
    """
    return f"pkg:pypi/agent-evidence-vectors@{version or package_version()}#reader/{record_class}"


def _subject_reader(subject_type: str) -> Reader:
    def read(raw: bytes) -> list[str]:
        subject = w3creport.load_json(raw)
        shape = w3creport.subject_shape_errors(subject_type, subject)
        if shape:
            return [f"shape: {error}" for error in shape]
        if subject_type == "report":
            lines = w3creport.verdict_lines(subject)
            return [] if lines == ["conforms"] else lines
        return list(w3creport.subject_rejections(subject_type, subject))

    return read


def _checker_path() -> Path:
    """Where the run-record checker sits: in the wheel, or in a checkout."""
    here = Path(__file__).resolve().parent
    for root in (here, here.parent.parent):
        candidate = root.joinpath(*RUN_RECORD_CHECKER)
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("the run-record checker is not in this installation")


def _load_checker() -> ModuleType:
    path = _checker_path()
    spec = importlib.util.spec_from_file_location("aev_check_run_record", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_record(raw: bytes) -> list[str]:
    record = json.loads(raw)
    if not isinstance(record, dict):
        return ["shape: a run record is a JSON object"]
    verdict = _load_checker().check_record(record)
    lines = [f"missing: {line}" for line in verdict["missing"]]
    if not verdict["figureMeansWhatItSays"]:
        lines.append("figure: the headline figure disagrees with its own counting rule")
    if verdict["independence"] == "undeclared":
        lines.append("independence: undeclared")
    return lines


READERS: dict[str, Reader] = {
    "w3c-report": _subject_reader("report"),
    "agent-run-metrics": _subject_reader("agent-run-metrics"),
    "llm-context-discovery": _subject_reader("llm-context-discovery"),
    "run-record": _run_record,
}
RECORD_CLASSES = tuple(READERS)


def expand(patterns: list[str]) -> list[str]:
    """Every file the patterns match, sorted and once each. Patterns may be
    newline-separated, as a workflow input carries them."""
    found: set[str] = set()
    for chunk in patterns:
        for pattern in (p.strip() for p in chunk.splitlines()):
            if pattern:
                found.update(p for p in glob.glob(pattern, recursive=True) if os.path.isfile(p))
    return sorted(found)


def _declared(record_class: str, raw: bytes) -> dict[str, Any]:
    """The pinnable facts a record states about itself, beyond its bytes."""
    if record_class != "w3c-report":
        return {}
    try:
        report = w3creport.load_json(raw)
        binding = report.get("check-set") if isinstance(report, dict) else None
        out: dict[str, Any] = {}
        if isinstance(report, dict) and isinstance(report.get("checks"), list):
            out["count"] = len(report["checks"])
        rollup = report.get("roll-up") if isinstance(report, dict) else None
        if isinstance(rollup, dict) and "declared" in rollup:
            out["declared"] = rollup["declared"]
        if isinstance(binding, dict) and "sha256" in binding:
            out["checkSetRoot"] = binding["sha256"]
        return out
    except (ValueError, RecursionError):
        return {}


def pin_mismatches(observed: dict[str, Any], pin: dict[str, Any]) -> list[str]:
    """Each pinned field the record does not match, in words."""
    out = []
    for key in PIN_KEYS:
        if key in pin and observed.get(key) != pin[key]:
            out.append(f"{key}: produced {observed.get(key)!r}, pinned {pin[key]!r}")
    return out


def judge_record(record_class: str, path: str, pin: dict[str, Any] | None) -> dict[str, Any]:
    """One record's entry in the receipt."""
    entry: dict[str, Any] = {"path": path}
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        entry.update(verdict=NO_VERDICT_STATE, findings=[f"cannot be read: {exc}"])
        return entry
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
    entry["size"] = len(raw)
    entry.update(_declared(record_class, raw))
    try:
        findings = READERS[record_class](raw)
        entry["verdict"] = CONFORMS if not findings else DOES_NOT_CONFORM
    except Exception as exc:  # noqa: BLE001 - a crash is no verdict, never a rejection
        findings = [f"the reader failed: {exc!r}"]
        entry["verdict"] = NO_VERDICT_STATE
    entry["findings"] = findings
    if pin is not None:
        entry["pinMismatches"] = pin_mismatches(entry, pin)
    return entry


PIN_KEYS = ("sha256", "size", "count", "declared", "checkSetRoot")
# A producer that already keeps one expected-digests file (an EXPECTED.json) can
# hand it over as it is: its keys map onto the pins, and it pins the one record.
EXPECTED_KEYS = {
    "report-sha256": "sha256",
    "report-bytes": "size",
    "declared": "declared",
    "check-set-sha256": "checkSetRoot",
}
SINGLE = "*"


def load_pins(path: str) -> dict[str, dict[str, Any]]:
    """The pins file, in either of two shapes.

    ``{"records": {"<path>": {"sha256", "size", "count", "declared", "checkSetRoot"}}}``
    pins each record by path. A flat object of the producer's own expected
    digests (``report-sha256``, ``report-bytes``, ``declared``,
    ``check-set-sha256``) pins the one record the producer emits.
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(document, dict) and "records" not in document:
        flat = {EXPECTED_KEYS[k]: v for k, v in document.items() if k in EXPECTED_KEYS}
        if flat:
            return {SINGLE: flat}
    records = document.get("records") if isinstance(document, dict) else None
    if not isinstance(records, dict) or not all(isinstance(v, dict) for v in records.values()):
        raise ValueError(
            "a pins file is an object whose `records` maps each path to its pins, "
            "or a flat object of expected digests (report-sha256, report-bytes, "
            "declared, check-set-sha256)"
        )
    return {os.path.normpath(k): v for k, v in records.items()}


def bind_single(pins: dict[str, dict[str, Any]] | None, paths: list[str]) -> dict[str, dict[str, Any]] | None:
    """Give a flat pin the path of the one record that was produced."""
    if pins is None or SINGLE not in pins:
        return pins
    if len(paths) == 1:
        return {os.path.normpath(paths[0]): pins[SINGLE]}
    return {f"{SINGLE} (one record expected, {len(paths)} produced)": pins[SINGLE]}


def build_receipt(
    record_class: str,
    paths: list[str],
    pins: dict[str, dict[str, Any]] | None,
    producer: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The receipt over every produced record, with its result."""
    pins = bind_single(pins, paths)
    records = [
        judge_record(record_class, p, None if pins is None else pins.get(os.path.normpath(p), {}))
        for p in paths
    ]
    unproduced = sorted(set(pins or {}) - {os.path.normpath(p) for p in paths})
    if pins is not None:
        for entry in records:
            if os.path.normpath(entry["path"]) not in pins:
                entry["pinMismatches"] = ["produced but not pinned"]
    counts = {state: 0 for state in (CONFORMS, DOES_NOT_CONFORM, NO_VERDICT_STATE)}
    for entry in records:
        counts[entry["verdict"]] += 1
    mismatched = sum(1 for e in records if e.get("pinMismatches")) + len(unproduced)
    if not records or counts[NO_VERDICT_STATE]:
        result, status = "no-verdict", NO_VERDICT
    elif counts[DOES_NOT_CONFORM] or mismatched:
        result, status = "fail", FAIL
    else:
        result, status = "pass", PASS
    version = package_version()
    receipt: dict[str, Any] = {
        "format": RECEIPT_FORMAT,
        "recordClass": record_class,
        "records": records,
        "unproduced": unproduced,
        "totals": {
            "records": len(records),
            "conforms": counts[CONFORMS],
            "doesNotConform": counts[DOES_NOT_CONFORM],
            "noVerdict": counts[NO_VERDICT_STATE],
            "pinMismatches": mismatched,
            "pinned": pins is not None,
        },
        "reference": {"verifier": {"id": reader_id(record_class, version), "version": version}},
        "result": result,
        "status": status,
    }
    if producer:
        receipt["producer"] = producer
    return receipt


def summary_markdown(receipt: dict[str, Any], limit: int = 20) -> str:
    """The job summary for a receipt."""
    totals = receipt["totals"]
    lines = [
        f"## agent-evidence-vectors producer mode: {receipt['result']}\n\n",
        f"Record class `{receipt['recordClass']}`; reader "
        f"`{receipt['reference']['verifier']['id']}`.\n\n",
        f"{totals['conforms']} of {totals['records']} records conform; "
        f"{totals['doesNotConform']} do not; {totals['noVerdict']} had no verdict; "
        f"{totals['pinMismatches']} pin mismatches"
        f"{'' if totals['pinned'] else ' (no pins file was given)'}.\n\n",
    ]
    bad = [e for e in receipt["records"] if e["verdict"] != CONFORMS or e.get("pinMismatches")]
    if bad or receipt["unproduced"]:
        lines.append("| record | verdict | first finding |\n| --- | --- | --- |\n")
        for entry in bad[:limit]:
            first = (entry["findings"] or entry.get("pinMismatches") or [""])[0]
            lines.append(f"| `{entry['path']}` | {entry['verdict']} | {first[:200]} |\n")
        for path in receipt["unproduced"][:limit]:
            lines.append(f"| `{path}` | not produced | pinned but missing |\n")
    return "".join(lines)


def write_github(receipt: dict[str, Any], receipt_path: str) -> None:
    """Append the step outputs and the job summary, when GitHub provides them."""
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        totals = receipt["totals"]
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(
                f"receipt={receipt_path}\nresult={receipt['result']}\n"
                f"records={totals['records']}\nconform={totals['conforms']}\n"
                f"reference-verifier-id={receipt['reference']['verifier']['id']}\n"
            )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(summary_markdown(receipt))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-evidence-vectors-produced",
        description="check the records a producer emitted against the pinned reader",
    )
    parser.add_argument("record_class", help=f"one of {', '.join(RECORD_CLASSES)}")
    parser.add_argument("records", nargs="+", help="paths or globs of the emitted records")
    parser.add_argument("--pins", default=None, help="JSON file pinning each record's digests")
    parser.add_argument("--receipt", default="agent-evidence-vectors-receipt.json")
    parser.add_argument("--producer-command", default=None)
    parser.add_argument("--producer-commit", default=None)
    parser.add_argument("--github", action="store_true", help="write step outputs and summary")
    args = parser.parse_args(argv)
    if args.record_class not in READERS:
        print(
            f"no verdict: no reader for record class {args.record_class!r}; "
            f"the classes are {', '.join(RECORD_CLASSES)}",
            file=sys.stderr,
        )
        return NO_VERDICT
    pins = None
    if args.pins:
        try:
            pins = load_pins(args.pins)
        except (OSError, ValueError) as exc:
            print(f"no verdict: the pins file {args.pins} cannot be read: {exc}", file=sys.stderr)
            return NO_VERDICT
    producer = {
        k: v for k, v in (("command", args.producer_command), ("commit", args.producer_commit)) if v
    }
    paths = expand(args.records)
    if not paths:
        print(f"no verdict: no file matched {args.records}", file=sys.stderr)
    receipt = build_receipt(args.record_class, paths, pins, producer or None)
    Path(args.receipt).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    for entry in receipt["records"]:
        print(f"{entry['path']}: {entry['verdict']}")
        for line in entry["findings"] + entry.get("pinMismatches", []):
            print(f"  {line}")
    for path in receipt["unproduced"]:
        print(f"{path}: pinned but not produced")
    print(f"result {receipt['result']}")
    print(f"reference.verifier.id {receipt['reference']['verifier']['id']}")
    if args.github:
        write_github(receipt, args.receipt)
    return int(receipt["status"])


if __name__ == "__main__":
    raise SystemExit(main())
