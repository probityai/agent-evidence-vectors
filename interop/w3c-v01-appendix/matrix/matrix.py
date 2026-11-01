#!/usr/bin/env python3
"""Reader conformance matrix for the v0.1 paper's reports, with negative controls.

    python matrix.py run --work DIR --observed observed.json
    python matrix.py check observed.json        # exit 1 when a cell or input differs from matrix.json
    python matrix.py adopt observed.json        # write matrix.json from a run
    python matrix.py render                     # matrix.json -> matrix.md and verification.tex

``run`` reruns the appendix rows that write a v0.1 report, by importing
``../rerun.py``, writes the single-field mutants of mutants.py beside them, and
puts every report and every mutant through every reader in READERS. Nothing a
reader prints is adjusted: a reader that accepts a mutant is recorded as
accepting it. Needs git, uv, Node (R3, R4), Go and a Rust toolchain.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
APPENDIX = HERE.parent
REPO = HERE.parents[2]
sys.path.insert(0, str(APPENDIX))
sys.path.insert(0, str(HERE))
import mutants as M  # noqa: E402
import rerun  # noqa: E402

MATRIX = HERE / "matrix.json"
MD = HERE / "matrix.md"
TEX = HERE / "verification.tex"
FORMAT = "public-agent-conformance/report/v0.1"

#: The appendix rows whose reruns write the reports, in the order they run.
PRODUCING = ["R1", "R2", "R3", "R3-v01", "R4", "R5"]
#: (report id, row, file under the rerun work directory). The rerun of 2026-11-01
#: wrote no other file declaring the v0.1 format under R1 to R5, R7 or R13.
REPORTS = [
    ("R1", "R1", "R1/out/report.json"),
    ("R2-v0.2", "R2", "R2/out/run-residue-v0.2.json"),
    ("R2-v0.3", "R2", "R2/out/run-residue-v0.3.json"),
    ("R2-v0.4", "R2", "R2/out/run-residue-v0.4.json"),
    ("R3-v01", "R3-v01", "R3-v01/out/run-report-v01.json"),
    ("R4-heldfast", "R4", "R4/out/reports/heldfast-profiles.json"),
    ("R4-native", "R4", "R4/out/reports/native-verify-mjs.json"),
    ("R4-map", "R4", "R4/out/reports/probity-map-reader.json"),
    ("R5", "R5", "R5/out/finality-threshold-report.level1.json"),
]
#: R5's report carries 150,006 checks: it gets the one control the paper names
#: for it, a flipped state under an unchanged root, rather than the full set.
ONLY = {"R5": ("state-flipped-root-kept",)}

#: The Python reference reader at the releases the results table names, and at
#: the newest release on PyPI when this matrix was made (read 2026-11-01).
PY_RELEASES = ["0.12.0", "0.13.0", "0.17.4", "0.18.1", "0.31.0"]
CURRENT_PYPI = "0.31.0"
#: The release whose --read-w3c-report flag the verify commands name. Until it
#: is published the commands carry this placeholder, and the LaTeX a macro.
READ_RELEASE = "{release}"

READERS: list[dict[str, Any]] = (
    [{"id": f"py-{v}", "label": f"Python {v}", "kind": "python", "version": v} for v in PY_RELEASES]
    + [{"id": "go-v0.18.1", "label": "Go v0.18.1", "kind": "go", "ref": "v0.18.1"},
       {"id": "go-main", "label": "Go main", "kind": "go", "ref": "main"},
       {"id": "rs-v0.18.1", "label": "Rust v0.18.1", "kind": "rust", "ref": "v0.18.1"},
       {"id": "rs-main", "label": "Rust main", "kind": "rust", "ref": "main"},
       {"id": "abbas-0039", "label": "0039 reader", "kind": "abbas"},
       {"id": "kroehl-6d8ee54b", "label": "Kroehl 6d8ee54b", "kind": "kroehl"}])

#: Every row of the results table: whether its rerun yields a v0.1 report, why
#: not when it does not, its unit, and the class of evidence it is.
ROW_META: dict[str, dict[str, Any]] = {
    "R1": {"yields": True, "unit": "checks", "class": "O8 reproduction",
           "why": "the 0.12.0 emitter writes one v0.1 report"},
    "R2": {"yields": True, "unit": "checks", "class": "O8 reproduction",
           "why": "three v0.1 reports; the control fixture records beside them are not reports"},
    "R3": {"yields": False, "unit": "checks", "class": "O8 reproduction",
           "why": "its records are the producer's own encoding; R3-v01 re-encodes them as a v0.1 report"},
    "R3-v01": {"yields": True, "unit": "checks", "class": "producer glue",
               "why": "the posted converter writes one v0.1 report from the R3 records"},
    "R4": {"yields": True, "unit": "checks", "class": "O8 reproduction",
           "why": "three v0.1 reports; the single-change controls are records, not reports"},
    "R4-driver": {"yields": False, "unit": "cases", "class": "producer glue",
                  "why": "this repository's driver writes a comparison report, not a v0.1 report"},
    "R5": {"yields": True, "unit": "checks", "class": "O8 reproduction",
           "why": "one v0.1 report"},
    "R6": {"yields": False, "unit": "tests", "class": "O8 reproduction",
           "why": "the commands print a check line and test results; no report file is written"},
    "R7": {"yields": False, "unit": "outcomes", "class": "O8 reproduction",
           "why": "a native (state, reason) packet, not a v0.1 report (footnote, no cell)"},
    "R8": {"yields": False, "unit": "members", "class": "text-only reader",
           "why": "a reader's verdicts over corpus members"},
    "R8-compare": {"yields": False, "unit": "members", "class": "comparison",
                   "why": "a comparison of R8's verdicts with the manifest"},
    "R9": {"yields": False, "unit": "members", "class": "comparison",
           "why": "selection counts over the corpus at three releases"},
    "R10": {"yields": False, "unit": "cases", "class": "comparison",
            "why": "the bytes two readers write for one value"},
    "R11": {"yields": False, "unit": "members", "class": "text-only reader",
            "why": "a reader's verdicts over corpus members"},
    "R12": {"yields": False, "unit": "members x paths", "class": "comparison",
            "why": "a scorer's per-member verdicts"},
    "R13": {"yields": False, "unit": "files checked", "class": "O8 reproduction",
            "why": "the experiment writes case files and results.json; none declares the v0.1 format"},
    "R14": {"yields": False, "unit": "verdicts", "class": "comparison",
            "why": "reader verdicts posted on the list; this matrix reruns them with commands"},
    "R15": {"yields": False, "unit": "artifacts", "class": "recorded, no command",
            "why": "a census file of artifact states"},
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def row_denominator(row: str) -> int | None:
    """The row's denominator from rows.json where it states one; report rows are measured."""
    expect = rerun.ROWS["rows"][row].get("expect", {})
    if row == "R6":
        return expect.get("tests")
    if row == "R7":
        return sum(expect.get("outcomes", {}).values())
    if row == "R8-compare":
        return expect.get("judged")
    if row in ("R9",):
        return sum(expect["v0.18.1"]["selected"].values())
    if row == "R13":
        return expect.get("files")
    if row == "R15":
        return expect.get("tally", {}).get("rows")
    return None


# --------------------------------------------------------------------------
# Inputs: rerun the producing rows, keep their reports, write the mutants.
# --------------------------------------------------------------------------

def jcs_leaf() -> Any:
    """The RFC 8785 form under the jcs-sha256 profile, from this repository's own reader."""
    sys.path.insert(0, str(REPO / "packaging"))
    from agent_evidence_vectors import w3creport  # noqa: PLC0415
    return w3creport.jcs_sha256


def build_inputs(work: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    statuses = {row: rerun.rerun(row, work, work / "results") for row in PRODUCING}
    inputs_dir = work / "inputs"
    if inputs_dir.exists():
        shutil.rmtree(inputs_dir)
    inputs_dir.mkdir(parents=True)
    jcs = jcs_leaf()
    entries: list[dict[str, Any]] = []
    for report_id, row, rel in REPORTS:
        source = work / rel
        base = {"report": report_id, "row": row, "source": rel.split("/")[-1]}
        if not source.is_file():
            entries.append({**base, "id": report_id, "mutant": None, "missing": True})
            continue
        data = source.read_bytes()
        target = inputs_dir / f"{report_id}.json"
        target.write_bytes(data)
        report = json.loads(data)
        entries.append({**base, "id": report_id, "mutant": None, "file": str(target),
                        "sha256": sha256(data), "checks": len(report.get("checks", [])),
                        "format": report.get("format")})
        made, skipped = M.mutants(report, jcs, ONLY.get(report_id))
        for m in made:
            body = json.dumps(m.pop("report"), indent=1, ensure_ascii=False).encode("utf-8") + b"\n"
            mid = f"{report_id}.{m['mutant']}"
            path = inputs_dir / f"{mid}.json"
            path.write_bytes(body)
            entries.append({**base, "id": mid, **m, "file": str(path), "sha256": sha256(body)})
        for s in skipped:
            entries.append({**base, "id": f"{report_id}.{s['mutant']}", "mutant": s["mutant"],
                            "target": s["target"], "table_row": M.table_row(s["target"]),
                            "not_applicable": s["why"]})
    return entries, statuses


# --------------------------------------------------------------------------
# Readers. Each returns {file: {"outcome", "cited", "note"}}.
# --------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None,
         stdout: Path | None = None, timeout: int = 3600) -> int:
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"\n$ (cd {cwd}) {' '.join(cmd)}\n")
        handle.flush()
        out = stdout.open("wb") if stdout else handle
        try:
            proc = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, stdout=out,
                                  stderr=handle, check=False, timeout=timeout)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = 124
        finally:
            if stdout:
                out.close()
        handle.write(f"[exit {code}]\n")
    return code


def _jsonl(path: Path) -> dict[str, dict[str, Any]]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            out[item["file"]] = {"outcome": item["outcome"], "cited": list(item.get("cited") or []),
                                 "note": item.get("note", "")}
    return out


def checkout(ref: str, work: Path, log: Path) -> tuple[Path, str]:
    """The repository at a release tag (fetched by its pinned commit), or the tree this file is in."""
    if ref == "main":
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                              text=True, check=False).stdout.strip()
        return REPO, head or "unknown"
    commit = rerun.ROWS["aev_tags"][ref]
    dest = work / f"aev-{ref}"
    if not (dest / ".git").is_dir():
        rerun.fetch_commit(rerun.ROWS["aev_repository"], commit, dest, log)
    return dest, commit


def read_python(reader: dict[str, Any], files: Path, work: Path, log: Path) -> dict[str, Any]:
    out = work / f"{reader['id']}.jsonl"
    code = _run(["uv", "run", "-q", "--no-project", "--python", "3.13", "--with",
                 f"agent-evidence-vectors=={reader['version']}", "python", "-I",
                 str(HERE / "drivers" / "py_reader.py"), str(files), str(out)], work, log)
    reader["exit"] = code
    return _jsonl(out) if out.is_file() else {}


def read_go(reader: dict[str, Any], files: Path, work: Path, log: Path) -> dict[str, Any]:
    root, commit = checkout(reader["ref"], work, log)
    reader["commit"] = commit
    driver = root / "corpora" / "w3c_matrix_driver_test.go"
    driver.write_bytes((HERE / "drivers" / "w3c_matrix_driver_test.go.txt").read_bytes())
    out = work / f"{reader['id']}.jsonl"
    try:
        code = _run(["go", "test", "./corpora", "-run", "^TestW3CMatrixDriver$", "-count=1"], root, log,
                    env={"W3C_MATRIX_LIST": str(files), "W3C_MATRIX_OUT": str(out)})
    finally:
        driver.unlink()
    reader["exit"] = code
    return _jsonl(out) if out.is_file() else {}


ROWS_LINE = re.compile(r"^(ok  |FAIL) rows: (.*)$", re.M)


def rust_line(text: str, code: int) -> dict[str, Any]:
    """The Rust reader's rows line, read as the matrix's outcome."""
    verdict = next((x for x in text.splitlines() if x.startswith("verdict:")), "")
    found = ROWS_LINE.search(text)
    if code == 2 or "not readable JSON" in text or found is None:
        return {"outcome": "cannot-read", "cited": [], "note": text.strip().splitlines()[-1][:300] if text.strip() else f"exit {code}"}
    status, rest = found.groups()
    if status.startswith("ok"):
        return {"outcome": "conforms", "cited": [], "note": verdict}
    if rest.startswith("not a v0.1 report"):
        return {"outcome": "rejected", "cited": ["shape"], "note": rest[:300]}
    inside = re.search(r"rejected under \[([^\]]*)\]", rest)
    cited = [x.strip() for x in inside.group(1).split(",") if x.strip()] if inside else []
    return {"outcome": "rejected", "cited": sorted(cited), "note": rest[:300]}


def read_rust(reader: dict[str, Any], files: Path, work: Path, log: Path) -> dict[str, Any]:
    root, commit = checkout(reader["ref"], work, log)
    reader["commit"] = commit
    target = work / f"target-{reader['id']}"
    manifest = root / "readers" / "w3c-report-rs" / "Cargo.toml"
    code = _run(["cargo", "build", "--locked", "--release", "--manifest-path", str(manifest),
                 "--target-dir", str(target)], root, log)
    binary = target / "release" / ("w3c-report-rs.exe" if os.name == "nt" else "w3c-report-rs")
    reader["exit"] = code
    if code != 0 or not binary.is_file():
        return {}
    out: dict[str, Any] = {}
    for path in files.read_text(encoding="utf-8").split():
        proc = subprocess.run([str(binary), "--report", path], capture_output=True, text=True,
                              check=False, timeout=600)
        out[path] = rust_line(proc.stdout + proc.stderr, proc.returncode)
    return out


def members(files: Path, work: Path, name: str) -> tuple[Path, dict[str, str]]:
    """The adapter both spec-text readers need: each report wrapped as a corpus member.

    The member carries the two fields those readers take from a member, its id
    (the matrix input id) and the report as its subject. It carries no
    ``resolves`` store, so a referenced observation reads as unresolved.
    """
    folder = work / f"members-{name}"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir()
    ids = {}
    for path in files.read_text(encoding="utf-8").split():
        member_id = Path(path).stem
        ids[member_id] = path
        try:
            subject: Any = json.loads(Path(path).read_bytes())
        except ValueError:
            continue
        (folder / f"{member_id}.json").write_text(
            json.dumps({"id": member_id, "subject": subject}, ensure_ascii=False), encoding="utf-8")
    return folder, ids


def read_abbas(reader: dict[str, Any], files: Path, work: Path, log: Path) -> dict[str, Any]:
    pins = rerun.ROWS["rows"]["R8"]["pins"]
    data = rerun.attachment(pins["reader"], work / "_attachments")
    reader["tarball_sha256"] = sha256(data)
    unpacked = work / "abbas"
    if unpacked.exists():
        shutil.rmtree(unpacked)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(unpacked, filter="data")
    base = unpacked / "v01-reader-run1"
    folder, ids = members(files, work, "abbas")
    py = rerun.venv(work, "abbas", pins["python"], [], log)
    out = work / "abbas-out"
    code = _run([str(py), "-B", "reader/v01reader.py", str(folder), str(out)], base, log,
                env={"PYTHONHASHSEED": "0"})
    reader["exit"] = code
    result: dict[str, Any] = {}
    if (out / "verdicts.tsv").is_file():
        for line in (out / "verdicts.tsv").read_text(encoding="utf-8").splitlines():
            member_id, verdict, rows, flags = (line.split("\t") + ["", "", ""])[:4]
            cited = [] if rows in ("-", "") else [f"row {x}" if x.isdigit() else x for x in rows.split(",")]
            outcome = {"accept": "conforms", "reject": "rejected", "cannot-tell": "cannot-tell"}.get(verdict, verdict)
            result[ids.get(member_id, member_id)] = {"outcome": outcome, "cited": cited, "note": flags[:300]}
    if (out / "not-selected.tsv").is_file():
        for line in (out / "not-selected.tsv").read_text(encoding="utf-8").splitlines():
            member_id = line.split("\t")[0]
            result[ids.get(member_id, member_id)] = {"outcome": "cannot-read", "cited": [],
                                                     "note": "not selected: the subject has no checks list"}
    return result


GROUND = re.compile(r"^(row \d+|line \d+)")


def read_kroehl(reader: dict[str, Any], files: Path, work: Path, log: Path) -> dict[str, Any]:
    pins = rerun.ROWS["rows"]["R11"]["pins"]
    src = work / "kroehl"
    if not (src / ".git").is_dir():
        rerun.fetch_commit(pins["repository"], pins["commit"], src, log)
    reader["commit"] = pins["commit"]
    folder, ids = members(files, work, "kroehl")
    py = rerun.venv(work, "kroehl", pins["python"], [], log)
    out = work / "kroehl.jsonl"
    code = _run([str(py), "-I", "reader.py", str(folder)], src, log, env={"PYTHONHASHSEED": "0"},
                stdout=out)
    reader["exit"] = code
    result: dict[str, Any] = {}
    if out.is_file():
        for line in out.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            outcome = {"accept": "conforms", "reject": "rejected", "cannot-tell": "cannot-tell"}[item["verdict"]]
            cited = sorted({m.group(1) for g in item.get("grounds", []) if (m := GROUND.match(g))})
            note = item.get("ground", "") if outcome != "cannot-tell" else ", ".join(item.get("open", []))
            result[ids.get(item["id"], item["id"])] = {"outcome": outcome, "cited": cited, "note": note[:300]}
    return result


KINDS = {"python": read_python, "go": read_go, "rust": read_rust, "abbas": read_abbas,
         "kroehl": read_kroehl}


# --------------------------------------------------------------------------
# Scoring the controls.
# --------------------------------------------------------------------------

def target_cited(reader: dict[str, Any], entry: dict[str, Any], cell: dict[str, Any]) -> bool | None:
    """Whether the reader named the row the mutant aims at; None where its labels do not say."""
    target = entry["target"]
    cited = cell["cited"]
    if reader["kind"] in ("python", "go", "rust"):
        return target in cited
    if target == M.SHAPE:
        return None
    if entry.get("table_row") is None:
        return None
    return f"row {entry['table_row']}" in cited


def controls(readers: list[dict[str, Any]], inputs: list[dict[str, Any]],
             cells: dict[str, dict[str, Any]]) -> dict[str, Any]:
    table: dict[str, Any] = {}
    negative = [e for e in inputs if e.get("mutant") and "file" in e and e["target"] != M.POSITIVE]
    positive = [e for e in inputs if e.get("mutant") and "file" in e and e["target"] == M.POSITIVE]
    for reader in readers:
        counts = {"mutants": len(negative), "rejected": 0, "conforms": 0, "cannot-tell": 0,
                  "cannot-read": 0, "not-run": 0, "target_cited": 0, "target_comparable": 0}
        rows: dict[str, int] = {}
        accepted = []
        for e in negative:
            cell = cells[e["id"]][reader["id"]]
            counts[cell["outcome"]] = counts.get(cell["outcome"], 0) + 1
            if cell["outcome"] == "conforms":
                accepted.append(e["id"])
            for r in cell["cited"]:
                rows[r] = rows.get(r, 0) + 1
            hit = target_cited(reader, e, cell) if cell["outcome"] != "not-run" else None
            if hit is not None:
                counts["target_comparable"] += 1
                counts["target_cited"] += int(hit)
        table[reader["id"]] = {**counts, "rows_cited": dict(sorted(rows.items())), "accepted": accepted,
                               "positive_controls": {e["id"]: cells[e["id"]][reader["id"]]["outcome"]
                                                     for e in positive}}
    return table


# --------------------------------------------------------------------------
# Commands.
# --------------------------------------------------------------------------

def verify_commands(inputs: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [{"report": e["id"], "row": e["row"],
             "command": f"uvx agent-evidence-vectors=={READ_RELEASE} --read-w3c-report {e['source']}"}
            for e in inputs if not e.get("mutant")]


def cmd_run(args: argparse.Namespace) -> int:
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    log = work / "matrix-log.txt"
    inputs, statuses = build_inputs(work)
    present = [e for e in inputs if "file" in e]
    files = work / "files.txt"
    files.write_text("\n".join(e["file"] for e in present) + "\n", encoding="utf-8")
    readers = [dict(r) for r in READERS]
    results: dict[str, Any] = {}
    for reader in readers:
        print(f"reader {reader['id']}", flush=True)
        try:
            results[reader["id"]] = KINDS[reader["kind"]](reader, files, work, log)
        except rerun.Refused as exc:
            reader["refused"] = str(exc)
            results[reader["id"]] = {}
    cells: dict[str, dict[str, Any]] = {}
    for e in inputs:
        if "file" not in e:
            continue
        cells[e["id"]] = {}
        for reader in readers:
            got = results[reader["id"]].get(e["file"])
            cells[e["id"]][reader["id"]] = got if got else {"outcome": "not-run", "cited": [],
                                                           "note": "the reader returned nothing for this file"}
    for e in inputs:
        e.pop("file", None)
    for row in cells.values():
        for cell in row.values():
            cell["note"] = cell["note"].replace(str(work) + "/", "")
    observed = {
        "matrix": "W3C v0.1 reader conformance matrix",
        "platform": f"{platform.system()} {platform.machine()}",
        "producer_reruns": statuses,
        "current_pypi_release": CURRENT_PYPI,
        "readers": readers,
        "rows": {row: {**meta, "denominator": row_denominator(row)} for row, meta in ROW_META.items()},
        "inputs": inputs,
        "cells": cells,
        "controls": controls(readers, inputs, cells),
        "verify_commands": verify_commands(inputs),
    }
    for e in inputs:
        if not e.get("mutant") and "checks" in e:
            observed["rows"][e["row"]].setdefault("denominators", {})[e["id"]] = e["checks"]
    args.observed.write_text(json.dumps(observed, indent=1, ensure_ascii=True, sort_keys=True) + "\n",
                             encoding="utf-8")
    bad = [r for r, s in statuses.items() if s not in (rerun.REPRODUCED,)]
    print(f"producer reruns: {statuses}")
    return 1 if bad else 0


def comparable(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """What check compares: each cell's outcome and rows, each input's digest or absence."""
    cells = {i: {r: {"outcome": c["outcome"], "cited": c["cited"]} for r, c in row.items()}
             for i, row in doc["cells"].items()}
    inputs = {e["id"]: e.get("sha256") or e.get("not_applicable") or "missing" for e in doc["inputs"]}
    return cells, inputs


def cmd_check(args: argparse.Namespace) -> int:
    observed = json.loads(args.observed.read_text(encoding="utf-8"))
    committed = json.loads(MATRIX.read_text(encoding="utf-8"))
    oc, oi = comparable(observed)
    cc, ci = comparable(committed)
    diffs = []
    for key in sorted(set(ci) | set(oi)):
        if ci.get(key) != oi.get(key):
            diffs.append(f"input {key}: committed {ci.get(key)}, observed {oi.get(key)}")
    for key in sorted(set(cc) | set(oc)):
        for reader in sorted(set(cc.get(key, {})) | set(oc.get(key, {}))):
            a, b = cc.get(key, {}).get(reader), oc.get(key, {}).get(reader)
            if a != b:
                diffs.append(f"cell {key} x {reader}: committed {a}, observed {b}")
    for line in diffs:
        print(line)
    print(f"{len(diffs)} difference(s) from the committed matrix on {observed['platform']}")
    return 1 if diffs else 0


def cmd_adopt(args: argparse.Namespace) -> int:
    observed = json.loads(args.observed.read_text(encoding="utf-8"))
    MATRIX.write_text(json.dumps(observed, indent=1, ensure_ascii=True, sort_keys=True) + "\n",
                      encoding="utf-8")
    import render  # noqa: PLC0415
    render.write()
    return 0


def cmd_render(_: argparse.Namespace) -> int:
    import render  # noqa: PLC0415
    render.write()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--work", type=Path, default=Path(".build/w3c-v01-matrix"))
    run.add_argument("--observed", type=Path, required=True)
    for name in ("check", "adopt"):
        p = sub.add_parser(name)
        p.add_argument("observed", type=Path)
    sub.add_parser("render")
    args = parser.parse_args()
    return {"run": cmd_run, "check": cmd_check, "adopt": cmd_adopt, "render": cmd_render}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
