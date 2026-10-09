#!/usr/bin/env python3
"""The three rails that judge vectors-w3c-report/ print the same bytes.

``aee-verify <dir>`` judges the corpus through corpora/w3creport.go,
``packaging/run_vectors.py --corpus vectors-w3c-report`` judges it through
packaging/agent_evidence_vectors/w3creport.py, and ``w3c-report-rs <dir>``
judges it through readers/w3c-report-rs, a Rust reader written from the v0.1
text and the corpus alone, with no code path shared with the other two (see
docs/research/w3c-reader-independence.md). Each is a full statement of the
v0.1 rows, and three statements of one set of rules drift unless something
holds them together. This holds them together: the committed corpus and a set
of mutated copies are judged by all three, and every line of output is
compared. A rail that cannot be built fails the test; none is skipped.

The mutations are chosen so that different parts of the reader answer: a
flipped byte (identifier and corpus digest), a manifest row expecting the wrong
requirement (the validator's answer against the manifest's), a member whose
report loses its roll-up field (a row firing where none was expected), and a
member whose check-set count is edited (the set-binding row), a member whose
store resolves a reference to other bytes (the reading table's mismatch line),
a member whose fixed slot restates the domain (the domain-once row), a member
whose check-set names a tree shape outside the closed set, a pass carrying the
confinement cause (two rows at once), a control rebound to another constraint
set, and the reference emitter's published run with a wrong digest and with a
report the validator would reject. Four more give a member a field of the wrong
JSON type: robots exclusion rules as an integer, step_count as a string, a
cache ledger's tokens as a string, and a delta's changes as a string.

Usage: python3 scripts/w3c-rails-parity-test.py
Exit 0 when every case prints identically on all three rails; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "vectors-w3c-report"


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def manifest_of(corpus: Path) -> dict[str, Any]:
    with open(corpus / "MANIFEST.json", encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
        return data


def write_manifest(corpus: Path, manifest: dict[str, Any]) -> None:
    (corpus / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def flip_first_member(corpus: Path) -> None:
    """Flip one byte inside the first check identity, so the file stays JSON.

    A flip in the structure would test the two parsers' error messages, which
    differ by design; a flip inside a string value tests what this holds
    together, the identifier and the corpus digest recomputed by both rails.
    """
    entry = next(e for e in manifest_of(corpus)["vectors"] if e["subjectType"] == "report")
    path = corpus / entry["file"]
    body = bytearray(path.read_bytes())
    marker = b'"check": "'
    body[body.index(marker) + len(marker)] ^= 0x01
    path.write_bytes(bytes(body))


def wrong_row(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    for entry in manifest["vectors"]:
        if entry["kind"] == "reject":
            entry["expected"]["rejects"] = ["W3C-R-012"]
            entry["requirements"] = ["W3C-R-012"]
            break
    write_manifest(corpus, manifest)


def edit_member(
    corpus: Path,
    edit: Callable[[dict[str, Any]], None],
    with_evidence: bool = False,
    family: str | None = None,
) -> None:
    entry = next(
        e for e in manifest_of(corpus)["vectors"]
        if e["kind"] == "accept" and e["subjectType"] == "report"
        and (not with_evidence or e["family"] == "w3c-f-21")
        and (family is None or e["family"] == family)
    )
    path = corpus / entry["file"]
    document = json.loads(path.read_text(encoding="utf-8"))
    edit(document)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def mismatched_store(corpus: Path) -> None:
    """A member's store resolving a reference to bytes with another digest: rule 20."""
    def edit(document: dict[str, Any]) -> None:
        document["resolves"]["obs-fail"]["sha256"] = "0" * 64

    edit_member(corpus, edit, with_evidence=True)


def restated_domain(corpus: Path) -> None:
    """The fixed slot restating the domain as an object: rule 28."""
    def edit(document: dict[str, Any]) -> None:
        document["subject"]["evidence"][0]["fixed"]["domain"] = {"id": "d-run"}

    edit_member(corpus, edit, with_evidence=True)


def drop_negative_capable(corpus: Path) -> None:
    edit_member(corpus, lambda document: document["subject"]["roll-up"].pop("negative-capable"))


def miscount_check_set(corpus: Path) -> None:
    def edit(document: dict[str, Any]) -> None:
        report = document["subject"]
        report["check-set"]["leaf-count"] = report["check-set"]["leaf-count"] + 1

    edit_member(corpus, edit)


def float_count(corpus: Path) -> None:
    def edit(document: dict[str, Any]) -> None:
        report = document["subject"]
        report["roll-up"]["declared"] = float(report["roll-up"]["declared"])

    edit_member(corpus, edit)


def unregistered_shape(corpus: Path) -> None:
    """A check-set naming its tree in free text: the closed set refuses it (rule 15)."""
    def edit(document: dict[str, Any]) -> None:
        document["subject"]["check-set"]["tree-shape"] = "RFC 9162 SHA-256"

    edit_member(corpus, edit)


def confinement_on_pass(corpus: Path) -> None:
    """The confinement cause on a pass: rows 4 and 7 both fire, on both rails."""
    def edit(document: dict[str, Any]) -> None:
        document["subject"]["checks"][0]["cause"] = {"code": "confinement-failed-during-check"}

    edit_member(corpus, edit)


def rebound_control(corpus: Path) -> None:
    """A bound control moved to another constraint set than the run's (rule 29)."""
    def edit(document: dict[str, Any]) -> None:
        control = document["subject"]["roll-up"]["negative-capable"]["control"]
        control["fixed"]["constraint-set"] = "cs-3"

    def bound(document: dict[str, Any]) -> bool:
        return "fixed" in document["subject"]

    manifest = manifest_of(corpus)
    for entry in manifest["vectors"]:
        if entry["family"] != "w3c-f-29" or entry["kind"] != "accept":
            continue
        path = corpus / entry["file"]
        document = json.loads(path.read_text(encoding="utf-8"))
        if bound(document):
            edit(document)
            path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            return
    raise SystemExit("no bound control member to rebind")


def edit_subject(corpus: Path, subject_type: str, edit: Callable[[dict[str, Any]], None]) -> None:
    """Edit the subject of the first accept member of one subject type."""
    entry = next(
        e for e in manifest_of(corpus)["vectors"]
        if e["kind"] == "accept" and e["subjectType"] == subject_type
    )
    path = corpus / entry["file"]
    document = json.loads(path.read_text(encoding="utf-8"))
    edit(document["subject"])
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def robots_integer(corpus: Path) -> None:
    """robots.disallow as an integer: refused as malformed, and the run goes on."""
    edit_subject(
        corpus, "llm-context-discovery",
        lambda subject: subject["robots"].__setitem__("disallow", 2),
    )


def string_step_count(corpus: Path) -> None:
    """step_count as a string: the Run is malformed (draft section 3.1 makes it an integer)."""
    edit_subject(
        corpus, "agent-run-metrics", lambda subject: subject.__setitem__("step_count", "3")
    )


def string_ledger_tokens(corpus: Path) -> None:
    """A ledger element's tokens as a string cannot sum to cache_write_tokens: row 14."""
    def edit(subject: dict[str, Any]) -> None:
        subject["steps"][0]["usage"]["cache_writes"][0]["tokens"] = "10"

    edit_subject(corpus, "agent-run-metrics", edit)


def string_delta_changes(corpus: Path) -> None:
    """A stated delta whose changes is a string: the report is malformed."""
    def edit(document: dict[str, Any]) -> None:
        item = next(e for e in document["subject"]["evidence"] if "delta" in e)
        item["delta"]["changes"] = "fired-rule list"

    edit_member(corpus, edit, with_evidence=True)


def emitter_run_digest(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["referenceEmitterRuns"][0]["sha256"] = "0" * 64
    write_manifest(corpus, manifest)


def emitter_run_rejected(corpus: Path) -> None:
    """A published report the validator would reject, re-pinned so its digest holds."""
    manifest = manifest_of(corpus)
    run = manifest["referenceEmitterRuns"][0]
    path = corpus / run["path"]
    report = json.loads(path.read_text(encoding="utf-8"))
    report["checks"][0]["state"] = "pass"
    report["checks"][0]["cause"] = {"code": "out_of_scope"}
    body = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(body)
    run["sha256"] = hashlib.sha256(body).hexdigest()
    write_manifest(corpus, manifest)


CASES: list[tuple[str, Callable[[Path], None] | None]] = [
    ("committed", None),
    ("flipped-byte", flip_first_member),
    ("wrong-row", wrong_row),
    ("silent-roll-up", drop_negative_capable),
    ("miscounted-set", miscount_check_set),
    ("float-count", float_count),
    ("mismatched-store", mismatched_store),
    ("restated-domain", restated_domain),
    ("unregistered-shape", unregistered_shape),
    ("confinement-on-pass", confinement_on_pass),
    ("rebound-control", rebound_control),
    ("robots-integer", robots_integer),
    ("string-step-count", string_step_count),
    ("string-ledger-tokens", string_ledger_tokens),
    ("string-delta-changes", string_delta_changes),
    ("emitter-run-digest", emitter_run_digest),
    ("emitter-run-rejected", emitter_run_rejected),
]

#: What a case's output must say beyond a changed identifier, so a case whose
#: mutation both rails let through as well-formed cannot pass on agreement.
EXPECT: dict[str, str] = {
    "robots-integer": "robots.disallow",
    "string-step-count": "step_count",
    "string-ledger-tokens": "ARM-R-014",
    "string-delta-changes": "delta.changes",
}


def build_rust_reader(work: Path) -> Path | None:
    """Build the Rust reader into ``work``; a missing toolchain is a failure."""
    manifest = REPO / "readers" / "w3c-report-rs" / "Cargo.toml"
    target = work / "rs-target"
    try:
        status, output = run(
            ["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest),
             "--target-dir", str(target)],
            REPO,
        )
    except FileNotFoundError:
        print("FAIL: cargo is not installed, so the Rust rail cannot be built")
        return None
    if status != 0:
        print(f"FAIL: w3c-report-rs did not build:\n{output}")
        return None
    return target / "release" / "w3c-report-rs"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="w3c-parity-") as tmp:
        work = Path(tmp)
        binary = work / "aee-verify"
        status, output = run(["go", "build", "-o", str(binary), "./cmd/aee-verify"], REPO)
        if status != 0:
            print(f"FAIL: aee-verify did not build:\n{output}")
            return 1
        rust = build_rust_reader(work)
        if rust is None:
            return 1
        failures = 0
        for name, mutate in CASES:
            corpus = work / name / CORPUS
            shutil.copytree(REPO / CORPUS, corpus)
            if mutate is not None:
                mutate(corpus)
            go_status, go_out = run([str(binary), str(corpus)], REPO)
            py_status, py_out = run(
                [sys.executable, "packaging/run_vectors.py", "--vectors", str(corpus)], REPO
            )
            rs_status, rs_out = run([str(rust), str(corpus)], REPO)
            same = (
                go_out == py_out == rs_out
                and go_status == py_status == rs_status
            )
            findings = sum(1 for line in go_out.splitlines() if line.startswith("FAIL"))
            mark = "ok  " if same else "FAIL"
            print(
                f"{mark} {name}: exit go={go_status} py={py_status} rs={rs_status}, "
                f"{findings} finding line(s)"
            )
            if mutate is not None and go_status == 0:
                print(f"FAIL {name}: the mutation was not noticed, so the case asserted nothing")
                failures += 1
            want = EXPECT.get(name)
            if want is not None and (want not in go_out or want not in py_out):
                print(f"FAIL {name}: the output does not name {want}")
                failures += 1
            if not same:
                failures += 1
                for label, text in (("go", go_out), ("py", py_out), ("rs", rs_out)):
                    print(f"--- {label}\n{text}")
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
