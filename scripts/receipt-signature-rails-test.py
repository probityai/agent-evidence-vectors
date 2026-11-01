#!/usr/bin/env python3
"""Both readers of corpora/vectors-receipt-signature/ agree, and the contract scores a
named verifier the way the corpus README says.

Two halves.

Parity. ``aee-verify <dir>`` judges the corpus through
corpusreaders/receiptsignature.go and ``packaging/run_vectors.py --vectors <dir>``
through packaging/agent_evidence_vectors/receiptsignature.py. The committed
corpus and a set of mutated copies are judged by both and every line of output
is compared. Each mutation must also turn both rails red, so a case that stopped
reaching the check it was written for fails here instead of agreeing on a
clean run.

Contract. Stub verifiers are run through ``--verifier``: one that honours the
Section 9.2 windows, one that skips them, one that refuses everything, one that
never answers and one whose answer line contradicts its exit status. Each must
get the totals, the executed count and the exit status the grading rules give.

Usage: python3 scripts/receipt-signature-rails-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "corpora/vectors-receipt-signature"


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout


def manifest_of(corpus: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    return data


def write_manifest(corpus: Path, manifest: dict[str, Any]) -> None:
    (corpus / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def first(manifest: dict[str, Any], kind: str) -> dict[str, Any]:
    row: dict[str, Any] = next(v for v in manifest["vectors"] if v["kind"] == kind)
    return row


def flip_signature(corpus: Path) -> None:
    """One hex digit of an accept member's signature, so the file stays JSON."""
    path = corpus / first(manifest_of(corpus), "accept")["file"]
    body = path.read_text(encoding="utf-8")
    marker = '"sig": "'
    at = body.index(marker) + len(marker)
    path.write_text(body[:at] + ("1" if body[at] != "1" else "2") + body[at + 1:], encoding="utf-8")


def relabel_indeterminate(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    first(manifest, "indeterminate")["kind"] = "reject"
    write_manifest(corpus, manifest)


def must_as_should(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["requirements"][0]["level"] = "SHOULD"
    write_manifest(corpus, manifest)


def windowed_bare_set(corpus: Path) -> None:
    path = corpus / manifest_of(corpus)["keySets"]["withoutWindows"]["file"]
    keys = json.loads(path.read_text(encoding="utf-8"))
    keys["keys"][0]["valid_until"] = "2026-06-01T00:00:00Z"
    path.write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")


def forged_origin(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["origins"][0]["members"][0]["sha256"] = "0" * 64
    write_manifest(corpus, manifest)


def gap_relabelled_accept(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    first(manifest, "gap")["kind"] = "accept"
    write_manifest(corpus, manifest)


def gap_closed_with_another_code(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    first(manifest, "gap")["expectedIfGapClosed"]["code"] = "key_outside_validity_window"
    write_manifest(corpus, manifest)


def commitment_byte_flipped(corpus: Path) -> None:
    """The commitment's signature, one hex digit, so the file stays JSON."""
    path = next((corpus / "context").iterdir())
    body = path.read_text(encoding="utf-8")
    at = body.index('"sig": "') + len('"sig": "')
    path.write_text(body[:at] + ("1" if body[at] != "1" else "2") + body[at + 1:], encoding="utf-8")


def logged_at_moved(corpus: Path) -> None:
    """The contradicted commitment moved before issued_at: the gap member no longer
    refuses when the gap is closed, and its identifier no longer recomputes."""
    manifest = manifest_of(corpus)
    member = next(v for v in manifest["vectors"]
                  if v["kind"] == "gap" and (v.get("context") or {}).get("commitment"))
    member["context"]["commitmentLoggedAt"] = "2026-02-01T00:00:00Z"
    write_manifest(corpus, manifest)


def revoked_at_in_the_bare_set(corpus: Path) -> None:
    path = corpus / manifest_of(corpus)["keySets"]["withoutWindows"]["file"]
    keys = json.loads(path.read_text(encoding="utf-8"))
    keys["keys"][-1]["revoked_at"] = "2026-04-01T00:00:00Z"
    path.write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")


def undeclared_gap(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["conditions"]["rs-c-7"]["gaps"] = ["RS-G-999"]
    write_manifest(corpus, manifest)


def orphaned_condition(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["vectors"] = [
        v for v in manifest["vectors"]
        if not (v["kind"] == "accept" and v["conditions"] == ["rs-c-4"])
    ]
    write_manifest(corpus, manifest)


def wrong_signed_input(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    first(manifest, "accept")["signedInputHex"] = "00"
    write_manifest(corpus, manifest)


PARITY: list[tuple[str, Callable[[Path], None] | None]] = [
    ("committed", None),
    ("flipped-signature", flip_signature),
    ("indeterminate-relabelled-reject", relabel_indeterminate),
    ("must-read-as-should", must_as_should),
    ("window-in-the-bare-set", windowed_bare_set),
    ("forged-origin", forged_origin),
    ("orphaned-condition", orphaned_condition),
    ("wrong-signed-input", wrong_signed_input),
    ("gap-relabelled-accept", gap_relabelled_accept),
    ("gap-closed-with-another-code", gap_closed_with_another_code),
    ("commitment-byte-flipped", commitment_byte_flipped),
    ("logged-at-moved", logged_at_moved),
    ("revoked-at-in-the-bare-set", revoked_at_in_the_bare_set),
    ("undeclared-gap", undeclared_gap),
]

# A stub verifier: the reference verification of the Python reader, with the
# windows honoured or skipped, or a fixed misbehaviour. It is written to disk
# and run as a separate program, because the contract is about programs.
STUB = """
import json, os, sys
sys.path.insert(0, {packaging!r})
from agent_evidence_vectors import receiptsignature as rs
import run_vectors  # noqa: F401  (the rail the reader borrows Ed25519 from)
mode = {mode!r}
if mode == "silent":
    sys.exit(os.EX_SOFTWARE)  # a status the contract gives no meaning
if mode == "contradicts":
    print(json.dumps({{"verdict": "invalid", "code": None}}))
    sys.exit(0)
if mode == "refuse-all":
    print(json.dumps({{"verdict": "invalid", "code": "signature_invalid"}}))
    sys.exit(1)
with open(os.environ["AEV_RECEIPT_JWKS"]) as handle:
    keys = {{k["kid"]: k for k in json.load(handle)["keys"]}}
if mode == "skip-windows":
    keys = {{kid: {{m: v for m, v in k.items() if m not in ("valid_from", "valid_until")}}
            for kid, k in keys.items()}}
context = None
if "AEV_RECEIPT_CONTEXT" in os.environ and mode != "ignores-context":
    with open(os.environ["AEV_RECEIPT_CONTEXT"]) as handle:
        handed = json.load(handle)
    def read(path):
        with open(path, "rb") as h:
            return h.read()
    context = rs.Context([read(p) for p in handed["chain"]],
                         read(handed["commitment"]) if "commitment" in handed else None,
                         handed.get("commitmentLoggedAt"))
windowed = any("valid_from" in k or "valid_until" in k for k in keys.values())
closed = mode == "closes-gaps" or (mode == "closes-gaps-with-windows-only" and windowed)
with open(sys.argv[1], "rb") as handle:
    answer = rs.verify_in_context(handle.read(), keys, context, gap_closed=closed)
verdict, _, code = answer.partition(" ")
print(json.dumps({{"verdict": verdict, "code": code or None}}))
sys.exit({{"valid": 0, "invalid": 1, "undecidable": 2}}[verdict])
"""


def contract_case(work: Path, mode: str) -> tuple[int, dict[str, Any] | None, str]:
    stub = work / f"stub-{mode}.py"
    stub.write_text(STUB.format(packaging=str(REPO / "packaging"), mode=mode), encoding="utf-8")
    report = work / f"report-{mode}.json"
    status, out = run(
        [sys.executable, "packaging/run_vectors.py", "--vectors", str(REPO / CORPUS),
         "--verifier", f"{sys.executable} {stub}", "--report", str(report)],
        REPO,
    )
    data = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
    return status, data, out


def expected_contract(manifest: dict[str, Any]) -> dict[str, tuple[int, dict[str, int]]]:
    total = len(manifest["vectors"])
    counts = manifest["counts"]
    decided = counts["accept"] + counts["reject"] + counts["gap"]
    in_context = sum(1 for v in manifest["vectors"]
                     if v["kind"] == "reject" and "context" in v)
    split = _gaps_closed_without_windows(manifest)
    none = {"notHonoured": 0, "closesGap": 0}
    return {
        "honours-windows": (0, {**none, "pass": total, "fail": 0, "executed": total}),
        "skip-windows": (0, {**none, "pass": decided, "notHonoured": counts["indeterminate"],
                             "fail": 0, "executed": total}),
        "closes-gaps": (0, {**none, "pass": total - counts["gap"], "closesGap": counts["gap"],
                            "fail": 0, "executed": total}),
        "closes-gaps-with-windows-only": (1, {**none, "pass": total - counts["gap"],
                                              "closesGap": counts["gap"] - split,
                                              "fail": split, "executed": total}),
        "ignores-context": (1, {**none, "pass": total - in_context, "fail": in_context,
                                "executed": total}),
        "refuse-all": (1, {**none, "pass": counts["reject"] - _other_codes(manifest),
                           "fail": total - counts["reject"] + _other_codes(manifest),
                           "executed": total}),
        "silent": (2, {**none, "pass": 0, "fail": total, "executed": 0}),
        "contradicts": (2, {**none, "pass": 0, "fail": total, "executed": 0}),
    }


def _gaps_closed_without_windows(manifest: dict[str, Any]) -> int:
    """Gap members the closing rule refuses in the windowless pass too: a verifier
    that closes the gap in one pass only answers them incoherently and fails."""
    return sum(
        1 for v in manifest["vectors"]
        if v["kind"] == "gap" and v["expectedIfGapClosedWithoutWindows"]["verdict"] == "invalid"
    )


def _other_codes(manifest: dict[str, Any]) -> int:
    """Reject members whose code is not signature_invalid: refuse-all answers the
    right verdict with the wrong code on them."""
    return sum(
        1 for v in manifest["vectors"]
        if v["kind"] == "reject" and v["expected"]["code"] != "signature_invalid"
    )


def check_parity(work: Path, binary: Path) -> int:
    failures = 0
    for name, mutate in PARITY:
        corpus = work / name / CORPUS
        shutil.copytree(REPO / CORPUS, corpus)
        if mutate is not None:
            mutate(corpus)
        go_status, go_out = run([str(binary), str(corpus)], REPO)
        py_status, py_out = run(
            [sys.executable, "packaging/run_vectors.py", "--vectors", str(corpus)], REPO
        )
        want = 0 if mutate is None else 1
        if go_out != py_out or go_status != py_status or go_status != want:
            failures += 1
            print(f"FAIL parity/{name}: go exit {go_status}, python exit {py_status}, want {want}")
            print("--- go\n" + go_out + "--- python\n" + py_out)
        else:
            print(f"ok   parity/{name}: both rails exit {go_status} and print the same lines")
    return failures


def check_contract(work: Path) -> int:
    failures = 0
    for mode, (want_status, want) in expected_contract(manifest_of(REPO / CORPUS)).items():
        status, report, out = contract_case(work, mode)
        if report is None:
            failures += 1
            print(f"FAIL contract/{mode}: no report was written\n{out}")
            continue
        totals = report["totals"]
        got = {"pass": totals["pass"], "notHonoured": totals["notHonoured"],
               "closesGap": totals["closesGap"], "fail": totals["fail"],
               "executed": report["verifier"]["vectorsExecuted"]}
        if status != want_status or got != want or report["rail"] != "external":
            failures += 1
            print(f"FAIL contract/{mode}: exit {status} want {want_status}; got {got} want {want}")
            print(out)
        else:
            print(f"ok   contract/{mode}: exit {status}, {got}")
    return failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="receipt-signature-rails-") as tmp:
        work = Path(tmp)
        binary = work / "aee-verify"
        status, output = run(["go", "build", "-o", str(binary), "./cmd/aee-verify"], REPO)
        if status != 0:
            print(f"FAIL: aee-verify did not build:\n{output}")
            return 1
        failures = check_parity(work, binary) + check_contract(work)
    if failures:
        print(f"\n{failures} case(s) failed")
        return 1
    print("\nOK every case holds on both rails and through the contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
