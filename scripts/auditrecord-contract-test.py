#!/usr/bin/env python3
"""The agent audit record corpus runs a named verifier through its contract.

Three runs of packaging/run_vectors.py over corpora/vectors-agent-audit-record:

1. The reference reader, answering through the contract, must conform on every
   member: exit 0 and a report whose totals show every member executed.
2. The oracle verifier with one verdict flipped must fail, naming that member.
3. The oracle verifier with its exit status inverted must fail on every member,
   because the exit status and the verdict disagree.

Before this contract the harness refused any named verifier on this corpus with
exit 2, so an outside implementer could only score it by hand.

    python3 scripts/auditrecord-contract-test.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "packaging" / "run_vectors.py"
CORPUS = ROOT / "corpora" / "vectors-agent-audit-record"
READER = ROOT / "packaging" / "agent_evidence_vectors" / "auditrecord.py"
#: The controls start from the oracle, which answers as the MANIFEST declares
#: and starts in a fraction of the reader's time.
ORACLE = ROOT / "scripts" / "oracle-verifier.py"

WRAPPER = '''
import json, subprocess, sys
mode, reader, member = sys.argv[1], sys.argv[2], sys.argv[3]
done = subprocess.run([sys.executable, reader, member, "--json"], capture_output=True, text=True)
answer = json.loads(done.stdout.strip().splitlines()[-1])
status = 0 if answer["verdict"] == "valid" else 1
if mode == "flip" and member.endswith(sys.argv[4]):
    answer["verdict"] = "malformed" if answer["verdict"] == "valid" else "valid"
    status = 1 - status
if mode == "exit":
    status = 1 - status
print(json.dumps(answer))
sys.exit(status)
'''


def harness(verifier: str, report: Path) -> tuple[int, str]:
    done = subprocess.run(
        [sys.executable, str(HARNESS), "--vectors", str(CORPUS), "--verifier", verifier,
         "--report", str(report)],
        capture_output=True, text=True, check=False,
    )
    return done.returncode, done.stdout + done.stderr


def _scoring_cases(entries: list[dict[str, Any]]) -> list[str]:
    """Codes inside set and dating are reported, never scored, and a proposed
    member never fails a verifier. CS7, CS8, CS17, SQ5, X17 and X18 once failed
    an outside verifier whose set verdicts matched on set codes alone."""
    sys.path.insert(0, str(ROOT / "packaging"))
    from agent_evidence_vectors import auditrecord

    out: list[str] = []
    by_id = {e["draftId"]: e for e in entries}
    for draft_id in ("CS7", "CS8", "CS17", "SQ5"):
        entry = by_id[draft_id]
        expected = entry["expected"]
        answer = {"verdict": expected["verdict"], "codes": [],
                  "derivedTier": expected.get("derivedTier", ""),
                  "set": {**expected["set"], "codes": ["another-name"]}}
        normative, parity = auditrecord.contract_findings(entry, answer)
        if normative or not any("set codes" in p for p in parity):
            out.append(f"{draft_id}: set codes scored ({normative}) or not reported ({parity})")
        flipped = "valid" if expected["set"]["verdict"] == "malformed" else "malformed"
        answer["set"]["verdict"] = flipped
        if not auditrecord.contract_findings(entry, answer)[0]:
            out.append(f"{draft_id}: a wrong set verdict was not scored")
    dated = next(
        e for e in entries if "dating" in e["expected"] and e["expected"]["dating"]["codes"]
    )
    answer = {"verdict": dated["expected"]["verdict"], "codes": [],
              "derivedTier": dated["expected"].get("derivedTier", ""),
              "dating": {**dated["expected"]["dating"], "codes": ["another-name"]}}
    normative, parity = auditrecord.contract_findings(dated, answer)
    if normative or not parity:
        out.append(f"{dated['draftId']}: dating codes scored ({normative}) or not reported")
    if auditrecord.text_status(by_id["CS18"]) != "proposed":
        out.append("CS18 should be proposed")
    return out


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    accept = next(e for e in entries if e.get("kind") == "accept" and "set" not in e["expected"]
                  and "dating" not in e["expected"])
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        wrapper = Path(tmp) / "wrap.py"
        wrapper.write_text(WRAPPER, encoding="utf-8")
        report = Path(tmp) / "report.json"

        status, out = harness(f"{sys.executable} {READER}", report)
        if status != 0:
            failures.append(
                f"reference reader through the contract exited {status}:\n{out[-2000:]}"
            )
        else:
            totals = json.loads(report.read_text(encoding="utf-8"))["totals"]
            if totals["conform"] != len(entries) or totals["fail"] != 0:
                failures.append(
                    f"reference reader totals {totals}, expected {len(entries)} conforming"
                )

        stem = Path(str(accept["file"])).name
        flip = Path(tmp) / "flip.py"
        flip.write_text(
            "import sys, runpy\n"
            f"sys.argv = [sys.argv[0], 'flip', {str(ORACLE)!r}, sys.argv[1], {stem!r}]\n"
            f"runpy.run_path({str(wrapper)!r}, run_name='__main__')\n",
            encoding="utf-8",
        )
        status, out = harness(f"{sys.executable} {flip}", report)
        if status != 1 or str(accept["draftId"]) not in out:
            failures.append(
                f"a flipped verdict on {accept['draftId']} was not caught (exit {status})"
            )

        inverted = Path(tmp) / "exit.py"
        inverted.write_text(
            "import sys, runpy\n"
            f"sys.argv = [sys.argv[0], 'exit', {str(ORACLE)!r}, sys.argv[1]]\n"
            f"runpy.run_path({str(wrapper)!r}, run_name='__main__')\n",
            encoding="utf-8",
        )
        status, out = harness(f"{sys.executable} {inverted}", report)
        if status != 1 or out.count("disagrees with verdict") != len(entries):
            failures.append(
                f"an inverted exit status was not caught on every member (exit {status})"
            )

    failures.extend(_scoring_cases(entries))
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print(
        f"ok: the contract scores {len(entries)} members, and catches a flipped verdict "
        "and a wrong exit status"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
