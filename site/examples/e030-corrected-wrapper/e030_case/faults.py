"""Author-created report projections injected instead of a producer verifier run."""

import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .report import EXPECTED, PROFILE


def utc_now() -> str:
    """Match the producer's native UTC millisecond timestamp representation."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def report_fixture(generated: str) -> dict:
    """Build only the published native fields used by this finite comparison."""
    return {"profile": PROFILE, "generated_at": generated, **copy.deepcopy(EXPECTED)}


def emit(fault: str, output: Path) -> None:
    """Write one clearly documented injection without evaluating producer claims."""
    if fault == "absent":
        return
    if fault == "malformed":
        output.write_bytes(b"{broken-json\n")
        return
    report = report_fixture(utc_now())
    if fault == "wrong-profile":
        report["profile"] = "another.report.v1"
    elif fault == "wrong-input":
        report["pins"]["aps_commit"] = "0" * 40
    elif fault == "wrong-claim":
        report["claims"][0]["result"] = "NOT_ESTABLISHED"
    elif fault == "wrong-summary":
        report["summary"]["established"] = 0
    elif fault == "stale-generation":
        report["generated_at"] = "2000-01-01T00:00:00.000Z"
    elif fault == "future-generation":
        report["generated_at"] = "2100-01-01T00:00:00.000Z"
    elif fault == "symlink":
        target = output.parent / "linked-report.json"
        target.write_text(json.dumps(report) + "\n")
        output.symlink_to(target.name)
        return
    elif fault != "matching":
        raise ValueError("unknown fixture fault")
    output.write_text(json.dumps(report) + "\n")


def main(argv=None) -> int:
    """Serve the wrapper's fixed `node verify.mjs ... --out` injection point."""
    args = sys.argv[1:] if argv is None else argv
    with Path(os.environ["VECTOR_LOG"]).open("a") as log:
        log.write("node:" + args[0] + "\n")
    code = int(os.environ["NODE_EXIT"])
    if code:
        return code
    if args.count("--out") != 1:
        raise ValueError("expected one explicit report destination")
    emit(os.environ["E030_FAULT"], Path(args[args.index("--out") + 1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
