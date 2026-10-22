"""Answer one vectors-trace-anchor case with TRACE's own TR-ANC-002 check.

The TRACE conformance suite (agentrust-io/trace-spec, ``conformance/``) is
imported from the checkout named by ``TRACE_CONFORMANCE_SRC``, the directory
that holds the ``trace_tests`` package. This file never installs it and never
patches it: it calls ``trace_tests.modules.tr_anc.check`` with the case's
claim and receipt, and with the registry entry when that version of the check
accepts one, then maps the TR-ANC-002 finding to the corpus contract.

    TRACE_CONFORMANCE_SRC=<trace-spec>/conformance/src \\
        python3 tr_anc_reader.py <case.json> --json

A TR-ANC-002 pass prints ``anchored``; anything else prints ``refused``, with
the suite's own message as the reason, so the comparison is on the decision.
"""

from __future__ import annotations

import inspect
import json
import os
import sys
from pathlib import Path


def answer(case_path: Path) -> dict[str, str]:
    source = os.environ.get("TRACE_CONFORMANCE_SRC")
    if not source or not (Path(source) / "trace_tests").is_dir():
        raise SystemExit("TRACE_CONFORMANCE_SRC must name the directory holding trace_tests")
    sys.path.insert(0, source)
    from trace_tests.modules import tr_anc  # type: ignore[import-not-found]

    case = json.loads(case_path.read_text(encoding="utf-8"))
    claim, receipt, entry = case.get("claim"), case.get("receipt"), case.get("entry")
    if "entry" in inspect.signature(tr_anc.check).parameters:
        findings = tr_anc.check(claim, receipt, entry)
    else:
        findings = tr_anc.check(claim, receipt)
    for finding in findings:
        if finding.code == "TR-ANC-002":
            passed = str(getattr(finding.status, "value", finding.status)).lower() == "pass"
            return {"decision": "anchored" if passed else "refused", "reason": finding.message}
    first = findings[0].message if findings else "no TR-ANC finding"
    return {"decision": "refused", "reason": first}


def main() -> int:
    result = answer(Path(sys.argv[1]))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"] == "anchored" else 1


if __name__ == "__main__":
    raise SystemExit(main())
