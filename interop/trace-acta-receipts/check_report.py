"""Require a complete external receipt-signature comparison, including key windows."""

import json
import sys
from pathlib import Path


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if report["suite"] != "vectors-receipt-signature" or report["rail"] != "external":
        raise ValueError("the report does not grade the external receipt-signature reader")
    totals = report["totals"]
    if type(totals["vectors"]) is not int or totals["vectors"] <= 0:
        raise ValueError("the corpus has no measured members")
    if report["verifier"]["vectorsExecuted"] != totals["vectors"]:
        raise ValueError("the external reader did not answer every member in both passes")
    for field in ("fail", "notExercised", "notHonoured", "closesGap", "suiteRefusals"):
        if type(totals[field]) is not int or totals[field] != 0:
            raise ValueError(f"the comparison reports {field}: {totals[field]}")
    print(f"All {totals['vectors']} members answered in both passes with the expected verdicts.")


if __name__ == "__main__":
    main()

