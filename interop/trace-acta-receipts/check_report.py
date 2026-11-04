"""Require a complete external receipt-signature comparison, including key windows."""

import json
import sys
from pathlib import Path

# The one member where the pinned reader answers the corpus's verdict under its own code:
# for an issued_at with no time-zone designator it answers undecidable and names the code
# "malformed", where the corpus names window_not_applicable. Any other failure, and any
# change in this answer, fails the job.
KNOWN_ANSWERS = {"v429ea40212de7b5d": ("undecidable malformed", "valid")}


def main() -> None:
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if report["suite"] != "vectors-receipt-signature" or report["rail"] != "external":
        raise ValueError("the report does not grade the external receipt-signature reader")
    totals = report["totals"]
    if type(totals["vectors"]) is not int or totals["vectors"] <= 0:
        raise ValueError("the corpus has no measured members")
    if report["verifier"]["vectorsExecuted"] != totals["vectors"]:
        raise ValueError("the external reader did not answer every member in both passes")
    for field in ("notExercised", "notHonoured", "closesGap", "suiteRefusals"):
        if type(totals[field]) is not int or totals[field] != 0:
            raise ValueError(f"the comparison reports {field}: {totals[field]}")
    failing = {row["id"]: (row["withWindows"], row["withoutWindows"])
               for row in report["vectors"] if row["status"] == "FAIL"}
    if failing != KNOWN_ANSWERS or totals["fail"] != len(KNOWN_ANSWERS):
        raise ValueError(f"the members that fail changed: {failing}, recorded {KNOWN_ANSWERS}")
    print(f"All {totals['vectors']} members answered in both passes; the verdict of "
          f"{len(KNOWN_ANSWERS)} differs from the corpus only in the code it names.")


if __name__ == "__main__":
    main()

