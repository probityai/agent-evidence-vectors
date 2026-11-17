"""Re-mint corpora/vectors-source-coverage from its published case table.

    python -E -s -S vectors-source-coverage.py OUT

A second generator: it shares no code with the corpus generator, so the committed source
pages, records, policies and manifest are shown to follow from the README's table.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from _layout import pretty, write_case, write_manifest

PARAGRAPHS = (
    "The publisher described the initial incident.",
    "Several channels were removed after the publisher contacted the platform.",
    "The publisher later corrected the incident date.",
)
HIDDEN = "A hidden claim was never published."


def html_page(head: str, paragraphs: list[str]) -> bytes:
    """An article page: the head, then each paragraph inside the article element."""
    body = "".join(f"<p>{text}</p>" for text in paragraphs)
    page = (
        f"<!doctype html><html><head>{head}</head><body><article>{body}</article></body></html>\n"
    )
    return page.encode()


INCIDENT_PAGE = html_page(f"<script>{HIDDEN}</script>", list(PARAGRAPHS))
INCIDENT_REPORT = "".join(line + "\n" for line in PARAGRAPHS).encode()
REPO_LINES = [f"repo-{n:02d} scanned: no credential-shaped value" for n in range(1, 13)]
SCAN_PAGE = html_page("<title>scan</title>", REPO_LINES)
CLEAN = "no credential-shaped values found in public repositories\n"
TRUNCATED_REPORT = (
    "\n".join(REPO_LINES[:7]) + "\ntruncated: 5 repo(s) not opened\n" + CLEAN
).encode()
COMPLETE_REPORT = ("\n".join(REPO_LINES) + "\n" + CLEAN).encode()
DAY = ("2019-06-26T00:00:00Z", "2019-06-26T23:59:59Z")
EARLIER_DAY = ("2019-04-13T00:00:00Z", "2019-04-13T23:59:59Z")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def table() -> list[dict[str, Any]]:
    """The README's case table."""
    second = PARAGRAPHS[1]
    rows = [
        ("complete", INCIDENT_REPORT, second, DAY, True, "supported", "all_selected_spans_present"),
        ("self-hashed-truncation", (PARAGRAPHS[0] + "\nSeveral channels were rem").encode(), second,
         DAY, True, "contradicted", "selected_span_missing_from_record"),
        ("middle-omission", (PARAGRAPHS[0] + "\n" + PARAGRAPHS[2] + "\n").encode(), second, DAY,
         True,
         "contradicted", "selected_span_missing_from_record"),
        ("returned-after-requested-window", INCIDENT_REPORT, second, EARLIER_DAY, True,
         "not_established", "witness_outside_source_window"),
        ("capture-absent", INCIDENT_REPORT, second, DAY, False, "not_established",
         "artifact_unavailable_or_unbound"),
        ("hidden-script-only", INCIDENT_REPORT, HIDDEN, DAY, True, "not_established",
         "selected_span_not_in_witness"),
    ]  # fmt: skip
    cases = [
        {"name": n, "record": r, "span": s, "window": w, "captured": c, "decision": d,
         "reason": why, "source": INCIDENT_PAGE}
        for n, r, s, w, c, d, why in rows
    ]  # fmt: skip
    for name, report, decision, reason in (
        ("scanner-truncation-reported-clean", TRUNCATED_REPORT, "contradicted",
         "selected_span_missing_from_record"),
        ("scanner-complete-scan", COMPLETE_REPORT, "supported", "all_selected_spans_present"),
    ):  # fmt: skip
        cases.append(
            {"name": name, "record": report, "span": REPO_LINES[-1], "window": DAY,
             "captured": True,
             "decision": decision, "reason": reason, "source": SCAN_PAGE}
        )  # fmt: skip
    return cases


def mint(out: Path) -> None:
    """Write the corpus under ``out``."""
    entries = []
    for case in table():
        source, record = case["source"], case["record"]
        case_id = "source-coverage-" + case["name"]
        description = {
            "artifacts": {
                "record": {"length": len(record), "path": "report.txt", "sha256": sha(record)},
                "source": {"length": len(source), "path": "source.html", "sha256": sha(source)},
            },
            "case_id": case_id,
            "schema_version": "source-coverage-case/v1",
        }
        policy = {
            "assessments": {
                case_id: {
                    "claim_type": "source_text_coverage/v1",
                    "record_artifact": "record",
                    "record_sha256": sha(record),
                    "record_version": "synthetic-v1",
                    "required_spans": [{"id": "selected", "text": case["span"]}],
                    "source_window": {"end": case["window"][1], "start": case["window"][0]},
                    "source_witness": "capture",
                }
            },
            "schema_version": "source-coverage-policy/v1",
            "witnesses": {
                "capture": {
                    "artifact": "source",
                    "authority": "Synthetic fixture; no public archive claim",
                    "captured_at": "2019-06-26T12:00:00Z",
                    "sha256": sha(source),
                    "source_format": "html_article_text/v1",
                    "source_url": "https://example.org/synthetic-source",
                }
            },
        }
        files = {
            "case.json": pretty(description),
            "policy.json": pretty(policy),
            "report.txt": record,
        }
        if case["captured"]:
            files["source.html"] = source
        entries.append(
            {
                "expected": {"decision": case["decision"], "reason": case["reason"]},
                "files": write_case(out, case["name"], files),
                "id": case["name"],
                "path": "cases/" + case["name"],
            }
        )
    write_manifest(
        out,
        entries,
        suite="source-text-coverage/v1",
        verifierContract="verifier case.json --policy policy.json --json",
    )


if __name__ == "__main__":
    mint(Path(sys.argv[1]))
