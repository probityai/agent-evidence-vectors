"""Build deterministic source-coverage cases for an external adjudicator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIRST = "The publisher described the initial incident."
SECOND = "Several channels were removed after the publisher contacted the platform."
THIRD = "The publisher later corrected the incident date."
SOURCE = ("<!doctype html><html><head><script>" +
          "A hidden claim was never published.</script></head><body><article>" +
          f"<p>{FIRST}</p><p>{SECOND}</p><p>{THIRD}</p>" +
          "</article></body></html>\n").encode()
FULL = f"{FIRST}\n{SECOND}\n{THIRD}\n".encode()

# The record bytes and their case digests change together. The consumer policy
# stays separate, so a producer cannot narrow the required source passage.
CASES = (
    ("complete", FULL, SECOND, "2019-06-26T12:00:00Z",
     "2019-06-26T00:00:00Z", "2019-06-26T23:59:59Z", True,
     "supported", "all_selected_spans_present"),
    ("self-hashed-truncation", f"{FIRST}\nSeveral channels were rem".encode(),
     SECOND, "2019-06-26T12:00:00Z", "2019-06-26T00:00:00Z",
     "2019-06-26T23:59:59Z", True,
     "contradicted", "selected_span_missing_from_record"),
    ("middle-omission", f"{FIRST}\n{THIRD}\n".encode(), SECOND,
     "2019-06-26T12:00:00Z", "2019-06-26T00:00:00Z",
     "2019-06-26T23:59:59Z", True,
     "contradicted", "selected_span_missing_from_record"),
    ("returned-after-requested-window", FULL, SECOND,
     "2019-06-26T12:00:00Z", "2019-04-13T00:00:00Z",
     "2019-04-13T23:59:59Z", True,
     "not_established", "witness_outside_source_window"),
    ("capture-absent", FULL, SECOND, "2019-06-26T12:00:00Z",
     "2019-06-26T00:00:00Z", "2019-06-26T23:59:59Z", False,
     "not_established", "artifact_unavailable_or_unbound"),
    ("hidden-script-only", FULL, "A hidden claim was never published.",
     "2019-06-26T12:00:00Z", "2019-06-26T00:00:00Z",
     "2019-06-26T23:59:59Z", True,
     "not_established", "selected_span_not_in_witness"),
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def generate(root: Path = ROOT) -> dict:
    """Write cases and return the manifest.

    Parameters
    ----------
    root : Path
        Output corpus directory.

    Returns
    -------
    dict
        Manifest with expected decisions and byte commitments.
    """
    entries = []
    for (name, record, span, captured_at, start, end, capture_present,
         decision, reason) in CASES:
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case_id = f"source-coverage-{name}"
        case = {
            "schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": {
                "source": {"path": "source.html", "sha256": _digest(SOURCE),
                           "length": len(SOURCE)},
                "record": {"path": "report.txt", "sha256": _digest(record),
                           "length": len(record)},
            },
        }
        policy = {
            "schema_version": "probity-policy/v1",
            "witnesses": {"capture": {
                "artifact": "source", "sha256": _digest(SOURCE),
                "captured_at": captured_at,
                "source_url": "https://example.org/synthetic-source",
                "authority": "Synthetic fixture; no public archive claim",
                "source_format": "html_article_text/v1",
            }},
            "assessments": {case_id: {
                "claim_type": "source_text_coverage/v1",
                "source_witness": "capture", "record_artifact": "record",
                "record_sha256": _digest(record), "record_version": "synthetic-v1",
                "source_window": {"start": start, "end": end},
                "required_spans": [{"id": "selected", "text": span}],
            }},
        }
        files = {"case.json": _json(case), "policy.json": _json(policy),
                 "report.txt": record}
        if capture_present:
            files["source.html"] = SOURCE
        else:
            (directory / "source.html").unlink(missing_ok=True)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({"id": name, "path": f"cases/{name}",
                        "files": {key: _digest(value) for key, value in sorted(files.items())},
                        "expected": {"decision": decision, "reason": reason}})
    manifest = {"suite": "source-text-coverage/v1", "vectors": entries,
                "verifierContract": "probity-verify case.json --policy policy.json --json"}
    manifest["corpusDigest"] = _digest(_json(entries))
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
