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

# A scanner that reached its fetch cap, printed the truncation, and reported a
# clean account anyway (sushant-me/reputation@95717bd, case2_truncation_exit_code.py,
# the defect arm: exit 0 over 40 unopened repositories). The source is the report a
# complete scan of the twelve repositories produces; the selected passage is the
# last repository's line.
REPOS = [f"repo-{n:02d} scanned: no credential-shaped value" for n in range(1, 13)]
SCAN_SOURCE = ("<!doctype html><html><head><title>scan</title></head><body><article>" +
               "".join(f"<p>{line}</p>" for line in REPOS) +
               "</article></body></html>\n").encode()
LAST_REPO = REPOS[-1]
TRUNCATED_SCAN = ("\n".join(REPOS[:7]) + "\ntruncated: 5 repo(s) not opened\n"
                  "no credential-shaped values found in public repositories\n").encode()
COMPLETE_SCAN = ("\n".join(REPOS) + "\n"
                 "no credential-shaped values found in public repositories\n").encode()

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
    ("scanner-truncation-reported-clean", TRUNCATED_SCAN, LAST_REPO,
     "2019-06-26T12:00:00Z", "2019-06-26T00:00:00Z",
     "2019-06-26T23:59:59Z", True,
     "contradicted", "selected_span_missing_from_record", SCAN_SOURCE),
    ("scanner-complete-scan", COMPLETE_SCAN, LAST_REPO,
     "2019-06-26T12:00:00Z", "2019-06-26T00:00:00Z",
     "2019-06-26T23:59:59Z", True,
     "supported", "all_selected_spans_present", SCAN_SOURCE),
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(manifest: dict, root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        actual = {p.name for p in directory.iterdir() if p.is_file()}
        if actual != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _digest((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _digest(_json(entries))


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
    for case in CASES:
        name, record, span, captured_at, start, end, capture_present, decision, reason, *own = case
        source = own[0] if own else SOURCE
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case_id = f"source-coverage-{name}"
        case = {
            "schema_version": "source-coverage-case/v1", "case_id": case_id,
            "artifacts": {
                "source": {"path": "source.html", "sha256": _digest(source),
                           "length": len(source)},
                "record": {"path": "report.txt", "sha256": _digest(record),
                           "length": len(record)},
            },
        }
        policy = {
            "schema_version": "source-coverage-policy/v1",
            "witnesses": {"capture": {
                "artifact": "source", "sha256": _digest(source),
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
            files["source.html"] = source
        else:
            (directory / "source.html").unlink(missing_ok=True)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({"id": name, "path": f"cases/{name}",
                        "files": {key: _digest(value) for key, value in sorted(files.items())},
                        "expected": {"decision": decision, "reason": reason}})
    manifest = {"suite": "source-text-coverage/v1", "vectors": entries,
                "verifierContract": "verifier case.json --policy policy.json --json"}
    manifest["corpusDigest"] = _digest(_json(entries))
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
