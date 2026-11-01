"""A public run registry: a directory of signed conformance result records and an index of them.

``records/<sha256>.dsse.json`` holds one envelope, named by the SHA-256 of its canonical JSON, and
``index.json`` lists every record. The index is a convenience: ``verify_registry`` reads the
records, so an index that omits, adds or mislabels a record fails.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import conformance_result as cr

INDEX_VERSION = 1


def _envelope_digest(envelope: dict) -> str:
    return cr.digest_of(envelope)


def _entry(envelope: dict, verdict: cr.Verdict) -> dict:
    digest = _envelope_digest(envelope)
    return {
        "envelopeSha256": digest,
        "file": f"records/{digest}.dsse.json",
        "implementation": verdict.implementation,
        "suiteRevision": verdict.revision,
        "keyid": verdict.keyid,
    }


def _read_index(root: Path) -> list[dict]:
    path = root / "index.json"
    if not path.exists():
        return []
    index = json.loads(path.read_text(encoding="utf-8"))
    if index.get("version") != INDEX_VERSION or not isinstance(index.get("entries"), list):
        raise ValueError("index.json is not a version 1 registry index")
    return index["entries"]


def add_record(root: Path, envelope: dict, trusted: dict[str, bytes]) -> dict:
    """Append a record the trusted keys vouch for; raise ``ValueError`` for one that does not verify or is already listed."""
    verdict = cr.verify_record(envelope, trusted)
    if not verdict.ok:
        raise ValueError("record does not verify: " + ", ".join(verdict.reasons))
    entries = _read_index(root)
    entry = _entry(envelope, verdict)
    if any(e["envelopeSha256"] == entry["envelopeSha256"] for e in entries):
        raise ValueError(f"record {entry['envelopeSha256']} is already registered")
    (root / "records").mkdir(parents=True, exist_ok=True)
    (root / entry["file"]).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entries.append(entry)
    entries.sort(key=lambda e: (e["implementation"], e["suiteRevision"], e["envelopeSha256"]))
    (root / "index.json").write_text(json.dumps({"version": INDEX_VERSION, "entries": entries}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return entry


def verify_registry(root: Path, trusted: dict[str, bytes]) -> list[dict]:
    """One finding per problem: ``{"file", "reasons"}``. Empty when every record verifies and the index matches the files."""
    findings = []
    listed = {}
    for entry in _read_index(root):
        listed[entry["file"]] = entry
    on_disk = sorted((root / "records").glob("*.dsse.json")) if (root / "records").is_dir() else []
    seen = set()
    for path in on_disk:
        relative = f"records/{path.name}"
        seen.add(relative)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            findings.append({"file": relative, "reasons": [f"unreadable:{error}"]})
            continue
        verdict = cr.verify_record(envelope, trusted)
        reasons = list(verdict.reasons)
        if path.name != f"{_envelope_digest(envelope)}.dsse.json":
            reasons.append("file-name-not-digest")
        entry = listed.get(relative)
        if entry is None:
            reasons.append("not-in-index")
        elif verdict.ok and entry != _entry(envelope, verdict):
            reasons.append("index-entry-differs")
        if reasons:
            findings.append({"file": relative, "reasons": reasons})
    for relative in sorted(set(listed) - seen):
        findings.append({"file": relative, "reasons": ["listed-but-missing"]})
    return findings
