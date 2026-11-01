"""Build the deterministic open-weight release cases for AI Act Article 53(2)."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUITE = "open-weight-art53/v1"
BASE = "https://example.org/models/example-7b"
GOOD = {
    "schema_version": "open-weight-release/v1",
    "model": "example-7b",
    "provider": "Example Lab",
    "released": "2026-01-15",
    "licence": {"spdx": "Apache-2.0", "url": f"{BASE}/LICENSE"},
    "weights": {"access": "public", "url": f"{BASE}/weights.safetensors",
                "sha256": hashlib.sha256(b"example-7b weights").hexdigest()},
    "architecture": {"url": f"{BASE}/architecture.md"},
    "usage": {"url": f"{BASE}/usage.md"},
    "monetisation": [],
    "training": {"compute_flop": 3.0e24},
    "systemic_risk": {},
    "copyright_policy": {"url": f"{BASE}/copyright-policy.md"},
    "training_summary": {"url": f"{BASE}/training-summary.md"},
}


def _variant(**changes: object) -> dict:
    release = copy.deepcopy(GOOD)
    for key, value in changes.items():
        if value is None:
            release.pop(key, None)
        else:
            release[key] = value
    return release


# id, release, decision, reason. The order is the order of the README table.
CASES = (
    ("exempt-open-release", GOOD, "exempt", "all_conditions_evidenced"),
    ("exempt-attribution-licence",
     _variant(licence={"spdx": "CC-BY-4.0", "url": f"{BASE}/LICENSE"}),
     "exempt", "all_conditions_evidenced"),
    ("exempt-without-copyright-policy", _variant(copyright_policy=None, training_summary=None),
     "exempt", "all_conditions_evidenced"),
    ("exempt-systemic-presumption-rebutted",
     _variant(training={"compute_flop": 2.0e25},
              systemic_risk={"commission_decision_not_systemic": f"{BASE}/commission-decision"}),
     "exempt", "all_conditions_evidenced"),
    ("noncommercial-licence",
     _variant(licence={"spdx": "CC-BY-NC-4.0", "url": f"{BASE}/LICENSE"}),
     "not-exempt", "licence_restricts_use"),
    ("licence-not-recognised", _variant(licence={"spdx": "LicenseRef-example-custom"}),
     "not-established", "licence_not_recognised"),
    ("weights-private", _variant(weights={"access": "private"}),
     "not-exempt", "weights_not_public"),
    ("weights-gated", _variant(weights={**GOOD["weights"], "access": "gated"}),
     "not-established", "weights_access_gated"),
    ("weights-without-digest",
     _variant(weights={"access": "public", "url": f"{BASE}/w.safetensors"}),
     "not-established", "weights_not_digest_bound"),
    ("architecture-missing", _variant(architecture=None),
     "not-established", "architecture_not_evidenced"),
    ("usage-information-missing", _variant(usage=None),
     "not-established", "usage_information_not_evidenced"),
    ("monetised-by-personal-data", _variant(monetisation=["access-requires-personal-data"]),
     "not-exempt", "monetised_release"),
    ("monetisation-not-stated", _variant(monetisation=None),
     "not-established", "monetisation_not_stated"),
    ("systemic-risk-presumed", _variant(training={"compute_flop": 2.0e25}),
     "not-exempt", "systemic_risk_presumed"),
    ("systemic-risk-designated",
     _variant(systemic_risk={"commission_designation": f"{BASE}/designation"}),
     "not-exempt", "systemic_risk_designated"),
    ("training-compute-not-stated", _variant(training=None),
     "not-established", "training_compute_not_stated"),
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
    """Write the cases under ``root`` and return the manifest.

    Parameters
    ----------
    root : Path
        Output corpus directory.

    Returns
    -------
    dict
        Manifest with the expected decision for every case and its byte commitments.
    """
    entries = []
    for name, release, decision, reason in CASES:
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        files = {
            "case.json": _json({"schema_version": "open-weight-case/v1", "case_id": name,
                                "release": "release.json"}),
            "release.json": _json(release),
        }
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({"id": name, "path": f"cases/{name}",
                        "files": {key: _digest(value) for key, value in sorted(files.items())},
                        "expected": {"decision": decision, "reason": reason}})
    manifest = {"suite": SUITE, "vectors": entries,
                "verifierContract": "verifier case.json --json"}
    manifest["corpusDigest"] = _digest(_json(entries))
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
