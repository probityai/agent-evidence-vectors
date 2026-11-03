"""Build the evidence-state cases byte-identically.

Every case is one record: a system, the code its producer declares and the
observations that ground it. Each allowed case is a control at one of the nine
codes, so a verifier that denies everything, or reads every silence as clean,
fails the corpus. Each denied case changes a control so the check it names is
the first that fails and every earlier check passes. Every member is synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import evidencestate as reader  # noqa: E402

SUITE = reader.SUITE
QUIET = {"anomaliesRecorded": 0, "changeThreshold": 5, "containmentRecorded": False,
         "containmentVerified": False, "coverageMeasured": True,
         "externalEffectsConfirmed": False, "pathwayIdentified": False,
         "propagationObserved": False, "restartRequested": False, "scopeBounded": False}
#: The observations of one control per code, each a change to QUIET.
LADDER: dict[str, dict[str, Any]] = {
    "ES0": {"coverageMeasured": False},
    "ES1": {},
    "ES2": {"anomaliesRecorded": 1},
    "ES3": {"anomaliesRecorded": 6},
    "ES4": {"anomaliesRecorded": 6, "propagationObserved": True},
    "ES5": {"anomaliesRecorded": 6, "propagationObserved": True, "pathwayIdentified": True},
    "ES6": {"anomaliesRecorded": 6, "propagationObserved": True, "pathwayIdentified": True,
            "scopeBounded": True, "containmentRecorded": True, "containmentVerified": True},
    "ES7": {"anomaliesRecorded": 6, "propagationObserved": True, "pathwayIdentified": True,
            "externalEffectsConfirmed": True},
    "ES8": {"anomaliesRecorded": 6, "propagationObserved": True, "pathwayIdentified": True,
            "scopeBounded": True, "containmentRecorded": True, "containmentVerified": True,
            "restartRequested": True},
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def build(name: str, state: str, seen: dict[str, Any], **top: Any) -> dict[str, Any]:
    """One record: the declared code and the observations at one assessment."""
    record: dict[str, Any] = {
        "assessedAt": "2026-11-02T09:00:00Z",
        "contractId": reader.CONTRACT_ID,
        "evidenceState": state,
        "observations": {**QUIET, **seen},
        "recordId": f"record-{name}",
        "system": "agent-system-1",
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


Case = tuple[str, dict[str, Any], str, str, str]

_CONTROL_TEXT = {
    "ES0": "no anomaly and coverage never measured, declared as the unmeasured silence it is",
    "ES1": "no anomaly over monitors whose coverage was measured",
    "ES2": "one anomaly below the declared threshold of five",
    "ES3": "six anomalies past the declared threshold of five",
    "ES4": "propagation observed with its pathway not identified",
    "ES5": "the pathway identified and the scope not yet bounded",
    "ES6": "the scope bounded and containment verified",
    "ES7": "effects confirmed outside the organisation",
    "ES8": "containment recorded and a restart requested",
}


def _controls() -> list[Case]:
    ok = reader.ALLOWED_REASON
    cases = [(f"allow-{code.lower()}", build(f"allow-{code.lower()}", code, seen), "allow", ok,
              f"control: {_CONTROL_TEXT[code]}") for code, seen in LADDER.items()]
    cases.append(("allow-es2-two-anomalies-below-threshold",
                  build("allow-es2-two-anomalies-below-threshold", "ES2",
                        {"anomaliesRecorded": 2}),
                  "allow", ok, "control: two anomalies below the declared threshold stay ES2"))
    cases.append(("allow-es2-no-threshold-declared",
                  build("allow-es2-no-threshold-declared", "ES2",
                        {"anomaliesRecorded": 9, "changeThreshold": None}),
                  "allow", ok, "control: with no threshold declared, nine anomalies are ES2"))
    return cases


def _denied() -> list[Case]:
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    es6, es2 = LADDER["ES6"], LADDER["ES2"]
    return [
        ("reject-contract-id-missing", build("reject-contract-id-missing", "ES1", {},
                                             contractId=None),
         "deny", "contract_id_missing", "the record names no contract"),
        ("reject-contract-id-unknown", build("reject-contract-id-unknown", "ES1", {},
                                             contractId=unknown),
         "deny", "contract_id_unknown", "the record names a contract version that does not "
         "exist"),
        ("reject-record-malformed", build("reject-record-malformed", "ES2",
                                          {"anomaliesRecorded": -1}),
         "deny", "record_malformed", "a negative anomaly count"),
        ("reject-state-unregistered", build("reject-state-unregistered", "ES9", es6),
         "deny", "evidence_state_unregistered", "a code the vocabulary does not define"),
        ("reject-pathway-without-propagation",
         build("reject-pathway-without-propagation", "ES5",
               {"anomaliesRecorded": 6, "pathwayIdentified": True}),
         "deny", "observations_inconsistent", "a propagation pathway identified for a "
         "propagation nobody observed"),
        ("reject-propagation-without-anomaly",
         build("reject-propagation-without-anomaly", "ES4", {"propagationObserved": True}),
         "deny", "observations_inconsistent", "propagation observed beside no recorded "
         "anomaly"),
        ("reject-verified-containment-unrecorded",
         build("reject-verified-containment-unrecorded", "ES6",
               {**es6, "containmentRecorded": False}),
         "deny", "observations_inconsistent", "containment verified that was never recorded"),
        ("reject-clean-without-coverage",
         build("reject-clean-without-coverage", "ES1", {"coverageMeasured": False}),
         "deny", "clean_without_coverage", "a silence declared clean over monitors whose "
         "coverage nobody measured"),
        ("reject-es3-below-threshold",
         build("reject-es3-below-threshold", "ES3", {"anomaliesRecorded": 4}),
         "deny", "evidence_state_unsupported", "four anomalies declared past a threshold of "
         "five"),
        ("reject-es6-containment-unverified",
         build("reject-es6-containment-unverified", "ES6", {**es6, "containmentVerified": False}),
         "deny", "evidence_state_unsupported", "the scope declared bounded and contained with "
         "containment recorded and not verified"),
        ("reject-es8-containment-unrecorded",
         build("reject-es8-containment-unrecorded", "ES8",
               {**LADDER["ES5"], "restartRequested": True}),
         "deny", "evidence_state_unsupported", "a restart requested with no containment "
         "recorded, declared as the post-containment state"),
        ("reject-es1-with-anomaly",
         build("reject-es1-with-anomaly", "ES1", es2),
         "deny", "evidence_state_understated", "a recorded anomaly declared as a clean "
         "silence"),
        ("reject-es2-with-propagation",
         build("reject-es2-with-propagation", "ES2", LADDER["ES4"]),
         "deny", "evidence_state_understated", "observed propagation declared as a single "
         "anomaly"),
        ("reject-es6-with-external-effects",
         build("reject-es6-with-external-effects", "ES6",
               {**es6, "externalEffectsConfirmed": True}),
         "deny", "evidence_state_understated", "effects confirmed outside the organisation "
         "declared as contained inside it"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    return [*_controls(), *_denied()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {"record.json": _sha(data)}, "id": name,
                        "path": f"cases/{name}", "retained": reader.retained(copy.deepcopy(body))})
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "suite": SUITE,
        "synthetic": True,
        "termUri": reader.TERM_URI,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
