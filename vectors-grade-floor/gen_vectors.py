"""Build the deterministic evidence-grade floor cases.

    uv run python vectors-grade-floor/gen_vectors.py

Each grade E0..E4 of the ladder in AAIF Observability WG issue #37
(https://github.com/aaif/wg-observability-and-traceability/issues/37) gets one
accepted member whose evidence supports exactly that grade, and at least one
rejected twin one mutation away that overclaims. Every case, the manifest and
the index are functions of this file alone.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "evidence-grade-floor/v1"
ISSUE = "https://github.com/aaif/wg-observability-and-traceability/issues/37"
SCHEMA = "evidence-grade-record/v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _hex(label: str) -> str:
    return _sha(label.encode())


SELF_REPORT = {
    "engine": "agent-runtime-log", "source": "self_report", "relationship": "direct",
    "observation_vantage": "artifact", "observation_directness": "reconstructed",
    "witness_scope": "SELF",
}
FRAMEWORK = {
    "engine": "orchestrator-trace", "source": "framework", "relationship": "direct",
    "observation_vantage": "artifact", "observation_directness": "reconstructed",
    "witness_scope": "PEER",
}
GATEWAY = {
    "engine": "egress-gateway", "source": "gateway", "relationship": "independent",
    "observation_vantage": "substrate", "observation_directness": "intercepted",
    "witness_scope": "EXTERNAL",
}
SECOND_ENGINE = {
    "engine": "syscall-supervisor", "source": "gateway", "relationship": "independent",
    "observation_vantage": "substrate", "observation_directness": "intercepted",
    "witness_scope": "EXTERNAL",
}
DENIAL = {"action": "http.post https://exfil.example.invalid/upload",
          "policy": "egress-allowlist/v3", "recorded_by": "egress-gateway"}
MARKERS = {
    "external_timestamp": {"authority": "https://tsa.example.invalid",
                           "token_sha256": _hex("timestamp-token"), "witness_scope": "EXTERNAL"},
    "chain_link": {"prev_sha256": _hex("previous-record")},
    "independent_verification": {"verifier": "https://verifier.example.invalid",
                                 "result": "verified", "witness_scope": "EXTERNAL"},
}
ALL_TRUE = {"external_timestamp": True, "chain_link": True,
            "independent_verification": True}


def _record(grade: str) -> dict[str, Any]:
    """A record whose evidence supports exactly ``grade``."""
    rung = int(grade[1])
    observations = [SELF_REPORT]
    if rung >= 1:
        observations.append(FRAMEWORK)
    if rung >= 2:
        observations.append(GATEWAY)
    if rung >= 3:
        observations.append(SECOND_ENGINE)
    record: dict[str, Any] = {
        "schema": SCHEMA, "declared_grade": grade,
        "claim": "operationally-conformant" if rung >= 3 else "observed",
        "observations": copy.deepcopy(observations),
        "enforcement": {"policy_enforced_at_boundary": rung >= 2,
                        "denials": [dict(DENIAL)] if rung >= 2 else []},
        "reconciliation": "agreement" if rung >= 3 else "no_independent_evidence",
        "integrity_claims": {},
        "integrity_markers": copy.deepcopy(MARKERS) if rung >= 4 else {},
    }
    return record


def _self_stamped_e4(r: dict[str, Any]) -> None:
    r["declared_grade"] = "E4"
    r["integrity_claims"] = dict(ALL_TRUE)


def _conformant_claim(r: dict[str, Any]) -> None:
    r["claim"] = "operationally-conformant"


def _no_denial(r: dict[str, Any]) -> None:
    r["enforcement"]["denials"] = []


def _single_self_report_engine(r: dict[str, Any]) -> None:
    r["observations"][-1] = {**SELF_REPORT, "engine": "agent-self-check"}


def _contradiction(r: dict[str, Any]) -> None:
    r["reconciliation"] = "contradiction"


def _drop_marker(name: str) -> Callable[[dict[str, Any]], None]:
    def mutate(r: dict[str, Any]) -> None:
        del r["integrity_markers"][name]
        r["integrity_claims"] = {name: True}
    return mutate


# (id, accepted twin's grade or None for an accepted member, mutation, the
# derived grade, the refusal code, what the mutation does)
MEMBERS: tuple[tuple[str, str, Callable[[dict[str, Any]], None] | None, str, str, str], ...] = (
    ("e0-declared", "E0", None, "E0", "grade_derived",
     "agent self-report only"),
    ("e1-observed", "E1", None, "E1", "grade_derived",
     "a framework trace observed the run"),
    ("e2-enforced", "E2", None, "E2", "grade_derived",
     "boundary policy enforced and a denial recorded at the substrate"),
    ("e3-corroborated", "E3", None, "E3", "grade_derived",
     "two independent basis engines agree; operationally-conformant claim"),
    ("e4-anchored", "E4", None, "E4", "grade_derived",
     "external timestamp, chain link and independent verification present"),
    ("e0-self-stamped-e4", "E0", _self_stamped_e4, "E0", "e1_no_external_observer",
     "self-report stamped E4 with every integrity boolean true"),
    ("e1-claims-operationally-conformant", "E1", _conformant_claim, "E1",
     "claim_floor_below_e3", "E1 evidence carrying an operationally-conformant claim"),
    ("e2-no-recorded-denial", "E2", _no_denial, "E1", "e2_no_recorded_denial",
     "boundary policy declared enforced, no denial recorded"),
    ("e3-single-self-report-engine", "E3", _single_self_report_engine, "E2",
     "e3_insufficient_independent_engines",
     "second engine replaced by a direct self-report: one independent engine"),
    ("e3-contradiction-claims-conformant", "E3", _contradiction, "E3",
     "claim_floor_contradiction",
     "reconciliation is contradiction under an operationally-conformant claim"),
    ("e4-missing-chain-link", "E4", _drop_marker("chain_link"), "E3",
     "e4_missing_chain_link", "chain-link marker absent, declared true"),
    ("e4-missing-external-timestamp", "E4", _drop_marker("external_timestamp"), "E3",
     "e4_missing_external_timestamp", "external timestamp marker absent, declared true"),
    ("e4-missing-independent-verification", "E4",
     _drop_marker("independent_verification"), "E3",
     "e4_missing_independent_verification",
     "independent verification marker absent, declared true"),
)

_ACCEPT_ID = {grade: name for name, grade, mutate, *_ in MEMBERS if mutate is None}


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Evidence grade floor vectors", "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.", "",
        f"Suite: `{SUITE}`. Ladder: E0-E4 in AAIF Observability WG issue #37 ({ISSUE}).", "",
        f"Corpus digest: `{digest}`", "",
        "| id | decision | derived grade | reason | twin | mutation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(f"| `{e['id']}` | {x['decision']} | {x['derivedGrade']} | "
                     f"`{x['reason']}` | {e.get('twin', '')} | {e['description']} |")
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest and the index; return the manifest."""
    entries = []
    for name, grade, mutate, derived, reason, description in MEMBERS:
        record = _record(grade)
        if mutate is not None:
            mutate(record)
        record["case_id"] = f"grade-floor-{name}"
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(record)
        (directory / "case.json").write_bytes(data)
        entry: dict[str, Any] = {
            "id": name, "path": f"cases/{name}", "files": {"case.json": _sha(data)},
            "description": description,
            "expected": {"decision": "accepted" if mutate is None else "rejected",
                         "derivedGrade": derived, "reason": reason},
        }
        if mutate is not None:
            entry["twin"] = _ACCEPT_ID[grade]
        entries.append(entry)
    digest = _sha(_json(entries))
    manifest = {"suite": SUITE, "ladder": ISSUE, "vectors": entries,
                "verifierContract": "verifier case.json --json", "corpusDigest": digest}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
