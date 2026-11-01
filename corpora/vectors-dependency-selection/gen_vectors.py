#!/usr/bin/env python3
"""Generate the dependency-selection conformance corpus.

One worked record of an AI-assisted dependency change, and one twin per way a
reviewer must refuse it. The record is an artifact-binding/v1 manifest judged
under the consumer-held profile ``dependency-selection/v1``
(``spec/artifact-binding/v1.md`` section 6.2), so the verifier, the signature
scheme and the three verdicts are the ones the artifact-binding corpus already
pins. Regenerate byte-identically with:

    python3 vectors-dependency-selection/gen_vectors.py

The record binds, by SHA-256 and length:

- the lockfile before and after the change (``lockfile_before``,
  ``lockfile_after``);
- the skill or instruction file in force when the agent chose
  (``skill_instructions``), which the consumer additionally pins by digest;
- the output of every check that ran over the choice
  (``provenance_check_output``, ``vulnerability_scan_output``);
- the human approval, which names the approver and the lockfile digest they
  approved (``approval``);
- the check definitions themselves, as grading inputs.

Each reject member differs from the accepting record in one thing. Every input
is fixed: the signing seed is a published TEST key and ``recorded_at`` is a
constant, so two machines produce the same corpus digest.

TEST KEYS ONLY. The seed is the one the artifact-binding corpus publishes.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / "tools" / "artifact-binding"
sys.path.insert(0, str(TOOLS))

import manifest as manifest_mod  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402


def _load_digest() -> Any:
    """The corpus-digest preimage, from this corpus's stdlib-only digest.py."""
    spec = importlib.util.spec_from_file_location("dependency_selection_digest", HERE / "digest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.corpus_digest


corpus_digest = _load_digest()

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RECORDED_AT = "2026-01-01T00:00:00Z"
CASES_DIR = HERE / "cases"
ID_HEX = 16
PROFILE = manifest_mod.DEPENDENCY_SELECTION_PROFILE
FRAMEWORK = "dependency-selection"
CHANGE_ID = "depsel-synthetic-0001"
TASK_NAME = "add-yaml-parser"

LOCK_BEFORE = """# requirements.lock (before)
certifi==2026.7.4 \\
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
"""

LOCK_AFTER = """# requirements.lock (after)
certifi==2026.7.4 \\
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
pyyaml==6.0.3 \\
    --hash=sha256:2222222222222222222222222222222222222222222222222222222222222222
"""

SKILL_IN_FORCE = """# Dependency selection instructions (v1)
1. Prefer a package already in the lockfile over a new one.
2. A new package must have a verifiable build provenance attestation.
3. A new package must have no known vulnerability at the pinned version.
4. Pin the exact version and its hash. Never add a range.
5. A human approves the lockfile diff before it merges.
"""

SKILL_OTHER = """# Dependency selection instructions (v2, not approved)
1. Prefer the most popular package for the task.
2. Pin the exact version and its hash.
"""

PROVENANCE_LOG = """$ provenance-check pyyaml==6.0.3
subject: pyyaml-6.0.3.tar.gz sha256:2222222222222222222222222222222222222222222222222222222222222222
attestation: build provenance present, signature verified
result: PASS
"""

VULN_LOG = """$ vulnerability-scan requirements.lock
scanned: 2 packages
known vulnerabilities: 0
result: PASS
"""

CHECKS = """# Checks run over every dependency change
provenance-check <package>==<version>
vulnerability-scan requirements.lock
"""


def _approval(lock_after: str) -> str:
    """The human approval: who approved, and exactly which lockfile bytes."""
    return (
        json.dumps(
            {
                "approver": "reviewer@example.org",
                "decision": "approved",
                "lockfile_after_sha256": hashlib.sha256(lock_after.encode()).hexdigest(),
                "approved_at": RECORDED_AT,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


#: Role -> path inside the change directory.
LAYOUT: dict[str, str] = {
    "lockfile_before": "lock/before/requirements.lock",
    "lockfile_after": "lock/after/requirements.lock",
    "skill_instructions": "agent/skills/dependency-selection.md",
    "provenance_check_output": "checks/provenance-check.log",
    "vulnerability_scan_output": "checks/vulnerability-scan.log",
    "approval": "approval/approval.json",
}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def vector_id(payload: bytes) -> str:
    return "v" + hashlib.sha256(payload).hexdigest()[:ID_HEX]


def build_change(root: Path, *, skill: str = SKILL_IN_FORCE) -> Path:
    """Write a complete change directory; return it."""
    change = root / "trial"
    contents = {
        "lockfile_before": LOCK_BEFORE,
        "lockfile_after": LOCK_AFTER,
        "skill_instructions": skill,
        "provenance_check_output": PROVENANCE_LOG,
        "vulnerability_scan_output": VULN_LOG,
        "approval": _approval(LOCK_AFTER),
    }
    for role, rel in LAYOUT.items():
        _write(change / rel, contents[role])
    _write(root / "checks-definition" / "checks.txt", CHECKS)
    return change


def sign_change(root: Path, *, omit: tuple[str, ...] = (), seed: bytes = TEST_SEED) -> None:
    """Build, canonicalize and sign the record over the change directory."""
    change = root / "trial"
    entries = [
        manifest_mod.file_entry(change, change / rel, role)
        for role, rel in LAYOUT.items()
        if role not in omit
    ]
    facts = manifest_mod.TrialFacts(
        trial_id=CHANGE_ID,
        trial_id_source="synthetic",
        task_name=TASK_NAME,
        reward=None,
        reward_path=None,
        entries=entries,
    )
    # The check definitions are captured into the change directory and covered
    # as grading inputs, exactly as a Harbor verifier is.
    manifest_mod.collect_grading_inputs(change, root / "checks-definition", facts)
    record = manifest_mod.build(
        facts,
        verifier_id="dependency-checks@v1",
        signer_key_id=sign.key_id(sign.public_bytes(seed)),
        recorded_at=RECORDED_AT,
        framework=FRAMEWORK,
    )
    raw = manifest_mod.write(record, change / "binding" / "manifest.json")
    (change / "binding" / "manifest.sig").write_text(
        sign.sign_bytes(seed, raw).hex(), encoding="utf-8"
    )
    shutil.rmtree(root / "checks-definition")


def case_intact(root: Path) -> None:
    build_change(root)
    sign_change(root)


def case_lockfile_changed(root: Path) -> None:
    case_intact(root)
    swapped = LOCK_AFTER.replace("pyyaml==6.0.3", "pyyaml==6.0.4")
    _write(root / "trial" / LAYOUT["lockfile_after"], swapped)


def case_skill_not_in_force(root: Path) -> None:
    build_change(root, skill=SKILL_OTHER)
    sign_change(root)


def case_scan_absent(root: Path) -> None:
    build_change(root)
    (root / "trial" / LAYOUT["vulnerability_scan_output"]).unlink()
    sign_change(root, omit=("vulnerability_scan_output",))


def case_approval_absent(root: Path) -> None:
    build_change(root)
    shutil.rmtree(root / "trial" / "approval")
    sign_change(root, omit=("approval",))


def case_wrong_signer(root: Path) -> None:
    build_change(root)
    sign_change(root, seed=bytes(range(1, 33)))


CASES: tuple[tuple[str, Any, str, list[str], str], ...] = (
    (
        "intact-selection",
        case_intact,
        "verified",
        [],
        "the worked record: lockfile before and after, the instruction file in force, "
        "the provenance and vulnerability check outputs, and the approval naming the "
        "lockfile digest it approved, all covered and signed by the pinned key",
    ),
    (
        "lockfile-after-changed",
        case_lockfile_changed,
        "failed",
        ["artifact-digest-mismatch"],
        "the lockfile on disk is not the one the record covers and the approval names: "
        "the merged change differs from the reviewed one",
    ),
    (
        "skill-not-in-force",
        case_skill_not_in_force,
        "failed",
        ["role-not-in-force"],
        "every byte matches and the signature holds, but the instruction file the "
        "record covers is not the one the consumer holds as in force",
    ),
    (
        "vulnerability-scan-absent",
        case_scan_absent,
        "not-established",
        ["required-role-absent"],
        "the record carries no vulnerability-scan output. Not a pass and not a "
        "tampering finding: the change cannot be checked to a conclusion",
    ),
    (
        "approval-absent",
        case_approval_absent,
        "not-established",
        ["required-role-absent"],
        "no human approval is covered, so the record does not establish that anyone "
        "approved the lockfile change",
    ),
    (
        "wrong-signer",
        case_wrong_signer,
        "failed",
        ["signer-key-mismatch"],
        "a record correctly signed by a key the consumer did not pin, refused by "
        "identity before the signature is checked",
    ),
)


def in_force() -> dict[str, str]:
    """The consumer's pins: the instruction file its policy says was in force."""
    return {"skill_instructions": hashlib.sha256(SKILL_IN_FORCE.encode()).hexdigest()}


def observed_messages_digest(root: Path) -> str:
    trial = root / "trial"
    outcome = verify_mod.verify(
        trial,
        trial / "binding" / "manifest.json",
        trial / "binding" / "manifest.sig",
        sign.public_bytes(TEST_SEED),
        PROFILE,
        in_force(),
    )
    joined = "\n".join(sorted(outcome.messages))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def build() -> dict[str, Any]:
    if CASES_DIR.exists():
        shutil.rmtree(CASES_DIR)
    CASES_DIR.mkdir(parents=True)
    entries: list[dict[str, Any]] = []
    for name, builder, verdict, codes, cites in CASES:
        root = CASES_DIR / name
        root.mkdir(parents=True)
        builder(root)
        manifest_path = root / "trial" / "binding" / "manifest.json"
        entries.append(
            {
                "id": vector_id(manifest_path.read_bytes() + name.encode("utf-8")),
                "kind": "accept" if verdict == "verified" else "reject",
                "case": f"cases/{name}",
                "trial": f"cases/{name}/trial",
                "manifest": f"cases/{name}/trial/binding/manifest.json",
                "signature": f"cases/{name}/trial/binding/manifest.sig",
                "expected": {
                    "verdict": verdict,
                    "codes": sorted(codes),
                    "messagesDigest": observed_messages_digest(root),
                },
                "cites": cites,
            }
        )
    entries.sort(key=lambda entry: entry["id"])
    verified = sum(1 for entry in entries if entry["expected"]["verdict"] == "verified")
    failed = sum(1 for entry in entries if entry["expected"]["verdict"] == "failed")
    manifest = {
        "suite": "artifact-binding-conformance",
        "contract": "artifact-binding/v1",
        "contractSpec": "spec/artifact-binding/v1.md",
        "profile": PROFILE,
        "inForce": in_force(),
        "publicKey": sign.public_bytes(TEST_SEED).hex(),
        "keyNote": (
            "A published TEST key. The corpus is regenerable by anyone, which is "
            "the point: a suite a stranger cannot rebuild is one they must trust."
        ),
        "counts": {
            "verified": verified,
            "failed": failed,
            "notEstablished": len(entries) - verified - failed,
        },
        "note": (
            "One worked record of an AI-assisted dependency change and one twin per "
            "refusal. profile and inForce are the consumer's: the roles a complete "
            "record must carry, and the instruction-file digest it accepts."
        ),
        "vectors": entries,
    }
    manifest["corpusDigest"] = corpus_digest({"vectors": entries})
    (HERE / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (HERE / "public.key").write_text(sign.public_bytes(TEST_SEED).hex(), encoding="utf-8")
    write_index(entries)
    return manifest


def write_index(entries: list[dict[str, Any]]) -> None:
    lines = [
        "# Dependency-selection corpus index",
        "",
        "Emitted by `gen_vectors.py`. One row per member; what each member is for",
        "is in `MANIFEST.json` under `cites`.",
        "",
        "| id | verdict | codes | case |",
        "|---|---|---|---|",
    ]
    for entry in sorted(entries, key=lambda item: str(item["case"])):
        expected = entry["expected"]
        codes = ", ".join(expected["codes"]) or "(none)"
        lines.append(
            f"| `{entry['id']}` | {expected['verdict']} | {codes} | `{entry['case']}` |"
        )
    (HERE / "INDEX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    built = build()
    print(f"wrote {len(built['vectors'])} vectors, corpusDigest {built['corpusDigest']}")
