"""Build an artifact-binding manifest from a Harbor trial directory.

The contract is ``spec/artifact-binding/v1.md``. This module implements section
3 (the manifest), section 5 (the ATIF binding) and section 6 (the required-role
profile), and nothing else: it reads finalized bytes off disk and writes a
record about them. It never mutates the trial directory and it never consults
Harbor's own equality machinery, which compares configurations for resume and
cache decisions and is not a wire format.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from jcs import JSONValue, canonical_bytes, digest

SCHEMA_VERSION = "artifact-binding/v1"
TOOL_NAME = "aee-bind"
TOOL_VERSION = "1.0.0"
PROFILE_NAME = "harbor/single-step/v1"

#: Roles a complete record must carry under ``harbor/single-step/v1``. Held here
#: rather than read from the record, because a producer that chooses its own
#: completeness bar can withdraw a role and still look complete; the contract
#: puts the profile on the consumer side for the reason AEE puts the demanded
#: assessment classes there (vendored spec lines 1837 to 1864).
REQUIRED_ROLES: tuple[str, ...] = (
    "atif_trajectory",
    "trial_result",
    "verifier_files",
    "reward",
    "grading_stdout",
    "grading_stderr",
)

#: The ``dependency-selection/v1`` profile: a record of one AI-assisted
#: dependency change. The consumer, not the producer, holds this bar, for the
#: same reason as above. Each role is one piece of evidence a reviewer of the
#: change needs and cannot reconstruct afterwards: the lockfile before and
#: after, the skill or instruction file that was in force when the agent chose,
#: the output of every check that ran over the choice, and the human approval.
DEPENDENCY_SELECTION_PROFILE = "dependency-selection/v1"
DEPENDENCY_SELECTION_ROLES: tuple[str, ...] = (
    "lockfile_before",
    "lockfile_after",
    "skill_instructions",
    "provenance_check_output",
    "vulnerability_scan_output",
    "approval",
)

#: Every profile a consumer may name, with the roles it requires. A profile
#: absent from this table is refused, never treated as "no roles required".
PROFILES: dict[str, tuple[str, ...]] = {
    PROFILE_NAME: REQUIRED_ROLES,
    DEPENDENCY_SELECTION_PROFILE: DEPENDENCY_SELECTION_ROLES,
}

#: Covered when present, never required: Harbor does not always produce them.
OPTIONAL_ROLES: tuple[str, ...] = ("trial_lock", "collection_manifest")

#: The roles that make up the ARCHIVE: what the agent execution left behind, as
#: opposed to what a grading operation produced. ``source_archive_digest`` is
#: computed over these alone, so a regrade of the same saved bytes with a
#: different verifier carries the same value as the record it derives from. That
#: equality is what makes the fourth demonstration arm checkable.
ARCHIVE_ROLES: frozenset[str] = frozenset(
    {"atif_trajectory", "collected_artifact", "trial_lock", "trial_result"}
)

#: The one role that lives in ``verification_inputs.grading_inputs`` rather than
#: in ``artifacts``, because it is an input to grading and not an output of the
#: run.
GRADING_INPUT_ROLE = "verifier_files"


class BindingError(Exception):
    """A record could not be built, and the tool refuses rather than guessing."""


@dataclass(frozen=True)
class Entry:
    """One covered file: a role, a relative path, a length and a digest."""

    role: str
    path: str
    length: int
    sha256: str

    def as_json(self) -> dict[str, JSONValue]:
        return {
            "role": self.role,
            "path": self.path,
            "length": self.length,
            "sha256": self.sha256,
        }


@dataclass
class Uncovered:
    """A dependency the record names and does not cover."""

    reference: str
    reason: str

    def as_json(self) -> dict[str, JSONValue]:
        return {"reference": self.reference, "reason": self.reason}


@dataclass
class TrialFacts:
    """What was read off a trial directory before any record was written."""

    trial_id: str | None
    trial_id_source: str
    task_name: str
    reward: float | None
    reward_path: str | None
    entries: list[Entry] = field(default_factory=list)
    grading_inputs: list[Entry] = field(default_factory=list)
    uncovered: list[Uncovered] = field(default_factory=list)
    atif_trajectory_id: str | None = None
    atif_pointer: dict[str, JSONValue] | None = None


def file_entry(root: Path, path: Path, role: str) -> Entry:
    """A covered-file entry for *path*, relative to *root*."""
    raw = path.read_bytes()
    return Entry(
        role=role,
        path=path.relative_to(root).as_posix(),
        length=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def safe_relative(root: Path, path: Path) -> bool:
    """Whether *path* stays inside *root* after symlink resolution.

    The threat-model row for untrusted archive paths says this record covers
    the integrity of declared bytes AFTER safe resolution and does not itself
    make extraction safe. This is the resolution half.
    """
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return resolved.is_relative_to(root.resolve())


def read_reward(trial_dir: Path) -> tuple[float | None, str | None]:
    """The reward the grading produced, and the covered path it was read from."""
    text_path = trial_dir / "verifier" / "reward.txt"
    if text_path.exists():
        try:
            return float(text_path.read_text(encoding="utf-8").strip()), "verifier/reward.txt"
        except ValueError:
            return None, "verifier/reward.txt"
    json_path = trial_dir / "verifier" / "reward.json"
    if json_path.exists():
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "reward" in payload:
            value = payload["reward"]
            if isinstance(value, int | float):
                return float(value), "verifier/reward.json"
        return None, "verifier/reward.json"
    return None, None


def find_atif(trial_dir: Path) -> Path | None:
    """The finalized ATIF trajectory document, if the agent wrote one.

    ATIF v1.7 documents declare ``schema_version`` starting ``ATIF-``. Matching
    on that rather than on a filename means a producer that names the file
    anything still gets it covered, and a producer that wrote no trajectory is
    reported as missing the role rather than as having an empty one.
    """
    agent_dir = trial_dir / "agent"
    if not agent_dir.is_dir():
        return None
    for candidate in sorted(agent_dir.rglob("*.json")):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue
        if isinstance(payload, dict):
            version = payload.get("schema_version")
            if isinstance(version, str) and version.startswith("ATIF-"):
                return candidate
    return None


def atif_facts(path: Path) -> tuple[str | None, dict[str, JSONValue] | None, list[Uncovered]]:
    """The trajectory id, the discoverability pointer and uncovered dependencies.

    A pointer at root ``extra.artifact_binding`` is a breadcrumb and grants no
    trust; the authoritative relation runs from the manifest to these bytes.
    External references the record does not cover are returned so the caller can
    report the dependency set as incomplete rather than staying silent.
    """
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise BindingError(f"{path} is not an ATIF document")
    trajectory_id = payload.get("trajectory_id")
    extra = payload.get("extra")
    pointer = None
    if isinstance(extra, dict):
        candidate = extra.get("artifact_binding")
        if isinstance(candidate, dict):
            pointer = candidate
    uncovered: list[Uncovered] = []
    continued = payload.get("continued_trajectory_ref")
    if isinstance(continued, str) and continued:
        uncovered.append(Uncovered(continued, "continuation trajectory outside the covered set"))
    uncovered.extend(_external_subagent_refs(payload))
    return (
        trajectory_id if isinstance(trajectory_id, str) else None,
        pointer,
        uncovered,
    )


def _external_subagent_refs(payload: dict[str, JSONValue]) -> list[Uncovered]:
    """Subagent trajectories held in a separate file, which this record does not cover."""
    out: list[Uncovered] = []
    steps = payload.get("steps")
    if not isinstance(steps, list):
        return out
    for step in steps:
        if not isinstance(step, dict):
            continue
        observation = step.get("observation")
        if not isinstance(observation, dict):
            continue
        results = observation.get("results")
        if not isinstance(results, list):
            continue
        out.extend(_refs_in_results(results))
    return out


def _refs_in_results(results: list[JSONValue]) -> list[Uncovered]:
    """External subagent references carried by one step's observation results."""
    out: list[Uncovered] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        refs = result.get("subagent_trajectory_ref")
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict) and isinstance(ref.get("trajectory_path"), str):
                out.append(
                    Uncovered(
                        str(ref["trajectory_path"]),
                        "external subagent trajectory outside the covered set",
                    )
                )
    return out


def collect_facts(trial_dir: Path, verifier_dir: Path | None = None) -> TrialFacts:
    """Read a Harbor trial directory into the facts a record is built from."""
    result_path = trial_dir / "result.json"
    if not result_path.exists():
        raise BindingError(f"{trial_dir} is not a trial directory (no result.json)")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    trial_id = result.get("id") if isinstance(result, dict) else None
    task_name = result.get("task_name") if isinstance(result, dict) else None
    reward, reward_path = read_reward(trial_dir)

    facts = TrialFacts(
        trial_id=str(trial_id) if isinstance(trial_id, str) else None,
        trial_id_source="result.json:id" if isinstance(trial_id, str) else "absent",
        task_name=str(task_name) if isinstance(task_name, str) else trial_dir.name,
        reward=reward,
        reward_path=reward_path,
    )
    _collect_run_artifacts(trial_dir, facts)
    collect_grading_inputs(trial_dir, verifier_dir, facts)
    return facts


def _collect_run_artifacts(trial_dir: Path, facts: TrialFacts) -> None:
    """Every covered output of the run, by role."""
    fixed: tuple[tuple[str, str], ...] = (
        ("trial_result", "result.json"),
        ("trial_lock", "lock.json"),
        ("collection_manifest", "artifacts/manifest.json"),
        ("grading_stdout", "verifier/test-stdout.txt"),
        ("grading_stderr", "verifier/test-stderr.txt"),
    )
    for role, rel in fixed:
        path = trial_dir / rel
        if path.is_file() and safe_relative(trial_dir, path):
            facts.entries.append(file_entry(trial_dir, path, role))

    if facts.reward_path is not None:
        reward_file = trial_dir / facts.reward_path
        if reward_file.is_file():
            facts.entries.append(file_entry(trial_dir, reward_file, "reward"))

    atif_path = find_atif(trial_dir)
    if atif_path is not None and safe_relative(trial_dir, atif_path):
        facts.entries.append(file_entry(trial_dir, atif_path, "atif_trajectory"))
        trajectory_id, pointer, uncovered = atif_facts(atif_path)
        facts.atif_trajectory_id = trajectory_id
        facts.atif_pointer = pointer
        facts.uncovered.extend(uncovered)

    artifacts_dir = trial_dir / "artifacts"
    if artifacts_dir.is_dir():
        for path in sorted(artifacts_dir.rglob("*")):
            if path.is_file() and path.name != "manifest.json" and safe_relative(trial_dir, path):
                facts.entries.append(file_entry(trial_dir, path, "collected_artifact"))


#: Where captured grading inputs land inside the trial directory.
GRADING_INPUT_DIR = "binding/grading-inputs"


def collect_grading_inputs(trial_dir: Path, verifier_dir: Path | None, facts: TrialFacts) -> None:
    """Capture the verifier or test files INTO the archive, then cover them.

    A verifier that lives outside the trial directory is not re-checkable: a
    consumer holding only the archive cannot hash a file it does not have, and a
    record that named such a path would be asserting something nobody can
    verify offline. So the grading inputs are copied under
    ``binding/grading-inputs/`` first and covered at their captured paths. This
    is the same requirement Harbor already enforces for regrade in a weaker
    form, where the new verifier's declared inputs must be present in the source
    trial's collection manifest; here the bytes themselves are pinned rather
    than the fact that a collection was attempted.
    """
    if verifier_dir is None or not verifier_dir.is_dir():
        return
    captured_root = trial_dir / GRADING_INPUT_DIR
    for path in sorted(verifier_dir.rglob("*")):
        if not path.is_file() or not safe_relative(verifier_dir, path):
            continue
        destination = captured_root / path.relative_to(verifier_dir)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.resolve() != path.resolve():
            shutil.copy2(path, destination)
        facts.grading_inputs.append(file_entry(trial_dir, destination, GRADING_INPUT_ROLE))


def _sorted_entries(entries: list[Entry]) -> list[dict[str, JSONValue]]:
    """Entries in ``(role, path)`` order, so two producers write the same bytes."""
    return [entry.as_json() for entry in sorted(entries, key=lambda e: (e.role, e.path))]


def archive_digest(entries: list[Entry]) -> str:
    """The identity of the saved archive: the run's outputs, not the grading's.

    Restricted to ``ARCHIVE_ROLES`` on purpose. A regrade produces a new reward,
    a new grading stdout and a new grading stderr, so a digest over every
    covered entry would differ between two gradings of one archive and the
    lineage check in section 8 of the contract could never hold.
    """
    archive = [entry for entry in entries if entry.role in ARCHIVE_ROLES]
    return digest(list(_sorted_entries(archive)))


def verifier_digest(grading_inputs: list[Entry]) -> str:
    """The identity of the grading inputs; a changed verifier changes this alone."""
    return digest(list(_sorted_entries(grading_inputs)))


def build(
    facts: TrialFacts,
    *,
    operation: str = "execute",
    verifier_id: str = "unknown",
    signer_key_id: str,
    source_record_digest: str | None = None,
    recorded_at: str | None = None,
    producer_id: str = "independent",
    framework: str = "harbor",
) -> dict[str, JSONValue]:
    """The manifest object for *facts*, ready to canonicalize and sign."""
    if operation not in ("execute", "regrade"):
        raise BindingError(f"operation is 'execute' or 'regrade', not {operation!r}")
    if operation == "regrade" and source_record_digest is None:
        raise BindingError("a regrade record must carry source_record_digest")
    stamp = recorded_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    atif_present = any(entry.role == "atif_trajectory" for entry in facts.entries)
    atif_sha = next(
        (entry.sha256 for entry in facts.entries if entry.role == "atif_trajectory"), None
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "producer": {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "producer_id": producer_id,
        },
        "run": {
            "framework": framework,
            "trial_id": facts.trial_id,
            "trial_id_source": facts.trial_id_source,
            "task_name": facts.task_name,
            "recorded_at": stamp,
        },
        "operation": operation,
        "artifacts": list(_sorted_entries(facts.entries)),
        "source_record_digest": source_record_digest,
        "source_archive_digest": archive_digest(facts.entries),
        "verification_inputs": {
            "verifier_id": verifier_id,
            "verifier_digest": verifier_digest(facts.grading_inputs),
            "grading_inputs": list(_sorted_entries(facts.grading_inputs)),
        },
        "dependencies": {
            "status": "incomplete" if facts.uncovered else "covered",
            "uncovered": [item.as_json() for item in facts.uncovered],
        },
        "atif": {
            "present": atif_present,
            "trajectory_id": facts.atif_trajectory_id,
            "document_sha256": atif_sha,
            "pointer": facts.atif_pointer,
        },
        "graded_outcome": {"reward": facts.reward, "source_path": facts.reward_path},
        "signer_key_id": signer_key_id,
    }


def write(manifest: dict[str, JSONValue], path: Path) -> bytes:
    """Write *manifest* in canonical form and return the bytes that were written."""
    raw = canonical_bytes(manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw
