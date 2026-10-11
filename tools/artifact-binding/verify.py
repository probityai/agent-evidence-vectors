"""Offline verification of an artifact-binding record against bytes on disk.

Section 7 of ``spec/artifact-binding/v1.md`` defines exactly three outcomes and
this module produces exactly those three. The distinction that matters, and the
one a signature-only checker cannot make, is between ``failed`` (the record
asserts something the bytes contradict) and ``not-established`` (the record
cannot be checked to a conclusion because something required is absent). A
checker that folds the second into the first reports a producer as dishonest
for a file nobody captured; a checker that folds it into a pass reports an
incomplete record as a good one, which is the failure AEE's consumer
obligations at vendored spec lines 1866 to 1878 exist to prevent.

The verifier reads the manifest, the signature, the public key it was handed
and the files on disk. It contacts nothing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import manifest as manifest_mod
import sign
from jcs import JSONValue, canonical_bytes, is_canonical

VERIFIED = "verified"
FAILED = "failed"
NOT_ESTABLISHED = "not-established"

EXIT_VERIFIED = 0
EXIT_USAGE = 1
EXIT_FAILED = 2
EXIT_NOT_ESTABLISHED = 3

_EXIT_BY_VERDICT = {
    VERIFIED: EXIT_VERIFIED,
    FAILED: EXIT_FAILED,
    NOT_ESTABLISHED: EXIT_NOT_ESTABLISHED,
}


@dataclass
class Outcome:
    """One verdict, the codes that produced it and a line naming what failed."""

    verdict: str
    codes: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return _EXIT_BY_VERDICT[self.verdict]

    def report(self) -> str:
        head = f"verdict: {self.verdict}"
        if not self.messages:
            return head
        return head + "\n" + "\n".join(f"  {line}" for line in self.messages)


def _as_object(raw: bytes) -> dict[str, JSONValue] | None:
    try:
        parsed: JSONValue = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _entries(record: dict[str, JSONValue], key: str) -> list[dict[str, JSONValue]]:
    value = record.get(key)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _grading_inputs(record: dict[str, JSONValue]) -> list[dict[str, JSONValue]]:
    inputs = record.get("verification_inputs")
    if isinstance(inputs, dict):
        return _entries(inputs, "grading_inputs")
    return []


def check_encoding(raw: bytes, out: Outcome) -> dict[str, JSONValue] | None:
    """The manifest parses, is canonical, and declares this contract version."""
    record = _as_object(raw)
    if record is None:
        out.codes.append("manifest-unparseable")
        out.messages.append("the manifest is not a JSON object")
        return None
    if not is_canonical(raw):
        out.codes.append("manifest-encoding-not-canonical")
        out.messages.append(
            "the manifest bytes are not the RFC 8785 form of the value they parse to; "
            "a signature over them verifies only for the party that wrote them"
        )
    if record.get("schema_version") != manifest_mod.SCHEMA_VERSION:
        out.codes.append("schema-version-unsupported")
        out.messages.append(
            f"schema_version is {record.get('schema_version')!r}, "
            f"and this verifier implements {manifest_mod.SCHEMA_VERSION!r}"
        )
    return record


def check_signer(record: dict[str, JSONValue], public_key: bytes, out: Outcome) -> None:
    """The record names the key the consumer pinned.

    Checked by identity before the signature is checked, so a record signed by
    an unexpected key is refused by name rather than by a signature failure that
    reads like corruption.
    """
    expected = sign.key_id(public_key)
    declared = record.get("signer_key_id")
    if declared != expected:
        out.codes.append("signer-key-mismatch")
        out.messages.append(
            f"the record names signer {declared!r} and the pinned key is {expected!r}"
        )


def check_artifacts(
    trial_dir: Path, record: dict[str, JSONValue], out: Outcome
) -> tuple[set[str], bool]:
    """Every covered file exists with its declared length and digest.

    Returns the roles that were checked, and whether any covered file was
    absent, because absence and mismatch are different verdicts.
    """
    roles: set[str] = set()
    absent = False
    for entry in _entries(record, "artifacts") + _grading_inputs(record):
        role = str(entry.get("role", ""))
        rel = str(entry.get("path", ""))
        roles.add(role)
        path = trial_dir / rel
        if ".." in Path(rel).parts or Path(rel).is_absolute():
            out.codes.append("artifact-path-unsafe")
            out.messages.append(f"{rel}: the declared path escapes the trial directory")
            continue
        if not path.is_file():
            absent = True
            out.codes.append("artifact-absent")
            out.messages.append(f"{rel}: covered by the record and not present on disk")
            continue
        blob = path.read_bytes()
        if len(blob) != entry.get("length"):
            out.codes.append("artifact-length-mismatch")
            out.messages.append(
                f"{rel}: the record declares {entry.get('length')} bytes and the file is "
                f"{len(blob)}"
            )
        actual = hashlib.sha256(blob).hexdigest()
        if actual != entry.get("sha256"):
            out.codes.append("artifact-digest-mismatch")
            out.messages.append(
                f"{rel}: the record declares sha256 {entry.get('sha256')} and the file "
                f"hashes to {actual}"
            )
    return roles, absent


def check_profile(roles: set[str], profile: str, out: Outcome) -> bool:
    """Every role the profile requires is present. Returns whether any is missing.

    The caller names *profile*; it is never read from the record. A profile this
    verifier does not know is a usage error raised to the caller, because
    answering it with an empty role list would pass every record.
    """
    required = manifest_mod.PROFILES.get(profile)
    if required is None:
        raise ValueError(f"unknown profile {profile!r}")
    missing = [role for role in required if role not in roles]
    for role in missing:
        out.codes.append("required-role-absent")
        out.messages.append(
            f"role {role!r} is required by profile {profile} and the "
            "record carries no entry for it"
        )
    return bool(missing)


def check_in_force(
    record: dict[str, JSONValue], in_force: dict[str, str], out: Outcome
) -> None:
    """Each pinned role covers exactly the bytes the consumer holds as in force.

    The consumer names, per role, the digest it accepts: for a dependency
    change, the skill or instruction file its policy says was in force. A
    record can be honestly signed over a DIFFERENT instruction file, every byte
    on disk matching, and still describe a change made under instructions the
    consumer never approved. That is a contradiction, so it fails.
    """
    entries = _entries(record, "artifacts") + _grading_inputs(record)
    for role, pinned in sorted(in_force.items()):
        for entry in entries:
            if entry.get("role") == role and entry.get("sha256") != pinned:
                out.codes.append("role-not-in-force")
                out.messages.append(
                    f"{entry.get('path')}: role {role!r} covers sha256 "
                    f"{entry.get('sha256')} and the consumer holds {pinned} as in force"
                )


def check_outcome(trial_dir: Path, record: dict[str, JSONValue], out: Outcome) -> None:
    """``graded_outcome`` is re-derived from the covered bytes, never trusted."""
    graded = record.get("graded_outcome")
    if not isinstance(graded, dict):
        return
    source = graded.get("source_path")
    if not isinstance(source, str):
        return
    path = trial_dir / source
    if not path.is_file():
        return
    declared = graded.get("reward")
    try:
        actual = float(path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return
    if not isinstance(declared, int | float) or float(declared) != actual:
        out.codes.append("graded-outcome-mismatch")
        out.messages.append(
            f"{source}: the record declares reward {declared!r} and the covered bytes "
            f"say {actual}"
        )


def check_atif(trial_dir: Path, record: dict[str, JSONValue], out: Outcome) -> None:
    """The ATIF pointer agrees with the document the record hashed."""
    atif = record.get("atif")
    if not isinstance(atif, dict) or not atif.get("present"):
        return
    declared = atif.get("document_sha256")
    covered = next(
        (
            entry
            for entry in _entries(record, "artifacts")
            if entry.get("role") == "atif_trajectory"
        ),
        None,
    )
    if covered is None:
        return
    if declared != covered.get("sha256"):
        out.codes.append("atif-document-digest-mismatch")
        out.messages.append(
            "atif.document_sha256 does not equal the digest of the covered "
            f"atif_trajectory entry at {covered.get('path')}"
        )
    path = trial_dir / str(covered.get("path", ""))
    if path.is_file():
        _check_atif_pointer(path, atif, out)


def _check_atif_pointer(path: Path, atif: dict[str, JSONValue], out: Outcome) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return
    if not isinstance(payload, dict):
        return
    declared_id = atif.get("trajectory_id")
    actual_id = payload.get("trajectory_id")
    if declared_id != actual_id:
        out.codes.append("atif-trajectory-id-mismatch")
        out.messages.append(
            f"the record names trajectory_id {declared_id!r} and the document says "
            f"{actual_id!r}"
        )


def check_dependencies(record: dict[str, JSONValue], out: Outcome) -> bool:
    """A record naming a dependency it does not cover is never ``verified``."""
    dependencies = record.get("dependencies")
    if not isinstance(dependencies, dict):
        return False
    if dependencies.get("status") != "incomplete":
        return False
    out.codes.append("dependencies-incomplete")
    uncovered = dependencies.get("uncovered")
    listed = uncovered if isinstance(uncovered, list) else []
    for item in listed:
        if isinstance(item, dict):
            out.messages.append(
                f"uncovered dependency {item.get('reference')!r}: {item.get('reason')}"
            )
    if not listed:
        out.messages.append("the record reports its dependency coverage as incomplete")
    return True


_INCONCLUSIVE = frozenset(
    {"artifact-absent", "required-role-absent", "dependencies-incomplete"}
)


def verify(
    trial_dir: Path,
    manifest_path: Path,
    signature_path: Path,
    public_key: bytes,
    profile: str = manifest_mod.PROFILE_NAME,
    in_force: dict[str, str] | None = None,
) -> Outcome:
    """Check one record against the bytes it names. Never re-runs any grading.

    *profile* and *in_force* are the consumer's: the completeness bar and the
    per-role digests it accepts. Neither is read from the record.
    """
    out = Outcome(verdict=VERIFIED)
    raw = manifest_path.read_bytes()
    record = check_encoding(raw, out)
    if record is None:
        out.verdict = FAILED
        return out

    check_signer(record, public_key, out)
    if "signer-key-mismatch" not in out.codes:
        signature = signature_path.read_bytes().strip()
        blob = bytes.fromhex(signature.decode("utf-8")) if len(signature) == 128 else signature
        if not sign.verify_bytes(public_key, raw, blob):
            out.codes.append("signature-invalid")
            out.messages.append(
                "the detached signature does not verify over the manifest bytes as stored"
            )

    roles, absent = check_artifacts(trial_dir, record, out)
    missing = check_profile(roles, profile, out)
    check_in_force(record, in_force or {}, out)
    incomplete = check_dependencies(record, out)
    check_outcome(trial_dir, record, out)
    check_atif(trial_dir, record, out)

    hard = [code for code in out.codes if code not in _INCONCLUSIVE]
    if hard:
        out.verdict = FAILED
    elif absent or missing or incomplete:
        out.verdict = NOT_ESTABLISHED
    return out


def read_record(manifest_path: Path) -> dict[str, JSONValue] | None:
    """The manifest at *manifest_path* as an object, or None if it is not one."""
    return _as_object(manifest_path.read_bytes())


def manifest_digest(manifest_path: Path) -> str:
    """The lineage name of a record: SHA-256 over its canonical bytes."""
    raw = manifest_path.read_bytes()
    record = _as_object(raw)
    if record is None:
        raise ValueError(f"{manifest_path} is not a JSON object")
    return hashlib.sha256(canonical_bytes(record)).hexdigest()
