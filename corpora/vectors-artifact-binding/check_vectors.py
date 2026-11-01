#!/usr/bin/env python3
"""Check that the artifact-binding corpus behaves as its manifest claims.

A different question from regenerability. That gate asks whether the committed
bytes are the bytes the generator emits; this asks whether those bytes BEHAVE as
declared: that the member claiming a digest mismatch actually mismatches, that
the member claiming not-established reaches neither neighbour, and that the
regrade member really shares an archive with the record it derives from.

It also asks the question a corpus of rejections cannot answer about itself. A
verifier that refuses everything scores full marks on a suite of failures alone,
so this checker refuses a corpus with no ``verified`` member and refuses one
whose ``not-established`` members could be satisfied by answering ``failed``.

    python3 vectors-artifact-binding/check_vectors.py [CORPUS_DIR]

CORPUS_DIR defaults to this directory. Any corpus of the artifact-binding suite
is judged the same way, under the profile and the in-force pins its own
MANIFEST.json declares on the consumer's behalf; ``vectors-dependency-selection``
is the second.

Exits 0 clean, 1 with one line per divergence.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from pathlib import Path

HERE = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "artifact-binding"))

import jcs  # noqa: E402
import manifest as manifest_mod  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402

FAILURES: list[str] = []


def fail(line: str) -> None:
    FAILURES.append(line)


def check_member(
    entry: dict[str, object], public_key: bytes, profile: str, in_force: dict[str, str]
) -> None:
    identifier = str(entry["id"])
    trial = HERE / str(entry["trial"])
    manifest_path = HERE / str(entry["manifest"])
    signature_path = HERE / str(entry["signature"])
    expected = entry["expected"]
    if not isinstance(expected, dict):
        fail(f"{identifier}: the manifest entry declares no expected verdict")
        return
    if not manifest_path.is_file():
        fail(f"{identifier}: {manifest_path} is missing")
        return

    outcome = verify_mod.verify(
        trial, manifest_path, signature_path, public_key, profile, in_force
    )
    if outcome.verdict != expected["verdict"]:
        fail(
            f"{identifier}: the manifest expects {expected['verdict']!r} and the "
            f"reference verifier answered {outcome.verdict!r} "
            f"(codes: {sorted(set(outcome.codes))})"
        )
        return
    declared = expected.get("codes")
    wanted = set(declared) if isinstance(declared, list) else set()
    emitted = set(outcome.codes)
    missing = wanted - emitted
    if missing:
        fail(f"{identifier}: expected code(s) {sorted(missing)} were not emitted")
    # And the reverse, which is the half a subset test cannot see. A member that is
    # ALREADY expected to fail absorbs any second fault silently: mutate a covered file
    # inside `cases/covered-byte-changed` and the verdict is still `failed`, so a
    # subset check reports the corpus clean while the committed bytes are not the ones
    # the generator emitted. Measured on this corpus before this clause existed.
    declared_digest = expected.get("messagesDigest")
    if isinstance(declared_digest, str):
        joined = "\n".join(sorted(outcome.messages))
        actual_digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        if actual_digest != declared_digest:
            fail(
                f"{identifier}: the verifier's messages hash to {actual_digest[:16]} and "
                f"the manifest declares {declared_digest[:16]}. A member carries exactly "
                "the faults it names, about exactly the files it names; a second fault of "
                "the same class is invisible to the code set and shows up here."
            )

    unexpected = emitted - wanted
    if unexpected:
        fail(
            f"{identifier}: emitted code(s) {sorted(unexpected)} the manifest does not "
            "declare. A member carries exactly the faults it names; a second fault means "
            "the bytes moved. Regenerate with gen_vectors.py rather than editing by hand."
        )
    if outcome.verdict != verify_mod.VERIFIED and not outcome.messages:
        fail(f"{identifier}: a non-verified verdict named nothing")


def check_lineage_member(entry: dict[str, object]) -> None:
    """The regrade member really derives from a record over the same archive."""
    record = verify_mod.read_record(HERE / str(entry["manifest"]))
    if record is None:
        fail(f"{entry['id']}: the regrade record is not a JSON object")
        return
    source = HERE / str(entry["case"]) / "source" / "binding" / "manifest.json"
    if not source.is_file():
        fail(f"{entry['id']}: the record it derives from is not in the case directory")
        return
    parent = verify_mod.read_record(source)
    if parent is None:
        fail(f"{entry['id']}: the source record is not a JSON object")
        return
    if record.get("source_record_digest") != verify_mod.manifest_digest(source):
        fail(f"{entry['id']}: source_record_digest does not resolve to the source record")
    if record.get("source_archive_digest") != parent.get("source_archive_digest"):
        fail(f"{entry['id']}: the two records do not share one source_archive_digest")
    graded = record.get("graded_outcome")
    parent_graded = parent.get("graded_outcome")
    if isinstance(graded, dict) and isinstance(parent_graded, dict):
        if graded.get("reward") == parent_graded.get("reward"):
            fail(
                f"{entry['id']}: the changed verifier produced the same reward, so the "
                "member does not demonstrate two preserved outcomes"
            )


def check_member_identity(entry: dict[str, object]) -> None:
    """The member's identifier is a function of its own bytes, so re-derive it.

    Without this the corpus has a hole a mutation walks straight through: flip a
    byte inside a member that is ALREADY expected to fail and the verdict is
    still `failed`, so a verdict-only checker reports the corpus clean while the
    committed bytes are not the bytes the generator emitted. Measured on this
    corpus before the check existed: mutating result.json inside
    `cases/covered-byte-changed` left the checker exiting 0.

    The identifier is `"v" + sha256(manifest bytes + case name)[:16]`, which is
    exactly what gen_vectors.vector_id computes, so a member whose record moved
    gets a new identifier and this refuses it by name.
    """
    identifier = str(entry["id"])
    manifest_path = HERE / str(entry["manifest"])
    if not manifest_path.is_file():
        return
    case_name = pathlib.PurePosixPath(str(entry["case"])).name
    derived = "v" + hashlib.sha256(
        manifest_path.read_bytes() + case_name.encode("utf-8")
    ).hexdigest()[:16]
    if derived != identifier:
        fail(
            f"{identifier}: the member's bytes derive identifier {derived}, so the "
            "record changed after the corpus was generated. Regenerate with "
            "gen_vectors.py rather than editing a case by hand."
        )


def check_published_key(vectors: list[dict[str, object]], public_key: bytes) -> None:
    """The published key is the key the passing member names.

    A corpus whose published key is not the one its passing member was signed
    with would report every member as a signer mismatch while looking like a
    signing bug rather than a manifest defect.
    """
    intact = next(
        (
            entry
            for entry in vectors
            if entry["expected"]["verdict"] == "verified"  # type: ignore[index]
            and "regrade" not in str(entry["case"])
        ),
        None,
    )
    if intact is None:
        fail("the corpus has no plain verified member to anchor the published key against")
        return
    record = verify_mod.read_record(HERE / str(intact["manifest"]))
    named = record.get("signer_key_id") if record is not None else None
    if named != sign.key_id(public_key):
        fail(
            f"MANIFEST.json publishes a key whose id is {sign.key_id(public_key)} and "
            f"the intact member names {named}"
        )


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    vectors = manifest["vectors"]
    public_key = bytes.fromhex(manifest["publicKey"])
    profile = str(manifest["profile"])
    if profile not in manifest_mod.PROFILES:
        print(f"FAIL MANIFEST.json names profile {profile!r}, which no verifier here knows")
        return 1
    in_force = {str(k): str(v) for k, v in manifest.get("inForce", {}).items()}
    # The corpus publishes the key its members were signed with, and a corpus
    # whose published key is not the key its passing member names would report
    # every member as a signer mismatch while looking like a signing bug.
    check_published_key(vectors, public_key)

    for entry in vectors:
        check_member_identity(entry)
        check_member(entry, public_key, profile, in_force)
        if entry["expected"]["verdict"] == "verified" and "regrade" in entry["case"]:
            check_lineage_member(entry)

    verdicts = {entry["expected"]["verdict"] for entry in vectors}
    if "verified" not in verdicts:
        fail(
            "the corpus contains no verified member, so a verifier that refuses "
            "everything would score full marks"
        )
    if "not-established" not in verdicts:
        fail("the corpus contains no not-established member, so the third outcome is untested")

    counts = manifest["counts"]
    actual = {
        "verified": sum(1 for e in vectors if e["expected"]["verdict"] == "verified"),
        "failed": sum(1 for e in vectors if e["expected"]["verdict"] == "failed"),
        "notEstablished": sum(
            1 for e in vectors if e["expected"]["verdict"] == "not-established"
        ),
    }
    if counts != actual:
        fail(f"MANIFEST.json declares counts {counts} and the entries are {actual}")
    if manifest["corpusDigest"] != jcs.digest(vectors):
        fail("corpusDigest does not match the vectors it names")

    if FAILURES:
        for line in FAILURES:
            print(f"FAIL {line}")
        return 1
    print(
        f"{HERE.name} ({profile}): {len(vectors)} vectors behave as MANIFEST.json claims "
        f"({actual['verified']} verified, {actual['failed']} failed, "
        f"{actual['notEstablished']} not-established)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
