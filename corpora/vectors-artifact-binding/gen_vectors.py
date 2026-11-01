#!/usr/bin/env python3
"""Generate the artifact-binding conformance corpus.

Eight cases, each a complete trial directory with a binding record beside it,
and each carrying the verdict an implementation of
``spec/artifact-binding/v1.md`` must reach. Regenerate byte-identically with:

    python3 vectors-artifact-binding/gen_vectors.py

Every input is fixed: the signing seed is a published TEST key, the trial bytes
come from ``tools/artifact-binding/fixture.py``, and ``recorded_at`` is a
constant. Nothing here reads the clock, the filesystem outside this directory,
or the network, so two machines produce the same corpus digest.

Why the corpus is three verdicts and not two. A suite of accept and reject
alone cannot catch the defect this contract was written against: a verifier
that answers "pass" or "fail" for a record it could not check to a conclusion.
Three cases below expect ``not-established``, and an implementation that
collapses them into either neighbour scores zero on them rather than passing
by accident.

TEST KEYS ONLY. The seed below is in this file on purpose: a corpus a stranger
cannot regenerate is a corpus they have to trust.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / "tools" / "artifact-binding"
sys.path.insert(0, str(TOOLS))

import fixture  # noqa: E402
import jcs  # noqa: E402

# The preimage lives in digest.py beside this file, which imports only the
# standard library, so scripts/release-digests.py can reach it without loading
# the signing stack above. Imported rather than restated: one spelling.
from digest import corpus_digest  # noqa: E402
import manifest as manifest_mod  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RECORDED_AT = "2026-01-01T00:00:00Z"
CASES_DIR = HERE / "cases"
ID_HEX = 16


def vector_id(payload: bytes) -> str:
    return "v" + hashlib.sha256(payload).hexdigest()[:ID_HEX]


def _sign_into(trial: Path, record: dict[str, Any]) -> bytes:
    raw = manifest_mod.write(record, trial / "binding" / "manifest.json")
    (trial / "binding" / "manifest.sig").write_text(
        sign.sign_bytes(TEST_SEED, raw).hex(), encoding="utf-8"
    )
    return raw


def _base(trial: Path, verifier: Path, **kwargs: Any) -> dict[str, Any]:
    facts = manifest_mod.collect_facts(trial, verifier)
    return manifest_mod.build(
        facts,
        signer_key_id=sign.key_id(sign.public_bytes(TEST_SEED)),
        verifier_id="conformance/tests@v1",
        recorded_at=RECORDED_AT,
        **kwargs,
    )


def _resign(trial: Path, mutate: Any, seed: bytes = TEST_SEED, canonical: bool = True) -> None:
    path = trial / "binding" / "manifest.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    mutate(record)
    raw = jcs.canonical_bytes(record) if canonical else json.dumps(record, indent=2).encode()
    path.write_bytes(raw)
    (trial / "binding" / "manifest.sig").write_text(
        sign.sign_bytes(seed, raw).hex(), encoding="utf-8"
    )


def case_intact(root: Path) -> None:
    trial = fixture.build_trial(root / "trial")
    verifier = fixture.build_verifier(root / "verifier")
    _sign_into(trial, _base(trial, verifier))


def case_tampered(root: Path) -> None:
    case_intact(root)
    target = root / "trial" / "artifacts" / "logs" / "artifacts" / "answer.txt"
    target.write_text("HARBOR-BINDING-DEMO-TAMPERED\n", encoding="utf-8")


def case_missing_role(root: Path) -> None:
    case_intact(root)
    (root / "trial" / "verifier" / "reward.txt").unlink()


def case_regrade(root: Path) -> None:
    """The fourth arm, shipped as the SECOND record of a two-record chain."""
    source = fixture.build_trial(root / "source")
    verifier = fixture.build_verifier(root / "verifier")
    source_record = _base(source, verifier)
    source_raw = _sign_into(source, source_record)

    trial = root / "trial"
    shutil.copytree(source, trial)
    shutil.rmtree(trial / "binding")
    (trial / "verifier" / "reward.txt").write_text("0\n", encoding="utf-8")
    (trial / "verifier" / "test-stdout.txt").write_text(
        "answer.txt does not match the stricter rule\n", encoding="utf-8"
    )
    changed = fixture.build_verifier(root / "verifier-changed", changed=True)
    record = _base(
        trial,
        changed,
        operation="regrade",
        source_record_digest=hashlib.sha256(source_raw).hexdigest(),
    )
    _sign_into(trial, record)


def case_wrong_signer(root: Path) -> None:
    case_intact(root)
    other = bytes(range(1, 33))
    _resign(
        root / "trial",
        lambda record: record.__setitem__(
            "signer_key_id", sign.key_id(sign.public_bytes(other))
        ),
        seed=other,
    )


def case_non_canonical(root: Path) -> None:
    case_intact(root)
    _resign(root / "trial", lambda record: None, canonical=False)


def case_incomplete_dependency(root: Path) -> None:
    trial = fixture.build_trial(root / "trial", external_subagent=True)
    verifier = fixture.build_verifier(root / "verifier")
    _sign_into(trial, _base(trial, verifier))


def case_atif_pointer_mismatch(root: Path) -> None:
    case_intact(root)

    def mutate(record: dict[str, Any]) -> None:
        record["atif"]["document_sha256"] = "0" * 64

    _resign(root / "trial", mutate)


CASES: tuple[tuple[str, Any, str, list[str], str], ...] = (
    (
        "intact-execute",
        case_intact,
        "verified",
        [],
        "the whole contract in one case: canonical bytes, a pinned signer, every "
        "required role, and every covered file hashing to what the record says",
    ),
    (
        "covered-byte-changed",
        case_tampered,
        "failed",
        ["artifact-digest-mismatch", "artifact-length-mismatch"],
        "one byte of a covered artifact changed. The verdict must be reached "
        "BEFORE any grading is re-run, and the message must name the file",
    ),
    (
        "required-role-absent",
        case_missing_role,
        "not-established",
        ["artifact-absent"],
        "a required-role file is gone. Neither a pass nor a plain failure: the "
        "record cannot be checked to a conclusion and says so",
    ),
    (
        "regrade-changed-verifier",
        case_regrade,
        "verified",
        [],
        "the fourth arm. A second record over the same archive with a different "
        "verifier and a different reward; both records validate and the archive "
        "digest is shared, so the lineage is checkable",
    ),
    (
        "wrong-signer",
        case_wrong_signer,
        "failed",
        ["signer-key-mismatch"],
        "a record correctly signed by a key the consumer did not pin. Refused by "
        "identity, not by a signature failure that reads like corruption",
    ),
    (
        "non-canonical-encoding",
        case_non_canonical,
        "failed",
        ["manifest-encoding-not-canonical"],
        "indented JSON with a VALID signature over those indented bytes. A "
        "signature-only verifier accepts this and a second implementation "
        "rejects it, which is the disagreement the canonical rule removes",
    ),
    (
        "dependency-incomplete",
        case_incomplete_dependency,
        "not-established",
        ["dependencies-incomplete"],
        "the trajectory names an external subagent document the record does not "
        "cover. Declared incomplete rather than silently narrowed",
    ),
    (
        "atif-pointer-mismatch",
        case_atif_pointer_mismatch,
        "failed",
        ["atif-document-digest-mismatch"],
        "the ATIF pointer disagrees with the document the record hashed, so the "
        "record names a trajectory it did not bind",
    ),
)


def observed_messages_digest(root: Path) -> str:
    """SHA-256 over the verifier's own sorted messages for this case.

    Codes alone cannot police a member. A member already expected to fail absorbs a
    SECOND fault of the same class silently: mutating result.json inside
    `cases/covered-byte-changed` leaves the verdict `failed` and the code set
    unchanged, because both faults are `artifact-digest-mismatch`, and the corpus
    reads clean while its committed bytes are not the ones this generator emitted.
    The messages name the files, so a digest over them separates the two.
    """
    trial = root / "trial"
    outcome = verify_mod.verify(
        trial,
        trial / "binding" / "manifest.json",
        trial / "binding" / "manifest.sig",
        sign.public_bytes(TEST_SEED),
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
        identifier = vector_id(manifest_path.read_bytes() + name.encode("utf-8"))
        messages_digest = observed_messages_digest(root)
        entries.append(
            {
                "id": identifier,
                "kind": "accept" if verdict == "verified" else "reject",
                "case": f"cases/{name}",
                "trial": f"cases/{name}/trial",
                "manifest": f"cases/{name}/trial/binding/manifest.json",
                "signature": f"cases/{name}/trial/binding/manifest.sig",
                "expected": {
                    "verdict": verdict,
                    "codes": sorted(codes),
                    "messagesDigest": messages_digest,
                },
                "cites": cites,
            }
        )
    entries.sort(key=lambda entry: entry["id"])
    verified = sum(1 for entry in entries if entry["expected"]["verdict"] == "verified")
    failed = sum(1 for entry in entries if entry["expected"]["verdict"] == "failed")
    not_established = len(entries) - verified - failed
    manifest = {
        "suite": "artifact-binding-conformance",
        "contract": "artifact-binding/v1",
        "contractSpec": "spec/artifact-binding/v1.md",
        "profile": manifest_mod.PROFILE_NAME,
        "publicKey": sign.public_bytes(TEST_SEED).hex(),
        "keyNote": (
            "A published TEST key. The corpus is regenerable by anyone, which is "
            "the point: a suite a stranger cannot rebuild is one they must trust."
        ),
        "counts": {
            "verified": verified,
            "failed": failed,
            "notEstablished": not_established,
        },
        "note": (
            "Three verdicts, not two. An implementation that collapses "
            "not-established into verified or into failed scores zero on the "
            "three members that expect it, rather than passing by accident."
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
    """The human index, emitted rather than typed, because it restates ids.

    An identifier here is a function of the bytes it names, so it is not
    something a person can write into a table and keep correct.
    """
    lines = [
        "# Artifact-binding corpus index",
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
