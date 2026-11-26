"""Build the model-preservation cases byte-identically.

Every case is one signed record, the verifier's trust inputs and, for a reference record,
the files of a copy someone else kept; for a swap record, the test set the requirement
names and the digest of the model now deployed. The cases give each record a match, a
tampered digest and a wrong signer, and the rules a reader of either record must apply.

The model files are a few bytes each and stand for a real model's files. Keys are Ed25519
seeds derived from published labels, so anyone can rebuild every signature. They are test
keys and protect nothing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import modelpreservation as reader  # noqa: E402

SUITE = reader.SUITE
SEED_PREFIX = "agent-evidence-vectors/model-preservation/v1/"
SOURCE = {
    "note": (
        "Synthetic models, records and keys. The reference record is the OpenSSF model-signing "
        "v1.0 statement with a fetch member; the swap record and the decision and reason tokens "
        "are this corpus's own."
    ),
    "source": (
        "Model preservation draft, open-source-ecosystem/ai-model-sovereignty PRESERVATION.md, "
        "sections on the reference record (T0), existing building blocks and hosted models"
    ),
}
ENDPOINT = "https://models.institution.example"
SWAPPER = "https://ai-ops.institution.example"
OTHER_PARTY = "https://procurement.institution.example"
SERVICE = "https://chat.institution.example"
MODEL_NAME = "example-org/small-model"
REVISION = hashlib.sha1(b"example-org/small-model@main", usedforsecurity=False).hexdigest()
FETCHED_AT = "2026-11-02T09:00:00Z"

#: The model's files: weights, configuration, model card and licence text.
FILES = {
    "LICENSE": b"Example licence text for the small model.\n",
    "README.md": b"# small-model\n\nModel card: a few bytes standing for a real model card.\n",
    "config.json": b'{"hidden_size": 8, "num_layers": 2}\n',
    "model.safetensors": bytes(range(64)),
}
TAMPERED_WEIGHTS = bytes(range(1, 65))
NEW_FILES = {**FILES, "model.safetensors": bytes(range(64, 128))}


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> str:
    return str(rail.ed25519_public_key(_seed(label)).hex())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def trusted(label: str, party: str) -> dict[str, str]:
    """A key the verifier trusts, with the party it belongs to."""
    key = _public(label)
    return {"key": key, "keyid": reader.keyid(key), "party": party}


def resources(files: dict[str, bytes], pointer: tuple[str, ...] = ()) -> list[dict[str, str]]:
    """The model-signing resource list, in name order."""
    out = []
    for name in sorted(files):
        if name in pointer:
            out.append(
                {"algorithm": reader.POINTER, "digest": reader.pointer_id(files[name]),
                 "name": name}
            )
        else:
            out.append({"algorithm": "sha256", "digest": _sha(files[name]), "name": name})
    return out


def reference_statement(
    files: dict[str, bytes] = FILES,
    pointer: tuple[str, ...] = (),
    fetched_at: str = FETCHED_AT,
    subject_digest: str | None = None,
) -> dict[str, Any]:
    """A reference record: the model-signing v1.0 statement plus where and when it was fetched."""
    res = resources(files, pointer)
    return {
        "_type": reader.STATEMENT_TYPE,
        "predicate": {
            "fetch": {
                "endpoint": ENDPOINT,
                "fetchedAt": fetched_at,
                "revision": REVISION,
                "source": f"https://hub.example/{MODEL_NAME}",
            },
            "resources": res,
            "serialization": {
                "allow_symlinks": False,
                "hash_type": "sha256",
                "ignore_paths": [],
                "method": "files",
            },
        },
        "predicateType": reader.REFERENCE_PREDICATE,
        "subject": [{"digest": {"sha256": subject_digest or reader.root_digest(res)},
                     "name": MODEL_NAME}],
    }


def model_digest(files: dict[str, bytes]) -> dict[str, str]:
    return {"sha256": reader.root_digest(resources(files))}


TEST_SET = {"sha256": _sha(b"held-back test set, rotation 2026-11")}
OTHER_TEST_SET = {"sha256": _sha(b"an easier test set")}
OLD_BY_DIGEST = {"digest": model_digest(FILES), "name": MODEL_NAME}
OLD_HOSTED = {"model": "provider-chat-large", "observedOn": "2026-11-01",
              "service": "https://api.provider.example/v1/chat"}


def swap_statement(old: dict[str, Any] = OLD_BY_DIGEST, verdict: str = "pass",
                   test_set: dict[str, str] = TEST_SET) -> dict[str, Any]:
    """A swap record: old model, new model as the subject, test set and verdict."""
    return {
        "_type": reader.STATEMENT_TYPE,
        "predicate": {
            "oldModel": old,
            "service": SERVICE,
            "swappedAt": "2026-11-10T12:00:00Z",
            "swapper": SWAPPER,
            "testSet": {"digest": test_set, "name": "held-back-rotation-2026-11"},
            "verdict": verdict,
        },
        "predicateType": reader.SWAP_PREDICATE,
        "subject": [{"digest": model_digest(NEW_FILES), "name": "example-org/small-model-v2"}],
    }


def envelope(statement: dict[str, Any], label: str, claimed: str | None = None) -> dict[str, Any]:
    """A DSSE envelope signed by the labelled key, naming ``claimed`` as its keyid."""
    payload = rail.jcs_dumps(statement)
    sig = rail.ed25519_sign(_seed(label), reader.pae(reader.PAYLOAD_TYPE, payload))
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": reader.PAYLOAD_TYPE,
        "signatures": [{"keyid": claimed or reader.keyid(_public(label)),
                        "sig": base64.b64encode(sig).decode()}],
    }


def retampered(env: dict[str, Any], edit: Any) -> dict[str, Any]:
    """The envelope with its payload edited after signing; the signature is kept."""
    statement = json.loads(base64.b64decode(env["payload"]))
    edit(statement)
    out = copy.deepcopy(env)
    out["payload"] = base64.b64encode(rail.jcs_dumps(statement)).decode()
    return out


def reference_case(copy_files: dict[str, bytes] = FILES,
                   withdrawn: str | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The verifier's inputs for a reference record and the copy's files."""
    names = {name: "copy-" + name for name in sorted(copy_files)}
    case: dict[str, Any] = {
        "copy": names,
        "kind": "reference",
        "record": "record.dsse.json",
        "suite": SUITE,
        "trusted": [trusted("endpoint", ENDPOINT)],
    }
    if withdrawn is not None:
        case["withdrawnAt"] = withdrawn
    return case, {names[n]: copy_files[n] for n in names}


def swap_case(deployed: dict[str, str] | None = None) -> dict[str, Any]:
    """The verifier's inputs for a swap record."""
    return {
        "deployed": deployed or model_digest(NEW_FILES),
        "kind": "swap",
        "record": "record.dsse.json",
        "requiredTestSet": TEST_SET,
        "suite": SUITE,
        "trusted": [trusted("swapper", SWAPPER), trusted("procurement", OTHER_PARTY)],
    }


Case = tuple[str, dict[str, Any], dict[str, bytes], dict[str, Any], str, str, str]


def _set_digest(name: str, data: bytes) -> Any:
    def edit(statement: dict[str, Any]) -> None:
        for r in statement["predicate"]["resources"]:
            if r["name"] == name:
                r["digest"] = _sha(data)
        statement["subject"][0]["digest"]["sha256"] = reader.root_digest(
            statement["predicate"]["resources"])
    return edit


def _set_verdict(statement: dict[str, Any]) -> None:
    statement["predicate"]["verdict"] = "pass"


def _reference_cases() -> list[Case]:
    good = envelope(reference_statement(), "endpoint")
    case, copy_files = reference_case()
    tampered_copy = {**FILES, "model.safetensors": TAMPERED_WEIGHTS}
    t_case, t_files = reference_case(tampered_copy)
    missing = {k: v for k, v in FILES.items() if k != "config.json"}
    m_case, m_files = reference_case(missing)
    extra = {**FILES, "loader.py": b"print('not in the record')\n"}
    e_case, e_files = reference_case(extra)
    gated = envelope(reference_statement(pointer=("model.safetensors",)), "endpoint")
    w_case, w_files = reference_case(withdrawn="2026-11-01T00:00:00Z")
    return [
        ("reference-copy-matches", case, copy_files, good, "verified", "copy_matches_record",
         "every file of the copy has the digest the endpoint's signed record lists"),
        ("reference-copy-file-tampered", t_case, t_files, good, "mismatch",
         "file_digest_mismatch", "the copy's weights differ from the recorded digest"),
        ("reference-copy-file-missing", m_case, m_files, good, "mismatch", "file_missing",
         "the copy lacks a file the record lists"),
        ("reference-copy-extra-file", e_case, e_files, good, "mismatch", "file_not_in_record",
         "the copy carries a file the record does not list"),
        ("reference-record-digest-tampered", t_case, t_files,
         retampered(good, _set_digest("model.safetensors", TAMPERED_WEIGHTS)), "rejected",
         "signature_invalid",
         "the record's weights digest was rewritten after signing to match a tampered copy"),
        ("reference-wrong-signer", case, copy_files,
         envelope(reference_statement(), "adversary"), "rejected", "signer_not_trusted",
         "a valid signature by a key the verifier does not trust"),
        ("reference-wrong-signer-names-trusted-keyid", case, copy_files,
         envelope(reference_statement(), "adversary",
                  claimed=reader.keyid(_public("endpoint"))),
         "rejected", "signature_invalid",
         "a signature by another key that names the endpoint's keyid"),
        ("reference-root-digest-inconsistent", case, copy_files,
         envelope(reference_statement(subject_digest=_sha(b"another model")), "endpoint"),
         "rejected", "root_digest_inconsistent",
         "the subject digest is not the SHA-256 over the listed resource digests"),
        ("reference-gated-pointer-matches", case, copy_files, gated, "verified",
         "copy_matches_record",
         "the weights were recorded by their large-file pointer's git id before access; the "
         "pointer rebuilt from the copy has that id"),
        ("reference-gated-pointer-mismatch", t_case, t_files, gated, "mismatch",
         "file_digest_mismatch", "the pointer rebuilt from tampered weights has another git id"),
        ("reference-recorded-after-withdrawal", w_case, w_files,
         envelope(reference_statement(), "endpoint"), "not_established",
         "record_after_withdrawal",
         "the record was made after the model was withdrawn, so it cannot vouch for the copy"),
        ("reference-record-is-a-swap-record", case, copy_files,
         envelope(swap_statement(), "endpoint"), "rejected", "unexpected_predicate_type",
         "a signed swap record offered where a reference record is asked for"),
    ]


def _swap_cases() -> list[Case]:
    good = envelope(swap_statement(), "swapper")
    failed = envelope(swap_statement(verdict="fail"), "swapper")
    return [
        ("swap-passed", swap_case(), {}, good, "verified", "swap_passed",
         "the swapper signed a passing run of the required test set, and the new model is the "
         "one deployed"),
        ("swap-passed-hosted-old-model", swap_case(), {},
         envelope(swap_statement(old=OLD_HOSTED), "swapper"), "verified",
         "swap_passed_old_model_unproven",
         "the old model was a hosted service named by service and date, so its identity stays "
         "unproven while the behaviour passed"),
        ("swap-failed-test", swap_case(), {}, failed, "failed", "swap_failed_test",
         "a worse model swapped in: the run failed and the swapper is on record"),
        ("swap-verdict-tampered", swap_case(), {}, retampered(failed, _set_verdict), "rejected",
         "signature_invalid", "the verdict was changed from fail to pass after signing"),
        ("swap-wrong-signer", swap_case(), {}, envelope(swap_statement(), "adversary"),
         "rejected", "signer_not_trusted", "a valid signature by a key the verifier does not trust"),
        ("swap-signed-by-another-trusted-party", swap_case(), {},
         envelope(swap_statement(), "procurement"), "rejected", "signer_not_swapper",
         "signed by a trusted key of a party other than the swapper the record names"),
        ("swap-deployed-model-differs", swap_case(deployed=model_digest(FILES)), {}, good,
         "mismatch", "deployed_model_not_swapped_in",
         "the model now deployed is not the swap's new model"),
        ("swap-test-set-not-required", swap_case(), {},
         envelope(swap_statement(test_set=OTHER_TEST_SET), "swapper"), "mismatch",
         "test_set_not_required", "the run used a test set other than the one the requirement names"),
        ("swap-old-model-not-identified", swap_case(), {},
         envelope(swap_statement(old={"model": "provider-chat-large"}), "swapper"),
         "not_established", "old_model_not_identified",
         "the old model has neither a digest nor a service and date"),
    ]


def cases() -> list[Case]:
    """Every case: id, case file, copy files, record, decision, reason and what it shows."""
    return _reference_cases() + _swap_cases()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries: list[dict[str, Any]] = []
    for name, case, copy_files, record, decision, reason, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"case.json": _json(case), "record.dsse.json": _json(record), **copy_files}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "case.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "edit": shows,
                "expected": expected,
                "files": {filename: _sha(data) for filename, data in sorted(files.items())},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(directory / "case.json"),
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "provenance": copy.deepcopy(SOURCE),
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 failed, "
        "2 mismatch, 3 rejected, 4 not_established",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
