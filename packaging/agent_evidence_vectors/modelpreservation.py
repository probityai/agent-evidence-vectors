"""Judge a model-preservation record: a reference record against a held copy, or a swap record.

Two signed records keep a model checkable after its publisher or its hub is gone.

The reference record lists a digest for every file of a model, inside an in-toto
Statement v1 whose predicate is the OpenSSF model-signing v1.0 predicate
(``https://model_signing/signature/v1.0``: ``serialization`` and ``resources``, with the
subject digest a SHA-256 over every resource digest in resource order). The endpoint
that fetched the model signs it in a DSSE envelope, and adds a ``fetch`` member saying
where it fetched the model, at which revision and when; a v1.0 verifier ignores that
member. A copy obtained later from anyone is checked against the record, so the copy's
holder need not be trusted. A file the hub serves only to signed-in users can be recorded
before access is granted by the git id of its large-file pointer (algorithm
``git-lfs-pointer``), which fixes the file's SHA-256 and size; the reader rebuilds the
pointer from the copy and compares the git id.

The swap record says that a service replaced one model with another: the old model (by
digest where there is one, by service and date where there is not), the new model as the
statement's subject, the test set's digest and the verdict of the test run, signed by
whoever made the swap.

The reader checks in a fixed order and names the first check that fails:

1. a signature names a key the verifier trusts (``signer_not_trusted``);
2. that signature verifies over the DSSE pre-authentication encoding
   (``signature_invalid``);
3. the statement's predicate type is the one the case asks about
   (``unexpected_predicate_type``).

A record whose envelope, statement or predicate lacks a member these checks read is
``rejected`` with the reason ``malformed_record``, never judged on what is left.

For a reference record:

4. the subject digest is the SHA-256 over the listed resource digests
   (``root_digest_inconsistent``);
5. the record was made before the model was withdrawn, when the case says it was
   (``record_after_withdrawal``): a copy rescued later can only be checked against a
   record made before it went;
6. the copy holds every recorded file (``file_missing``) and no file the record does not
   list (``file_not_in_record``);
7. every file of the copy has its recorded digest (``file_digest_mismatch``), rebuilding
   the large-file pointer for a ``git-lfs-pointer`` resource.

For a swap record:

4. the key that signed is the swapper's (``signer_not_swapper``);
5. the old model is named by a digest, or by a service and the date it was observed
   (``old_model_not_identified``);
6. the test set is the one the requirement names (``test_set_not_required``);
7. the model now deployed is the swap's new model (``deployed_model_not_swapped_in``);
8. the verdict is ``pass`` (``swap_failed_test``, decision ``failed``): a worse swap shows
   as a failed run with the swapper on record.

A passing swap whose old model has no digest is ``verified`` with the reason
``swap_passed_old_model_unproven``: a run against a hosted service shows its behaviour,
never which model answered, so model identity is reported apart from the verdict.

The decisions are ``verified``, ``failed``, ``mismatch``, ``rejected`` and
``not_established``. The external-verifier contract: ``<verifier> <case-dir>/case.json
--json`` prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``verified``, 1 for ``failed``, 2 for ``mismatch``, 3 for ``rejected`` and 4 for
``not_established``.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictb64, strictjson
from agent_evidence_vectors.anchoredchain import _fixture_error, _rail
from agent_evidence_vectors.monitorcoverage import _validated_entries, run_corpus

SUITE = "model-preservation/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REFERENCE_PREDICATE = "https://model_signing/signature/v1.0"
SWAP_PREDICATE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/model-swap"
PREDICATE_FOR = {"reference": REFERENCE_PREDICATE, "swap": SWAP_PREDICATE}
POINTER = "git-lfs-pointer"
VERIFIED, FAILED, MISMATCH, REJECTED, NOT_ESTABLISHED = (
    "verified",
    "failed",
    "mismatch",
    "rejected",
    "not_established",
)
EXIT_FOR = {VERIFIED: 0, FAILED: 1, MISMATCH: 2, REJECTED: 3, NOT_ESTABLISHED: 4}
#: Every rule a case can force, in the order the reader applies them.
CHECKS = (
    "signer_not_trusted",
    "signature_invalid",
    "predicate_type",
    "root_digest",
    "recorded_before_withdrawal",
    "file_set",
    "file_digest",
    "git_pointer",
    "signer_is_swapper",
    "old_model_identified",
    "test_set",
    "deployed_model",
    "verdict",
    "identity_unproven",
)
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-model-preservation"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-model-preservation"
)

Case = dict[str, Any]


class _Answer(Exception):
    """The first check that fails, carrying the decision and its reason."""

    def __init__(self, decision: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision, reason


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keyid(key_hex: str) -> str:
    """The keyid a signature names: the SHA-256 thumbprint of the raw public key."""
    return _sha(bytes.fromhex(key_hex))


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def root_digest(resources: list[dict[str, Any]]) -> str:
    """The model-signing v1.0 subject digest: SHA-256 over the raw resource digests."""
    return _sha(b"".join(bytes.fromhex(r["digest"]) for r in resources))


def pointer_id(data: bytes) -> str:
    """The git id of the large-file pointer that stands for these bytes."""
    pointer = (
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{_sha(data)}\nsize {len(data)}\n"
    ).encode()
    return hashlib.sha1(b"blob %d\x00" % len(pointer) + pointer, usedforsecurity=False).hexdigest()


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a base64 string")
    try:
        return strictb64.std(value)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not standard base64") from exc


def _signed_statement(
    case: Case, envelope: Any, skip: frozenset[str]
) -> tuple[Any, dict[str, Any]]:
    """The statement and the trusted entry whose key signed it, or the first refusal."""
    trusted = {t["keyid"]: t for t in case["trusted"]}
    message = pae(envelope["payloadType"], _b64(envelope["payload"]))
    named = None
    for sig in envelope["signatures"]:
        entry = trusted.get(sig["keyid"])
        if entry is None and "signer_not_trusted" in skip:
            entry = next(iter(trusted.values()))
        if entry is None:
            continue
        named = entry
        if "signature_invalid" in skip or _rail().ed25519_verify(
            bytes.fromhex(entry["key"]), message, _b64(sig["sig"])
        ):
            return strictjson.loads(_b64(envelope["payload"])), entry
    if named is None:
        raise _Answer(REJECTED, "signer_not_trusted")
    raise _Answer(REJECTED, "signature_invalid")


def _check_reference(
    case: Case, statement: Any, directory: Path, skip: frozenset[str]
) -> dict[str, str]:
    predicate = statement["predicate"]
    resources = predicate["resources"]
    if "root_digest" not in skip and statement["subject"][0]["digest"]["sha256"] != root_digest(
        resources
    ):
        raise _Answer(REJECTED, "root_digest_inconsistent")
    withdrawn = case.get("withdrawnAt")
    if (
        "recorded_before_withdrawal" not in skip
        and withdrawn is not None
        and predicate["fetch"]["fetchedAt"] >= withdrawn
    ):
        raise _Answer(NOT_ESTABLISHED, "record_after_withdrawal")
    copy: dict[str, str] = case["copy"]
    recorded = {r["name"]: r for r in resources}
    if "file_set" not in skip:
        if set(recorded) - set(copy):
            raise _Answer(MISMATCH, "file_missing")
        if set(copy) - set(recorded):
            raise _Answer(MISMATCH, "file_not_in_record")
    if "file_digest" not in skip:
        for name, resource in sorted(recorded.items()):
            if name not in copy:
                continue
            data = (directory / copy[name]).read_bytes()
            pointer = resource["algorithm"] == POINTER and "git_pointer" not in skip
            if (pointer_id(data) if pointer else _sha(data)) != resource["digest"]:
                raise _Answer(MISMATCH, "file_digest_mismatch")
    return {"decision": VERIFIED, "reason": "copy_matches_record"}


def _identified(old: Any) -> bool:
    if not isinstance(old, dict):
        return False
    digest = old.get("digest")
    if isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
        return True
    return isinstance(old.get("service"), str) and isinstance(old.get("observedOn"), str)


def _check_swap(
    case: Case, statement: Any, signer: dict[str, Any], skip: frozenset[str]
) -> dict[str, str]:
    predicate = statement["predicate"]
    if "signer_is_swapper" not in skip and signer["party"] != predicate["swapper"]:
        raise _Answer(REJECTED, "signer_not_swapper")
    old = predicate["oldModel"]
    if "old_model_identified" not in skip and not _identified(old):
        raise _Answer(NOT_ESTABLISHED, "old_model_not_identified")
    if "test_set" not in skip and predicate["testSet"]["digest"] != case["requiredTestSet"]:
        raise _Answer(MISMATCH, "test_set_not_required")
    if "deployed_model" not in skip and statement["subject"][0]["digest"] != case["deployed"]:
        raise _Answer(MISMATCH, "deployed_model_not_swapped_in")
    if "verdict" not in skip and predicate["verdict"] != "pass":
        raise _Answer(FAILED, "swap_failed_test")
    digest = old.get("digest") if isinstance(old, dict) else None
    if "identity_unproven" not in skip and not isinstance(digest, dict):
        return {"decision": VERIFIED, "reason": "swap_passed_old_model_unproven"}
    return {"decision": VERIFIED, "reason": "swap_passed"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one case."""
    case = _load(case_path)
    envelope = _load(case_path.parent / case["record"])
    try:
        statement, signer = _signed_statement(case, envelope, skip)
        if "predicate_type" not in skip and (
            envelope["payloadType"] != PAYLOAD_TYPE
            or statement.get("_type") != STATEMENT_TYPE
            or statement.get("predicateType") != PREDICATE_FOR[case["kind"]]
        ):
            raise _Answer(REJECTED, "unexpected_predicate_type")
        if case["kind"] == "reference":
            return _check_reference(case, statement, case_path.parent, skip)
        return _check_swap(case, statement, signer, skip)
    except _Answer as answer:
        return {"decision": answer.decision, "reason": answer.reason}
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return {"decision": REJECTED, "reason": "malformed_record"}


def retained(case_path: Path) -> dict[str, Any]:
    """The facts the manifest declares about a case, recomputed from its bytes."""
    case = _load(case_path)
    envelope = _load(case_path.parent / case["record"])
    statement = strictjson.loads(_b64(envelope["payload"]))
    facts: dict[str, Any] = {"predicateType": statement["predicateType"]}
    if statement["predicateType"] == REFERENCE_PREDICATE:
        facts["rootDigestConsistent"] = statement["subject"][0]["digest"]["sha256"] == root_digest(
            statement["predicate"]["resources"]
        )
    return facts


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(case_path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        case_path = directory / "case.json"
        if retained(case_path) != entry["retained"]:
            errors.append(f"{name}: declared record facts do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(case_path, skip)
        else:
            ran, observed = _external_answer(command, case_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
