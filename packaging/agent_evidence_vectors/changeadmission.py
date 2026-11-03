"""Verify signed agent-change-admission decisions against a pinned consumer policy.

The corpus this module reads pins the verification rules of the
agent-change-admission predicate, version 1
(https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md):
one signed decision about whether a proposed change to an AI agent's harness
was admitted, and the evidence the decision names.

Two carriages are read. ``dsse-bare``: the DSSE payload is the decision object
itself and carries ``predicateType``. ``dsse-intoto``: the payload is an in-toto
Statement v1 whose ``predicate`` is the decision and whose subject is the
candidate harness.

The reader checks in a fixed order and names the first check that fails:

1. the envelope parses as DSSE v1 (else no verdict, ``malformed_envelope``);
2. its payload type is the one the policy pins (``unsupported_payload_type``);
3. a signature naming a pinned keyid verifies over the DSSE pre-authentication
   encoding (``untrusted_key`` when no signature names a pinned key,
   ``signature_invalid`` when one does and fails). A signature naming any
   other key is ignored, never trusted;
4. the payload is a JSON object (``payload_not_json_object``); in the in-toto
   carriage it is a Statement v1 (``unsupported_statement_type``);
5. the predicate type is the one the policy pins (``unsupported_predicate``);
6. every required field is well formed, in the order of ``FIELDS``
   (``payload_field_invalid:<field>``);
7. in the in-toto carriage, a subject carries the candidate digest
   (``subject_digest_mismatch``);
8. every gate the policy requires is recorded (``gate_missing:<gate>``), an
   admitted decision passed all of them (``admitted_with_failed_gate:<gate>``)
   and a rejected one failed at least one (``rejected_with_all_gates_passed``).
   A check whose name the policy does not require is informational;
9. every supplied report is named (``report_not_named:<name>``) and matches
   the digest named for it (``report_digest_mismatch:<name>``); under a policy
   that requires reports, every named report is supplied
   (``report_not_supplied:<name>``).

A decision that passes all nine is ``supported``, with the reason
``admitted_receipt_verified`` or ``rejection_receipt_verified``. A supported
rejection is a verified record that the change was refused.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints
one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``supported``, 1 for ``contradicted`` or ``not_established``, and 2 when no
verdict was reached.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

SUITE = "agent-change-admission/v1"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
STATEMENT_V1 = "https://in-toto.io/Statement/v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
FIELDS = ("parent", "candidate", "candidate_digest", "evaluator",
          "evaluator.components.suite_file", "exceptions", "admitted", "checks",
          "corpus_digests", "report_digests")

# Every rule the reader applies, by the name the mutation check switches off.
RULES = (
    "payload_type", "pinned_keys_only", "signature", "payload_object", "statement_type",
    "predicate", *(f"field:{f}" for f in FIELDS), "subject", "gate_missing",
    "admitted_with_failed_gate", "rejected_with_all_gates_passed", "required_gates_only",
    "report_not_named", "report_digest_mismatch", "report_not_supplied",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-agent-change-admission" if
        (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-agent-change-admission")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)


class Refusal(Exception):
    """The first failed check: a decision and a reason code."""

    def __init__(self, decision: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision, reason


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to
    dispatch the suite, so a module-level import would be a cycle."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


@lru_cache(maxsize=4096)
def _ed25519_verify(key: bytes, message: bytes, sig: bytes) -> bool:
    """The rail's pure-Python Ed25519, memoised: it is deterministic and slow, and
    the mutation sweep asks the same question once per rule."""
    return bool(_rail().ed25519_verify(key, message, sig))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise Refusal(NO_VERDICT, "malformed_envelope")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refusal(NO_VERDICT, "malformed_envelope") from exc


def parse_envelope(raw: bytes) -> tuple[str, bytes, list[tuple[str, bytes]]]:
    """(payloadType, payload, [(keyid, sig)]) or a no-verdict refusal."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise Refusal(NO_VERDICT, "malformed_envelope")
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal(NO_VERDICT, "malformed_envelope") from exc
    if not isinstance(doc, dict):
        raise Refusal(NO_VERDICT, "malformed_envelope")
    payload_type, entries = doc.get("payloadType"), doc.get("signatures")
    if not isinstance(payload_type, str) or not payload_type:
        raise Refusal(NO_VERDICT, "malformed_envelope")
    if not isinstance(entries, list) or not entries:
        raise Refusal(NO_VERDICT, "malformed_envelope")
    sigs = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str):
            raise Refusal(NO_VERDICT, "malformed_envelope")
        sigs.append((entry["keyid"], _b64(entry.get("sig"))))
    return payload_type, _b64(doc.get("payload")), sigs


def _signed_by(payload_type: str, body: bytes, sigs: list[tuple[str, bytes]],
               trusted: dict[str, bytes], skip: frozenset[str]) -> None:
    message = pae(payload_type, body)
    named = False
    for kid, sig in sigs:
        key = trusted.get(kid)
        if key is None:
            if "pinned_keys_only" not in skip:
                continue
            key = next(iter(trusted.values()))
        named = True
        if "signature" in skip or _ed25519_verify(key, message, sig):
            return
    raise Refusal(CONTRADICTED, "signature_invalid" if named else "untrusted_key")


def _digest_map(value: Any, nonempty: bool) -> bool:
    return (isinstance(value, dict) and (bool(value) or not nonempty)
            and all(isinstance(k, str) and NAME.fullmatch(k) and isinstance(v, str)
                    and HEX64.fullmatch(v) for k, v in value.items()))


def _field_ok(field: str, d: dict[str, Any]) -> bool:
    value = d.get(field.split(".")[0])
    if field in ("parent", "candidate"):
        return isinstance(value, str) and bool(value)
    if field == "candidate_digest":
        return isinstance(value, str) and bool(HEX64.fullmatch(value))
    if field == "evaluator":
        return (isinstance(value, dict) and isinstance(value.get("version"), str)
                and bool(value["version"]))
    if field == "evaluator.components.suite_file":
        components = value.get("components") if isinstance(value, dict) else None
        suite = components.get("suite_file") if isinstance(components, dict) else None
        return isinstance(suite, str) and bool(HEX64.fullmatch(suite))
    if field == "exceptions":
        return isinstance(value, list) and all(isinstance(e, str) for e in value)
    if field == "admitted":
        return isinstance(value, bool)
    if field == "checks":
        return isinstance(value, list) and all(
            isinstance(c, dict) and isinstance(c.get("name"), str)
            and isinstance(c.get("passed"), bool) for c in value)
    return _digest_map(value, nonempty=field == "report_digests")


def _carried(payload: dict[str, Any], carriage: str, skip: frozenset[str]) -> tuple[Any, Any]:
    """(predicate type, decision object) as the carriage places them."""
    if carriage != "dsse-intoto":
        return payload.get("predicateType"), payload
    if payload.get("_type") != STATEMENT_V1 and "statement_type" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_statement_type")
    return payload.get("predicateType"), payload.get("predicate")


def _subject_matches(payload: dict[str, Any], candidate: Any) -> bool:
    subjects = payload.get("subject")
    return isinstance(subjects, list) and any(
        isinstance(s, dict) and isinstance(s.get("digest"), dict)
        and s["digest"].get("sha256") == candidate for s in subjects)


def _decision_object(payload: Any, carriage: str, policy: dict[str, Any],
                     skip: frozenset[str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        if "payload_object" in skip and isinstance(payload, list) and payload:
            payload = payload[0]
        else:
            raise Refusal(NOT_ESTABLISHED, "payload_not_json_object")
    predicate_type, d = _carried(payload, carriage, skip)
    if predicate_type != policy["predicate_type"] and "predicate" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_predicate")
    if not isinstance(d, dict):
        raise Refusal(NOT_ESTABLISHED, "payload_field_invalid:predicate")
    for field in FIELDS:
        if f"field:{field}" not in skip and not _field_ok(field, d):
            raise Refusal(NOT_ESTABLISHED, f"payload_field_invalid:{field}")
    if (carriage == "dsse-intoto" and "subject" not in skip
            and not _subject_matches(payload, d.get("candidate_digest"))):
        raise Refusal(CONTRADICTED, "subject_digest_mismatch")
    return d


def _gates(d: dict[str, Any], required: list[str], skip: frozenset[str]) -> None:
    checks = [c for c in d.get("checks") or [] if isinstance(c, dict)]
    if "required_gates_only" in skip:
        required = list(dict.fromkeys([*required, *(str(c.get("name")) for c in checks)]))
    passed = {c.get("name"): c.get("passed") is True for c in checks}
    missing = [g for g in required if g not in passed]
    if missing and "gate_missing" not in skip:
        raise Refusal(NOT_ESTABLISHED, f"gate_missing:{missing[0]}")
    failed = [g for g in required if not passed.get(g, False)]
    if d.get("admitted") is True and failed and "admitted_with_failed_gate" not in skip:
        raise Refusal(CONTRADICTED, f"admitted_with_failed_gate:{failed[0]}")
    if d.get("admitted") is False and not failed and "rejected_with_all_gates_passed" not in skip:
        raise Refusal(CONTRADICTED, "rejected_with_all_gates_passed")


def _reports(d: dict[str, Any], supplied: dict[str, bytes], require: bool,
             skip: frozenset[str]) -> None:
    digests = d.get("report_digests")
    named: dict[str, Any] = digests if isinstance(digests, dict) else {}
    unnamed = sorted(set(supplied) - set(named))
    if unnamed and "report_not_named" not in skip:
        raise Refusal(CONTRADICTED, f"report_not_named:{unnamed[0]}")
    for name in sorted(set(supplied) & set(named)):
        if _sha(supplied[name]) != named[name] and "report_digest_mismatch" not in skip:
            raise Refusal(CONTRADICTED, f"report_digest_mismatch:{name}")
    unverified = sorted(set(named) - set(supplied))
    if require and unverified and "report_not_supplied" not in skip:
        raise Refusal(NOT_ESTABLISHED, f"report_not_supplied:{unverified[0]}")


def judge(envelope: bytes, policy: dict[str, Any], carriage: str, supplied: dict[str, bytes],
          skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one signed admission decision."""
    trusted = {str(k): base64.b64decode(v) for k, v in policy["trusted_keys"].items()}
    try:
        payload_type, body, sigs = parse_envelope(envelope)
        if payload_type != policy["payload_type"] and "payload_type" not in skip:
            raise Refusal(NOT_ESTABLISHED, "unsupported_payload_type")
        _signed_by(payload_type, body, sigs, trusted, skip)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, ValueError):
            payload = None
        d = _decision_object(payload, carriage, policy, skip)
        _gates(d, list(policy["required_gates"]), skip)
        _reports(d, supplied, bool(policy["require_reports"]), skip)
    except Refusal as stop:
        return {"decision": stop.decision, "reason": stop.reason}
    admitted = d.get("admitted") is True
    reason = "admitted_receipt_verified" if admitted else "rejection_receipt_verified"
    return {"decision": SUPPORTED, "reason": reason}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    supplied = {name: (base / file).read_bytes() for name, file in case["reports"].items()}
    return judge((base / case["envelope"]).read_bytes(), case["policy"], case["carriage"],
                 supplied, skip)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    ids = {entry["id"] for entry in entries}
    if not entries or len(ids) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != ids:
        return [], "case directories do not match manifest"
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        if entry["expected"]["decision"] == SUPPORTED:
            continue
        twin = by_id.get(entry.get("twin", ""))
        if twin is None or twin["expected"]["decision"] != SUPPORTED:
            return [], f"{entry['id']}: a refused member must name a supported twin"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout.strip().splitlines()[-1])
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError, IndexError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
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
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "case.json", skip)
        else:
            ran, observed = _external_answer(command, directory / "case.json")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", help="judge one case.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every case through this verifier instead")
    args = parser.parse_args(argv)
    if args.case:
        answer = verify(Path(args.case))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
