"""Verify signed agentic process evidence against a pinned consumer policy.

The corpus this module reads pins the field rules of the Agentic Process
Evidence predicate, version 0.1, as written in two places on 2026-10-15:

* in-toto/attestation pull request 609, ``spec/predicates/agentic-process.md``
  at head 7ac6780cf813377c07a66dafe066b819f08b3f01
  (https://github.com/in-toto/attestation/pull/609);
* jfrog/agentic-process-evidence ``spec/agentic-process-evidence.md`` and
  ``spec/agent-identifier.md`` at commit 1d2feec9678919178520f1ecaeed185f12657f3f
  (https://github.com/jfrog/agentic-process-evidence).

One member is one DSSE v1 envelope over an in-toto Statement v1 whose
predicate records an agentic process: the provider stacks that ran it, its
result, its accountable owner, its start and end, and the session logs, tools
and context artifacts it used. The consumer policy pins the payload type, the
predicate type and the trusted keys.

The reader checks in a fixed order and names the first check that fails:

1. the envelope parses as DSSE v1 (else no verdict, ``malformed_envelope``);
2. its payload type is the pinned one (``unsupported_payload_type``);
3. a signature naming a pinned keyid verifies over the DSSE pre-authentication
   encoding (``untrusted_key`` when no signature names a pinned key,
   ``signature_invalid`` when one does and fails). A signature naming any
   other key is ignored, never trusted;
4. the payload is a JSON object (``payload_not_json_object``) and an in-toto
   Statement v1 (``unsupported_statement_type``);
5. the predicate type is the pinned one (``unsupported_predicate``);
6. every field the specification constrains is well formed, in the order of
   ``FIELDS`` (``field_invalid:<field>``).

A member that passes all six is ``supported`` with the reason
``process_evidence_verified``. A ``FAILED`` or ``MISALIGNED`` result is still
supported: the record is verified, and what it records is the consumer's call.

Field rules, each from the specification's own tables:

* ``createdAt``, ``startTimestamp``, ``endTimestamp``: an ISO 8601 date-time,
  read in its RFC 3339 profile (extended format, seconds, a zone designator);
* ``createdBy``, ``processType``, ``owner``: a non-empty string;
* ``subject``: at least one entry, each with a ``uri`` and a digest set;
* ``providers``: at least one; each ``harness`` has a non-empty ``name`` and
  ``version``; ``agent`` fields and ``languageModels`` fields are non-empty
  when present;
* ``result``: one of the seven values the Process result table lists;
* ``traceId``: non-empty when present; ``sessionsLogs`` entries are resource
  descriptors with a ``uri`` and a digest set; ``tools`` entries carry a
  non-empty ``name`` and a ``version`` that is non-empty when present;
  ``contextArtifacts`` entries carry exactly one of ``uri`` or ``data``, a
  digest set when ``digest`` is present, and string ``tags``; ``custom`` is an
  object; ``intents`` and ``reviewers`` are string arrays; ``processSummary``
  is a string.

A URI is an absolute RFC 3986 URI: a scheme and no whitespace. A digest set is
the in-toto Statement v1 type: at least one algorithm key, every value a
non-empty string, and the algorithms in-toto names (``sha256``, ``sha512``,
``sha1``, ``gitCommit``) lowercase hex of their length. Unknown algorithm keys
and unknown fields are ignored, as both specifications require.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints
one JSON object carrying ``decision`` and ``reason`` on its last line, and
exits 0 for ``supported``, 1 for ``contradicted`` or ``not_established``, and 2
when no verdict was reached.
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

SUITE = "agentic-process-evidence/v0.1"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
VERIFIED = "process_evidence_verified"
STATEMENT_V1 = "https://in-toto.io/Statement/v1"
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
RESULTS = ("COMPLETED", "FAILED", "CANCELLED", "APPROVED", "REJECTED", "ALIGNED", "MISALIGNED")
# ASCII classes only, so the Go reader's RE2 patterns match the same strings.
TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$")
URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:[^\x00-\x20\x7f]+$")
HEX = re.compile(r"^[0-9a-f]+$")
DIGEST_LENGTHS = {"sha256": (64,), "sha512": (128,), "sha1": (40,), "gitCommit": (40, 64)}

# Every field the reader checks, in the order it checks them: the Statement's
# own fields first, then the predicate's required fields in the order of the
# specification's table, then its optional fields in the same order.
FIELDS = (
    "createdAt", "createdBy", "subject", "predicate",
    "predicate.processType", "predicate.providers", "predicate.providers[].harness",
    "predicate.providers[].agent", "predicate.providers[].languageModels",
    "predicate.result", "predicate.owner", "predicate.startTimestamp",
    "predicate.endTimestamp", "predicate.traceId", "predicate.sessionsLogs",
    "predicate.tools", "predicate.contextArtifacts", "predicate.custom",
    "predicate.intents", "predicate.processSummary", "predicate.reviewers",
)

# Every rule the reader applies, by the name the mutation check switches off.
RULES = (
    "payload_type", "pinned_keys_only", "signature", "payload_object", "statement_type",
    "predicate", *(f"field:{f}" for f in FIELDS),
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-agentic-process-evidence" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-agentic-process-evidence")
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


def _text(value: Any) -> bool:
    """A non-empty string."""
    return isinstance(value, str) and value != ""


def _optional_text(d: dict[str, Any], key: str) -> bool:
    return key not in d or _text(d[key])


def _timestamp(value: Any) -> bool:
    return isinstance(value, str) and bool(TIMESTAMP.fullmatch(value))


def _uri(value: Any) -> bool:
    return isinstance(value, str) and bool(URI.fullmatch(value))


def _digest_set(value: Any) -> bool:
    """The in-toto digest set: one or more algorithms, known ones lowercase hex."""
    if not isinstance(value, dict) or not value:
        return False
    for algorithm, digest in value.items():
        if not _text(digest):
            return False
        lengths = DIGEST_LENGTHS.get(algorithm)
        if lengths is not None and (len(digest) not in lengths or not HEX.fullmatch(digest)):
            return False
    return True


def _descriptor(value: Any) -> bool:
    return isinstance(value, dict) and _uri(value.get("uri")) and _digest_set(value.get("digest"))


def _objects(value: Any, nonempty: bool = False) -> list[dict[str, Any]] | None:
    """The list's entries when it is a list of objects, else None."""
    if not isinstance(value, list) or (nonempty and not value):
        return None
    if not all(isinstance(item, dict) for item in value):
        return None
    return value


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _providers(d: dict[str, Any]) -> list[dict[str, Any]]:
    return _objects(d.get("providers")) or []


def _harness_ok(provider: dict[str, Any]) -> bool:
    harness = provider.get("harness")
    return isinstance(harness, dict) and _text(harness.get("name")) and _text(
        harness.get("version"))


def _agent_ok(provider: dict[str, Any]) -> bool:
    if "agent" not in provider:
        return True
    agent = provider["agent"]
    return isinstance(agent, dict) and all(_optional_text(agent, k)
                                           for k in ("id", "name", "version"))


def _models_ok(provider: dict[str, Any]) -> bool:
    if "languageModels" not in provider:
        return True
    models = _objects(provider["languageModels"])
    return models is not None and all(
        _optional_text(m, "inferenceProvider") and _optional_text(m, "resolved") for m in models)


def _tools_ok(value: Any) -> bool:
    tools = _objects(value)
    return tools is not None and all(_text(t.get("name")) and _optional_text(t, "version")
                                     for t in tools)


def _artifact_ok(artifact: dict[str, Any]) -> bool:
    has_uri, has_data = "uri" in artifact, "data" in artifact
    if has_uri == has_data:
        return False
    if has_uri and not _uri(artifact["uri"]):
        return False
    if has_data and not isinstance(artifact["data"], str):
        return False
    if "digest" in artifact and not _digest_set(artifact["digest"]):
        return False
    return "tags" not in artifact or _strings(artifact["tags"])


def _optional(d: dict[str, Any], key: str, ok: Any) -> bool:
    return key not in d or bool(ok(d[key]))


def _field_ok(field: str, statement: dict[str, Any]) -> bool:
    if field in ("createdAt", "createdBy", "subject", "predicate"):
        value = statement.get(field)
        if field == "createdAt":
            return _timestamp(value)
        if field == "createdBy":
            return _text(value)
        if field == "subject":
            subjects = _objects(value, nonempty=True)
            return subjects is not None and all(_descriptor(s) for s in subjects)
        return isinstance(value, dict)
    # A predicate that is not an object is refused by the "predicate" rule, which
    # runs first; read as empty here so that rule stays the one that names it.
    d = statement.get("predicate")
    if not isinstance(d, dict):
        d = {}
    name = field.removeprefix("predicate.")
    checks: dict[str, Any] = {
        "processType": lambda: _text(d.get("processType")),
        "providers": lambda: _objects(d.get("providers"), nonempty=True) is not None,
        "providers[].harness": lambda: all(_harness_ok(p) for p in _providers(d)),
        "providers[].agent": lambda: all(_agent_ok(p) for p in _providers(d)),
        "providers[].languageModels": lambda: all(_models_ok(p) for p in _providers(d)),
        "result": lambda: d.get("result") in RESULTS,
        "owner": lambda: _text(d.get("owner")),
        "startTimestamp": lambda: _timestamp(d.get("startTimestamp")),
        "endTimestamp": lambda: _timestamp(d.get("endTimestamp")),
        "traceId": lambda: _optional_text(d, "traceId"),
        "sessionsLogs": lambda: _optional(
            d, "sessionsLogs",
            lambda v: _objects(v) is not None and all(_descriptor(e) for e in v)),
        "tools": lambda: _optional(d, "tools", _tools_ok),
        "contextArtifacts": lambda: _optional(
            d, "contextArtifacts",
            lambda v: _objects(v) is not None and all(_artifact_ok(a) for a in v)),
        "custom": lambda: _optional(d, "custom", lambda v: isinstance(v, dict)),
        "intents": lambda: _optional(d, "intents", _strings),
        "processSummary": lambda: _optional(d, "processSummary", lambda v: isinstance(v, str)),
        "reviewers": lambda: _optional(d, "reviewers", _strings),
    }
    return bool(checks[name]())


def _statement(payload: Any, policy: dict[str, Any], skip: frozenset[str]) -> None:
    if not isinstance(payload, dict):
        if "payload_object" in skip and isinstance(payload, list) and payload:
            payload = payload[0]
        else:
            raise Refusal(NOT_ESTABLISHED, "payload_not_json_object")
    if payload.get("_type") != STATEMENT_V1 and "statement_type" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_statement_type")
    if payload.get("predicateType") != policy["predicate_type"] and "predicate" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_predicate")
    for field in FIELDS:
        if f"field:{field}" in skip:
            continue
        if not _field_ok(field, payload):
            raise Refusal(NOT_ESTABLISHED, f"field_invalid:{field}")


def judge(envelope: bytes, policy: dict[str, Any],
          skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one signed process evidence statement."""
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
        _statement(payload, policy, skip)
    except Refusal as stop:
        return {"decision": stop.decision, "reason": stop.reason}
    return {"decision": SUPPORTED, "reason": VERIFIED}


def check_statement(statement: Any, predicate_type: str) -> str | None:
    """The first field rule an unsigned Statement breaks, or None when it holds.

    For reading a published example that carries no envelope: steps 4 to 6 only.
    """
    try:
        _statement(statement, {"predicate_type": predicate_type}, frozenset())
    except Refusal as stop:
        return stop.reason
    return None


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    return judge((case_path.parent / case["envelope"]).read_bytes(), case["policy"], skip)


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
