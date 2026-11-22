"""Verify signed credential-reachability/v1 records against a verifier's policy.

The corpus this module reads, ``corpora/vectors-credential-reachability/``, pins the
rules of spec/predicates/credential-reachability.md: a probe ran inside an agent's
environment, tried every ambient credential class of a closed list, and a key outside
the agent's reach signed what it found. The reader applies the document's 26 rules in
order, names the first that fails, and recomputes every class verdict and the result
from the attempts instead of copying them.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON
object carrying ``decision`` and ``reason``, and exits 0 for ``supported``, 1 for
``contradicted`` or ``not_established``, and 2 when no verdict was reached.

This is the Python rail for ``corpusreaders/credreach.go``; the two agree on every
member of the corpus.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import importlib
import json
import re
import shlex
import subprocess
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, TypeGuard

from . import strictb64, strictjson

SUITE = "credential-reachability/v1"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
STATEMENT_V1 = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = ("https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
                  "credential-reachability")
CLASS_SET = "credential-reachability/v1"
CLASSES = ("ssh-agent", "ssh-key-file", "cloud-metadata", "cloud-config-file",
           "registry-config-file", "browser-cookie-store", "environment-token",
           "cluster-service-account", "git-credential", "host-keyring")
VERDICTS = ("reachable", "not_reachable", "could_not_test")
OUTCOMES = ("found", "issued_to_agent", "placeholder", "absent", "denied", "error", "not_run")
RESULTS = ("contained", "incomplete", "exposed")  # best first
MEMBERS = ("classSet", "audience", "challenge", "probedAt", "vantage", "probe",
           "placeholders", "issuedToAgent", "classes", "result")
FIELDS = ("audience", "challenge", "probedAt", "vantage", "probe", "placeholders",
          "issuedToAgent", "classes", "result")
ATTEMPT_MEMBERS = frozenset({"locator", "outcome", "digestPrefix", "detail"})
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024

# Go's regexp ``$`` matches only at the end of the text; fullmatch keeps both readings equal.
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX12 = re.compile(r"[0-9a-f]{12}")
TEXT200 = re.compile(r"[\x20-\x7e]{1,200}")
TEXT512 = re.compile(r"[\x20-\x7e]{1,512}")
DETAIL = re.compile(r"[\x20-\x7e]{0,200}")
UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

# Every rule the reader applies, by the name the mutation check switches off.
RULES = (
    "payload_type", "agent_key", "pinned_keys_only", "signature", "strict_json",
    "payload_object", "statement_type", "predicate", "subject_shape", "environment",
    "predicate_object", "members", "class_set", *(f"field:{f}" for f in FIELDS),
    "attempt_fields", "vantage", "audience", "challenge", "future", "stale", "probe_pin",
    "class_duplicate", "class_missing", "issued_to_agent", "placeholder", "class_verdict", "result",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-credential-reachability" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-credential-reachability")
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify",)


class Refusal(Exception):
    """The first failed rule: a decision and a reason code."""

    def __init__(self, decision: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision, reason


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to dispatch the
    suite, so a module-level import would be a cycle."""
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
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        raise Refusal(NO_VERDICT, "malformed_envelope")
    try:
        return strictb64.std(value)
    except (binascii.Error, ValueError) as exc:
        raise Refusal(NO_VERDICT, "malformed_envelope") from exc


def parse_envelope(raw: bytes) -> tuple[str, bytes, list[tuple[str, bytes]]]:
    """(payloadType, payload, [(keyid, sig)]) or a no-verdict refusal."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise Refusal(NO_VERDICT, "malformed_envelope")
    try:
        doc = strictjson.loads(raw)
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


def _keys(table: Any) -> dict[str, bytes]:
    if not isinstance(table, dict):
        raise Refusal(NO_VERDICT, "policy_invalid")
    keys = {}
    for kid, encoded in table.items():
        try:
            raw = strictb64.std(encoded)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise Refusal(NO_VERDICT, "policy_invalid") from exc
        if len(raw) != 32 or not HEX64.fullmatch(str(kid)):
            raise Refusal(NO_VERDICT, "policy_invalid")
        keys[str(kid)] = raw
    return keys


def _signatures(payload_type: str, body: bytes, sigs: list[tuple[str, bytes]],
                trusted: dict[str, bytes], agent: dict[str, bytes],
                skip: frozenset[str]) -> None:
    message = pae(payload_type, body)
    if "agent_key" not in skip:
        for _, sig in sigs:
            if any(_ed25519_verify(k, message, sig) for k in agent.values()):
                raise Refusal(CONTRADICTED, "signed_by_agent_key")
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


def _text(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _exact(value: Any, members: set[str]) -> TypeGuard[dict[str, Any]]:
    return isinstance(value, dict) and set(value) == members


def _utc(value: Any) -> datetime | None:
    if not _text(value, UTC_SECONDS):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _lenient_utc(value: Any) -> datetime | None:
    """Only a mutation run that switched the probedAt rule off reaches a non-UTC time."""
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _attempt_ok(a: Any) -> bool:
    return (isinstance(a, dict) and _text(a.get("locator"), TEXT512)
            and a.get("outcome") in OUTCOMES
            and ("detail" not in a or _text(a["detail"], DETAIL)))


def _field_ok(field: str, p: dict[str, Any]) -> bool:
    value = p.get(field)
    if field in ("audience", "vantage"):
        return _text(value, TEXT200)
    if field == "challenge":
        return _text(value, HEX64)
    if field == "probedAt":
        return _utc(value) is not None
    if field == "probe":
        return (_exact(value, {"name", "version", "digest"}) and _text(value["name"], TEXT200)
                and _text(value["version"], TEXT200) and _exact(value["digest"], {"sha256"})
                and _text(value["digest"]["sha256"], HEX64))
    if field == "placeholders":
        return isinstance(value, list) and all(
            _exact(e, {"prefix"}) and _text(e["prefix"], TEXT200) for e in value)
    if field == "issuedToAgent":
        return isinstance(value, list) and all(
            _exact(e, {"id", "digestPrefix"}) and _text(e["id"], TEXT200)
            and _text(e["digestPrefix"], HEX12) for e in value)
    if field == "classes":
        return isinstance(value, list) and all(
            _exact(c, {"class", "verdict", "attempts"}) and c["class"] in CLASSES
            and c["verdict"] in VERDICTS and isinstance(c["attempts"], list)
            and bool(c["attempts"]) and all(_attempt_ok(a) for a in c["attempts"])
            for c in value)
    return value in RESULTS


def derive_verdict(attempts: list[dict[str, Any]]) -> str:
    outcomes = {a.get("outcome") for a in attempts if isinstance(a, dict)}
    if "found" in outcomes:
        return "reachable"
    if outcomes & {"error", "not_run"}:
        return "could_not_test"
    return "not_reachable"


def derive_result(verdicts: list[str]) -> str:
    if "reachable" in verdicts:
        return "exposed"
    if "could_not_test" in verdicts:
        return "incomplete"
    return "contained"


def _classes(p: dict[str, Any]) -> list[dict[str, Any]]:
    value = p.get("classes")
    return [c for c in value if isinstance(c, dict)] if isinstance(value, list) else []


def _attempts(c: dict[str, Any]) -> list[dict[str, Any]]:
    value = c.get("attempts")
    return [a for a in value if isinstance(a, dict)] if isinstance(value, list) else []


def _statement(body: bytes, policy: dict[str, Any], skip: frozenset[str]) -> dict[str, Any]:
    try:
        payload: Any = (json.loads(body) if "strict_json" in skip else strictjson.loads(body))
    except (UnicodeDecodeError, ValueError):
        payload = None
    if not isinstance(payload, dict):
        if "payload_object" in skip and isinstance(payload, list) and payload:
            payload = payload[0]
        else:
            raise Refusal(NOT_ESTABLISHED, "payload_not_json_object")
    if payload.get("_type") != STATEMENT_V1 and "statement_type" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_statement_type")
    if payload.get("predicateType") != PREDICATE_TYPE and "predicate" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_predicate")
    subjects = payload.get("subject")
    first = subjects[0] if isinstance(subjects, list) and subjects else None
    shaped = (isinstance(subjects, list) and len(subjects) == 1
              and _exact(first, {"name", "digest"}) and _text(first["name"], TEXT512)
              and _exact(first["digest"], {"sha256"}) and _text(first["digest"]["sha256"], HEX64))
    if not shaped and "subject_shape" not in skip:
        raise Refusal(NOT_ESTABLISHED, "subject_malformed")
    env = policy["environment"]
    digest = first.get("digest") if isinstance(first, dict) else None
    matches = (isinstance(first, dict) and first.get("name") == env["name"]
               and isinstance(digest, dict) and digest.get("sha256") == env["sha256"])
    if not matches and "environment" not in skip:
        raise Refusal(CONTRADICTED, "environment_mismatch")
    p = payload.get("predicate")
    if not isinstance(p, dict):
        if "predicate_object" not in skip:
            raise Refusal(NOT_ESTABLISHED, "predicate_field_invalid:predicate")
        p = {}
    return p


def _wellformed(p: dict[str, Any], skip: frozenset[str]) -> None:
    if set(p) != set(MEMBERS) and "members" not in skip:
        raise Refusal(NOT_ESTABLISHED, "predicate_field_invalid:members")
    if p.get("classSet") != CLASS_SET and "class_set" not in skip:
        raise Refusal(NOT_ESTABLISHED, "class_set_unsupported")
    for field in FIELDS:
        if f"field:{field}" not in skip and not _field_ok(field, p):
            raise Refusal(NOT_ESTABLISHED, f"predicate_field_invalid:{field}")
    if "attempt_fields" in skip:
        return
    for c in _classes(p):
        for a in _attempts(c):
            needs = a.get("outcome") in ("found", "issued_to_agent")
            if (not set(a) <= ATTEMPT_MEMBERS or ("digestPrefix" in a) != needs
                    or (needs and not _text(a.get("digestPrefix"), HEX12))):
                raise Refusal(CONTRADICTED, "attempt_fields")


def _binding(p: dict[str, Any], policy: dict[str, Any], skip: frozenset[str]) -> None:
    if p.get("vantage") != "agent-process" and "vantage" not in skip:
        raise Refusal(NOT_ESTABLISHED, "vantage_not_agent")
    if p.get("audience") != policy["audience"] and "audience" not in skip:
        raise Refusal(CONTRADICTED, "audience_mismatch")
    if p.get("challenge") != policy["challenge"] and "challenge" not in skip:
        raise Refusal(CONTRADICTED, "challenge_mismatch")
    judged = _utc(policy["judged_at"])
    probed = _utc(p.get("probedAt")) or _lenient_utc(p.get("probedAt"))
    if judged is None:
        raise Refusal(NO_VERDICT, "policy_invalid")
    if probed is not None and probed > judged and "future" not in skip:
        raise Refusal(CONTRADICTED, "probed_in_future")
    age = (judged - probed).total_seconds() if probed is not None else None
    if (age is None or age > policy["max_age_seconds"]) and "stale" not in skip:
        raise Refusal(NOT_ESTABLISHED, "result_stale")
    pins = policy["probe_digests"]
    probe = p.get("probe")
    digest = probe.get("digest") if isinstance(probe, dict) else None
    found = digest.get("sha256") if isinstance(digest, dict) else None
    if pins and found not in pins and "probe_pin" not in skip:
        raise Refusal(NOT_ESTABLISHED, "probe_not_pinned")


def _coverage(p: dict[str, Any], skip: frozenset[str]) -> None:
    seen: set[Any] = set()
    for c in _classes(p):
        if c.get("class") in seen and "class_duplicate" not in skip:
            raise Refusal(CONTRADICTED, f"class_duplicate:{c.get('class')}")
        seen.add(c.get("class"))
    for name in CLASSES:
        if name not in seen and "class_missing" not in skip:
            raise Refusal(CONTRADICTED, f"class_missing:{name}")
    issued = p.get("issuedToAgent")
    declared = {e.get("digestPrefix") for e in issued if isinstance(e, dict)} \
        if isinstance(issued, list) else set()
    placeholders = p.get("placeholders")
    attempts = [a for c in _classes(p) for a in _attempts(c)]
    if "issued_to_agent" not in skip and any(
            a.get("outcome") == "issued_to_agent" and a.get("digestPrefix") not in declared
            for a in attempts):
        raise Refusal(CONTRADICTED, "issued_to_agent_undeclared")
    if "placeholder" not in skip and not placeholders and any(
            a.get("outcome") == "placeholder" for a in attempts):
        raise Refusal(CONTRADICTED, "placeholder_undeclared")


def _verdicts(p: dict[str, Any], skip: frozenset[str]) -> str:
    by_class = {c.get("class"): c for c in _classes(p)}
    derived = []
    for name in CLASSES:
        c = by_class.get(name)
        if c is None:
            continue
        want, said = derive_verdict(_attempts(c)), c.get("verdict")
        derived.append(want)
        if want == said or "class_verdict" in skip:
            continue
        if said == "not_reachable":
            word = "reachable" if want == "reachable" else "untested"
            raise Refusal(CONTRADICTED, f"{word}_reported_clean:{name}")
        raise Refusal(CONTRADICTED, f"class_verdict_mismatch:{name}")
    result, said = derive_result(derived), p.get("result")
    if result != said and "result" not in skip:
        better = said in RESULTS and RESULTS.index(said) < RESULTS.index(result)
        raise Refusal(CONTRADICTED, "result_overstates" if better else "result_mismatch")
    return result


def judge(envelope: bytes, policy: dict[str, Any],
          skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one signed credential-reachability record."""
    try:
        trusted, agent = _keys(policy.get("trusted_signers")), _keys(policy.get("agent_keys"))
        if (not trusted or set(trusted.values()) & set(agent.values())
                or _utc(policy.get("judged_at")) is None):
            raise Refusal(NO_VERDICT, "policy_invalid")
        payload_type, body, sigs = parse_envelope(envelope)
        if payload_type != policy["payload_type"] and "payload_type" not in skip:
            raise Refusal(NOT_ESTABLISHED, "unsupported_payload_type")
        _signatures(payload_type, body, sigs, trusted, agent, skip)
        p = _statement(body, policy, skip)
        _wellformed(p, skip)
        _binding(p, policy, skip)
        _coverage(p, skip)
        result = _verdicts(p, skip)
    except Refusal as stop:
        return {"decision": stop.decision, "reason": stop.reason}
    return {"decision": SUPPORTED, "reason": f"{result}_verified"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    case = strictjson.loads(case_path.read_text(encoding="utf-8"))
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
    manifest = strictjson.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
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
        answer = strictjson.loads(result.stdout.strip().splitlines()[-1])
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError, IndexError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
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
        manifest = strictjson.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
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
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
