"""Judge the done-contract and done-receipt corpora, and the three that build on them.

Five corpora share one reader, because they share one question: given the records
of a coding agent's run, what does an outside verifier conclude? ``done-contract``
asks it of a sealed contract. ``done-receipt`` asks it of a whole run and of the
receipt that summarises the run. ``spoofed-tool-output``, ``test-tampering`` and
``grader-isolation`` ask it of the runs in which an agent fabricates a tool run,
edits what it is graded by, or reaches the grader.

A member is a directory of records. The reader names, for each member, what it
derives, and the manifest declares the same thing: the corpus never states a
verdict the reader does not recompute.

These corpora have no external-verifier contract: a named verifier is refused. An
independent implementation is replayed with
``vectors-done-receipt/crosscheck_probity_verify.py``, which runs every member's
case and policy through ``probity-verify`` and compares each check.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import donechecks as checks
from . import donerecords as rec
from .donerecords import RecordError

CONTRACT_SUITE = "done-contract/v1"
RECEIPT_SUITE = "done-receipt/v1"
SPOOFED_SUITE = "spoofed-tool-output/v1"
TAMPERING_SUITE = "test-tampering/v1"
GRADER_SUITE = "grader-isolation/v1"
SUITES = (CONTRACT_SUITE, RECEIPT_SUITE, SPOOFED_SUITE, TAMPERING_SUITE, GRADER_SUITE)
URI = "https://w3id.org/agent-evidence/predicate/v1/"
CONTRACT_TYPE = URI + "done-contract"
RECEIPT_TYPE = URI + "done-receipt"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RECEIPT_SCHEMA = "probity-done-receipt/v1"
# The verifier identity the reference command line writes into predicate.verifier.id.
VERIFIER_URI = "https://github.com/probityai/probity"
CORE_ROLES = ("contract", "tree", "observation", "capability", "grade", "claims")
LAUNCH_ROLES = ("launch", "launch_receipt")
ROLE_FILES = {role: f"{role.replace('_', '-')}.json" for role in CORE_ROLES + LAUNCH_ROLES}
LAUNCH_FIELDS = {
    "schema_version", "backend", "image", "image_id", "runtime_version", "strace_version",
    "container_argv", "trace_expression", "tracer_flags", "tracer_uid_separated", "agent_argv",
    "agent_uid", "env", "network", "container_workspace", "start_tarball_sha256",
    "observer_source_sha256", "timeout_seconds"}
LAUNCH_RECEIPT_FIELDS = {
    "schema_version", "claim_id", "invocation_id", "producer", "witnessScope", "launch_sha256",
    "trace_expression", "watch_list", "start_tarball_sha256", "tree_sha256", "coverage",
    "container_exit", "agent_exit", "timed_out", "transcript_sha256", "trace_sha256",
    "observation_sha256", "capability_sha256", "sensors", "doesNotAssert"}
SENSOR_FIELDS = {"s1_inotify", "s2_strace", "s3_tree", "join", "external_effects"}
ROOT_PARENT = Path(__file__).resolve().parent


class ReceiptInvalid(ValueError):
    """The receipt disagrees with the records it names; the records themselves parse."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --- the done-contract statement ------------------------------------------------------------


def _statement(data: bytes, expected_type: str, prefix: str) -> dict[str, Any]:
    """The in-toto Statement envelope: type, predicate type and one digest-keyed subject."""
    try:
        statement = rec.fields(rec.strict_json(data, prefix), prefix,
                               {"_type", "subject", "predicateType", "predicate"})
    except RecordError as exc:
        raise ReceiptInvalid(exc.code) from exc
    if statement["_type"] != STATEMENT_TYPE:
        raise ReceiptInvalid(f"{prefix}_type_wrong")
    if statement["predicateType"] != expected_type:
        raise ReceiptInvalid(f"{prefix}_predicate_type_wrong")
    subject = statement["subject"]
    if not isinstance(subject, list) or len(subject) != 1:
        raise ReceiptInvalid(f"{prefix}_subject_malformed")
    entry = subject[0]
    ok = (isinstance(entry, dict) and set(entry) == {"name", "digest"}
          and isinstance(entry["name"], str) and entry["name"]
          and isinstance(entry["digest"], dict) and set(entry["digest"]) == {"sha256"}
          and isinstance(entry["digest"]["sha256"], str)
          and rec.HEX64.fullmatch(entry["digest"]["sha256"]))
    if not ok:
        raise ReceiptInvalid(f"{prefix}_subject_malformed")
    return statement


def judge_contract(member: Path) -> dict[str, Any]:
    """A contract record and the Statement that carries it."""
    statement_bytes = rec.read_member_file(member, "statement.json", "member_unreadable")
    contract_bytes = rec.read_member_file(member, "contract.json", "member_unreadable")
    if statement_bytes is None or contract_bytes is None:
        raise RecordError("member_incomplete", str(member.name))
    try:
        statement = _statement(statement_bytes, CONTRACT_TYPE, "statement")
        record = rec.contract(contract_bytes)
        if statement["subject"][0]["digest"]["sha256"] != rec.sha256(contract_bytes):
            raise ReceiptInvalid("statement_subject_unbound")
        if statement["predicate"] != record:
            raise ReceiptInvalid("statement_predicate_differs")
    except ReceiptInvalid as exc:
        return {"verdict": "invalid", "code": exc.code}
    except RecordError as exc:
        return {"verdict": "invalid", "code": exc.code}
    return {"verdict": "valid"}


# --- launch records ------------------------------------------------------------------------


def _launch(data: bytes) -> dict[str, Any]:
    record = rec.fields(rec.strict_json(data, "launch"), "launch", LAUNCH_FIELDS)
    if record["schema_version"] != "probity-launch/v1":
        raise RecordError("launch_schema_unsupported")
    rec.choice(record["backend"], "launch_backend", ("docker", "apptainer"))
    for key in ("image", "image_id", "runtime_version", "strace_version", "trace_expression",
                "container_workspace"):
        rec.text(record[key], f"launch_{key}")
    for key in ("container_argv", "tracer_flags", "agent_argv"):
        rec.argv(record[key], f"launch_{key}")
    if (type(record["tracer_uid_separated"]) is not bool or type(record["network"]) is not bool
            or type(record["agent_uid"]) is not int
            or type(record["timeout_seconds"]) is not int):
        raise RecordError("launch_types")
    if not isinstance(record["env"], dict):
        raise RecordError("launch_types")
    rec.digest(record["start_tarball_sha256"], "launch_digest_malformed")
    rec.digest(record["observer_source_sha256"], "launch_digest_malformed")
    return record


def _effect(item: Any) -> dict[str, Any]:
    effect = rec.fields(item, "launch_receipt_effect", {"type", "time"}, {"paths", "address"})
    rec.text(effect["type"], "launch_receipt_effect")
    rec.instant(effect["time"], "launch_receipt_effect")
    if ("paths" in effect) == ("address" in effect):
        raise RecordError("launch_receipt_effect")
    if "paths" in effect and (not isinstance(effect["paths"], list) or not effect["paths"]
                              or any(not isinstance(p, str) or not p for p in effect["paths"])):
        raise RecordError("launch_receipt_effect")
    if "address" in effect:
        rec.text(effect["address"], "launch_receipt_effect")
    return effect


def _sensors(sensors: Any) -> dict[str, Any]:
    found = rec.fields(sensors, "launch_receipt_sensors", SENSOR_FIELDS)
    if (not isinstance(found["s1_inotify"], dict) or not isinstance(found["s2_strace"], dict)
            or not isinstance(found["join"], dict)):
        raise RecordError("launch_receipt_sensors")
    rec.choice(found["s2_strace"].get("tracer"), "launch_receipt_sensors", ("complete", "lost"))
    tree = rec.fields(found["s3_tree"], "launch_receipt_sensors", {"tree_sha256"},
                      {"files", "symlinks", "special"})
    rec.digest(tree["tree_sha256"], "launch_receipt_sensors")
    if not isinstance(found["external_effects"], list):
        raise RecordError("launch_receipt_sensors")
    for item in found["external_effects"]:
        _effect(item)
    return found


def _launch_receipt(data: bytes) -> dict[str, Any]:
    record = rec.fields(rec.strict_json(data, "launch_receipt"), "launch_receipt",
                        LAUNCH_RECEIPT_FIELDS)
    if record["schema_version"] != "probity-launch-receipt/v1":
        raise RecordError("launch_receipt_schema_unsupported")
    for key in ("claim_id", "invocation_id", "producer"):
        rec.text(record[key], f"launch_receipt_{key}")
    rec.choice(record["witnessScope"], "launch_receipt_witness_scope", rec.SCOPES)
    rec.choice(record["coverage"], "launch_receipt_coverage", rec.COVERAGES)
    for key in ("launch_sha256", "start_tarball_sha256", "tree_sha256", "transcript_sha256",
                "trace_sha256", "observation_sha256", "capability_sha256"):
        rec.digest(record[key], "launch_receipt_digest_malformed")
    if type(record["timed_out"]) is not bool or not isinstance(record["watch_list"], list):
        raise RecordError("launch_receipt_types")
    for key in ("container_exit", "agent_exit"):
        if record[key] is not None and type(record[key]) is not int:
            raise RecordError("launch_receipt_types")
    _sensors(record["sensors"])
    return record


def external_effects(member: Path) -> list[dict[str, Any]]:
    """The effects outside the workspace a member's launch receipt carries, or none."""
    data = rec.read_member_file(member, ROLE_FILES["launch_receipt"], "member_unreadable")
    return [] if data is None else _launch_receipt(data)["sensors"]["external_effects"]


# --- the done-receipt statement --------------------------------------------------------------


def _predicate(statement: dict[str, Any]) -> dict[str, Any]:
    try:
        predicate = rec.fields(statement["predicate"], "receipt_predicate",
                               {"schema_version", "claim_id", "invocation_id", "records",
                                "checks", "verdict", "external_effects", "verifier"},
                               {"policy", "verifier_isolation", "stop_decision"})
    except RecordError as exc:
        raise ReceiptInvalid(exc.code) from exc
    if predicate["schema_version"] != RECEIPT_SCHEMA:
        raise ReceiptInvalid("receipt_schema_unsupported")
    for key in ("claim_id", "invocation_id"):
        if not isinstance(predicate[key], str) or not predicate[key]:
            raise ReceiptInvalid("receipt_predicate_malformed")
    verifier = predicate["verifier"]
    if (not isinstance(verifier, dict) or set(verifier) != {"id"}
            or not isinstance(verifier["id"], str) or not VERIFIER_ID.fullmatch(verifier["id"])):
        raise ReceiptInvalid("receipt_verifier_malformed")
    if "policy" in predicate:
        policy = predicate["policy"]
        if (not isinstance(policy, dict) or set(policy) != {"table_sha256"}
                or not isinstance(policy["table_sha256"], str)
                or not rec.HEX64.fullmatch(policy["table_sha256"])):
            raise ReceiptInvalid("receipt_predicate_malformed")
    _optional_blocks(predicate)
    return predicate


# A URI: a scheme, a colon and at least one more character with no white space.
VERIFIER_ID = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s]+")

STOP_ACTIONS = ("continue", "replan", "escalate", "stop")


def _optional_blocks(predicate: dict[str, Any]) -> None:
    """The verifier's isolation report and the policy's stop decision, when carried."""
    if "verifier_isolation" in predicate:
        report = predicate["verifier_isolation"]
        if not isinstance(report, dict) or not isinstance(report.get("contract_sha256"), str):
            raise ReceiptInvalid("receipt_isolation_malformed")
    if "stop_decision" in predicate:
        stop = predicate["stop_decision"]
        if (not isinstance(stop, dict) or set(stop) != {"action", "reason"}
                or stop["action"] not in STOP_ACTIONS
                or not isinstance(stop["reason"], str) or not stop["reason"]):
            raise ReceiptInvalid("receipt_stop_decision_malformed")


def _record_digests(records: Any) -> dict[str, str]:
    ok = isinstance(records, dict) and all(
        isinstance(v, dict) and set(v) == {"sha256"} and isinstance(v["sha256"], str)
        and rec.HEX64.fullmatch(v["sha256"]) for v in records.values())
    roles = set(records) if ok else set()
    if not ok or roles not in (set(CORE_ROLES), set(CORE_ROLES) | set(LAUNCH_ROLES)):
        raise ReceiptInvalid("receipt_records_shape")
    return {role: records[role]["sha256"] for role in records}


def _read_roles(member: Path, digests: dict[str, str]) -> dict[str, bytes]:
    data: dict[str, bytes] = {}
    for role, pinned in digests.items():
        found = rec.read_member_file(member, ROLE_FILES[role], "member_unreadable")
        if found is None:
            raise ReceiptInvalid("receipt_record_missing")
        if rec.sha256(found) != pinned:
            raise ReceiptInvalid("receipt_record_digest_mismatch")
        data[role] = found
    return data


def _launch_bound(data: dict[str, bytes], tree: dict[str, Any], observation: dict[str, Any],
                  claim_id: str, invocation: str) -> None:
    """The launch receipt describes this run, this tree and no more coverage than it saw."""
    _launch(data["launch"])
    launched = _launch_receipt(data["launch_receipt"])
    if launched["claim_id"] != claim_id or launched["invocation_id"] != invocation:
        raise ReceiptInvalid("receipt_launch_context_mismatch")
    if launched["launch_sha256"] != rec.sha256(data["launch"]):
        raise ReceiptInvalid("receipt_launch_digest_unbound")
    named = ("observation", "capability", "tree")
    if any(launched[f"{role}_sha256"] != rec.sha256(data[role]) for role in named):
        raise ReceiptInvalid("receipt_launch_records_unbound")
    if launched["sensors"]["s3_tree"]["tree_sha256"] != tree["tree_sha256"]:
        raise ReceiptInvalid("receipt_launch_tree_unbound")
    if launched["witnessScope"] != tree["witness_scope"] or (
            launched["witnessScope"] != observation["witness_scope"]):
        raise ReceiptInvalid("receipt_launch_scope_differs")
    if launched["coverage"] != observation["coverage"]:
        raise ReceiptInvalid("receipt_launch_coverage_differs")
    if sensors_lost_events(launched["sensors"]) and observation["coverage"] == "complete":
        raise ReceiptInvalid("receipt_launch_coverage_overstated")


def sensors_lost_events(sensors: dict[str, Any]) -> bool:
    """Whether the sensors report a loss that a complete coverage cannot stand beside."""
    inotify, strace = sensors["s1_inotify"], sensors["s2_strace"]
    return bool(strace["tracer"] == "lost" or inotify.get("overflow")
                or inotify.get("watch_failures") or strace.get("escapes")
                or strace.get("unresolved") or strace.get("unparsed_lines")
                or sensors["join"].get("unattributed"))


def _recomputed(member: Path) -> list[dict[str, Any]]:
    return [checks.run_check(claim_type, member) for claim_type in checks.CLAIM_TYPES]


def _compare_checks(carried: Any, computed: list[dict[str, Any]]) -> None:
    if not isinstance(carried, list):
        raise ReceiptInvalid("receipt_predicate_malformed")
    expected = [{"claim_type": item["claim_type"], **checks.projection(item)}
                for item in computed]
    if carried != expected:
        raise ReceiptInvalid("receipt_check_not_recomputed")


def judge_receipt(member: Path) -> dict[str, Any]:
    """A done-receipt Statement, recomputed against the records it names."""
    data = rec.read_member_file(member, "receipt.json", "member_unreadable")
    if data is None:
        raise RecordError("member_incomplete", member.name)
    out: dict[str, Any] = {}
    try:
        statement = _statement(data, RECEIPT_TYPE, "receipt")
        predicate = _predicate(statement)
        digests = _record_digests(predicate["records"])
        report = predicate.get("verifier_isolation")
        if report is not None and report["contract_sha256"] != digests["contract"]:
            raise ReceiptInvalid("receipt_isolation_contract_differs")
        raw = _read_roles(member, digests)
        tree = rec.tree(raw["tree"])
        observation = rec.observation(raw["observation"])
        if statement["subject"][0]["digest"]["sha256"] != tree["tree_sha256"]:
            raise ReceiptInvalid("receipt_subject_unbound")
        if "launch" in raw:
            _launch_bound(raw, tree, observation, predicate["claim_id"],
                          predicate["invocation_id"])
        effects = external_effects(member)
        if predicate["external_effects"] != effects:
            raise ReceiptInvalid("receipt_external_effects_differ")
        computed = _recomputed(member)
        out["checks"] = {item["claim_type"]: checks.projection(item) for item in computed}
        out["done"] = checks.combine(computed, effects)
        _compare_checks(predicate["checks"], computed)
        if predicate["verdict"] != out["done"]:
            raise ReceiptInvalid("receipt_verdict_not_derived")
    except ReceiptInvalid as exc:
        return {**out, "receipt": {"verdict": "invalid", "code": exc.code}}
    return {**out, "receipt": {"verdict": "valid"}}


# --- one member ---------------------------------------------------------------------------


def judge_checks(member: Path, declared: list[str]) -> dict[str, Any]:
    results = [checks.run_check(claim_type, member) for claim_type in declared]
    out: dict[str, Any] = {"checks": {item["claim_type"]: checks.projection(item)
                                      for item in results}}
    if set(declared) == set(checks.CLAIM_TYPES):
        ordered = [item for claim_type in checks.CLAIM_TYPES for item in results
                   if item["claim_type"] == claim_type]
        out["done"] = checks.combine(ordered, external_effects(member))
    return out


def judge_member(suite: str, member: Path, declared: list[str]) -> dict[str, Any]:
    """What the reader derives for one member; ``refused`` names a record that broke a rule."""
    try:
        if suite == CONTRACT_SUITE:
            return {"contract": judge_contract(member)}
        if (member / "receipt.json").exists():
            return judge_receipt(member)
        return judge_checks(member, declared)
    except RecordError as exc:
        return {"refused": exc.code}


# --- corpus ---------------------------------------------------------------------------------


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(entries: list[dict[str, Any]]) -> str:
    return rec.sha256(_json(entries))


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {p.name for p in directory.iterdir() if p.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(rec.sha256((directory / name).read_bytes()) != value for name, value in files.items()):
        return "fixture digest mismatch"
    return None


def validated_entries(root: Path, suite: str) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if manifest.get("suite") != suite:
        return [], "unexpected suite"
    if corpus_digest(entries) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != {e["id"] for e in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def declared_view(entry: dict[str, Any]) -> dict[str, Any]:
    """The expectation a manifest entry declares, without the prose around it."""
    return dict(entry["expected"])


def _compare(entry: dict[str, Any], got: dict[str, Any]) -> str | None:
    want = declared_view(entry)
    return None if got == want else f"expected {want}, got {got}"


def check(suite: str, root: Path | None = None) -> tuple[int, list[str]]:
    """Check every member through the reference reader.

    Returns the number of members answered and every disagreement.
    """
    base = root or _default_root(suite)
    try:
        entries, problem = validated_entries(base, suite)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if problem:
        return 0, [problem]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        directory = base / entry["path"]
        fixture = _fixture_error(directory, entry)
        if fixture:
            errors.append(f"{entry['id']}: {fixture}")
            continue
        declared = list(entry.get("checks", []))
        got = judge_member(suite, directory, declared)
        answered += 1
        finding = _compare(entry, got)
        if finding:
            errors.append(f"{entry['id']}: {finding}")
    return answered, errors


def _default_root(suite: str) -> Path:
    name = "vectors-" + suite.split("/")[0]
    packaged = ROOT_PARENT / "corpora" / name
    return packaged if packaged.exists() else ROOT_PARENT.parents[1] / name


def run(suite: str, root: str, verifier: list[str] | None, report_path: str,
        rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    if verifier is not None:
        print(f"the verifier {shlex.join(verifier)!r} did NOT run: the corpus {suite!r} is "
              "judged only by this package's own reader and has no external-verifier contract")
        return 2
    directory = Path(root)
    answered, errors = check(suite, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    print(f"{suite}: reference reader answered {answered} of {total} cases, "
          f"{len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": suite, "rail": "own-reader",
        "verifier": {"command": None, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def runner(suite: str) -> Callable[[str, list[str] | None, str, str], int]:
    """The ``run`` entry the harness calls for one suite."""
    def call(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
        return run(suite, root, verifier, report_path, rail_note)
    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("corpus", nargs="?",
                        help="the corpus directory (default: the packaged one)")
    args = parser.parse_args(argv)
    root = Path(args.corpus) if args.corpus else None
    answered, errors = check(args.suite, root)
    for error in errors:
        print(error)
    print(f"answered {answered} cases, {len(errors)} disagreements")
    return 1 if errors or not answered else 0


if __name__ == "__main__":
    raise SystemExit(main())
