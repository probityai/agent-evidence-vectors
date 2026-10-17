"""Parse the records of a done run, and name the first rule one breaks.

A coding agent's claim to be done is checked against records made outside the
agent: a sealed contract, the final tree, an observer's events, a verifier's
grade and the commands the agent says it ran. This module reads those records
and the consumer's case and policy files that pin them, under the rules in
``spec/predicates/done-records.md``. A record that breaks a rule is refused with
a code, never read leniently: a verdict taken from a record the reader had to
repair is not a verdict about the record that was signed.

The codes are ``<record>_<rule>``. A record is refused at the first rule it
breaks, in the order the specification lists them, so two rails give one code.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

MUTATION_TYPES = frozenset({"write", "create", "rename", "link", "unlink", "truncate", "chmod"})
EXEC_TYPE = "exec"
SCOPES = ("PEER", "EXTERNAL")
VANTAGES = ("independent", "self_reported")
COVERAGES = ("complete", "incomplete", "unknown")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ORIGIN_FIELDS = {"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class RecordError(ValueError):
    """A record, case or policy broke a rule; no verdict was reached."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes, record: str) -> Any:
    """Parse UTF-8 JSON, refusing a duplicate member or a non-JSON number."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        found: dict[str, Any] = {}
        for key, value in pairs:
            if key in found:
                raise RecordError(f"{record}_json_duplicate_key", key)
            found[key] = value
        return found

    def refuse(token: str) -> None:
        raise RecordError(f"{record}_json_number", token)

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=refuse)
    except (UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, RecordError):
            raise
        raise RecordError(f"{record}_json_invalid", str(exc)) from exc


def fields(value: Any, record: str, required: set[str],
           optional: frozenset[str] | set[str] = frozenset()) -> dict[str, Any]:
    """An object with exactly the required members and any optional ones."""
    if not isinstance(value, dict) or required - value.keys() or value.keys() - required - optional:
        raise RecordError(f"{record}_fields", f"expected {sorted(required)}")
    return value


def text(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecordError(code)
    return value


def digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise RecordError(code)
    return value


def instant(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not INSTANT.fullmatch(value):
        raise RecordError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RecordError(code) from exc


def count(value: Any, code: str) -> int:
    if type(value) is not int or value < 0:
        raise RecordError(code)
    return value


def exit_status(value: Any, code: str) -> int:
    if type(value) is not int or not -255 <= value <= 255:
        raise RecordError(code)
    return value


def choice(value: Any, code: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise RecordError(code)
    return value


def relative_path(value: Any, code: str) -> str:
    """A normalized workspace-relative POSIX path."""
    name = text(value, code)
    if ("\x00" in name or name.startswith("/") or name.endswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise RecordError(code, name)
    return name


def argv(value: Any, code: str) -> list[str]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) for item in value) or not value[0]):
        raise RecordError(code)
    return value


def under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + "/")


def protects(entry: dict[str, Any], name: str) -> bool:
    """Whether a protected entry covers a path, after its excluded segment names."""
    if not under(name, entry["path"]):
        return False
    below = name[len(entry["path"]) + 1:].split("/") if name != entry["path"] else []
    return not set(below) & set(entry.get("exclude", ()))


def tree_digest(files: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<sha256>  <path>\\n"`` lines, as sha256sum prints them."""
    ordered = sorted(files, key=lambda item: item.encode("utf-8"))
    return sha256("".join(f"{files[name]}  {name}\n" for name in ordered).encode("utf-8"))


def _protected_entry(item: Any, index: int) -> dict[str, Any]:
    label = f"contract.protected_paths[{index}]"
    entry = fields(item, "contract_protected_path", {"path", "kind", "sha256"}, {"exclude"})
    relative_path(entry["path"], "contract_protected_path_not_normalized")
    kind = choice(entry["kind"], "contract_protected_kind", ("file", "directory"))
    digest(entry["sha256"], "contract_digest_malformed")
    if "exclude" in entry:
        names = entry["exclude"]
        if (kind != "directory" or not isinstance(names, list) or not names
                or len(set(map(str, names))) != len(names)
                or any(not isinstance(n, str) or n in ("", ".", "..") or "/" in n or "\x00" in n
                       for n in names)):
            raise RecordError("contract_exclude_invalid", label)
    return entry


def _acceptance(items: Any) -> None:
    if not isinstance(items, list) or not items:
        raise RecordError("contract_acceptance_empty")
    seen: set[str] = set()
    for item in items:
        entry = fields(item, "contract_acceptance", {"id", "argv"})
        name = text(entry["id"], "contract_acceptance_id")
        argv(entry["argv"], "contract_acceptance_argv")
        if name in seen:
            raise RecordError("contract_acceptance_duplicate_id", name)
        seen.add(name)


def contract(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "contract"), "contract",
                    {"schema_version", "contract_id", "protected_paths", "acceptance", "adequacy"},
                    {"task", "heldout_split_sha256", "mutant_set_sha256", "authority_sha256"})
    if record["schema_version"] != "probity-done-contract/v1":
        raise RecordError("contract_schema_unsupported")
    text(record["contract_id"], "contract_id")
    if "task" in record:
        text(record["task"], "contract_task")
    for key in ("heldout_split_sha256", "mutant_set_sha256", "authority_sha256"):
        if key in record:
            digest(record[key], "contract_digest_malformed")
    protected = record["protected_paths"]
    if not isinstance(protected, list):
        raise RecordError("contract_protected_paths_type")
    paths = [_protected_entry(item, index)["path"] for index, item in enumerate(protected)]
    if len(set(paths)) != len(paths):
        raise RecordError("contract_protected_duplicate")
    _acceptance(record["acceptance"])
    adequacy = fields(record["adequacy"], "contract_adequacy", {"mutants", "killed"})
    mutants = count(adequacy["mutants"], "contract_adequacy_count")
    if count(adequacy["killed"], "contract_adequacy_count") > mutants:
        raise RecordError("contract_adequacy_overcount")
    return record


def _origin(record: dict[str, Any], name: str) -> None:
    text(record["claim_id"], f"{name}_claim_id")
    text(record["invocation_id"], f"{name}_invocation_id")
    text(record["producer"], f"{name}_producer")
    choice(record["vantage"], f"{name}_vantage", VANTAGES)
    choice(record["witness_scope"], f"{name}_witness_scope", SCOPES)


def tree(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "tree"), "tree",
                    {"schema_version", "tree_sha256", "files"} | ORIGIN_FIELDS)
    if record["schema_version"] != "probity-tree/v1":
        raise RecordError("tree_schema_unsupported")
    _origin(record, "tree")
    files = record["files"]
    if not isinstance(files, dict):
        raise RecordError("tree_files_type")
    for name, value in files.items():
        relative_path(name, "tree_path_not_normalized")
        digest(value, "tree_digest_malformed")
    if tree_digest(files) != digest(record["tree_sha256"], "tree_digest_malformed"):
        raise RecordError("tree_digest_mismatch")
    return record


def scope(value: Any, name: str) -> dict[str, Any]:
    found = fields(value, f"{name}_scope", {"id", "start", "end"})
    text(found["id"], f"{name}_scope_id")
    start = instant(found["start"], f"{name}_scope_instant")
    if instant(found["end"], f"{name}_scope_instant") < start:
        raise RecordError(f"{name}_scope_order")
    return found


def _gaps(record: dict[str, Any]) -> list[Any]:
    coverage = choice(record["coverage"], "observation_coverage", COVERAGES)
    gaps = record.get("gaps", [])
    if coverage == "incomplete":
        if not isinstance(gaps, list) or not gaps:
            raise RecordError("observation_gaps_required")
    elif "gaps" in record:
        raise RecordError("observation_gaps_unexpected")
    start = instant(record["scope"]["start"], "observation_scope_instant")
    end = instant(record["scope"]["end"], "observation_scope_instant")
    for item in gaps:
        gap = fields(item, "observation_gap", {"start", "end"})
        if not start <= instant(gap["start"], "observation_gap_instant") < instant(
                gap["end"], "observation_gap_instant") <= end:
            raise RecordError("observation_gap_outside_scope")
    return list(gaps)


def _exec_event(event: dict[str, Any]) -> None:
    argv(event.get("argv"), "observation_exec_argv")
    if "exit" in event:
        exit_status(event["exit"], "observation_exec_exit")
    if "path" in event or "target" in event:
        raise RecordError("observation_exec_path")


def _file_event(event: dict[str, Any]) -> None:
    kind = event["type"]
    if "argv" in event or "exit" in event:
        raise RecordError("observation_argv_on_file_event")
    if kind in MUTATION_TYPES and "path" not in event:
        raise RecordError("observation_path_required")
    if "path" in event:
        relative_path(event["path"], "observation_path_not_normalized")
    if "target" in event:
        if kind not in ("rename", "link"):
            raise RecordError("observation_target_unexpected")
        relative_path(event["target"], "observation_path_not_normalized")


def _event(item: Any, exec_ids: set[str]) -> dict[str, Any]:
    event = fields(item, "observation_event", {"id", "type", "time", "step"},
                   {"path", "target", "argv", "exit", "origin"})
    text(event["id"], "observation_event_id")
    text(event["type"], "observation_event_type")
    count(event["step"], "observation_step")
    if "origin" in event and event["origin"] not in exec_ids:
        raise RecordError("observation_origin_unknown")
    if event["type"] == EXEC_TYPE:
        _exec_event(event)
    else:
        _file_event(event)
    return event


def _events(record: dict[str, Any]) -> None:
    events = record.get("events", [])
    if not isinstance(events, list):
        raise RecordError("observation_events_type")
    start = instant(record["scope"]["start"], "observation_scope_instant")
    end = instant(record["scope"]["end"], "observation_scope_instant")
    seen: set[str] = set()
    exec_ids: set[str] = set()
    previous = -1
    for item in events:
        event = _event(item, exec_ids)
        moment = instant(event["time"], "observation_event_instant")
        if event["id"] in seen or not start <= moment <= end:
            raise RecordError("observation_event_duplicate_or_outside")
        if event["step"] <= previous:
            raise RecordError("observation_steps_not_increasing")
        previous = event["step"]
        seen.add(event["id"])
        if event["type"] == EXEC_TYPE:
            exec_ids.add(event["id"])


def observation(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "observation"), "observation",
                    {"schema_version", "scope", "coverage"} | ORIGIN_FIELDS, {"events", "gaps"})
    if record["schema_version"] != "probity-observation/v2":
        raise RecordError("observation_schema_unsupported")
    _origin(record, "observation")
    scope(record["scope"], "observation")
    _gaps(record)
    _events(record)
    return record


def capability(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "capability"), "capability",
                    {"schema_version", "claim_id", "invocation_id", "producer",
                     "visible_event_types"})
    if record["schema_version"] != "probity-capabilities/v1":
        raise RecordError("capability_schema_unsupported")
    for key in ("claim_id", "invocation_id", "producer"):
        text(record[key], f"capability_{key}")
    types = record["visible_event_types"]
    if not isinstance(types, list) or any(not isinstance(t, str) or not t for t in types):
        raise RecordError("capability_types")
    if len(types) != len(set(types)):
        raise RecordError("capability_types_duplicate")
    return record


def grade(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "grade"), "grade",
                    {"schema_version", "contract_sha256", "tree_sha256", "results"}
                    | ORIGIN_FIELDS)
    if record["schema_version"] != "probity-acceptance-grade/v1":
        raise RecordError("grade_schema_unsupported")
    _origin(record, "grade")
    digest(record["contract_sha256"], "grade_digest_malformed")
    digest(record["tree_sha256"], "grade_digest_malformed")
    if not isinstance(record["results"], list):
        raise RecordError("grade_results_type")
    seen: set[str] = set()
    for item in record["results"]:
        entry = fields(item, "grade_result", {"id", "argv", "exit"})
        name = text(entry["id"], "grade_result_id")
        argv(entry["argv"], "grade_result_argv")
        exit_status(entry["exit"], "grade_result_exit")
        if name in seen:
            raise RecordError("grade_result_duplicate_id")
        seen.add(name)
    return record


def claims(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "claims"), "claims",
                    {"schema_version", "claim_id", "invocation_id", "producer", "claims"})
    if record["schema_version"] != "probity-tool-claims/v1":
        raise RecordError("claims_schema_unsupported")
    for key in ("claim_id", "invocation_id", "producer"):
        text(record[key], f"claims_{key}")
    if not isinstance(record["claims"], list):
        raise RecordError("claims_type")
    seen: set[str] = set()
    for item in record["claims"]:
        entry = fields(item, "claims_entry", {"id", "argv"}, {"exit"})
        name = text(entry["id"], "claims_entry_id")
        argv(entry["argv"], "claims_entry_argv")
        if "exit" in entry:
            exit_status(entry["exit"], "claims_entry_exit")
        if name in seen:
            raise RecordError("claims_duplicate_id")
        seen.add(name)
    return record


def independent(record: dict[str, Any], pin: dict[str, Any], observed_party: str) -> bool:
    """The consumer pin and the record agree on an independent producer."""
    return bool(record["vantage"] == pin["vantage"] == "independent"
                and record["producer"] == pin["producer"]
                and record["producer"] != observed_party)


def scope_of(*pairs: tuple[dict[str, Any], dict[str, Any]]) -> str:
    """EXTERNAL only when every record and its consumer pin both say EXTERNAL."""
    external = all(record["witness_scope"] == pin["witness_scope"] == "EXTERNAL"
                   for record, pin in pairs)
    return "EXTERNAL" if external else "PEER"


# --- consumer case and policy ------------------------------------------------------------


def read_member_file(root: Path, name: str, code: str) -> bytes | None:
    """The bytes of a regular, non-link file under ``root``, or None if it is absent."""
    target = root / name
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecordError(code, str(exc)) from exc
    if not target.is_file() or target.is_symlink() or info.st_size > MAX_ARTIFACT_BYTES:
        raise RecordError(code, name)
    return target.read_bytes()


def artifact(root: Path, meta: Any, name: str) -> tuple[bytes | None, dict[str, Any]]:
    """Read one artifact the case binds by path, length and digest."""
    found = fields(meta, "case_artifact", {"path", "sha256", "length"})
    rel = text(found["path"], "case_artifact_path")
    parts = rel.split("/")
    if "\x00" in rel or rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise RecordError("case_artifact_path_not_normalized", name)
    pinned = digest(found["sha256"], "case_artifact_digest_malformed")
    length = found["length"]
    if type(length) is not int or not 0 <= length <= MAX_ARTIFACT_BYTES:
        raise RecordError("case_artifact_length")
    data = read_member_file(root, rel, "case_artifact_unsafe")
    if data is None:
        return None, {"status": "unavailable", "path": rel}
    if len(data) != length or sha256(data) != pinned:
        raise RecordError("case_artifact_binding_mismatch", name)
    return data, {"status": "bound", "path": rel, "sha256": pinned, "length": length}


def witness(case: dict[str, Any], policy: dict[str, Any], witness_id: str, root: Path,
            observed: bool) -> tuple[bytes | None, dict[str, Any]]:
    witnesses = policy["witnesses"]
    if witness_id not in witnesses:
        raise RecordError("policy_witness_unknown", witness_id)
    needed = {"artifact", "sha256", "authority"} | ({"producer", "vantage", "witness_scope"}
                                                    if observed else set())
    pin_in = fields(witnesses[witness_id], "policy_witness", needed)
    artifact_id = text(pin_in["artifact"], "policy_witness_artifact")
    if artifact_id not in case["artifacts"]:
        raise RecordError("case_artifact_unknown", artifact_id)
    pinned = digest(pin_in["sha256"], "policy_witness_digest_malformed")
    text(pin_in["authority"], "policy_witness_authority")
    data, binding = artifact(root, case["artifacts"][artifact_id], artifact_id)
    if binding.get("sha256") != pinned:
        data = None
    pin: dict[str, Any] = {"id": witness_id, "artifact": artifact_id,
                           "consumer_pinned_sha256": pinned, "binding": binding}
    if observed:
        pin["producer"] = text(pin_in["producer"], "policy_witness_producer")
        pin["vantage"] = choice(pin_in["vantage"], "policy_witness_vantage", VANTAGES)
        pin["witness_scope"] = choice(pin_in["witness_scope"], "policy_witness_scope", SCOPES)
    return data, pin


def start(case: Any, policy: Any, claim_type: str, assessment_fields: set[str]
          ) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate the case and policy envelopes; return case id, assessment, case, policy."""
    case = fields(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = fields(policy, "policy", {"schema_version", "witnesses", "assessments"})
    if (case["schema_version"] != "probity-case/v1"
            or policy["schema_version"] != "probity-policy/v1"):
        raise RecordError("case_schema_unsupported")
    case_id = text(case["case_id"], "case_id")
    if not isinstance(case["artifacts"], dict) or not isinstance(policy["witnesses"], dict):
        raise RecordError("case_objects")
    assessments = policy["assessments"]
    if not isinstance(assessments, dict) or case_id not in assessments:
        raise RecordError("policy_assessment_missing", case_id)
    assessment = fields(assessments[case_id], "policy_assessment", assessment_fields)
    if assessment["claim_type"] != claim_type:
        raise RecordError("policy_claim_type_unsupported")
    return case_id, assessment, case, policy


def bind(case: dict[str, Any], policy: dict[str, Any], assessment: dict[str, Any], root: Path,
         roles: dict[str, bool]) -> dict[str, tuple[bytes | None, dict[str, Any]]]:
    """Bind each named witness role; True roles need producer, vantage and scope pins."""
    ids = {role: text(assessment[f"{role}_witness"], f"policy_{role}_witness") for role in roles}
    if len(set(ids.values())) != len(ids):
        raise RecordError("policy_witness_shared")
    bound = {role: witness(case, policy, ids[role], root, observed)
             for role, observed in roles.items()}
    if len({pin["artifact"] for _, pin in bound.values()}) != len(bound):
        raise RecordError("policy_artifact_shared")
    return bound
