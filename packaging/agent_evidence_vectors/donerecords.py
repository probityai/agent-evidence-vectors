"""Parse the records of a done run, and name the first rule one breaks.

A coding agent's claim to be done is checked against records made outside the
agent: a sealed contract, the final tree, an observer's events, a verifier's
grade and the runs the agent says it made. This module reads those records and
the consumer's case and policy files that pin them, under the rules in
``spec/predicates/done-records.md``. They are the rules of probity-verify's
done adapters (``done_records.py``), restated with a code for each: a record the
verifier refuses is refused here, and a record it reads is read here the same way.

A record that breaks a rule is refused with a code, never read leniently: a verdict
taken from a record the reader had to repair is not a verdict about the record that
was signed. The codes are ``<record>_<rule>``, and a record is refused at the first
rule it breaks, in the order the specification lists them.

Two things the verifier can do, these readers refuse to guess at, each with its own
code: an ``EXTERNAL`` witness scope earned from a witness co-signature
(``policy_witness_witnessed_unverified``), and a protected file judged unchanged by
its Python syntax tree (``contract_equivalence_unjudged``).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

MUTATION_TYPES = frozenset({"write", "create", "rename", "link", "unlink", "truncate", "chmod"})
EXEC_TYPE = "exec"
CONNECT_TYPE = "connect"
SCOPES = ("PEER", "EXTERNAL")
EXTERNAL = "EXTERNAL"
PEER = "PEER"
VANTAGES = ("independent", "self_reported")
COVERAGES = ("complete", "incomplete", "unknown")
GAP_CAUSES = ("agent", "host", "sensor", "unknown")
LOCATIONS = ("grader_path", "outside_workspace")
SPECIAL_KINDS = ("fifo", "socket", "char", "block")
LOADER_ENV = frozenset({
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
    "PYTHONSAFEPATH", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONNOUSERSITE",
    "PYTHONPYCACHEPREFIX", "PYTHONWARNINGS", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
    "NODE_OPTIONS", "NODE_PATH"})
GRADER_FILES = frozenset({"sitecustomize.py", "usercustomize.py", "reward.json", "reward.txt"})
GRADER_SEGMENTS = frozenset({"site-packages", "dist-packages", "verifier"})
# Files pytest reads from the workspace and from every directory above it, with no flag.
ANCESTOR_CONFIG = frozenset({"conftest.py", "pytest.ini", "pyproject.toml", "tox.ini",
                             "setup.cfg"})
# Never a whole execution-surface entry: each holds or is shared with honest scratch space.
SURFACE_FORBIDDEN = frozenset({"/", "/tmp", "/var/tmp"})
ALIAS_HOPS = 40
FAILURE_KINDS = ("assertion", "candidate_exit", "candidate")
EQUIVALENCES = ("python_ast",)
PROBES = ("determinism", "type_strict", "import_side_effects")
TIERS = ("trusted", "synthesized")
STRENGTHS = ("gated", "reference_free", "synthesized_spec")
COMPLETION_BASES = ("final_text", "tool_claim", "both")
DETECTOR_REASONS = ("impure_on_visible", "type_strict_on_visible", "repeat_divergence",
                    "isolated_branch")
ATTRIBUTIONS = ("agent", "test_author")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ORIGIN_FIELDS = {"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
UNWITNESSED = "no witness bundle is pinned for this record"


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


def absolute_path(value: Any, code: str) -> str:
    """A normalized absolute POSIX path, as the observer writes container paths."""
    name = text(value, code)
    if ("\x00" in name or not name.startswith("/") or name.startswith("//")
            or posixpath.normpath(name) != name):
        raise RecordError(code, name)
    return name


def argv(value: Any, code: str) -> list[str]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) for item in value) or not value[0]):
        raise RecordError(code)
    return value


def under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix.rstrip("/") + "/")


def protects(entry: dict[str, Any], name: str) -> bool:
    """Whether a protected entry covers a path, after its exclusions.

    An exclusion without ``/`` is a path segment name left out at any depth; one with
    ``/`` is a workspace path under the entry, left out with everything below it.
    """
    if not under(name, entry["path"]):
        return False
    below = name[len(entry["path"]) + 1:].split("/") if name != entry["path"] else []
    for item in entry.get("exclude", ()):
        if (item in below) if "/" not in item else under(name, item):
            return False
    return True


def ancestor_config(name: str, root: str) -> bool:
    """A pytest configuration file in the workspace's own parent chain."""
    head, base = posixpath.split(name)
    return base in ANCESTOR_CONFIG and under(root, head)


def grader_path(name: str) -> bool:
    """A path where a mutation can change how a grader runs or scores a run."""
    parts = name.split("/")
    return (parts[-1] in GRADER_FILES or parts[-1].endswith(".pth")
            or bool(set(parts[:-1]) & GRADER_SEGMENTS))


def _sorted_lines(lines: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<value>  <path>\\n"`` lines, as sha256sum prints them."""
    body = "".join(f"{lines[name]}  {name}\n"
                   for name in sorted(lines, key=lambda item: item.encode("utf-8")))
    return sha256(body.encode("utf-8"))


def tree_digest(files: dict[str, str]) -> str:
    return _sorted_lines(files)


def record_digest(record: dict[str, Any]) -> str:
    """The ``probity-tree/v2`` digest: one sorted line per entry of the tree."""
    executable = set(record["executable"])
    lines = {name: ("x:" if name in executable else "") + value
             for name, value in record["files"].items()}
    for name, target in record["symlinks"].items():
        lines[name] = "l:" + sha256(target.encode("utf-8", "surrogateescape"))
    for name, kind in record["special"].items():
        lines[name] = "s:" + kind
    return _sorted_lines(lines)


# --- the done contract ------------------------------------------------------------------


def _distinct_paths(value: Any, code: str) -> list[str]:
    if (not isinstance(value, list)
            or len({item for item in value if isinstance(item, str)}) != len(value)):
        raise RecordError(code)
    return [relative_path(item, code) for item in value]


def _exclude(names: Any, entry_path: str, kind: str) -> None:
    code = "contract_exclude_invalid"
    if (kind != "directory" or not isinstance(names, list) or not names
            or len({item for item in names if isinstance(item, str)}) != len(names)):
        raise RecordError(code)
    for item in names:
        if not isinstance(item, str):
            raise RecordError(code)
        if "/" in item:
            if relative_path(item, code) == entry_path or not under(item, entry_path):
                raise RecordError(code)
        elif item in ("", ".", "..") or "\x00" in item:
            raise RecordError(code)


def _protected_entry(item: Any) -> dict[str, Any]:
    entry = fields(item, "contract_protected_path", {"path", "kind", "sha256"},
                   {"exclude", "equivalence"})
    name = relative_path(entry["path"], "contract_protected_path_not_normalized")
    kind = choice(entry["kind"], "contract_protected_kind", ("file", "directory"))
    digest(entry["sha256"], "contract_digest_malformed")
    if "exclude" in entry:
        _exclude(entry["exclude"], name, kind)
    if "equivalence" in entry:
        choice(entry["equivalence"], "contract_equivalence", EQUIVALENCES)
        if kind != "file":
            raise RecordError("contract_equivalence")
    return entry


def _sorted_absolute(value: Any, code: str) -> None:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) for item in value) or value != sorted(set(value))):
        raise RecordError(code)
    for name in value:
        absolute_path(name, code)


def _seal(entry: dict[str, Any]) -> None:
    """Where and how a command runs: ``cwd`` and ``exe`` together, then ``interpreter``."""
    if ("cwd" in entry) != ("exe" in entry):
        raise RecordError("contract_acceptance_seal")
    if "cwd" in entry:
        absolute_path(entry["cwd"], "contract_acceptance_seal")
        if isinstance(entry["exe"], list):
            _sorted_absolute(entry["exe"], "contract_acceptance_seal")
        else:
            absolute_path(entry["exe"], "contract_acceptance_seal")
    if "interpreter" in entry:
        if "exe" not in entry:
            raise RecordError("contract_acceptance_interpreter")
        _sorted_absolute(entry["interpreter"], "contract_acceptance_interpreter")


def _acceptance_entry(item: Any) -> dict[str, Any]:
    entry = fields(item, "contract_acceptance", {"id", "argv"},
                   {"ids", "run_writes", "cwd", "exe", "interpreter", "tier", "probe",
                    "in_process_twin_of"})
    if "tier" in entry:
        choice(entry["tier"], "contract_acceptance_tier", TIERS)
    if "probe" in entry:
        choice(entry["probe"], "contract_acceptance_probe", PROBES)
    text(entry["id"], "contract_acceptance_id")
    argv(entry["argv"], "contract_acceptance_argv")
    _seal(entry)
    if "in_process_twin_of" in entry:
        text(entry["in_process_twin_of"], "contract_acceptance_twin")
    if "ids" in entry:
        ids = entry["ids"]
        if (not isinstance(ids, list) or not ids or len(set(map(str, ids))) != len(ids)
                or any(not isinstance(test, str) or not test for test in ids)):
            raise RecordError("contract_acceptance_ids")
    if "run_writes" in entry:
        _distinct_paths(entry["run_writes"], "contract_acceptance_run_writes")
    return entry


def _adequacy(value: Any) -> None:
    adequacy = fields(value, "contract_adequacy", {"mutants", "killed"},
                      {"by_class", "kill_vector_sha256", "gates"})
    if "gates" in adequacy:
        gates = adequacy["gates"]
        if not isinstance(gates, dict) or any(
                not isinstance(gate, dict) or type(gate.get("pass")) is not bool
                for gate in gates.values()):
            raise RecordError("contract_adequacy_gates")
    mutants = count(adequacy["mutants"], "contract_adequacy_count")
    if count(adequacy["killed"], "contract_adequacy_count") > mutants:
        raise RecordError("contract_adequacy_overcount")
    if "kill_vector_sha256" in adequacy:
        digest(adequacy["kill_vector_sha256"], "contract_digest_malformed")
    if "by_class" in adequacy:
        classes = adequacy["by_class"]
        if not isinstance(classes, dict) or not classes:
            raise RecordError("contract_adequacy_by_class")
        totals = [0, 0]
        for name, counts in classes.items():
            text(name, "contract_adequacy_by_class")
            counts = fields(counts, "contract_adequacy_by_class", {"mutants", "killed"})
            made = count(counts["mutants"], "contract_adequacy_by_class")
            dead = count(counts["killed"], "contract_adequacy_by_class")
            if dead > made:
                raise RecordError("contract_adequacy_by_class")
            totals = [totals[0] + made, totals[1] + dead]
        if totals != [mutants, adequacy["killed"]]:
            raise RecordError("contract_adequacy_by_class")


def _surface(record: dict[str, Any]) -> None:
    """The sealed execution surface and the image links that lead into it."""
    if "execution_surface" in record:
        entries = record["execution_surface"]
        _sorted_absolute(entries, "contract_execution_surface")
        if any(name in SURFACE_FORBIDDEN for name in entries):
            raise RecordError("contract_execution_surface_shared_root")
    if "surface_aliases" in record:
        aliases = record["surface_aliases"]
        if not isinstance(aliases, dict) or "execution_surface" not in record:
            raise RecordError("contract_surface_aliases")
        for link, target in aliases.items():
            absolute_path(link, "contract_surface_aliases")
            absolute_path(target, "contract_surface_aliases")


def _contract_head(record: dict[str, Any]) -> None:
    """The members checked before the protected paths, in the verifier's order."""
    if "strength" in record:
        choice(record["strength"], "contract_strength", STRENGTHS)
    loaded = record.get("native_loaded", [])
    if not isinstance(loaded, list):
        raise RecordError("contract_native_loaded")
    for item in loaded:
        entry = fields(item, "contract_native_loaded", {"path", "sha256"})
        relative_path(entry["path"], "contract_native_loaded")
        digest(entry["sha256"], "contract_native_loaded")
    if record["schema_version"] != "probity-done-contract/v1":
        raise RecordError("contract_schema_unsupported")
    text(record["contract_id"], "contract_id")
    if "task" in record:
        text(record["task"], "contract_task")
    for key in ("heldout_split_sha256", "mutant_set_sha256", "authority_sha256"):
        if key in record:
            digest(record[key], "contract_digest_malformed")


def _protected_list(protected: Any) -> None:
    if not isinstance(protected, list):
        raise RecordError("contract_protected_paths_type")
    seen: set[str] = set()
    for item in protected:
        name = _protected_entry(item)["path"]
        if name in seen:
            raise RecordError("contract_protected_duplicate")
        seen.add(name)


def _acceptance_list(acceptance: Any) -> None:
    if not isinstance(acceptance, list) or not acceptance:
        raise RecordError("contract_acceptance_empty")
    ids: set[str] = set()
    for item in acceptance:
        command_id = _acceptance_entry(item)["id"]
        if command_id in ids:
            raise RecordError("contract_acceptance_duplicate_id", command_id)
        ids.add(command_id)
    for item in acceptance:
        twin = item.get("in_process_twin_of")
        if twin is not None and (twin == item["id"] or twin not in ids or any(
                other["id"] == twin and "probe" in other for other in acceptance)):
            raise RecordError("contract_acceptance_twin")


def contract(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "contract"), "contract",
                    {"schema_version", "contract_id", "protected_paths", "acceptance",
                     "adequacy"},
                    {"task", "heldout_split_sha256", "mutant_set_sha256", "authority_sha256",
                     "module_under_test", "strength", "native_loaded", "execution_surface",
                     "surface_aliases"})
    _contract_head(record)
    _protected_list(record["protected_paths"])
    _acceptance_list(record["acceptance"])
    _surface(record)
    _adequacy(record["adequacy"])
    if "module_under_test" in record:
        modules = _distinct_paths(record["module_under_test"], "contract_module_under_test")
        if not modules:
            raise RecordError("contract_module_under_test")
    return record


def surface(record_contract: dict[str, Any] | None,
            record: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    """The contract's execution surface and aliases, checked against the observed run.

    An entry that is the workspace, lies inside it or above it would make honest work in
    the workspace into a mutation of the surface, so the contract is refused.
    """
    if record_contract is None or "execution_surface" not in record_contract:
        return [], {}
    root = record["workspace_root"]
    for name in record_contract["execution_surface"]:
        if under(name, root) or under(root, name):
            raise RecordError("contract_execution_surface_covers_workspace", name)
    return record_contract["execution_surface"], record_contract.get("surface_aliases", {})


def resolve(name: str, aliases: dict[str, str]) -> str:
    """A path with each image link prefix replaced by what it resolves to, longest first."""
    for _ in range(ALIAS_HOPS):
        link = max((key for key in aliases if under(name, key)), key=len, default=None)
        if link is None:
            return name
        name = (aliases[link].rstrip("/") + name[len(link):]) or "/"
    raise RecordError("contract_surface_aliases_cycle")


def on_surface(name: str, entries: list[str], aliases: dict[str, str]) -> bool:
    """Whether a path, as written or after the image links, lies under a surface entry."""
    candidates = [name, resolve(name, aliases)]
    return any(under(candidate, entry) for candidate in candidates for entry in entries)


def surface_effects(record: dict[str, Any], entries: list[str],
                    aliases: dict[str, str]) -> list[str]:
    """Ids of outside mutations of any type, unlink included, on the execution surface."""
    return [entry["id"] for entry in record["external_mutations"]
            if any(on_surface(name, entries, aliases) for name in entry["paths"])]


# --- the observed records ---------------------------------------------------------------


def _origin(record: dict[str, Any], name: str) -> None:
    text(record["claim_id"], f"{name}_claim_id")
    text(record["invocation_id"], f"{name}_invocation_id")
    text(record["producer"], f"{name}_producer")
    choice(record["vantage"], f"{name}_vantage", VANTAGES)
    choice(record["witness_scope"], f"{name}_witness_scope", SCOPES)


def _tree_entries(record: dict[str, Any]) -> list[str]:
    """Every path the three entry maps list, each value checked by its kind."""
    names: list[str] = []
    for member in ("files", "symlinks", "special"):
        entries = record[member]
        if not isinstance(entries, dict):
            raise RecordError("tree_entries_type", member)
        for name, value in entries.items():
            names.append(relative_path(name, "tree_path_not_normalized"))
            if member == "files":
                digest(value, "tree_digest_malformed")
            elif member == "symlinks":
                text(value, "tree_symlink_target")
            else:
                choice(value, "tree_special_kind", SPECIAL_KINDS)
    return names


def tree(data: bytes) -> dict[str, Any]:
    """A ``probity-tree/v2`` record: every non-directory entry of the final workspace."""
    record = fields(strict_json(data, "tree"), "tree",
                    {"schema_version", "tree_sha256", "files", "executable", "symlinks",
                     "special"} | ORIGIN_FIELDS)
    if record["schema_version"] != "probity-tree/v2":
        raise RecordError("tree_schema_unsupported")
    _origin(record, "tree")
    names = _tree_entries(record)
    if len(set(names)) != len(names):
        raise RecordError("tree_path_duplicate")
    ordered = sorted(names, key=lambda item: item.encode("utf-8"))
    if any(under(later, earlier) for earlier, later in zip(ordered, ordered[1:], strict=False)):
        raise RecordError("tree_path_nested")
    executable = record["executable"]
    if (not isinstance(executable, list) or executable != sorted(set(executable))
            or any(name not in record["files"] for name in executable)):
        raise RecordError("tree_executable")
    if record_digest(record) != digest(record["tree_sha256"], "tree_digest_malformed"):
        raise RecordError("tree_digest_mismatch")
    return record


def scope(value: Any, name: str) -> dict[str, Any]:
    found = fields(value, f"{name}_scope", {"id", "start", "end"})
    text(found["id"], f"{name}_scope_id")
    start = instant(found["start"], f"{name}_scope_instant")
    if instant(found["end"], f"{name}_scope_instant") < start:
        raise RecordError(f"{name}_scope_order")
    return found


def _gaps(record: dict[str, Any], start: datetime, end: datetime) -> None:
    coverage = record["coverage"]
    gaps = record.get("gaps", [])
    if coverage == "incomplete":
        if not isinstance(gaps, list) or not gaps:
            raise RecordError("observation_gaps_required")
    elif "gaps" in record:
        raise RecordError("observation_gaps_unexpected")
    for item in gaps:
        gap = fields(item, "observation_gap", {"start", "end", "gap_cause"})
        choice(gap["gap_cause"], "observation_gap_cause", GAP_CAUSES)
        if not start <= instant(gap["start"], "observation_gap_instant") < instant(
                gap["end"], "observation_gap_instant") <= end:
            raise RecordError("observation_gap_outside_scope")


EXEC_FIELDS = {"argv", "exit", "exe", "cwd", "env"}


def _exec_fields(event: dict[str, Any]) -> None:
    argv(event.get("argv"), "observation_exec_argv")
    absolute_path(event.get("exe"), "observation_exec_exe")
    absolute_path(event.get("cwd"), "observation_exec_cwd")
    env = event.get("env")
    if (not isinstance(env, dict) or set(env) - LOADER_ENV
            or any(not isinstance(value, str) for value in env.values())):
        raise RecordError("observation_exec_env")
    if "exit" in event:
        exit_status(event["exit"], "observation_exec_exit")
    if {"path", "target", "address"} & event.keys():
        raise RecordError("observation_exec_path")


def _event(item: Any, exec_ids: set[str]) -> dict[str, Any]:
    event = fields(item, "observation_event", {"id", "type", "time", "step"},
                   {"path", "target", "origin", "address"} | EXEC_FIELDS)
    text(event["id"], "observation_event_id")
    kind = text(event["type"], "observation_event_type")
    count(event["step"], "observation_step")
    # An origin names an exec event's id; a value that is not text names none.
    if "origin" in event and (not isinstance(event["origin"], str)
                              or event["origin"] not in exec_ids):
        raise RecordError("observation_origin_unknown")
    if kind == EXEC_TYPE:
        _exec_fields(event)
    else:
        _other_fields(event, kind)
    return event


def _other_fields(event: dict[str, Any], kind: str) -> None:
    """An event that is not an exec: a connect, a mutation or another file event."""
    if EXEC_FIELDS & event.keys():
        raise RecordError("observation_argv_on_file_event")
    if kind == CONNECT_TYPE:
        if not isinstance(event.get("address"), str) or {"path", "target"} & event.keys():
            raise RecordError("observation_connect_address")
        return
    if "address" in event:
        raise RecordError("observation_address_unexpected")
    if kind in MUTATION_TYPES and "path" not in event:
        raise RecordError("observation_path_required")
    if "path" in event:
        relative_path(event["path"], "observation_path_not_normalized")
    if "target" in event:
        if kind not in ("rename", "link"):
            raise RecordError("observation_target_unexpected")
        relative_path(event["target"], "observation_path_not_normalized")


def _external(item: Any, exec_ids: set[str], root: str) -> dict[str, Any]:
    entry = fields(item, "observation_external", {"id", "step", "time", "type", "paths",
                                                  "location"}, {"origin"})
    text(entry["id"], "observation_external_id")
    count(entry["step"], "observation_step")
    choice(entry["type"], "observation_external_type", tuple(sorted(MUTATION_TYPES)))
    choice(entry["location"], "observation_external_location", LOCATIONS)
    paths = entry["paths"]
    if not isinstance(paths, list) or not paths:
        raise RecordError("observation_external_paths")
    for name in paths:
        if under(absolute_path(name, "observation_external_paths"), root):
            raise RecordError("observation_external_in_workspace")
    if "origin" in entry and (not isinstance(entry["origin"], str)
                              or entry["origin"] not in exec_ids):
        raise RecordError("observation_origin_unknown")
    return entry


def observation(data: bytes) -> dict[str, Any]:
    """A ``probity-observation/v3`` record.

    ``events`` and ``external_mutations`` share one step sequence: steps are unique
    across both lists and increase within each, and an ``origin`` in either names an
    ``exec`` event with a smaller step.
    """
    record = fields(strict_json(data, "observation"), "observation",
                    {"schema_version", "scope", "coverage", "workspace_root", "events",
                     "external_mutations"} | ORIGIN_FIELDS, {"gaps"})
    if record["schema_version"] != "probity-observation/v3":
        raise RecordError("observation_schema_unsupported")
    _origin(record, "observation")
    scope(record["scope"], "observation")
    root = absolute_path(record["workspace_root"], "observation_workspace_root")
    choice(record["coverage"], "observation_coverage", COVERAGES)
    start = instant(record["scope"]["start"], "observation_scope_instant")
    end = instant(record["scope"]["end"], "observation_scope_instant")
    _gaps(record, start, end)
    events, external = record["events"], record["external_mutations"]
    if not isinstance(events, list) or not isinstance(external, list):
        raise RecordError("observation_events_type")
    rows = [(item, False) for item in events] + [(item, True) for item in external]
    for item, _ in rows:
        if not isinstance(item, dict) or type(item.get("step")) is not int:
            raise RecordError("observation_step")
    seen: set[str] = set()
    steps: set[int] = set()
    exec_ids: set[str] = set()
    indexes = {False: 0, True: 0}
    for item, outside in sorted(rows, key=lambda row: row[0]["step"]):
        index = indexes[outside]
        indexes[outside] += 1
        entry = _external(item, exec_ids, root) if outside else _event(item, exec_ids)
        moment = instant(entry["time"], "observation_event_instant")
        if entry["step"] in steps or (external if outside else events)[index] is not item:
            raise RecordError("observation_steps_not_increasing")
        if entry["id"] in seen or not start <= moment <= end:
            raise RecordError("observation_event_duplicate_or_outside")
        seen.add(entry["id"])
        steps.add(entry["step"])
        if not outside and entry["type"] == EXEC_TYPE:
            exec_ids.add(entry["id"])
    return record


def written(record: dict[str, Any], before: int | None = None) -> set[str]:
    """Absolute paths the observed run made or changed, optionally before a step."""
    root = record["workspace_root"].rstrip("/")
    found: set[str] = set()
    for event in record["events"]:
        if (event["type"] in MUTATION_TYPES and event["type"] != "unlink"
                and (before is None or event["step"] < before)):
            found.update(f"{root}/{event[key]}" for key in ("path", "target") if key in event)
    for entry in record["external_mutations"]:
        if entry["type"] != "unlink" and (before is None or entry["step"] < before):
            found.update(entry["paths"])
    return found


def agent_gap(record: dict[str, Any]) -> str | None:
    """The contradiction a gap the agent caused gives, or ``None``."""
    gaps = [gap for gap in record.get("gaps", []) if gap["gap_cause"] == "agent"]
    if not gaps:
        return None
    if any(gap["end"] == record["scope"]["end"] for gap in gaps):
        return "tracer_terminated_prematurely"
    return "coverage_sabotaged"


def external_grader_effects(record: dict[str, Any]) -> list[str]:
    """Ids of outside mutations at a grader path, by the record's label or by the path,
    and of pytest configuration written in a directory above the workspace."""
    root = record["workspace_root"]
    return [entry["id"] for entry in record["external_mutations"]
            if entry["location"] == "grader_path"
            or any(grader_path(name) or ancestor_config(name, root) for name in entry["paths"])]


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


def _result(item: Any) -> dict[str, Any]:
    entry = fields(item, "grade_result", {"id", "argv", "exit"},
                   {"collected", "replay", "timed_out", "failure_kind"})
    text(entry["id"], "grade_result_id")
    argv(entry["argv"], "grade_result_argv")
    exit_status(entry["exit"], "grade_result_exit")
    if "timed_out" in entry and (entry["timed_out"] is not True or entry["exit"] == 0):
        raise RecordError("grade_result_timed_out")
    if "failure_kind" in entry:
        choice(entry["failure_kind"], "grade_result_failure_kind", FAILURE_KINDS)
        if entry["exit"] == 0:
            raise RecordError("grade_result_failure_kind")
    if "collected" in entry:
        count(entry["collected"], "grade_result_collected")
    if "replay" in entry:
        replay = fields(entry["replay"], "grade_result_replay",
                        {"calls_intercepted", "distinct_calls"})
        calls = count(replay["calls_intercepted"], "grade_result_replay")
        if count(replay["distinct_calls"], "grade_result_replay") > calls:
            raise RecordError("grade_result_replay")
    return entry


def _hunk(item: Any) -> None:
    hunk = fields(item, "grade_hunk", {"path", "lines", "mutants", "killed"})
    relative_path(hunk["path"], "grade_hunk")
    lines = hunk["lines"]
    if (not isinstance(lines, list) or len(lines) != 2
            or any(type(line) is not int or line < 1 for line in lines) or lines[0] > lines[1]):
        raise RecordError("grade_hunk")
    if count(hunk["killed"], "grade_hunk") > count(hunk["mutants"], "grade_hunk"):
        raise RecordError("grade_hunk")


def _detectors(value: Any) -> None:
    """The grader's visible-test detectors: a status and one finding per rule that fired."""
    code = "grade_detectors"
    block = fields(value, code, {"status", "findings"})
    text(block["status"], code)
    if not isinstance(block["findings"], list):
        raise RecordError(code)
    for item in block["findings"]:
        finding = fields(item, code, {"reason", "refuses", "evidence"}, {"attribution"})
        reason = text(finding["reason"], code)
        if type(finding["refuses"]) is not bool:
            raise RecordError(code)
        if finding["refuses"]:
            choice(reason, code, DETECTOR_REASONS)
        if "attribution" in finding:
            if reason != "visible_test_unsatisfiable":
                raise RecordError(code)
            choice(finding["attribution"], code, ATTRIBUTIONS)


def grade(data: bytes) -> dict[str, Any]:
    record = fields(strict_json(data, "grade"), "grade",
                    {"schema_version", "contract_sha256", "tree_sha256", "results"}
                    | ORIGIN_FIELDS, {"hunks", "visible_detectors"})
    if record["schema_version"] != "probity-acceptance-grade/v1":
        raise RecordError("grade_schema_unsupported")
    _origin(record, "grade")
    digest(record["contract_sha256"], "grade_digest_malformed")
    digest(record["tree_sha256"], "grade_digest_malformed")
    if not isinstance(record["results"], list):
        raise RecordError("grade_results_type")
    seen: set[str] = set()
    for item in record["results"]:
        name = _result(item)["id"]
        if name in seen:
            raise RecordError("grade_result_duplicate_id")
        seen.add(name)
    hunks = record.get("hunks", [])
    if not isinstance(hunks, list):
        raise RecordError("grade_hunks_type")
    for item in hunks:
        _hunk(item)
    if "visible_detectors" in record:
        _detectors(record["visible_detectors"])
    return record


def claims(data: bytes) -> dict[str, Any]:
    """The ``probity-tool-claims/v2`` record: the runs the agent claims and whether it
    asserted completion."""
    record = fields(strict_json(data, "claims"), "claims",
                    {"schema_version", "claim_id", "invocation_id", "producer", "claims",
                     "completion"})
    if record["schema_version"] != "probity-tool-claims/v2":
        raise RecordError("claims_schema_unsupported")
    completion = fields(record["completion"], "claims_completion", {"asserted", "basis"})
    if type(completion["asserted"]) is not bool:
        raise RecordError("claims_completion_asserted")
    expected = COMPLETION_BASES if completion["asserted"] else ("none",)
    if completion["basis"] not in expected:
        raise RecordError("claims_completion_basis")
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


def scope_fields(*pairs: tuple[dict[str, Any] | None, dict[str, Any]]) -> dict[str, Any]:
    """The witness scope a verdict rests on, and the EXTERNAL claims nothing earned.

    Only a verified witness co-signature earns ``EXTERNAL``, and these readers verify
    none (an ``EXTERNAL`` pin is refused when bound), so every scope is ``PEER``. A record
    that says ``EXTERNAL`` anyway is named among the unwitnessed claims.
    """
    out: dict[str, Any] = {"witness_scope": PEER}
    unearned = [{"witness": pin["id"], "claimed": EXTERNAL, "earned": PEER, "reason": UNWITNESSED}
                for record, pin in pairs
                if record is not None and record["witness_scope"] == EXTERNAL]
    if unearned:
        out["unwitnessed_scope_claims"] = unearned
    return out


# --- consumer case and policy ------------------------------------------------------------


def read_member_file(root: Path, name: str, code: str) -> bytes | None:
    """The bytes of a regular, non-link file under ``root``, or None if it is absent."""
    target = root / name
    try:
        for parent in reversed(target.relative_to(root).parents[:-1]):
            if (root / parent).is_symlink():
                raise RecordError(code, name)
        info = target.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecordError(code, str(exc)) from exc
    if not target.is_file() or target.is_symlink() or info.st_size > MAX_ARTIFACT_BYTES:
        raise RecordError(code, name)
    return target.read_bytes()


def artifact(root: Path, meta: Any) -> tuple[bytes | None, dict[str, Any]]:
    """Read one artifact the case binds by path, length and digest."""
    found = fields(meta, "case_artifact", {"path", "sha256", "length"})
    rel = text(found["path"], "case_artifact_path")
    parts = rel.split("/")
    if ("\x00" in rel or rel.startswith("/") or str(PurePosixPath(rel)) != rel
            or any(p in ("", ".", "..") for p in parts)):
        raise RecordError("case_artifact_path_not_normalized", rel)
    pinned = digest(found["sha256"], "case_artifact_digest_malformed")
    length = found["length"]
    if type(length) is not int or not 0 <= length <= MAX_ARTIFACT_BYTES:
        raise RecordError("case_artifact_length")
    data = read_member_file(root, rel, "case_artifact_unsafe")
    if data is None:
        return None, {"status": "unavailable", "path": rel}
    if len(data) != length or sha256(data) != pinned:
        raise RecordError("case_artifact_binding_mismatch", rel)
    return data, {"status": "bound", "path": rel, "sha256": pinned, "length": length}


def witness(case: dict[str, Any], policy: dict[str, Any], witness_id: str, root: Path,
            observed: bool) -> tuple[bytes | None, dict[str, Any]]:
    witnesses = policy["witnesses"]
    if witness_id not in witnesses:
        raise RecordError("policy_witness_unknown", witness_id)
    needed = {"artifact", "sha256", "authority"} | ({"producer", "vantage", "witness_scope"}
                                                    if observed else set())
    pin_in = fields(witnesses[witness_id], "policy_witness", needed,
                    {"witnessed"} if observed else set())
    artifact_id = text(pin_in["artifact"], "policy_witness_artifact")
    if artifact_id not in case["artifacts"]:
        raise RecordError("case_artifact_unknown", artifact_id)
    pinned = digest(pin_in["sha256"], "policy_witness_digest_malformed")
    text(pin_in["authority"], "policy_witness_authority")
    data, binding = artifact(root, case["artifacts"][artifact_id])
    if binding.get("sha256") != pinned:
        data = None
    pin: dict[str, Any] = {"id": witness_id, "artifact": artifact_id,
                           "consumer_pinned_sha256": pinned, "binding": binding}
    if observed:
        pin["producer"] = text(pin_in["producer"], "policy_witness_producer")
        pin["vantage"] = choice(pin_in["vantage"], "policy_witness_vantage", VANTAGES)
        pin["witness_scope"] = choice(pin_in["witness_scope"], "policy_witness_scope", SCOPES)
        if "witnessed" in pin_in:
            pin["witnessed"] = pin_in["witnessed"]
    return data, pin


def start(case: Any, policy: Any, claim_type: str, assessment_fields: set[str],
          optional: frozenset[str] | set[str] = frozenset()
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
    assessment = fields(assessments[case_id], "policy_assessment", assessment_fields, optional)
    if assessment["claim_type"] != claim_type:
        raise RecordError("policy_claim_type_unsupported")
    return case_id, assessment, case, policy


def bind(case: dict[str, Any], policy: dict[str, Any], assessment: dict[str, Any], root: Path,
         roles: dict[str, bool]) -> dict[str, tuple[bytes | None, dict[str, Any]]]:
    """Bind each named witness role; True roles need producer, vantage and scope pins.

    An ``EXTERNAL`` scope pin must name a witness bundle, and a bundle may stand only
    beside an ``EXTERNAL`` pin. These readers do not verify the bundle's co-signature,
    so a pin that names one is refused rather than read as ``PEER``.
    """
    ids = {role: text(assessment[f"{role}_witness"], f"policy_{role}_witness") for role in roles}
    if len(set(ids.values())) != len(ids):
        raise RecordError("policy_witness_shared")
    bound = {role: witness(case, policy, ids[role], root, observed)
             for role, observed in roles.items()}
    if len({pin["artifact"] for _, pin in bound.values()}) != len(bound):
        raise RecordError("policy_artifact_shared")
    for role, observed in roles.items():
        pin = bound[role][1]
        if observed and pin["witness_scope"] == EXTERNAL:
            if "witnessed" not in pin:
                raise RecordError("policy_witness_unwitnessed", ids[role])
            raise RecordError("policy_witness_witnessed_unverified", ids[role])
        if "witnessed" in pin:
            raise RecordError("policy_witness_witnessed_unexpected", ids[role])
    return bound


def source(case: dict[str, Any], root: Path, value: str) -> bytes | None:
    """The bytes of a file by its SHA-256, from the case artifact ``source:<sha256>``."""
    meta = case["artifacts"].get(f"source:{value}")
    if meta is None:
        return None
    data, binding = artifact(root, meta)
    return data if binding.get("sha256") == value else None
