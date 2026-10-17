"""Build the records of a done run, byte for byte, for the five done corpora.

One task is run again and again with one thing changed: "make ``test_app`` pass",
with the test directory protected and a unit-test command as the acceptance
command. A ``Run`` holds what the run looked like from outside the agent: the files
it left, the events an observer recorded, the commands it claims to have run and
the grade a separate verifier gave. ``Run.records()`` turns that into the bytes of
every record, with the grade bound to the contract and the final tree it names.

Every digest is computed, never typed. A case departs from the honest run by
naming the departure, and the generator asserts the verdict the reader reaches.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "packaging"))

from agent_evidence_vectors import donechecks as checks  # noqa: E402
from agent_evidence_vectors import donerecords as rec  # noqa: E402
from agent_evidence_vectors import donerun  # noqa: E402

DAY = "2026-10-17"
SCOPE = {"id": "run-1", "start": f"{DAY}T00:00:00Z", "end": f"{DAY}T00:10:00Z"}
PYTEST = ["python", "-m", "pytest", "-q", "tests"]
MUTATIONS = ["chmod", "create", "exec", "link", "rename", "truncate", "unlink", "write"]
ROLES_OBSERVED = {"observation", "tree", "grade"}
TEST_TEXT = "def test_app():\n    assert app() == 1\n"
APP_FIXED = "def app():\n    return 1\n"
APP_BROKEN = "def app():\n    return 0\n"
CASE_FILES = {checks.PROTECTED: ("contract", "capability", "observation", "tree"),
              checks.ACCEPTANCE: ("contract", "tree", "grade"),
              checks.TOOLS: ("claims", "capability", "observation")}


def sha(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def enc(value: Any) -> bytes:
    """The byte form every record and control file is pinned by."""
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def stamp(step: int) -> str:
    return f"{DAY}T00:{step // 60:02d}:{step % 60:02d}Z"


def event(step: int, kind: str, **fields: Any) -> dict[str, Any]:
    return {"id": f"e{step}", "type": kind, "time": stamp(step), "step": step, **fields}


def _files(texts: dict[str, str]) -> dict[str, str]:
    return {name: sha(text) for name, text in texts.items()}


@dataclass(frozen=True)
class Run:
    """One run of the task, as an outside observer saw it."""

    name: str
    final: dict[str, str] = field(default_factory=lambda: {
        "src/app.py": APP_FIXED, "tests/test_app.py": TEST_TEXT})
    sealed: dict[str, str] = field(default_factory=lambda: {"tests/test_app.py": TEST_TEXT})
    protected: tuple[tuple[str, str, tuple[str, ...]], ...] = (("tests", "directory",
                                                                ("__pycache__",)),)
    acceptance: tuple[str, ...] = tuple(PYTEST)
    adequacy: tuple[int, int] = (4, 3)
    events: tuple[dict[str, Any], ...] = ()
    coverage: str = "complete"
    gaps: tuple[dict[str, str], ...] = ()
    visible: tuple[str, ...] = tuple(MUTATIONS)
    claims: tuple[dict[str, Any], ...] = ({"id": "c1", "argv": PYTEST, "exit": 0},)
    grade_exit: int = 0
    observed_party: str = "agent-1"
    invocation: str = "call-1"
    producer: str = "host-observer"
    grader: str = "harness-verifier"
    vantage: str = "independent"
    scope: str = "PEER"
    grade_scope: str = "PEER"
    grade_vantage: str = "independent"
    edits: tuple[tuple[str, Callable[[Any], Any]], ...] = ()
    pin_overrides: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()

    def with_edit(self, role: str, change: Callable[[Any], Any]) -> Run:
        return replace(self, edits=(*self.edits, (role, change)))

    def with_pin(self, role: str, **pin: str) -> Run:
        return replace(self, pin_overrides=(*self.pin_overrides, (role, tuple(pin.items()))))

    def contract(self) -> dict[str, Any]:
        entries = []
        for path, kind, exclude in self.protected:
            if kind == "file":
                digest = sha(self.sealed[path])
            else:
                under = {n: sha(t) for n, t in self.sealed.items()
                         if rec.protects({"path": path, "exclude": list(exclude)}, n)}
                digest = rec.tree_digest(under)
            entry: dict[str, Any] = {"path": path, "kind": kind, "sha256": digest}
            if exclude:
                entry["exclude"] = list(exclude)
            entries.append(entry)
        mutants, killed = self.adequacy
        return {"schema_version": "probity-done-contract/v1", "contract_id": "contract-app-1",
                "task": "make test_app pass", "protected_paths": entries,
                "acceptance": [{"id": "unit", "argv": list(self.acceptance)}],
                "adequacy": {"mutants": mutants, "killed": killed}}

    def origin(self) -> dict[str, str]:
        return {"claim_id": self.name, "invocation_id": self.invocation}

    def records(self) -> dict[str, bytes]:
        origin = self.origin()
        host = {**origin, "producer": self.producer, "vantage": self.vantage,
                "witness_scope": self.scope}
        files = _files(self.final)
        body: dict[str, dict[str, Any]] = {
            "contract": self.contract(),
            "tree": {"schema_version": "probity-tree/v1", **host,
                     "tree_sha256": rec.tree_digest(files), "files": files},
            "observation": {"schema_version": "probity-observation/v2", **host, "scope": SCOPE,
                            "coverage": self.coverage, "events": list(self.events),
                            **({"gaps": list(self.gaps)} if self.gaps else {})},
            "capability": {"schema_version": "probity-capabilities/v1", **origin,
                           "producer": self.producer, "visible_event_types": list(self.visible)},
            "claims": {"schema_version": "probity-tool-claims/v1", **origin,
                       "producer": "transcript-parser", "claims": list(self.claims)},
        }
        raw = {role: enc(self._edited(role, value)) for role, value in body.items()}
        grade = {"schema_version": "probity-acceptance-grade/v1", **origin,
                 "producer": self.grader, "vantage": self.grade_vantage,
                 "witness_scope": self.grade_scope,
                 "contract_sha256": sha(raw["contract"]),
                 "tree_sha256": body["tree"]["tree_sha256"],
                 "results": [{"id": "unit", "argv": list(self.acceptance),
                              "exit": self.grade_exit}]}
        raw["grade"] = enc(self._edited("grade", grade))
        return raw

    def _edited(self, role: str, value: dict[str, Any]) -> Any:
        for target, change in self.edits:
            if target == role:
                value = change(value)
        return value

    def pin_for(self, role: str, record: dict[str, Any] | None) -> dict[str, str]:
        pin = {} if record is None else {"producer": record["producer"],
                                         "vantage": record["vantage"],
                                         "witness_scope": record["witness_scope"]}
        for target, fields in self.pin_overrides:
            if target == role:
                pin.update(dict(fields))
        return pin


def case_and_policy(run: Run, raw: dict[str, bytes], claim_type: str, *,
                    scope: dict[str, str] | None = None, case_id: str | None = None,
                    observed_party: str | None = None, hide: tuple[str, ...] = (),
                    pinned_text: dict[str, bytes] | None = None) -> tuple[bytes, bytes]:
    """The consumer's case and policy for one check over a run's records.

    ``hide`` leaves a role's file out of the case's artifact bindings' reach by
    pinning a digest the file does not have; ``pinned_text`` replaces the bytes a
    role is pinned to.
    """
    roles = CASE_FILES[claim_type]
    name = case_id or run.name
    case: dict[str, Any] = {"schema_version": "probity-case/v1", "case_id": name, "artifacts": {}}
    witnesses: dict[str, Any] = {}
    assessment: dict[str, Any] = {"claim_type": claim_type, "invocation_id": run.invocation,
                                  "observed_party": observed_party or run.observed_party}
    if claim_type != checks.ACCEPTANCE:
        assessment["scope"] = scope or SCOPE
    for role in roles:
        data = raw[role]
        digest = sha(data)
        case["artifacts"][role] = {"path": f"{role}.json", "length": len(data), "sha256": digest}
        pin: dict[str, str] = {"artifact": role, "authority": "synthetic fixture",
                               "sha256": sha(pinned_text[role]) if pinned_text and role
                               in pinned_text else digest}
        if role in ROLES_OBSERVED:
            parsed = json.loads(data)
            pin.update(run.pin_for(role, parsed))
        witnesses[role] = pin
        assessment[f"{role}_witness"] = role
    policy = {"schema_version": "probity-policy/v1", "witnesses": witnesses,
              "assessments": {name: assessment}}
    return enc(case), enc(policy)


@dataclass
class Member:
    """The files of one corpus member, and what the corpus declares about it."""

    id: str
    edit: str
    files: dict[str, bytes]
    expected: dict[str, Any]
    kind: str
    checks: list[str] = field(default_factory=list)


def run_files(run: Run, claim_types: tuple[str, ...],
              **options: Any) -> dict[str, bytes]:
    """Every record the named checks read, and the case and policy for each check.

    ``options`` go to ``case_and_policy`` for every check: an interval, a case id, an
    observed party, or a digest a role is pinned to other than its bytes.
    """
    raw = run.records()
    files: dict[str, bytes] = {}
    needed = sorted({role for ct in claim_types for role in CASE_FILES[ct]})
    for role in needed:
        files[f"{role}.json"] = raw[role]
    for claim_type in claim_types:
        case, policy = case_and_policy(run, raw, claim_type, **options)
        files[f"{checks.FILES[claim_type]}.case.json"] = case
        files[f"{checks.FILES[claim_type]}.policy.json"] = policy
    return files


def verdict(decision: str, reason: str, scope: str = "PEER") -> dict[str, str]:
    out = {"decision": decision, "reason": reason,
           "vantage": "unestablished" if decision == "not_established" else "independent"}
    if decision != "not_established":
        out["witness_scope"] = scope
    return out


def manifest_entry(member: Member) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "edit": member.edit, "expected": member.expected,
        "files": {name: sha(data) for name, data in sorted(member.files.items())},
        "id": member.id, "kind": member.kind, "path": f"cases/{member.id}",
    }
    if member.checks:
        entry["checks"] = member.checks
    return entry


def write_corpus(root: Path, suite: str, members: list[Member], extra: dict[str, Any]) -> None:
    """Write every member and the manifest; remove nothing a stale run left."""
    ids = [member.id for member in members]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate member ids: " + ", ".join(sorted(
            {name for name in ids if ids.count(name) > 1})))
    entries = []
    for member in members:
        directory = root / "cases" / member.id
        directory.mkdir(parents=True, exist_ok=True)
        for name, data in member.files.items():
            (directory / name).write_bytes(data)
        entries.append(manifest_entry(member))
    manifest = {"suite": suite, "corpusDigest": sha(enc(entries)), **extra, "vectors": entries}
    (root / "MANIFEST.json").write_bytes(enc(manifest))


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the corpus digest from the files on disk, not from the declared hashes."""
    base = Path(root)
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        found = {p.name for p in directory.iterdir() if p.is_file()}
        if found != set(entry["files"]):
            raise ValueError(f"{entry['id']}: file set changed")
        if {name: sha((directory / name).read_bytes()) for name in found} != entry["files"]:
            raise ValueError(f"{entry['id']}: file digest mismatch")
    return sha(enc(manifest["vectors"]))


def check_member(suite: str, member: Member) -> None:
    """Refuse to write a member whose declared verdicts the reader does not reach."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for name, data in member.files.items():
            (directory / name).write_bytes(data)
        got = donerun.judge_member(suite, directory, member.checks)
    if got != member.expected:
        raise SystemExit(f"{member.id}: declared {member.expected}, the reader derives {got}")


# --- launch records and receipts ---------------------------------------------------------------

TRACE_EXPRESSION = (
    "trace=execve,execveat,open,openat,openat2,creat,mkdir,mkdirat,mknod,mknodat,symlink,"
    "symlinkat,rename,renameat,renameat2,link,linkat,unlink,unlinkat,rmdir,truncate,ftruncate,"
    "chmod,fchmod,fchmodat,fchmodat2,chown,fchown,lchown,fchownat,utime,utimes,utimensat,"
    "futimesat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,mmap,connect,"
    "fork,vfork,clone,clone3,chdir,fchdir,io_uring_setup,ptrace,process_vm_writev")
TRACER_FLAGS = ["-f", "-q", "-y", "-ttt", "-xx", "-z"]
DOES_NOT_ASSERT = [
    "that the host operator is independent of the agent's operator (scope is PEER)",
    "effects through channels the trace expression does not name",
    "that a symbolic link in a path outside an open() call was resolved",
]


def launch_record(run: Run, backend: str = "docker") -> dict[str, Any]:
    return {
        "schema_version": "probity-launch/v1", "backend": backend,
        "image": "probity-observer-agent-test:local", "image_id": "sha256:" + sha("image"),
        "runtime_version": "docker 28.0.1", "strace_version": "6.13",
        "container_argv": ["docker", "run", "--rm", "--cap-add=SYS_PTRACE", "strace", "-f"],
        "trace_expression": TRACE_EXPRESSION, "tracer_flags": TRACER_FLAGS,
        "tracer_uid_separated": backend == "docker", "agent_argv": ["python3", "agent.py"],
        "agent_uid": 65534, "env": {}, "network": False, "container_workspace": "/workspace",
        "start_tarball_sha256": sha("start " + run.name),
        "observer_source_sha256": sha("observer source"), "timeout_seconds": 600}


def launch_receipt(run: Run, raw: dict[str, bytes], launch_bytes: bytes, *,
                   tracer: str = "complete", effects: tuple[dict[str, Any], ...] = (),
                   unattributed: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
    tree = json.loads(raw["tree"])
    observation = json.loads(raw["observation"])
    return {
        "schema_version": "probity-launch-receipt/v1", "claim_id": run.name,
        "invocation_id": run.invocation, "producer": run.producer, "witnessScope": run.scope,
        "launch_sha256": sha(launch_bytes), "trace_expression": TRACE_EXPRESSION,
        "watch_list": [{"path": "", "added": stamp(0)}, {"path": "src", "added": stamp(1)}],
        "start_tarball_sha256": sha("start " + run.name), "tree_sha256": sha(raw["tree"]),
        "coverage": observation["coverage"], "container_exit": 0, "agent_exit": 0,
        "timed_out": False, "transcript_sha256": sha("transcript " + run.name),
        "trace_sha256": sha("trace " + run.name), "observation_sha256": sha(raw["observation"]),
        "capability_sha256": sha(raw["capability"]),
        "sensors": {
            "s1_inotify": {"changes": 3, "overflow": False, "watch_failures": 0,
                           "watch_list": [], "mask": ["IN_CREATE", "IN_MODIFY"]},
            "s2_strace": {"tracer": tracer, "calls": 41, "unparsed_lines": 0, "unresolved": [],
                          "escapes": [], "origin_rule": "first exec of the command"},
            "s3_tree": {"tree_sha256": tree["tree_sha256"], "files": len(tree["files"]),
                        "symlinks": [], "special": []},
            "join": {"unattributed": list(unattributed)},
            "external_effects": list(effects)},
        "doesNotAssert": DOES_NOT_ASSERT}


def with_launch(run: Run, files: dict[str, bytes], **options: Any) -> dict[str, bytes]:
    """The files plus a launch record and the launch receipt that binds the run to it."""
    raw = {role: files[f"{role}.json"] for role in ("observation", "capability", "tree")}
    launch = enc(launch_record(run))
    receipt = enc(launch_receipt(run, raw, launch, **options))
    return {**files, "launch.json": launch, "launch-receipt.json": receipt}


def effect(kind: str, *paths: str, time: int = 4) -> dict[str, Any]:
    return {"type": kind, "paths": list(paths), "time": stamp(time)}


def connect(address: str, time: int = 4) -> dict[str, Any]:
    return {"type": "connect", "address": address, "time": stamp(time)}


def recomputed(files: dict[str, bytes]) -> list[dict[str, Any]]:
    """The three checks over a member's files, in the order a receipt carries them."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for name, data in files.items():
            (directory / name).write_bytes(data)
        return donerun._recomputed(directory)


def receipt_predicate(files: dict[str, bytes], run: Run) -> dict[str, Any]:
    """The receipt predicate a verifier would write for a member's current files."""
    roles = list(donerun.CORE_ROLES)
    if "launch.json" in files:
        roles += list(donerun.LAUNCH_ROLES)
    computed = recomputed(files)
    effects = (json.loads(files["launch-receipt.json"])["sensors"]["external_effects"]
               if "launch-receipt.json" in files else [])
    return {
        "schema_version": donerun.RECEIPT_SCHEMA, "claim_id": run.name,
        "invocation_id": run.invocation,
        "records": {role: {"sha256": sha(files[donerun.ROLE_FILES[role]])} for role in roles},
        "checks": [{"claim_type": item["claim_type"], **checks.projection(item)}
                   for item in computed],
        "verdict": checks.combine(computed, effects), "external_effects": effects,
        "verifier": {"id": donerun.VERIFIER_URI}}


def receipt_statement(files: dict[str, bytes], run: Run) -> dict[str, Any]:
    tree = json.loads(files["tree.json"])
    return {"_type": donerun.STATEMENT_TYPE,
            "subject": [{"name": "workspace-tree", "digest": {"sha256": tree["tree_sha256"]}}],
            "predicateType": donerun.RECEIPT_TYPE, "predicate": receipt_predicate(files, run)}


def with_receipt(files: dict[str, bytes], run: Run) -> dict[str, bytes]:
    return {**files, "receipt.json": enc(receipt_statement(files, run))}


# --- runs recorded from a real launcher ---------------------------------------------------------

RECORDED = HERE / "recorded"
RECORDED_ROLES = ("contract", "tree", "observation", "capability", "claims", "grade")


def recorded_files(name: str, claim_types: tuple[str, ...], *, launch: bool = False,
                   receipt: bool = False) -> dict[str, bytes]:
    """A member from a run the launcher recorded: its records, and the consumer's pins.

    The records are read as written. The consumer's case and policy are built from them
    the way a consumer would pin them: each record by its digest, and the producer,
    vantage and scope the record states for the roles that need one.
    """
    source = RECORDED / name
    raw = {role: (source / f"{role}.json").read_bytes()
           for role in RECORDED_ROLES if (source / f"{role}.json").exists()}
    observation = json.loads(raw["observation"])
    run = Run(name=name, producer=observation["producer"], invocation=observation["invocation_id"])
    files: dict[str, bytes] = {}
    for role in sorted({r for ct in claim_types for r in CASE_FILES[ct]}):
        files[f"{role}.json"] = raw[role]
    for claim_type in claim_types:
        case, policy = case_and_policy(run, raw, claim_type, scope=observation["scope"])
        files[f"{checks.FILES[claim_type]}.case.json"] = case
        files[f"{checks.FILES[claim_type]}.policy.json"] = policy
    if launch:
        for stored, wanted in (("launch.json", "launch.json"),
                               ("launch-receipt.json", "launch-receipt.json")):
            files[wanted] = (source / stored).read_bytes()
    return with_receipt(files, run) if receipt else files
