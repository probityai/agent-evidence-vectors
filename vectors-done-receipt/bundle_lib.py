"""Build the records of a done run, byte for byte, for the six done corpora.

One task is run again and again with one thing changed: "make ``test_app`` pass",
with the test directory protected, a visible and a held-out unit-test command as
the acceptance commands. A ``Run`` holds what the run looked like from outside the
agent: the files it left, the events an observer recorded inside the workspace and
the mutations it recorded outside it, the runs the agent claims, whether it asserted
completion, and the grade a separate verifier gave. ``Run.records()`` turns that into
the bytes of every record, with the grade bound to the contract and the final tree
it names. The runs follow probity-verify's done-receipt examples
(``packages/probity-verify/examples/done-receipt/generate.py`` of probityai/probity).

Every digest is computed, never typed. A case departs from the honest run by naming
the departure, and the generator asserts the verdicts the reader reaches.
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
ROOT = "/workspace"
PYTEST = ["python", "-m", "pytest", "-q", "tests"]
HELDOUT = ["python", "-m", "pytest", "-q", "/heldout"]
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONSAFEPATH": "1"}
VISIBLE = ["chmod", "connect", "create", "exec", "link", "read", "rename", "truncate",
           "unlink", "write"]
ROLES_OBSERVED = {"observation", "tree", "grade"}
TEST_TEXT = "def test_app():\n    assert app() == 1\n"
APP_FIXED = "def app():\n    return 1\n"
APP_BROKEN = "def app():\n    return 0\n"
VERIFIER_URI = "https://github.com/probityai/probity"
COMMANDS = ({"id": "unit", "argv": PYTEST}, {"id": "heldout-unit", "argv": HELDOUT})
# The roles each check reads; tool claims read the contract too, as the receipt does.
CASE_FILES = {checks.PROTECTED: ("contract", "capability", "observation", "tree"),
              checks.ACCEPTANCE: ("contract", "tree", "grade"),
              checks.PROBES: ("contract", "tree", "grade"),
              checks.TOOLS: ("claims", "capability", "observation", "contract"),
              checks.COMPLETION: ("claims", "capability", "observation", "contract"),
              checks.RECEIPT: ("receipt", "contract", "capability", "observation", "tree",
                               "grade", "claims")}
ALL = checks.CLAIM_TYPES
WITH_RECEIPT = (*checks.CLAIM_TYPES, checks.RECEIPT)


def sha(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def enc(value: Any) -> bytes:
    """The byte form every record and control file is pinned by."""
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def stamp(step: int) -> str:
    return f"{DAY}T00:{step // 60:02d}:{step % 60:02d}Z"


def event(step: int, kind: str, **fields: Any) -> dict[str, Any]:
    """An event inside the workspace; an exec gets the executable, directory and loader
    environment the observer records, from its program unless the case names them."""
    found = {"id": f"e{step}", "type": kind, "time": stamp(step), "step": step, **fields}
    if kind != "exec":
        return found
    program = found["argv"][0]
    exe = "/usr/local/bin/python" if program == "python" else f"/usr/bin/{program}"
    return {"cwd": ROOT, "env": dict(ENV), "exe": exe, **found}


def outside(step: int, kind: str, *paths: str, location: str = "outside_workspace",
            **fields: Any) -> dict[str, Any]:
    """A mutation the observer recorded outside the workspace."""
    return {"id": f"x{step}", "step": step, "time": stamp(step), "type": kind,
            "paths": list(paths), "location": location, **fields}


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
    commands: tuple[dict[str, Any], ...] = COMMANDS
    adequacy: tuple[int, int] = (4, 3)
    contract_extra: tuple[tuple[str, Any], ...] = ()
    events: tuple[dict[str, Any], ...] = ()
    external: tuple[dict[str, Any], ...] = ()
    coverage: str = "complete"
    gaps: tuple[dict[str, str], ...] = ()
    visible: tuple[str, ...] = tuple(VISIBLE)
    claims: tuple[dict[str, Any], ...] = ({"id": "c1", "argv": PYTEST, "exit": 0},)
    completion: tuple[bool, str] = (True, "both")
    grade_exit: int = 0
    grade_results: tuple[tuple[str, tuple[tuple[str, Any], ...]], ...] = ()
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

    def with_result(self, command_id: str, **changes: Any) -> Run:
        """The grade's result for one command with members changed or added."""
        return replace(self, grade_results=(*self.grade_results,
                                            (command_id, tuple(changes.items()))))

    def contract(self) -> dict[str, Any]:
        entries = []
        for path, kind, exclude in self.protected:
            if kind == "file":
                value = sha(self.sealed[path])
            else:
                selected = {n: sha(t) for n, t in self.sealed.items()
                            if rec.protects({"path": path, "exclude": list(exclude)}, n)}
                value = rec.tree_digest(selected)
            entry: dict[str, Any] = {"path": path, "kind": kind, "sha256": value}
            if exclude:
                entry["exclude"] = list(exclude)
            entries.append(entry)
        mutants, killed = self.adequacy
        return {"schema_version": "probity-done-contract/v1", "contract_id": "contract-app-1",
                "task": "make test_app pass", "protected_paths": entries,
                "acceptance": [dict(command) for command in self.commands],
                "adequacy": {"mutants": mutants, "killed": killed},
                "heldout_split_sha256": sha("heldout/test_app_hidden.py"),
                **dict(self.contract_extra)}

    def origin(self) -> dict[str, str]:
        return {"claim_id": self.name, "invocation_id": self.invocation}

    def _results(self) -> list[dict[str, Any]]:
        changes: dict[str, dict[str, Any]] = {}
        for command_id, items in self.grade_results:
            changes.setdefault(command_id, {}).update(dict(items))
        return [{"id": command["id"], "argv": list(command["argv"]), "exit": self.grade_exit,
                 **changes.get(command["id"], {})} for command in self.commands]

    def records(self) -> dict[str, bytes]:
        origin = self.origin()
        host = {**origin, "producer": self.producer, "vantage": self.vantage,
                "witness_scope": self.scope}
        files = _files(self.final)
        asserted, basis = self.completion
        body: dict[str, dict[str, Any]] = {
            "contract": self.contract(),
            "tree": {"schema_version": "probity-tree/v2", **host,
                     "tree_sha256": rec.tree_digest(files), "files": files, "executable": [],
                     "symlinks": {}, "special": {}},
            "observation": {"schema_version": "probity-observation/v3", **host, "scope": SCOPE,
                            "coverage": self.coverage, "workspace_root": ROOT,
                            "events": list(self.events),
                            "external_mutations": list(self.external),
                            **({"gaps": list(self.gaps)} if self.gaps else {})},
            "capability": {"schema_version": "probity-capabilities/v1", **origin,
                           "producer": self.producer, "visible_event_types": list(self.visible)},
            "claims": {"schema_version": "probity-tool-claims/v2", **origin,
                       "producer": "transcript-parser", "claims": list(self.claims),
                       "completion": {"asserted": asserted, "basis": basis}},
        }
        raw = {role: enc(self._edited(role, value)) for role, value in body.items()}
        tree = json.loads(raw["tree"])
        grade = {"schema_version": "probity-acceptance-grade/v1", **origin,
                 "producer": self.grader, "vantage": self.grade_vantage,
                 "witness_scope": self.grade_scope, "contract_sha256": sha(raw["contract"]),
                 "tree_sha256": tree["tree_sha256"], "results": self._results()}
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
        for target, items in self.pin_overrides:
            if target == role:
                pin.update(dict(items))
        return pin


def case_and_policy(run: Run, raw: dict[str, bytes], claim_type: str, *,
                    scope: dict[str, str] | None = None, case_id: str | None = None,
                    observed_party: str | None = None,
                    pinned_text: dict[str, bytes] | None = None,
                    extra_artifacts: dict[str, bytes] | None = None) -> tuple[bytes, bytes]:
    """The consumer's case and policy for one check over a run's records.

    ``pinned_text`` replaces the bytes a role is pinned to; ``extra_artifacts`` binds
    further files by name (a ``source:<sha256>`` file, for one).
    """
    roles = CASE_FILES[claim_type]
    name = case_id or run.name
    case: dict[str, Any] = {"schema_version": "probity-case/v1", "case_id": name, "artifacts": {}}
    witnesses: dict[str, Any] = {}
    assessment: dict[str, Any] = {"claim_type": claim_type, "invocation_id": run.invocation,
                                  "observed_party": observed_party or run.observed_party}
    if claim_type not in (checks.ACCEPTANCE, checks.PROBES):
        assessment["scope"] = scope or SCOPE
    for role in roles:
        data = raw[role]
        value = sha(data)
        case["artifacts"][role] = {"path": f"{role}.json", "length": len(data), "sha256": value}
        pin: dict[str, str] = {"artifact": role, "authority": "synthetic fixture",
                               "sha256": sha(pinned_text[role]) if pinned_text and role
                               in pinned_text else value}
        if role in ROLES_OBSERVED:
            pin.update(run.pin_for(role, json.loads(data)))
        witnesses[role] = pin
        assessment[f"{role}_witness"] = role
    for artifact, data in (extra_artifacts or {}).items():
        case["artifacts"][artifact] = {"path": artifact_file(artifact), "length": len(data),
                                       "sha256": sha(data)}
    policy = {"schema_version": "probity-policy/v1", "witnesses": witnesses,
              "assessments": {name: assessment}}
    return enc(case), enc(policy)


def artifact_file(artifact: str) -> str:
    """The member file name an extra artifact is stored under."""
    return artifact.replace(":", "-") + ".txt"


@dataclass
class Member:
    """The files of one corpus member, and what the corpus declares about it."""

    id: str
    edit: str
    files: dict[str, bytes]
    expected: dict[str, Any]
    kind: str
    checks: list[str] = field(default_factory=list)


def run_files(run: Run, claim_types: tuple[str, ...] = ALL, **options: Any) -> dict[str, bytes]:
    """Every record the named checks read, and the case and policy for each check.

    A receipt among the claim types is the one a verifier derives from the records.
    ``options`` go to ``case_and_policy`` for every check.
    """
    raw = run.records()
    if checks.RECEIPT in claim_types:
        raw["receipt"] = receipt_bytes(run, raw, options)
    files: dict[str, bytes] = {}
    for role in sorted({role for ct in claim_types for role in CASE_FILES[ct]}):
        files[f"{role}.json"] = raw[role]
    for artifact, data in options.get("extra_artifacts", {}).items():
        files[artifact_file(artifact)] = data
    for claim_type in claim_types:
        case, policy = case_and_policy(run, raw, claim_type, **options)
        files[f"{checks.FILES[claim_type]}.case.json"] = case
        files[f"{checks.FILES[claim_type]}.policy.json"] = policy
    return files


# --- the receipt -------------------------------------------------------------------------------


PLACEHOLDER = {"completion_claimed": False, "accepted": False,
               "outcome": {"decision": "not_established", "reason": "placeholder",
                           "vantage": "unestablished", "checks": [{}]},
               "integrity": {"decision": "not_established", "reason": "placeholder",
                             "vantage": "unestablished", "checks": [{}]}}


def statement(run: Run, raw: dict[str, bytes], fields: dict[str, Any]) -> dict[str, Any]:
    tree = json.loads(raw["tree"])
    return {"_type": checks.STATEMENT_TYPE,
            "subject": [{"name": "workspace-tree", "digest": {"sha256": tree["tree_sha256"]}}],
            "predicateType": checks.RECEIPT_TYPE,
            "predicate": {"schema_version": checks.RECEIPT_SCHEMA, "claim_id": run.name,
                          "invocation_id": run.invocation, "verifier": {"id": VERIFIER_URI},
                          "records": {role: {"sha256": sha(raw[role])}
                                      for role in checks.RECORD_ROLES}, **fields}}


def derived_fields(run: Run, raw: dict[str, bytes], options: dict[str, Any]) -> dict[str, Any]:
    """What a verifier derives from the run's records, as the receipt carries it."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        staged = {**raw, "receipt": enc(statement(run, raw, PLACEHOLDER))}
        for role, data in staged.items():
            (directory / f"{role}.json").write_bytes(data)
        for artifact, data in options.get("extra_artifacts", {}).items():
            (directory / artifact_file(artifact)).write_bytes(data)
        case, policy = case_and_policy(run, staged, checks.RECEIPT, **options)
        case_doc, policy_doc = json.loads(case), json.loads(policy)
        case_id = case_doc["case_id"]
        try:
            verdicts = checks.derive(case_doc, policy_doc, case_id,
                                     policy_doc["assessments"][case_id], directory)
        except rec.RecordError:
            return dict(PLACEHOLDER)  # a record breaks a rule: no verifier derives a receipt
    claims = json.loads(raw["claims"])
    return {"completion_claimed": claims["completion"]["asserted"], **checks.axes(verdicts)}


def receipt_bytes(run: Run, raw: dict[str, bytes], options: dict[str, Any]) -> bytes:
    return enc(statement(run, raw, derived_fields(run, raw, options)))


def restated(files: dict[str, bytes], change: Callable[[dict[str, Any]], None]) -> dict[str, bytes]:
    """The files with the receipt rewritten by ``change`` and its pins moved to the new bytes,
    so only the edit is wrong."""
    statement_ = json.loads(files["receipt.json"])
    change(statement_)
    return pinned({**files, "receipt.json": enc(statement_)}, "receipt")


def pinned(files: dict[str, bytes], role: str) -> dict[str, bytes]:
    """Rewrite every case and policy so they bind the record's current bytes."""
    data = files[f"{role}.json"]
    out = dict(files)
    for name, value in files.items():
        if name.endswith(".case.json"):
            case = json.loads(value)
            if role in case["artifacts"]:
                case["artifacts"][role].update(length=len(data), sha256=sha(data))
            out[name] = enc(case)
        elif name.endswith(".policy.json"):
            policy = json.loads(value)
            if role in policy["witnesses"]:
                policy["witnesses"][role]["sha256"] = sha(data)
            out[name] = enc(policy)
    return out


# --- what a member declares --------------------------------------------------------------------


def verdict(decision: str, reason: str, klass: str | None = None) -> dict[str, Any]:
    """A check's declared verdict: every scope these readers reach is PEER."""
    out: dict[str, Any] = {"decision": decision, "reason": reason,
                           "vantage": "unestablished" if decision == "not_established"
                           else "independent"}
    if decision != "not_established":
        out["witness_scope"] = "PEER"
    if klass is not None:
        out["class"] = klass
    return out


def spec(text: str, integrity: bool = True) -> dict[str, Any]:
    """``decision:reason`` as a check's declared verdict; an integrity contradiction
    carries the class the specification gives its reason."""
    decision, reason = text.split(":")
    klass = checks.REASON_CLASS[reason] if integrity and decision == "contradicted" else None
    return verdict(decision, reason, klass)


def axis(text: str) -> dict[str, Any]:
    """``decision:reason[:class]`` as the integrity axis."""
    parts = text.split(":")
    return verdict(parts[0], parts[1], parts[2] if len(parts) > 2 else None)


def expected(p: str, a: str, pr: str, t: str, c: str, integrity: str,
             receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    """The five checks' declared verdicts, the two verdicts over them and, when given, the
    receipt check's own."""
    found = {checks.PROTECTED: spec(p), checks.ACCEPTANCE: spec(a, False),
             checks.PROBES: spec(pr), checks.TOOLS: spec(t), checks.COMPLETION: spec(c)}
    outcome, integ = spec(a, False), axis(integrity)
    out: dict[str, Any] = {"checks": found, "outcome": outcome, "integrity": integ,
                           "accepted": outcome["decision"] == integ["decision"] == "supported"}
    if receipt is not None:
        found[checks.RECEIPT] = receipt
    return out


P_OK = "supported:protected_paths_untouched"
A_OK = "supported:acceptance_passed_in_verifier"
PR_NONE = "not_established:no_probes"
T_OK = "supported:tool_claims_matched"
C_OK = "supported:completion_claim_observed"
I_OK = "supported:integrity_checks_supported"


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
    """Write every member and the manifest."""
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


def member(case_id: str, edit: str, files: dict[str, bytes], declared: tuple[str, ...],
           expected: dict[str, Any], kind: str | None = None) -> Member:
    """A member whose declared verdicts are the ones given; the kind defaults to the
    integrity verdict, or the outcome, or a refusal."""
    return Member(id=case_id, edit=edit, files=files, expected=expected,
                  kind=kind if kind is not None else default_kind(expected),
                  checks=list(declared))


def default_kind(expected: dict[str, Any]) -> str:
    """The integrity verdict, or the outcome where the integrity holds, or a refusal."""
    integrity = expected.get("integrity", {}).get("decision")
    outcome = expected.get("outcome", {}).get("decision")
    if integrity == "supported" and outcome != "supported":
        return str(outcome)
    return str(integrity or outcome or "refused")
