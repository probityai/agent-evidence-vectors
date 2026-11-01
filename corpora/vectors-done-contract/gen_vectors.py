"""Build the done-contract cases byte-identically.

Every member is a sealed contract record and the unsigned in-toto Statement that
carries it under the done-contract predicate (spec/predicates/done-contract.md).
A valid member is accepted. An invalid member breaks exactly one rule, and the
manifest names the code the reader refuses it under. The first rules are the
record's own (spec/predicates/done-records.md), then the statement's.

Regenerate byte-identically:

    uv run python vectors-done-contract/gen_vectors.py

Nothing here is signed: the predicate URI is not served yet, and a signed
statement must not carry a URI that does not resolve.
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "vectors-done-receipt"))

import bundle_lib as lib  # noqa: E402
from agent_evidence_vectors import donerun  # noqa: E402

SUITE = donerun.CONTRACT_SUITE
corpus_digest = lib.corpus_digest
BASE = lib.Run(name="base").contract()
DIGEST = "a" * 64
ONE = {"path": "tests/test_app.py", "kind": "file", "sha256": lib.sha(lib.TEST_TEXT)}


def edited(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    record = copy.deepcopy(BASE)
    change(record)
    return record


def statement(record_bytes: bytes, predicate: Any = None, **replace: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "_type": donerun.STATEMENT_TYPE,
        "subject": [{"name": "contract.json", "digest": {"sha256": lib.sha(record_bytes)}}],
        "predicateType": donerun.CONTRACT_TYPE,
        "predicate": BASE if predicate is None else predicate,
    }
    body.update(replace)
    return body


def member(case_id: str, edit: str, record: bytes, stmt: dict[str, Any] | bytes,
           code: str | None) -> lib.Member:
    verdict: dict[str, Any] = {"verdict": "valid"} if code is None else {
        "verdict": "invalid", "code": code}
    return lib.Member(
        id=case_id, edit=edit, kind=verdict["verdict"], expected={"contract": verdict},
        files={"contract.json": record,
               "statement.json": stmt if isinstance(stmt, bytes) else lib.enc(stmt)})


def valid(case_id: str, edit: str, record: dict[str, Any]) -> lib.Member:
    raw = lib.enc(record)
    return member(case_id, edit, raw, statement(raw, record), None)


def bad_record(case_id: str, edit: str, record: dict[str, Any], code: str) -> lib.Member:
    """A record that breaks one rule, carried by a statement that restates it."""
    raw = lib.enc(record)
    return member(case_id, edit, raw, statement(raw, record), code)


def bad_bytes(case_id: str, edit: str, raw: bytes, code: str) -> lib.Member:
    return member(case_id, edit, raw, statement(raw), code)


def bad_statement(case_id: str, edit: str, code: str, **replace: Any) -> lib.Member:
    raw = lib.enc(BASE)
    return member(case_id, edit, raw, statement(raw, **replace), code)


def members() -> list[lib.Member]:
    raw = lib.enc(BASE)
    other = lib.enc(edited(lambda r: r.update(adequacy={"mutants": 4, "killed": 0})))
    base_json = json.dumps(BASE, sort_keys=True, indent=2)
    out = [
        valid("valid-directory-protected", "control: a protected directory with an excluded "
              "segment name, one acceptance command, three of four mutants killed", BASE),
        valid("valid-file-protected", "control: a protected file entry",
              edited(lambda r: r.update(protected_paths=[ONE]))),
        valid("valid-no-protected-paths", "control: a contract may protect nothing",
              edited(lambda r: r.update(protected_paths=[]))),
        valid("valid-two-acceptance-commands", "control: two acceptance commands",
              edited(lambda r: r["acceptance"].append(
                  {"id": "lint", "argv": ["python", "-m", "ruff", "check", "src"]}))),
        valid("valid-bound-digests", "control: the task and the three digests the compiler "
              "may bind",
              edited(lambda r: r.update(heldout_split_sha256=DIGEST,
                                        mutant_set_sha256="b" * 64,
                                        authority_sha256="c" * 64))),
        valid("valid-adequacy-zero", "control: a contract that killed no mutant is a valid "
              "contract; a receipt on it cannot say supported",
              edited(lambda r: r.update(adequacy={"mutants": 4, "killed": 0}))),
        bad_record("schema-unsupported", "schema_version names a version that does not exist",
                   edited(lambda r: r.update(schema_version="probity-done-contract/v0")),
                   "contract_schema_unsupported"),
        bad_record("member-unexpected", "a member the contract does not define",
                   edited(lambda r: r.update(owner="agent-1")), "contract_fields"),
        bad_record("member-missing", "adequacy is absent",
                   edited(lambda r: r.pop("adequacy")), "contract_fields"),
        bad_record("contract-id-empty", "the contract names no identifier",
                   edited(lambda r: r.update(contract_id="")), "contract_id"),
        bad_record("task-empty", "the task is present and empty",
                   edited(lambda r: r.update(task="")), "contract_task"),
        bad_record("bound-digest-uppercase", "a bound digest in uppercase hexadecimal",
                   edited(lambda r: r.update(heldout_split_sha256="A" * 64)),
                   "contract_digest_malformed"),
        bad_record("protected-digest-short", "a protected digest of 63 characters",
                   edited(lambda r: r["protected_paths"][0].update(sha256="a" * 63)),
                   "contract_digest_malformed"),
        bad_record("protected-paths-not-a-list", "protected_paths is an object",
                   edited(lambda r: r.update(protected_paths={})),
                   "contract_protected_paths_type"),
        bad_record("protected-path-dotdot", "a protected path that climbs out of the workspace",
                   edited(lambda r: r["protected_paths"][0].update(path="tests/../src")),
                   "contract_protected_path_not_normalized"),
        bad_record("protected-path-absolute", "a protected path that starts at the root",
                   edited(lambda r: r["protected_paths"][0].update(path="/tests")),
                   "contract_protected_path_not_normalized"),
        bad_record("protected-path-trailing-slash", "a protected directory written with a "
                   "trailing slash",
                   edited(lambda r: r["protected_paths"][0].update(path="tests/")),
                   "contract_protected_path_not_normalized"),
        bad_record("protected-kind-unknown", "a protected entry of kind symlink",
                   edited(lambda r: r["protected_paths"][0].update(kind="symlink")),
                   "contract_protected_kind"),
        bad_record("exclude-on-file", "an exclude list on a file entry",
                   edited(lambda r: r.update(protected_paths=[{**ONE, "exclude": ["x"]}])),
                   "contract_exclude_invalid"),
        valid("valid-exclude-path", "control: an exclusion with a separator is a workspace "
              "path under the entry, left out with everything below it",
              edited(lambda r: r["protected_paths"][0].update(
                  exclude=["__pycache__", "tests/helper.py"]))),
        bad_record("exclude-path-outside-the-entry", "an excluded path that does not lie under "
                   "the entry", edited(lambda r: r["protected_paths"][0].update(exclude=["a/b"])),
                   "contract_exclude_invalid"),
        bad_record("exclude-empty-list", "an exclude list with no name in it",
                   edited(lambda r: r["protected_paths"][0].update(exclude=[])),
                   "contract_exclude_invalid"),
        bad_record("exclude-duplicate-name", "the same excluded name twice",
                   edited(lambda r: r["protected_paths"][0].update(
                       exclude=["__pycache__", "__pycache__"])),
                   "contract_exclude_invalid"),
        bad_record("protected-path-duplicate", "the same path protected twice",
                   edited(lambda r: r["protected_paths"].append(dict(r["protected_paths"][0]))),
                   "contract_protected_duplicate"),
        bad_record("acceptance-empty", "no acceptance command",
                   edited(lambda r: r.update(acceptance=[])), "contract_acceptance_empty"),
        bad_record("acceptance-id-empty", "an acceptance command with an empty id",
                   edited(lambda r: r["acceptance"][0].update(id="")),
                   "contract_acceptance_id"),
        bad_record("acceptance-argv-empty", "an acceptance command with no argv",
                   edited(lambda r: r["acceptance"][0].update(argv=[])),
                   "contract_acceptance_argv"),
        bad_record("acceptance-argv-not-text", "an argv element that is a number",
                   edited(lambda r: r["acceptance"][0].update(argv=["pytest", 1])),
                   "contract_acceptance_argv"),
        bad_record("acceptance-id-duplicate", "two acceptance commands with one id",
                   edited(lambda r: r["acceptance"].append(dict(r["acceptance"][0]))),
                   "contract_acceptance_duplicate_id"),
        bad_record("adequacy-killed-exceeds-mutants", "more mutants killed than generated",
                   edited(lambda r: r.update(adequacy={"mutants": 3, "killed": 4})),
                   "contract_adequacy_overcount"),
        bad_record("adequacy-negative", "a negative mutant count",
                   edited(lambda r: r.update(adequacy={"mutants": -1, "killed": 0})),
                   "contract_adequacy_count"),
        bad_record("adequacy-boolean", "killed written as true",
                   edited(lambda r: r.update(adequacy={"mutants": 4, "killed": True})),
                   "contract_adequacy_count"),
        bad_record("adequacy-member-unexpected", "a member adequacy does not define",
                   edited(lambda r: r["adequacy"].update(survived=1)),
                   "contract_adequacy_fields"),
        *sealed_members(),
        bad_bytes("record-duplicate-member", "the record names adequacy twice, so two readers "
                  "could keep different ones",
                  raw.replace(b'"adequacy": {', b'"adequacy": {"mutants": 9, "killed": 9},\n'
                              b'  "adequacy": {', 1), "contract_json_duplicate_key"),
        bad_bytes("record-not-a-number", "killed is NaN, which is not JSON",
                  base_json.replace('"killed": 3', '"killed": NaN').encode() + b"\n",
                  "contract_json_number"),
        bad_bytes("record-truncated", "the record ends in the middle of an object",
                  raw[: len(raw) // 2], "contract_json_invalid"),
        bad_statement("statement-type-wrong", "the statement is typed as another statement "
                      "version", "statement_type_wrong",
                      _type="https://in-toto.io/Statement/v0.1"),
        bad_statement("statement-predicate-type-wrong", "the statement is typed as a receipt",
                      "statement_predicate_type_wrong", predicateType=donerun.RECEIPT_TYPE),
        bad_statement("statement-predicate-type-moved", "the statement carries the URI on "
                      "another host", "statement_predicate_type_wrong",
                      predicateType="https://example.org/probity/predicate/v1/done-contract"),
        bad_statement("statement-two-subjects", "the statement has two subjects",
                      "statement_subject_malformed",
                      subject=[{"name": "contract.json", "digest": {"sha256": lib.sha(raw)}},
                               {"name": "other", "digest": {"sha256": DIGEST}}]),
        bad_statement("statement-subject-other-algorithm", "the subject is digested with "
                      "sha512 alone", "statement_subject_malformed",
                      subject=[{"name": "contract.json", "digest": {"sha512": "a" * 128}}]),
        bad_statement("statement-subject-unbound", "the subject digests the record "
                      "re-serialized with other whitespace, not the record bytes",
                      "statement_subject_unbound",
                      subject=[{"name": "contract.json", "digest": {
                          "sha256": lib.sha(json.dumps(BASE, sort_keys=True).encode())}}]),
        member("statement-predicate-differs", "the statement says three mutants were killed "
               "and the record says none", other, statement(other, predicate=BASE),
               "statement_predicate_differs"),
        member("statement-duplicate-member", "the statement names its predicate type twice",
               raw, lib.enc(statement(raw)).replace(
                   b'"predicateType":', b'"predicateType": "x",\n  "predicateType":', 1),
               "statement_json_duplicate_key"),
        member("statement-not-a-number", "the statement holds NaN", raw,
               lib.enc(statement(raw)).replace(b'"_type":', b'"n": NaN, "_type":', 1),
               "statement_json_number"),
        member("statement-truncated", "the statement ends in the middle of an object", raw,
               lib.enc(statement(raw))[:40], "statement_json_invalid"),
        bad_statement("statement-member-unexpected", "a member the statement does not define",
                      "statement_fields", signature="none"),
    ]
    return out


SURFACE = ["/usr/lib/python3.12", "/usr/local/bin"]
PYTHONS = ["/usr/bin/python3", "/usr/local/bin/python"]


def command(**fields: Any) -> Callable[[dict[str, Any]], None]:
    """Seal more of the visible acceptance command."""
    return lambda r: r["acceptance"][0].update(fields)


def sealed_members() -> list[lib.Member]:
    """The members the contract compiler may seal beyond the command lines, valid and not."""
    twin = {"id": "unit-in-process", "argv": ["python", "tests/test_app.py"],
            "in_process_twin_of": "unit"}
    return [
        valid("valid-sealed-run", "control: the visible command sealed with the directory, the "
              "paths that name its executable, the interpreter, its test ids and the paths its "
              "run writes", edited(command(cwd="/workspace", exe=PYTHONS, interpreter=PYTHONS,
                                           ids=["tests/test_app.py::test_app"],
                                           run_writes=["build"]))),
        valid("valid-execution-surface", "control: a sealed execution surface, the image links "
              "into it and the module under test",
              edited(lambda r: r.update(execution_surface=SURFACE,
                                        surface_aliases={"/lib": "/usr/lib"},
                                        module_under_test=["src/app.py"]))),
        valid("valid-probes-and-twin", "control: an oracle-free probe, a generated held-out "
              "command and an in-process twin of the visible command",
              edited(lambda r: r["acceptance"].extend([
                  {"id": "visible_determinism", "argv": ["python", "-m", "pytest", "probes"],
                   "probe": "determinism"},
                  {"id": "heldout-generated", "argv": ["python", "-m", "pytest", "/gen"],
                   "tier": "synthesized"}, twin]))),
        valid("valid-measured-adequacy", "control: adequacy by mutant class, the kill vector "
              "digest and the gates the compiler measured, with the strength and the native "
              "code the commands loaded",
              edited(lambda r: r.update(
                  adequacy={"mutants": 4, "killed": 3, "kill_vector_sha256": DIGEST,
                            "by_class": {"arith": {"mutants": 3, "killed": 3},
                                         "cond": {"mutants": 1, "killed": 0}},
                            "gates": {"kill_rate": {"pass": True}}},
                  strength="gated", native_loaded=[{"path": "src/_app.so", "sha256": DIGEST}]))),
        valid("valid-file-equivalence", "control: a protected file judged by its Python syntax "
              "tree", edited(lambda r: r.update(protected_paths=[
                  {**ONE, "equivalence": "python_ast"}]))),
        bad_record("equivalence-on-a-directory", "a syntax-tree equivalence on a directory entry",
                   edited(lambda r: r["protected_paths"][0].update(equivalence="python_ast")),
                   "contract_equivalence"),
        bad_record("equivalence-unknown", "an equivalence the specification does not define",
                   edited(lambda r: r.update(protected_paths=[{**ONE, "equivalence": "bytes"}])),
                   "contract_equivalence"),
        bad_record("strength-unknown", "a strength the specification does not define",
                   edited(lambda r: r.update(strength="strong")), "contract_strength"),
        bad_record("native-loaded-path-absolute", "native code named by an absolute path",
                   edited(lambda r: r.update(native_loaded=[{"path": "/lib/x.so",
                                                             "sha256": DIGEST}])),
                   "contract_native_loaded"),
        bad_record("acceptance-member-unexpected", "a command with a member the contract does "
                   "not define", edited(command(timeout=60)), "contract_acceptance_fields"),
        bad_record("acceptance-tier-unknown", "a command of a tier that does not exist",
                   edited(command(tier="gold")), "contract_acceptance_tier"),
        bad_record("acceptance-probe-unknown", "a probe of a mode that does not exist",
                   edited(command(probe="fuzz")), "contract_acceptance_probe"),
        bad_record("acceptance-cwd-without-exe", "a sealed directory without the executable",
                   edited(command(cwd="/workspace")), "contract_acceptance_seal"),
        bad_record("acceptance-exe-unsorted", "the paths of the executable out of order",
                   edited(command(cwd="/workspace", exe=list(reversed(PYTHONS)))),
                   "contract_acceptance_seal"),
        bad_record("acceptance-cwd-relative", "a sealed directory that is not absolute",
                   edited(command(cwd="workspace", exe="/usr/bin/python3")),
                   "contract_acceptance_seal"),
        bad_record("acceptance-interpreter-without-exe", "an interpreter with no sealed "
                   "executable", edited(command(interpreter=PYTHONS)),
                   "contract_acceptance_interpreter"),
        bad_record("acceptance-ids-duplicate", "a test id sealed twice",
                   edited(command(ids=["t::a", "t::a"])), "contract_acceptance_ids"),
        bad_record("acceptance-run-writes-climb", "a run-writes path that climbs out of the "
                   "workspace", edited(command(run_writes=["../x"])),
                   "contract_acceptance_run_writes"),
        bad_record("twin-of-itself", "an in-process twin of its own id",
                   edited(command(in_process_twin_of="unit")), "contract_acceptance_twin"),
        bad_record("twin-of-unknown", "an in-process twin of an id the contract does not have",
                   edited(lambda r: r["acceptance"].append({**twin, "in_process_twin_of": "x"})),
                   "contract_acceptance_twin"),
        bad_record("twin-of-a-probe", "an in-process twin of a probe",
                   edited(lambda r: r["acceptance"].extend([
                       {"id": "p", "argv": ["python", "-m", "pytest", "probes"],
                        "probe": "determinism"}, {**twin, "in_process_twin_of": "p"}])),
                   "contract_acceptance_twin"),
        bad_record("surface-unsorted", "execution surface entries out of order",
                   edited(lambda r: r.update(execution_surface=list(reversed(SURFACE)))),
                   "contract_execution_surface"),
        bad_record("surface-shared-root", "/tmp as a whole execution surface entry",
                   edited(lambda r: r.update(execution_surface=["/tmp"])),
                   "contract_execution_surface_shared_root"),
        bad_record("surface-aliases-without-surface", "image links with no execution surface",
                   edited(lambda r: r.update(surface_aliases={"/lib": "/usr/lib"})),
                   "contract_surface_aliases"),
        bad_record("surface-alias-relative", "an image link to a relative path",
                   edited(lambda r: r.update(execution_surface=SURFACE,
                                             surface_aliases={"/lib": "usr/lib"})),
                   "contract_surface_aliases"),
        bad_record("module-under-test-empty", "a module-under-test list with nothing in it",
                   edited(lambda r: r.update(module_under_test=[])), "contract_module_under_test"),
        bad_record("adequacy-gate-not-boolean", "a gate whose pass is not a boolean",
                   edited(lambda r: r["adequacy"].update(gates={"kill_rate": {"pass": "yes"}})),
                   "contract_adequacy_gates"),
        bad_record("adequacy-classes-do-not-sum", "mutant classes that do not sum to the totals",
                   edited(lambda r: r["adequacy"].update(
                       by_class={"arith": {"mutants": 1, "killed": 1}})),
                   "contract_adequacy_by_class"),
        bad_record("kill-vector-digest-short", "a kill vector digest of 63 characters",
                   edited(lambda r: r["adequacy"].update(kill_vector_sha256="a" * 63)),
                   "contract_digest_malformed"),
    ]


def generate(root: Path = ROOT) -> None:
    built = members()
    for entry in built:
        lib.check_member(SUITE, entry)
    lib.write_corpus(root, SUITE, built, {
        "predicateType": donerun.CONTRACT_TYPE,
        "predicateSpec": "spec/predicates/done-contract.md",
        "recordSpec": "spec/predicates/done-records.md",
    })


if __name__ == "__main__":
    generate()
