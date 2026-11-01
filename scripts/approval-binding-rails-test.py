#!/usr/bin/env python3
"""Every reader of vectors-approval-binding gives one answer, on the corpus and off it.

The corpus has three ways in: the packaged reader
(``packaging/agent_evidence_vectors/approvalbinding.py``, called in process),
the corpus's own command (``vectors-approval-binding/check_vectors.py
<record> --json``, the external-verifier contract) and the Go reader
(``corpora/approvalbinding.go``, run through ``aee-verify``). This test holds
them to one decision and one reason:

1. on every committed member, all three give the decision and reason
   MANIFEST.json declares;
2. on a corpus of mutated copies of every member (the use's cited approval
   changed or removed, each transition moved to just before, at and just after
   the use, a second predecessor record added before or after the first, the
   presented list reversed, the renewal claim added or dropped, the effect
   state moved), every member declares a verdict no reader can match, so each
   reader's own decision and reason is printed, and the packaged and Go readers
   must give the same one (``check_vectors.py`` imports the packaged reader, so
   step 1 proves its command contract and the mutants would only repeat it).
   A corpus pins the cases somebody wrote down; the mutants are where readers
   that agree on every written case still part;
3. this test goes red when one reader skips one check.

    python3 scripts/approval-binding-rails-test.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "vectors-approval-binding"
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import approvalbinding as reader  # noqa: E402

Record = dict[str, Any]
Verdict = tuple[str, str]
SENTINEL = {"decision": "none", "reason": "none"}
DERIVED = re.compile(r"^derived (\w+)/(\w+), the manifest declares")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _shift(stamp: str, seconds: int) -> str:
    moved = reader._when(stamp) + timedelta(seconds=seconds)
    return moved.strftime("%Y-%m-%dT%H:%M:%SZ")


def _accept_at(index: int, stamp: str) -> Callable[[Record], None]:
    def move(r: Record) -> None:
        r["transitions"][index].update(acceptedAt=stamp)
    return move


def _propose(index: int) -> Callable[[Record], None]:
    def move(r: Record) -> None:
        r["transitions"][index].update(status="proposed")
    return move


def _present_at(index: int, approval: Record) -> Callable[[Record], None]:
    def move(r: Record) -> None:
        r["presentedApprovals"].insert(index, dict(approval))
    return move


def _set_effect(key: str, state: str) -> Callable[[Record], None]:
    def move(r: Record) -> None:
        r.setdefault("effectRegistry", {}).update({key: state})
    return move


def mutations(record: Record) -> list[tuple[str, Callable[[Record], None]]]:
    """One-field departures from ``record`` that move the bindings this corpus judges."""
    moves: list[tuple[str, Callable[[Record], None]]] = [
        ("use-cites-none", lambda r: r["use"].pop("approvalId", None)),
        ("use-cites-other", lambda r: r["use"].update(approvalId="appr-9999")),
        ("use-cites-predecessor", lambda r: r["use"].update(approvalId="appr-0001")),
        ("use-cites-successor", lambda r: r["use"].update(approvalId="appr-0002")),
        ("presented-reversed", lambda r: r["presentedApprovals"].reverse()),
        ("claims-renewal", lambda r: r["use"].update(authorityForm="renewed")),
        ("drops-renewal-claim", lambda r: r["use"].pop("authorityForm", None)),
    ]
    used = record["use"]["usedAt"]
    for i, _ in enumerate(record.get("transitions", [])):
        for label, seconds in (("before", -1), ("at", 0), ("after", 1)):
            moves.append((f"t{i}-accepted-{label}-use", _accept_at(i, _shift(used, seconds))))
        moves.append((f"t{i}-proposed", _propose(i)))
    for i, presented in enumerate(record["presentedApprovals"]):
        conflicting = {**presented, "decisionId": "dec-0099"}
        moves.append((f"p{i}-conflict-after", _present_at(i + 1, conflicting)))
        moves.append((f"p{i}-conflict-before", _present_at(i, conflicting)))
        moves.append((f"p{i}-identical-copy", _present_at(i, dict(presented))))
    for state in ("RESERVED", "CONSUMED", "UNCERTAIN_CLOSE"):
        key = record["use"].get("effectKey")
        if key is not None:
            moves.append((f"effect-{state}", _set_effect(key, state)))
    return moves


def write_corpus(dest: Path, members: list[tuple[str, Record, bytes]],
                 expected: Callable[[str], dict[str, str]]) -> None:
    entries = []
    for name, body, used in members:
        directory = dest / "cases" / name
        directory.mkdir(parents=True)
        files = {"payload.bin": used, "record.json": _json(body)}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "edit": "rails mutant", "expected": expected(name),
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "useMatchesApproval": reader.use_matches_approval(body, used),
        })
    manifest = {"contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)),
                "suite": reader.SUITE, "vectors": entries}
    (dest / "MANIFEST.json").write_bytes(_json(manifest))


def build(dest: Path) -> str:
    binary = str(dest / "aee-verify")
    subprocess.run(["go", "build", "-o", binary, "./cmd/aee-verify"], cwd=ROOT, check=True)
    return binary


def go_verdicts(binary: str, corpus: Path) -> dict[str, Verdict]:
    """Each member's decision and reason as the Go reader derives it.

    Every member of ``corpus`` declares SENTINEL, so the Go reader reports the
    verdict it derived for each one as a finding."""
    out = subprocess.run([binary, "-json", str(corpus)], capture_output=True, text=True,
                         check=False)
    result = json.loads(out.stdout)
    if result.get("findings"):
        raise SystemExit(f"FAIL: the Go reader refused the mutant corpus: {result['findings']}")
    verdicts: dict[str, Verdict] = {}
    for member in result["members"]:
        derived = [m for f in member.get("findings", []) if (m := DERIVED.match(f))]
        if len(derived) != 1 or len(member["findings"]) != 1:
            raise SystemExit(f"FAIL: Go gave no single verdict for {member['id']}: "
                             f"{member.get('findings')}")
        verdicts[member["id"]] = (derived[0].group(1), derived[0].group(2))
    return verdicts


def cli_verdict(record_path: Path) -> Verdict:
    """The corpus command's answer under the external-verifier contract."""
    out = subprocess.run([sys.executable, str(CORPUS / "check_vectors.py"), str(record_path),
                          "--json"], capture_output=True, text=True, check=False)
    answer = json.loads(out.stdout)
    if reader.EXIT_FOR[answer["decision"]] != out.returncode:
        raise SystemExit(f"FAIL: check_vectors.py exit {out.returncode} disagrees with "
                         f"{answer} on {record_path}")
    return answer["decision"], answer["reason"]


def py_verdict(record_path: Path, skip: frozenset[str] = frozenset()) -> Verdict:
    answer = reader.verify(record_path, skip)
    return answer["decision"], answer["reason"]


def committed() -> list[tuple[str, Record, bytes]]:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    members = []
    for entry in manifest["vectors"]:
        directory = CORPUS / entry["path"]
        members.append((entry["id"], json.loads((directory / "record.json").read_text(
            encoding="utf-8")), (directory / "payload.bin").read_bytes()))
    return members


def mutants() -> list[tuple[str, Record, bytes]]:
    out = []
    for name, body, used in committed():
        for label, move in mutations(body):
            changed = copy.deepcopy(body)
            move(changed)
            out.append((f"{name}--{label}", changed, used))
    return out


def check_committed(binary: str, work: Path, declared: dict[str, Verdict]) -> tuple[
        list[str], dict[str, Verdict]]:
    """Every reader gives the declared verdict on every committed member."""
    failures: list[str] = []
    go_clean = subprocess.run([binary, "-json", str(CORPUS)], capture_output=True, text=True,
                              check=False)
    if go_clean.returncode != 0:
        failures.append(f"the Go reader does not judge the committed corpus clean: "
                        f"{go_clean.stdout[:2000]}")
    restated = work / "committed"
    write_corpus(restated, committed(), lambda _: SENTINEL)
    go_committed = go_verdicts(binary, restated)
    for name, want in declared.items():
        path = CORPUS / "cases" / name / "record.json"
        got = {"packaged": py_verdict(path), "check_vectors.py": cli_verdict(path),
               "Go": go_committed[name]}
        failures += [f"{name}: {rail} gives {verdict}, MANIFEST declares {want}"
                     for rail, verdict in got.items() if verdict != want]
    return failures, go_committed


def check_mutants(mutated: Path, members: list[tuple[str, Record, bytes]],
                  go_mutants: dict[str, Verdict]) -> list[str]:
    """The packaged and Go readers give the same verdict on every mutant."""
    failures: list[str] = []
    reasons: set[str] = set()
    for name, _, _ in members:
        py, go = py_verdict(mutated / "cases" / name / "record.json"), go_mutants[name]
        reasons.add(py[1])
        if py != go:
            failures.append(f"{name}: packaged {py}, Go {go}")
    missing = set(reader.CHECKS) - reasons - {"contract_id_missing", "contract_id_unknown"}
    if missing:
        failures.append(f"the mutants never reach {sorted(missing)}, so they do not test "
                        "the readers there")
    return failures


def check_not_vacuous(mutated: Path, members: list[tuple[str, Record, bytes]],
                      go_mutants: dict[str, Verdict], go_committed: dict[str, Verdict]
                      ) -> list[str]:
    """A packaged reader that skips one check parts from Go somewhere."""
    records = [(mutated / "cases" / name / "record.json", go_mutants[name])
               for name, _, _ in members]
    records += [(CORPUS / "cases" / name / "record.json", verdict)
                for name, verdict in go_committed.items()]
    return [f"a packaged reader without {check} still agrees with Go everywhere, so this "
            "test cannot see that check" for check in reader.CHECKS
            if all(py_verdict(path, frozenset({check})) == go for path, go in records)]


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    declared = {e["id"]: (e["expected"]["decision"], e["expected"]["reason"])
                for e in manifest["vectors"]}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        binary = build(work)
        failures, go_committed = check_committed(binary, work, declared)
        mutated, members = work / "mutants", mutants()
        write_corpus(mutated, members, lambda _: SENTINEL)
        go_mutants = go_verdicts(binary, mutated)
        failures += check_mutants(mutated, members, go_mutants)
        failures += check_not_vacuous(mutated, members, go_mutants, go_committed)
    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"approval-binding rails: {len(declared)} members and {len(members)} mutants, "
          f"{len(declared) + len(members)} records, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
