#!/usr/bin/env python3
"""Both readers of vectors-delegation-lifecycle/ derive the same outcome for every case.

``aee-verify <dir>`` judges the corpus through corpora/delegationlifecycle.go and
``packaging/run_vectors.py --vectors <dir>`` through
packaging/agent_evidence_vectors/delegationlifecycle.py. Three checks hold the two
rails together.

Committed. Both rails print the same lines on the committed corpus and exit 0.

Derived. A copy of the corpus declares no real outcome for any case, so each rail
prints the decision and reason it derived for every case. The two lists must be
equal, and equal to what MANIFEST.json declares.

Mutants. Every case is mutated in three ways, once per record: the record is
dropped, one signature byte is flipped, and each time inside the record is moved an
hour either way and the record is signed again with the key that signed it. Every
mutant is a case of its own in one more copy, again with no declared outcome, and
the two rails must derive the same decision and reason for each. The mutants must
also move outcomes: a differential over mutants nobody notices proves nothing.

Usage: python3 scripts/delegation-lifecycle-rails-test.py
Exit 0 when every check holds; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "vectors-delegation-lifecycle"
DERIVED = re.compile(r"^FAIL (\S+): derived (\S+)/(\S+), the manifest declares ", re.M)
UNDECLARED = {"decision": "accept", "reason": "undeclared"}


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout


def load_mutate() -> Any:
    path = REPO / CORPUS / "mutate.py"
    spec = importlib.util.spec_from_file_location("delegation_lifecycle_mutate", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def undeclared_corpus(target: Path, cases: dict[str, Path]) -> None:
    """A corpus of the given case directories with no real outcome declared.

    Every row declares accept, so the twin rule has nothing to say, and a reason
    no rail derives, so each rail prints what it derived for each case.
    """
    rows = []
    for name in sorted(cases):
        directory = target / "cases" / name
        shutil.copytree(cases[name], directory)
        files = {p.name: sha(p.read_bytes()) for p in sorted(directory.iterdir()) if p.is_file()}
        rows.append({"id": name, "path": f"cases/{name}", "files": files,
                     "expected": UNDECLARED})
    manifest = {"corpusDigest": sha(pretty(rows)), "suite": "delegation-lifecycle/v1",
                "vectors": rows}
    (target / "MANIFEST.json").write_bytes(pretty(manifest))


def derived(out: str) -> dict[str, tuple[str, str]]:
    return {m.group(1): (m.group(2), m.group(3)) for m in DERIVED.finditer(out)}


def both(binary: Path, corpus: Path) -> tuple[tuple[int, str], tuple[int, str]]:
    go = run([str(binary), str(corpus)])
    py = run([sys.executable, "packaging/run_vectors.py", "--vectors", str(corpus)])
    return go, py


def check_committed(binary: Path) -> int:
    (go_status, go_out), (py_status, py_out) = both(binary, REPO / CORPUS)
    if go_out != py_out or go_status != 0 or py_status != 0:
        print(f"FAIL committed: go exit {go_status}, python exit {py_status}")
        print("--- go\n" + go_out + "--- python\n" + py_out)
        return 1
    print("ok   committed: both rails exit 0 and print the same lines")
    return 0


def check_derived(work: Path, binary: Path) -> int:
    manifest = json.loads((REPO / CORPUS / "MANIFEST.json").read_text())
    cases = {v["id"]: REPO / CORPUS / v["path"] for v in manifest["vectors"]}
    corpus = work / "derived" / CORPUS
    undeclared_corpus(corpus, cases)
    (_, go_out), (_, py_out) = both(binary, corpus)
    want = {v["id"]: (v["expected"]["decision"], v["expected"]["reason"])
            for v in manifest["vectors"]}
    go_derived, py_derived = derived(go_out), derived(py_out)
    if go_out != py_out or go_derived != want or py_derived != want:
        print("FAIL derived: the rails parted, or parted from MANIFEST.json")
        for name in sorted(want):
            row = (want[name], go_derived.get(name), py_derived.get(name))
            if len(set(row)) > 1:
                print(f"  {name}: manifest {row[0]}, go {row[1]}, python {row[2]}")
        return 1
    print(f"ok   derived: both rails derive the manifest's outcome for {len(want)} of "
          f"{len(want)} cases")
    return 0


def mutant_cases(work: Path) -> dict[str, Path]:
    mutate = load_mutate()
    manifest = json.loads((REPO / CORPUS / "MANIFEST.json").read_text())
    cases: dict[str, Path] = {}
    for vector in manifest["vectors"]:
        source = REPO / CORPUS / vector["path"]
        for label, apply in mutate.mutations(source):
            name = f"{vector['id']}--{re.sub(r'[^a-z0-9]+', '-', label.lower()).strip('-')}"
            directory = work / "mutants" / name
            shutil.copytree(source, directory)
            apply(directory)
            cases[name] = directory
    return cases


def check_mutants(work: Path, binary: Path) -> int:
    cases = mutant_cases(work)
    corpus = work / "mutant-corpus" / CORPUS
    undeclared_corpus(corpus, cases)
    (go_status, go_out), (py_status, py_out) = both(binary, corpus)
    go_derived, py_derived = derived(go_out), derived(py_out)
    parted = sorted(n for n in cases if go_derived.get(n) != py_derived.get(n))
    if go_out != py_out or go_status != 1 or py_status != 1 or len(go_derived) != len(cases):
        print(f"FAIL mutants: go exit {go_status}, python exit {py_status}, "
              f"{len(go_derived)} of {len(cases)} cases derived by go, "
              f"{len(py_derived)} by python")
        for name in parted[:20]:
            print(f"  {name}: go {go_derived.get(name)}, python {py_derived.get(name)}")
        return 1
    manifest = json.loads((REPO / CORPUS / "MANIFEST.json").read_text())
    base = {v["id"]: (v["expected"]["decision"], v["expected"]["reason"])
            for v in manifest["vectors"]}
    moved = sum(1 for n, got in go_derived.items() if got != base[n.split("--")[0]])
    reasons = {reason for _, reason in go_derived.values()}
    if moved < len(cases) // 4 or len(reasons) < 15:
        print(f"FAIL mutants: only {moved} of {len(cases)} moved an outcome across "
              f"{len(reasons)} reasons, so the differential is not exercising the rules")
        return 1
    print(f"ok   mutants: both rails derive the same outcome for {len(cases)} of "
          f"{len(cases)} mutated cases; {moved} moved an outcome, across {len(reasons)} reasons")
    return 0


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="delegation-lifecycle-rails-") as tmp:
        work = Path(tmp)
        binary = work / "aee-verify"
        status, output = run(
            ["env", "GOWORK=off", "go", "build", "-o", str(binary), "./cmd/aee-verify"])
        if status != 0:
            print(f"FAIL: aee-verify did not build:\n{output}")
            return 1
        failures = (check_committed(binary) + check_derived(work, binary)
                    + check_mutants(work, binary))
    if failures:
        print(f"\n{failures} check(s) failed")
        return 1
    print("\nOK both rails derive the same outcome for every case and every mutant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
