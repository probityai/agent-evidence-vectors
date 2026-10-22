#!/usr/bin/env python3
"""Both readers of vectors-a2a-jcs-v01/ agree, and the in-process API catches a wrong canonicalizer.

Two halves.

Parity. ``aee-verify <dir>`` judges the corpus through corpora/a2ajcs.go and
``packaging/run_vectors.py --vectors <dir>`` through
packaging/agent_evidence_vectors/a2ajcs.py. The two canonicalizers share no
code. The committed corpus and a set of mutated copies are judged by both, and
both must name the same failing members, the same corpus-level failure, and
exit with the same status. Most mutations are resealed (every manifest sha256
and the corpus digest recomputed), so the integrity checks pass and only a
reader that recomputes the bytes itself can catch the edit. Finding TEXT is not
compared, because each language words its own; the member a finding names is.

API. ``a2ajcs.check`` and ``a2ajcs.assert_conforms`` are what another project
runs against its canonicalizer. The module's own canonicalizer must pass every
vector of both targets in both argument modes; ``json.dumps`` with sorted keys,
the canonicalizer most projects start from, must fail exactly the members that
test what it gets wrong; a canonicalizer that keeps ``signatures`` must fail
exactly the four rule-3 members; ``assert_conforms`` must raise naming the
vector; and a corpus that fails its manifest must be refused, not tested.

The wheel half (``params()`` collected by pytest from the installed package,
outside the checkout) lives in scripts/wheel-jcs-bytes-test.py, which builds
the wheel once for every installed check.

Usage: python3 scripts/a2a-jcs-rails-test.py
Exit 0 when every case holds; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "vectors-a2a-jcs-v01"
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import a2ajcs  # noqa: E402

# The members json.dumps(sort_keys=True) gets wrong: code-point rather than
# UTF-16 key order (A3-006, A3-007), Python number spelling (A5-001, -006,
# -011, -012, -015), and NaN and Infinity written out instead of refused.
NAIVE_FAILS = {
    "A3-006",
    "A3-007",
    "A5-001",
    "A5-006",
    "A5-011",
    "A5-012",
    "A5-015",
    "A5-REJECT-016",
    "A5-REJECT-017",
    "A5-REJECT-018",
}
RULE_THREE = {"A2-001", "A2-002", "A2-REJECT-003", "A2-REJECT-004"}


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout


# ---------------------------------------------------------------------------
# Mutations, written into a copy of the corpus.


def manifest_of(corpus: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    return data


def write_sealed(corpus: Path, manifest: dict[str, Any]) -> None:
    """Write the manifest as upstream does: indent 2, corpusDigest last, over the rest."""
    body = {key: value for key, value in manifest.items() if key != "corpusDigest"}
    preimage = json.dumps(body, indent=2)
    digest = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    text = preimage[:-2] + f',\n  "corpusDigest": "{digest}"\n}}\n'
    (corpus / "MANIFEST.json").write_text(text, encoding="utf-8")


def reseal(corpus: Path) -> None:
    """Recompute every member's sha256 and the corpus digest, so integrity passes."""
    manifest = manifest_of(corpus)
    for entry in manifest["vectors"]:
        entry["sha256"] = hashlib.sha256((corpus / entry["path"]).read_bytes()).hexdigest()
    write_sealed(corpus, manifest)


def path_of(corpus: Path, member: str) -> Path:
    entry = next(e for e in manifest_of(corpus)["vectors"] if e["path"].endswith(f"/{member}.json"))
    return corpus / str(entry["path"])


def rewrite(corpus: Path, member: str, old: str, new: str) -> None:
    path = path_of(corpus, member)
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"FAIL: {member} does not contain {old!r}; the mutation cannot apply")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def wrong_expected_bytes(corpus: Path) -> None:
    # 0.000001 expected as the 1e-06 a2a-python wrote: only a recomputation sees it.
    rewrite(corpus, "A5-001", "302e3030303030317d", "31652d30367d")
    reseal(corpus)


def accept_relabelled_reject(corpus: Path) -> None:
    rewrite(corpus, "A3-001", '"disposition": "MUST-ACCEPT"', '"disposition": "MUST-REJECT"')
    reseal(corpus)


def reject_relabelled_accept(corpus: Path) -> None:
    rewrite(corpus, "A4-REJECT-013", '"disposition": "MUST-REJECT"', '"disposition": "MUST-ACCEPT"')
    reseal(corpus)


def rule_three_read_as_rfc8785(corpus: Path) -> None:
    # The member moves into the rfc8785 target, which now owns one more than it declares.
    rewrite(
        corpus, "A2-REJECT-003", '"clause": "a2a-spec-8.4.1-rule-3"', '"clause": "RFC8785-3.2.3"'
    )
    reseal(corpus)


def target_count_off_by_one(corpus: Path) -> None:
    manifest = manifest_of(corpus)
    manifest["targets"]["rfc8785"]["vectors"] -= 1
    write_sealed(corpus, manifest)


def edited_case_file(corpus: Path) -> None:
    # Not resealed: the member no longer hashes to what the manifest records.
    path = path_of(corpus, "A6-001")
    path.write_bytes(path.read_bytes().replace(b"\n", b"\n ", 1))


def edited_manifest(corpus: Path) -> None:
    # Not resealed: the manifest body no longer hashes to its corpusDigest.
    path = corpus / "MANIFEST.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"layer": "canonicalization"', '"layer": "edited"', 1))


PARITY: list[tuple[str, Callable[[Path], None] | None, set[str]]] = [
    ("committed", None, set()),
    ("resealed-unchanged", reseal, set()),
    ("wrong-expected-bytes", wrong_expected_bytes, {"A5-001"}),
    ("accept-relabelled-reject", accept_relabelled_reject, {"A3-001"}),
    ("reject-relabelled-accept", reject_relabelled_accept, {"A4-REJECT-013"}),
    ("rule-three-read-as-rfc8785", rule_three_read_as_rfc8785, {"A2-REJECT-003", "corpus"}),
    ("target-count-off-by-one", target_count_off_by_one, {"corpus"}),
    ("edited-case-file", edited_case_file, {"A6-001"}),
    ("edited-manifest", edited_manifest, {"corpus"}),
]


# ---------------------------------------------------------------------------
# What each rail says failed.


def go_failing(output: str) -> set[str]:
    """``FAIL <member>: ...`` and ``FAIL corpus: ...``, as aee-verify prints them."""
    return {line[5:].split(":", 1)[0] for line in output.splitlines() if line.startswith("FAIL ")}


def py_failing(output: str) -> set[str]:
    """The Python reader's FAIL lines, by the member each names or ``corpus``.

    A vector's verdict is ``FAIL <target> <id>: ...``; a member that does not
    match its manifest sha256 is named by its path, whose stem is its id; every
    other finding is about the corpus.
    """
    failing: set[str] = set()
    for line in output.splitlines():
        if not line.startswith("FAIL "):
            continue
        tokens = line[5:].split()
        if tokens[0] in a2ajcs.TARGETS:
            failing.add(tokens[1].rstrip(":"))
        elif tokens[0].endswith(".json") and tokens[0] != "MANIFEST.json":
            failing.add(Path(tokens[0]).stem)
        else:
            failing.add("corpus")
    return failing


def check_parity(work: Path, binary: Path) -> list[str]:
    failures: list[str] = []
    committed = (REPO / CORPUS / "MANIFEST.json").read_bytes()
    for name, mutate, expected in PARITY:
        corpus = work / name
        shutil.copytree(REPO / CORPUS, corpus, ignore=shutil.ignore_patterns("*.py", "tests"))
        if mutate is not None:
            mutate(corpus)
        if name == "resealed-unchanged" and (corpus / "MANIFEST.json").read_bytes() != committed:
            failures.append("resealing the committed corpus changed MANIFEST.json: no seal")
        go_status, go_out = run([str(binary), str(corpus)], REPO)
        py_status, py_out = run(
            [
                sys.executable,
                "packaging/run_vectors.py",
                "--vectors",
                str(corpus),
                "--report",
                str(work / f"{name}.json"),
            ],
            REPO,
        )
        got_go, got_py = go_failing(go_out), py_failing(py_out)
        if got_go != got_py:
            failures.append(f"{name}: the rails disagree: go {sorted(got_go)}, py {sorted(got_py)}")
        if got_go != expected:
            failures.append(f"{name}: expected {sorted(expected)}, go named {sorted(got_go)}")
        want = 1 if expected else 0
        if (go_status, py_status) != (want, want):
            failures.append(f"{name}: exit statuses go={go_status} py={py_status}, expected {want}")
    return failures


# ---------------------------------------------------------------------------
# The API another project runs.


def naive(value: Any) -> bytes:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def failing_ids(lines: list[str]) -> set[str]:
    return {line.split()[0] for line in lines}


def check_reference_conforms() -> list[str]:
    """The module's own two functions pass every vector of their target, in both modes."""
    failures: list[str] = []

    def canonical_text(text: Any) -> bytes:
        return a2ajcs.canonicalize(a2ajcs.parse(text))

    def signing_text(text: Any) -> bytes:
        return a2ajcs.signing_input(a2ajcs.parse(text))

    runs = [
        ("canonicalize", a2ajcs.canonicalize, "rfc8785", False),
        ("canonicalize, text mode", canonical_text, "rfc8785", True),
        ("signing_input", a2ajcs.signing_input, "card-signing-input", False),
        ("signing_input, text mode", signing_text, "card-signing-input", True),
    ]
    for label, fn, target, text in runs:
        found = a2ajcs.check(fn, target, text=text)
        if found:
            failures.append(f"{label} on {target} should conform and failed {found[:3]}")
    return failures


def returns_text(value: Any) -> Any:
    del value
    return "{}"


def check_wrong_canonicalizers() -> list[str]:
    """Each wrong canonicalizer fails exactly the vectors that test what it gets wrong."""
    failures: list[str] = []
    got = failing_ids(a2ajcs.check(naive))
    if got != NAIVE_FAILS:
        failures.append(
            f"json.dumps(sort_keys=True) should fail {sorted(NAIVE_FAILS)} and failed {sorted(got)}"
        )
    got = failing_ids(a2ajcs.check(a2ajcs.canonicalize, "card-signing-input"))
    if got != RULE_THREE:
        failures.append(f"a canonicalizer that keeps signatures failed {sorted(got)}")
    # Returning text is an error, not bytes and not a refusal, so it fails every
    # vector: an accept wanted bytes and a reject wanted a refusal.
    lines = a2ajcs.check(returns_text)
    total = len(list(a2ajcs.vectors()))
    if len(lines) != total or not all(": errored: " in line for line in lines):
        failures.append(f"a canonicalizer returning str was not errored on all {total} vectors")
    vector = next(v for v in a2ajcs.vectors() if v.id == "A5-001")
    try:
        a2ajcs.assert_conforms(naive, vector)
        failures.append("assert_conforms did not raise on a failing vector")
    except AssertionError as exc:
        if not str(exc).startswith("A5-001 (RFC8785-3.2.2.3): diverged"):
            failures.append(f"assert_conforms did not name the vector and clause: {exc}")
    return failures


def check_iteration() -> list[str]:
    """vectors() and params() yield what each target owns, in manifest order."""
    failures: list[str] = []
    declared = manifest_of(REPO / CORPUS)["targets"]
    for target in a2ajcs.TARGETS:
        owned = list(a2ajcs.vectors(target))
        want = declared[target]["vectors"]
        if len(owned) != want:
            failures.append(f"vectors({target!r}) yields {len(owned)}; the manifest says {want}")
        if [p.id for p in a2ajcs.params(target)] != [v.id for v in owned]:
            failures.append(f"params({target!r}) does not carry the vector ids in manifest order")
    if [v.id for v in a2ajcs.vectors()] != [v.id for v in a2ajcs.vectors("rfc8785")]:
        failures.append("the default target is not rfc8785")
    return failures


def check_refusals(work: Path) -> list[str]:
    """A corpus that fails its manifest, or a target it does not name, is refused."""
    failures: list[str] = []
    broken = work / "api-edited"
    shutil.copytree(REPO / CORPUS, broken, ignore=shutil.ignore_patterns("*.py", "tests"))
    edited_case_file(broken)
    try:
        a2ajcs.check(a2ajcs.canonicalize, root=broken)
        failures.append("check() tested a corpus whose member does not match its manifest")
    except ValueError as exc:
        if "A6-001.json does not match its manifest sha256" not in str(exc):
            failures.append(f"check() refused an edited corpus without naming the member: {exc}")
    try:
        list(a2ajcs.vectors("rfc-8785"))
        failures.append("vectors() accepted a target the corpus does not name")
    except ValueError:
        pass
    return failures


def check_api(work: Path) -> list[str]:
    return (
        check_reference_conforms()
        + check_wrong_canonicalizers()
        + check_iteration()
        + check_refusals(work)
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="a2a-jcs-rails-") as tmp:
        work = Path(tmp)
        binary = work / "aee-verify"
        build = subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/aee-verify"],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            print(f"FAIL: aee-verify did not build:\n{build.stdout}")
            return 1
        failures = check_parity(work, binary) + check_api(work)
    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1
    print(f"a2a-jcs rails: {len(PARITY)} parity cases agree and the in-process API holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
