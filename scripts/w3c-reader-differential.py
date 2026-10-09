#!/usr/bin/env python3
"""Differential run of the three W3C report readers over random single-field mutations.

scripts/w3c-rails-parity-test.py holds the three readers byte-identical on the
committed corpus and on twelve chosen mutations. This asks the wider question
the parity test cannot: on inputs nobody chose, do the readers reach the same
decision? Each round copies vectors-w3c-report/, applies one random mutation
to the subject of every member (delete a member, nudge an integer, or set a
value from a mixed pool of vocabulary and junk), runs all three readers over
the copy, and compares what each prints about each member.

Every member's lines are put in one of these classes, per pair of readers:

  identical       the same lines
  shape-wording   both refuse the subject as malformed, in their own words
  shape-vs-rows   both reject: one as malformed, the other under rows
  rows-differ     both reject under rows, with different row sets
  decision-a      the first reader of the pair rejects, the second accepts
  decision-b      the second reader of the pair rejects, the first accepts

A round in which a reader exits with a traceback or a status other than 0 or
1 is reported as a crash, with the mutation that caused it, and its members
are not counted.

Usage: python3 scripts/w3c-reader-differential.py [--rounds N] [--seed S]
Prints a table and the examples of each non-identical class; exit 0 always,
since this measures and does not gate.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CORPUS = "vectors-w3c-report"
POOL: list[Any] = [
    "pass", "fail", "void", "inconclusive", "not-exercised", "unknown", "demonstrated",
    "foreclosed", "possible-not-demonstrated", "out_of_scope", "integrity-failure",
    "confinement-failed-during-check", "checker rule", "input artifact", "constraint",
    "verdict", "fired-rule list", "error list", "nothing", "shown-by-run", "control-failed",
    "prior-discriminating-run", "flat", "rfc6962", "satisfied", "not-satisfied",
    "not-claimable", "running", "completed", "x", "", None, True, 0, 1, -1, 2, "cs-2",
    "d-other", "e-9", "https://example.invalid/llms-full.txt", "https://other.invalid/llms.txt",
    "/llms.txt", "text/html", "PT5M", "2026-09-18T10:00:00+02:00",
]


def paths(node: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(node, dict):
        for k, v in node.items():
            out += paths(v, prefix + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += paths(v, prefix + (i,))
    return out


def mutate(doc: dict[str, Any], rng: random.Random) -> str:
    candidates = [p for p in paths(doc["subject"]) if p]
    path = rng.choice(candidates)
    parent: Any = doc["subject"]
    for key in path[:-1]:
        parent = parent[key]
    key = path[-1]
    roll = rng.random()
    if roll < 0.25:
        del parent[key]
        return f"del {list(path)}"
    value = parent[key]
    if isinstance(value, int) and not isinstance(value, bool) and roll < 0.6:
        parent[key] = value + rng.choice([-1, 1])
        return f"nudge {list(path)}"
    parent[key] = copy.deepcopy(rng.choice(POOL))
    return f"set {list(path)} = {parent[key]!r}"


def per_member(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("FAIL v"):
            member, message = line[5:].split(": ", 1)
            out.setdefault(member, []).append(message)
    return out


def decision(lines: list[str] | None, expected: list[str]) -> tuple[str, Any]:
    for line in lines or []:
        if "is not the shape its definition gives" in line:
            return "reject", "shape"
    rows = expected
    for line in lines or []:
        found = re.search(r"rejects under \[([^\]]*)\]", line)
        if found:
            rows = [r for r in found.group(1).split(", ") if r]
    return ("reject" if rows else "accept"), tuple(rows)


def classify(a: list[str] | None, b: list[str] | None, expected: list[str]) -> str:
    if a == b:
        return "identical"
    da, db = decision(a, expected), decision(b, expected)
    if da[0] != db[0]:
        return "decision-a" if da[0] == "reject" else "decision-b"
    if da[1] == db[1] == "shape":
        return "shape-wording"
    if "shape" in (da[1], db[1]):
        return "shape-vs-rows"
    return "rows-differ" if da[1] != db[1] else "identical-decision"


CLASSES = [
    "identical", "identical-decision", "shape-wording", "shape-vs-rows", "rows-differ",
    "decision-a", "decision-b",
]
PAIRS = ("rs-py", "rs-go", "py-go")


def build_rails(work: Path) -> dict[str, list[str]]:
    """Build the Go and Rust readers into ``work`` and return each rail's command."""
    go_bin = work / "aee-verify"
    subprocess.run(["go", "build", "-o", str(go_bin), "./cmd/aee-verify"], cwd=REPO, check=True)
    target = work / "rs-target"
    manifest = REPO / "readers" / "w3c-report-rs" / "Cargo.toml"
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest),
         "--target-dir", str(target)],
        cwd=REPO, check=True, capture_output=True,
    )
    return {
        "go": [str(go_bin)],
        "py": [sys.executable, "packaging/run_vectors.py", "--vectors"],
        "rs": [str(target / "release" / "w3c-report-rs")],
    }


def crashed(proc: subprocess.CompletedProcess[str]) -> bool:
    noisy = "Traceback" in proc.stderr or "panic" in proc.stderr
    return noisy or proc.returncode not in (0, 1)


Round = tuple[Path, dict[str, Any], dict[str, str]]


def mutated_round(work: Path, r: int, rng: random.Random) -> Round:
    corpus = work / f"round{r}" / CORPUS
    shutil.copytree(REPO / CORPUS, corpus)
    manifest = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    notes: dict[str, str] = {}
    for entry in manifest["vectors"]:
        path = corpus / entry["file"]
        doc = json.loads(path.read_text(encoding="utf-8"))
        notes[entry["id"]] = mutate(doc, rng)
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return corpus, manifest, notes


def tally_round(
    outputs: dict[str, dict[str, list[str]]],
    manifest: dict[str, Any],
    notes: dict[str, str],
    tallies: dict[str, Counter[str]],
    examples: dict[tuple[str, str], list[str]],
) -> None:
    for entry in manifest["vectors"]:
        mid = entry["id"]
        expected = entry["expected"]["rejects"]
        for pair in PAIRS:
            a, b = pair.split("-")
            cls = classify(outputs[a].get(mid), outputs[b].get(mid), expected)
            tallies[pair][cls] += 1
            if cls in ("decision-a", "decision-b", "rows-differ"):
                examples.setdefault((pair, cls), []).append(
                    f"{mid} {notes[mid]}: {a}={decision(outputs[a].get(mid), expected)[1]} "
                    f"{b}={decision(outputs[b].get(mid), expected)[1]}"
                )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--seed", type=int, default=23)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    tallies: dict[str, Counter[str]] = {pair: Counter() for pair in PAIRS}
    examples: dict[tuple[str, str], list[str]] = {}
    crashes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="w3c-diff-") as tmp:
        work = Path(tmp)
        rails = build_rails(work)
        for r in range(args.rounds):
            corpus, manifest, notes = mutated_round(work, r, rng)
            outputs: dict[str, dict[str, list[str]]] = {}
            for name, cmd in rails.items():
                proc = subprocess.run(cmd + [str(corpus)], cwd=REPO, capture_output=True, text=True)
                if crashed(proc):
                    tail = (proc.stderr.strip().splitlines() or ["(no stderr)"])[-1]
                    crashes.append(f"round {r}: {name} exited {proc.returncode}: {tail}")
                outputs[name] = per_member(proc.stdout)
            if not any(c.startswith(f"round {r}:") for c in crashes):
                tally_round(outputs, manifest, notes, tallies, examples)
    print(f"seed {args.seed}, {args.rounds} rounds, {len(crashes)} round(s) with a crash")
    for line in crashes:
        print(f"  crash: {line}")
    for pair, tally in tallies.items():
        print(f"{pair}: " + ", ".join(f"{c} {tally[c]}" for c in CLASSES))
    for (pair, cls), items in sorted(examples.items()):
        print(f"\n{pair} {cls} ({len(items)}):")
        for item in items[:8]:
            print(f"  {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
