#!/usr/bin/env python3
"""Ablation lattice: which sets of a reader's rules decide each case, and do they only add.

    uv run python scripts/ablation-lattice.py                      # every gate corpus
    uv run python scripts/ablation-lattice.py vectors-grade-floor  # one corpus
    uv run python scripts/ablation-lattice.py --json out.json      # the full lattice as data

The single-rule sweeps beside some corpora (``mutation_check.py``) switch one rule off at a
time and ask whether any case notices. That answers "is this rule load-bearing" and nothing
about combinations. This runs the reference reader with every SET of rules kept and asks what
a single removal cannot answer.

A kept set MOVES a case when the reader's answer (decision and reason) with only those rules
on differs from its answer with every rule off. The full reader moves each refused case and
leaves each accepted case where it is.

* Sufficiency. For each moved case, the inclusion-minimal kept sets that move it. A case
  that one rule alone moves, and nothing smaller or different does, is reported as ``sole``:
  the corpus forces that rule through that case, so it is the case to keep when the corpus
  is pruned.
* Monotonicity. Keeping more rules may only move more. A kept set ``K`` that moves a case
  while ``K`` plus one more rule leaves it where it was is a reader whose rules interfere,
  and it FAILS the run. Checking every cover edge ``K -> K + {r}`` is enough: what holds on
  every edge holds along every chain, so it holds for all pairs.
* Stability. A case the full reader leaves where it is (accepted, or refused before any rule
  runs) that some kept set moves FAILS the run: removing checks must never refuse what the
  full reader admits.
* Interaction. A case moved by ``K`` exactly when ``K`` meets the rules that move it alone
  is a case whose rules act independently. Where that union model and the reader disagree,
  the case is reported with the kept set: the verdict then depends on rule order, which a
  second implementation must reproduce.

Each rule is reported with the cases it is sufficient for (it alone moves them) and the cases
it is necessary for (switched off alone, the answer differs from the full reader's: the
single-removal question, kept so the two views sit in one table).

Some rules narrow a check instead of adding one: switched off alone, the reader refuses a
case the full reader accepts (a rule that limits a gate check to the gates the policy
requires is one). Such a rule is reported as an exemption, with the cases it admits, and
held on for the whole lattice, because "keep more checks" is the axis the lattice walks and
an exemption is not a check.

A reader with at most ``--exhaustive`` rules (default 12) is run on every subset: ``2**n``
kept sets per case. A larger one is run on ``--chains`` seeded random maximal chains from the
empty set to the full set (default 16, seed 0); its minimal sets are the smallest sets those
chains met. The seed and the chain count are printed, so a finding is reproducible.

The corpora read here are the ones whose reference reader takes the switched-off rules as a
set: ``verify(case_path, skip: frozenset[str])`` beside a ``RULES`` tuple. A corpus whose
reader takes one disabled rule at a time joins when its reader takes a set.

Exit 0 when every corpus is monotone and stable and every full answer is the expected one;
1 otherwise; 2 when a corpus is named that has no set-taking reader.
"""

from __future__ import annotations

import argparse
import functools
import importlib
import itertools
import json
import random
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"

# corpus id -> reader module under packaging/agent_evidence_vectors. Each reader exposes
# RULES and verify(case_path, skip). A corpus joins this table when its reader takes a set.
GATE_CORPORA: dict[str, str] = {
    "vectors-agent-change-admission": "changeadmission",
    "vectors-agentic-process-evidence": "agenticprocess",
    "vectors-agent-payment-mandate": "paymentmandate",
    "vectors-connector-scope": "connectorscope",
    "vectors-grade-floor": "gradefloor",
}

Answer = tuple[str, str]
Verify = Callable[[Path, frozenset[str]], Answer]


@dataclass
class CaseResult:
    """What the lattice found for one case."""

    case_id: str
    expected: Answer
    full: Answer
    fires: list[str] = field(default_factory=list)
    necessary: list[str] = field(default_factory=list)
    minimal_sufficient: list[list[str]] = field(default_factory=list)
    interactions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Lattice:
    """The whole result for one corpus."""

    corpus: str
    rules: list[str]
    mode: str
    exemptions: dict[str, list[str]] = field(default_factory=dict)
    unmoved: list[str] = field(default_factory=list)
    cases: list[CaseResult] = field(default_factory=list)
    nonmonotone: list[str] = field(default_factory=list)
    moved_unmoved: list[str] = field(default_factory=list)
    wrong_full: list[str] = field(default_factory=list)
    kept_sets_run: int = 0

    def failures(self) -> list[str]:
        """Return each finding that fails the run."""
        return [*self.wrong_full, *self.nonmonotone, *self.moved_unmoved]

    def to_json(self) -> dict[str, Any]:
        sufficient: dict[str, list[str]] = {rule: [] for rule in self.rules}
        necessary: dict[str, list[str]] = {rule: [] for rule in self.rules}
        for case in self.cases:
            for rule in case.fires:
                sufficient[rule].append(case.case_id)
            for rule in case.necessary:
                necessary[rule].append(case.case_id)
        return {
            "corpus": self.corpus,
            "mode": self.mode,
            "rules": self.rules,
            "exemptions": self.exemptions,
            "keptSetsRun": self.kept_sets_run,
            "unmovedCases": self.unmoved,
            "rulesSufficientFor": sufficient,
            "rulesNecessaryFor": necessary,
            "cases": [
                {
                    "id": case.case_id,
                    "expected": list(case.expected),
                    "full": list(case.full),
                    "movesAlone": case.fires,
                    "necessary": case.necessary,
                    "minimalSufficientKeptSets": case.minimal_sufficient,
                    "sole": [len(kept) for kept in case.minimal_sufficient] == [1],
                    "interactions": case.interactions,
                }
                for case in self.cases
            ],
            "failures": self.failures(),
        }


def _answer(raw: dict[str, Any]) -> Answer:
    return (str(raw["decision"]), str(raw["reason"]))


def _memoize_rail() -> None:
    """Cache the rail's Ed25519 verification: the lattice re-reads the same bytes many times.

    The readers check signatures with the stdlib-only rail, which takes tens of milliseconds a
    call. The answer is a pure function of (key, message, signature), so a cache changes no
    verdict and turns a run of tens of minutes into seconds.
    """
    if str(PACKAGING) not in sys.path:
        sys.path.insert(0, str(PACKAGING))
    rail = importlib.import_module("run_vectors")
    original = rail.ed25519_verify
    if getattr(original, "cache_info", None) is None:
        rail.ed25519_verify = functools.lru_cache(maxsize=None)(original)


def load_reader(module_name: str) -> tuple[list[str], Verify]:
    """Import a reader and return its rules and a verify that returns (decision, reason)."""
    _memoize_rail()
    module = importlib.import_module(f"agent_evidence_vectors.{module_name}")
    rules = [str(rule) for rule in module.RULES]

    def verify(case_path: Path, skip: frozenset[str]) -> Answer:
        return _answer(module.verify(case_path, skip))

    return rules, verify


def _minimal(sets: Iterable[frozenset[str]]) -> list[list[str]]:
    """Return the inclusion-minimal sets, each sorted, in a stable order."""
    ordered = sorted(set(sets), key=lambda s: (len(s), sorted(s)))
    minimal: list[frozenset[str]] = []
    for candidate in ordered:
        if not any(kept <= candidate for kept in minimal):
            minimal.append(candidate)
    return [sorted(kept) for kept in minimal]


def _walks(
    rules: Sequence[str], exhaustive: int, chains: int, seed: int
) -> list[list[frozenset[str]]]:
    """Return the kept sets to run: every subset, or seeded random maximal chains."""
    if len(rules) <= exhaustive:
        every = itertools.chain.from_iterable(
            itertools.combinations(rules, size) for size in range(len(rules) + 1)
        )
        return [[frozenset(kept)] for kept in every]
    generator = random.Random(seed)
    walks = []
    for _ in range(chains):
        order = list(rules)
        generator.shuffle(order)
        walks.append([frozenset(order[:size]) for size in range(len(order) + 1)])
    return walks


def find_exemptions(
    rules: Sequence[str], verify: Verify, cases: Sequence[tuple[str, Path, Answer]]
) -> dict[str, list[str]]:
    """Return each rule that, switched off alone, moves a case the full reader leaves alone."""
    every_rule = frozenset(rules)
    exemptions: dict[str, list[str]] = {}
    for case_id, path, _ in cases:
        full = verify(path, frozenset())
        if full != verify(path, every_rule):
            continue
        for rule in rules:
            if verify(path, frozenset({rule})) != full:
                exemptions.setdefault(rule, []).append(case_id)
    return exemptions


class _Probe:
    """One case under the lattice: answers 'does this kept set move it', once per kept set."""

    def __init__(self, lattice: Lattice, verify: Verify, path: Path) -> None:
        self.lattice = lattice
        self.verify = verify
        self.path = path
        self.everything = frozenset(lattice.rules)
        self.base = verify(path, self.everything)
        self.seen: dict[frozenset[str], bool] = {}

    def moved(self, kept: frozenset[str]) -> bool:
        if kept not in self.seen:
            self.lattice.kept_sets_run += 1
            self.seen[kept] = self.verify(self.path, self.everything - kept) != self.base
        return self.seen[kept]

    def cancelled_edges(self) -> list[tuple[frozenset[str], str]]:
        """Return (kept set, rule) pairs: the set moves the case, the set plus the rule does not."""
        edges = []
        for kept, is_moved in self.seen.items():
            for rule in self.lattice.rules if is_moved else ():
                larger = kept | {rule}
                if rule not in kept and larger in self.seen and not self.seen[larger]:
                    edges.append((kept, rule))
        return edges


def _unmoved(
    lattice: Lattice, probe: _Probe, case_id: str, walks: list[list[frozenset[str]]]
) -> None:
    lattice.unmoved.append(case_id)
    for kept in itertools.chain.from_iterable(walks):
        if probe.moved(kept):
            lattice.moved_unmoved.append(
                f"{lattice.corpus}/{case_id}: the full reader leaves it at {probe.base}, "
                f"kept {sorted(kept)} moves it"
            )


def _moved(
    lattice: Lattice, probe: _Probe, result: CaseResult, walks: list[list[frozenset[str]]]
) -> None:
    rules = lattice.rules
    result.fires = [rule for rule in rules if probe.moved(frozenset({rule}))]
    result.necessary = [
        rule for rule in rules if probe.verify(probe.path, frozenset({rule})) != result.full
    ]
    fires = frozenset(result.fires)
    sufficient = [frozenset({rule}) for rule in result.fires]
    for kept in itertools.chain.from_iterable(walks):
        is_moved = probe.moved(kept)
        if is_moved:
            sufficient.append(kept)
        predicted = bool(kept & fires)
        if predicted != is_moved and len(result.interactions) < 5:
            result.interactions.append(
                {"kept": sorted(kept), "reader": is_moved, "unionModel": predicted}
            )
    for kept, rule in probe.cancelled_edges():
        lattice.nonmonotone.append(
            f"{lattice.corpus}/{result.case_id}: kept {sorted(kept)} moves it, "
            f"adding {rule} does not"
        )
    result.minimal_sufficient = _minimal(sufficient)
    lattice.cases.append(result)


def run_lattice(
    corpus: str,
    rules: Sequence[str],
    verify: Verify,
    cases: Sequence[tuple[str, Path, Answer]],
    *,
    exhaustive: int = 12,
    chains: int = 16,
    seed: int = 0,
) -> Lattice:
    """Compute the lattice for one corpus. ``cases`` holds (id, case path, expected answer)."""
    exemptions = find_exemptions(rules, verify, cases)
    kept_rules = [rule for rule in rules if rule not in exemptions]
    mode = "exhaustive" if len(kept_rules) <= exhaustive else f"chains:{chains}:seed:{seed}"
    lattice = Lattice(corpus=corpus, rules=kept_rules, mode=mode, exemptions=exemptions)
    walks = _walks(kept_rules, exhaustive, chains, seed)
    for case_id, path, expected in cases:
        full = verify(path, frozenset())
        if full != expected:
            lattice.wrong_full.append(
                f"{corpus}/{case_id}: full reader answers {full}, manifest expects {expected}"
            )
        probe = _Probe(lattice, verify, path)
        if full == probe.base:
            _unmoved(lattice, probe, case_id, walks)
        else:
            _moved(lattice, probe, CaseResult(case_id=case_id, expected=expected, full=full), walks)
    lattice.nonmonotone = sorted(set(lattice.nonmonotone))
    lattice.moved_unmoved = sorted(set(lattice.moved_unmoved))
    return lattice


def corpus_cases(corpus: str) -> list[tuple[str, Path, Answer]]:
    """Read a corpus manifest into (id, case path, expected answer)."""
    root = ROOT / "corpora" / corpus
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return [
        (str(entry["id"]), root / entry["path"] / "case.json", _answer(entry["expected"]))
        for entry in manifest["vectors"]
    ]


def _named(items: Iterable[str]) -> str:
    return ", ".join(items) or "none"


def report(lattice: Lattice) -> list[str]:
    """Return the human-readable lines for one corpus."""
    data = lattice.to_json()
    sufficient, necessary = data["rulesSufficientFor"], data["rulesNecessaryFor"]
    lines = [
        f"{lattice.corpus}: {len(lattice.rules)} rules, {len(lattice.cases)} cases on the lattice, "
        f"{len(lattice.unmoved)} unmoved (accepted or structurally refused), mode {lattice.mode}, "
        f"{lattice.kept_sets_run} kept sets run"
    ]
    for rule, admitted in lattice.exemptions.items():
        lines.append(f"  exemption {rule}: switched off, it refuses {_named(admitted)}; held on")
    sole = [case["id"] for case in data["cases"] if case["sole"]]
    lines.append(f"  sole-rule cases: {len(sole)} ({_named(sole)})")
    alone = (r for r in lattice.rules if not sufficient[r])
    lines.append(f"  rules sufficient for no case alone: {_named(alone)}")
    inert = (r for r in lattice.rules if not sufficient[r] and not necessary[r])
    lines.append(f"  rules neither sufficient nor necessary for any case: {_named(inert)}")
    ordered = (case["id"] for case in data["cases"] if case["interactions"])
    lines.append(f"  cases where rule order decides (the union model disagrees): {_named(ordered)}")
    lines.extend(f"  FAIL {failure}" for failure in lattice.failures())
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpora", nargs="*", help="corpus ids (default: every gate corpus)")
    parser.add_argument("--exhaustive", type=int, default=12, help="most rules run on every subset")
    parser.add_argument("--chains", type=int, default=16, help="random chains for a larger reader")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=Path, help="write the full lattice of every corpus here")
    args = parser.parse_args(argv)
    names = args.corpora or sorted(GATE_CORPORA)
    unknown = [name for name in names if name not in GATE_CORPORA]
    if unknown:
        print(f"not a gate corpus with a set-taking reader: {_named(unknown)}", file=sys.stderr)
        return 2
    results = []
    failed = 0
    for name in names:
        rules, verify = load_reader(GATE_CORPORA[name])
        options = {"exhaustive": args.exhaustive, "chains": args.chains, "seed": args.seed}
        lattice = run_lattice(name, rules, verify, corpus_cases(name), **options)
        results.append(lattice.to_json())
        print("\n".join(report(lattice)))
        failed += len(lattice.failures())
    if args.json:
        args.json.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(names)} corpora, {failed} failures")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
