#!/usr/bin/env python3
"""Surface-leakage gate: a conformance corpus may not be scoreable without the
specification.

The question, and why it is worth a gate
----------------------------------------

Every other check in this directory asks whether a particular vector forces a
particular rule. None of them asks the question a corpus can fail as a whole:
CAN A CONSUMER GET THE ANSWERS RIGHT WITHOUT IMPLEMENTING ANYTHING? If the label
of a vector is predictable from its surface -- what it is called, how long it is,
which members it happens to carry -- then a rail can post a good score while
having read the specification not at all, and every figure this suite publishes
about that rail means less than it appears to.

The surface is measured rather than argued about. A cheap classifier is trained
on features drawn from the corpus and asked to predict accept-or-reject, and the
figure reported is the area under its ROC curve out of sample. Chance is 0.5. The
target here is 0.55, which is close enough to chance that a rail scoring on
surface alone would gain almost nothing, and far enough from it that a real
regularity shows up.

That figure is a property of the CORPUS, not of any rail, which is what makes it
worth having: it generalises across every corpus this repository ships and across
every corpus it ever will, and it goes red for a leak nobody has thought of yet.
The two specific defects that motivated it -- an identifier namespace that names
the answer, and two differently-labelled vectors decoding to one statement -- are
each closed by their own check. This one is quantified over the whole surface, so
it does not need to be told what to look for.

What counts as the surface
--------------------------

Five groups, kept separate so a refusal names which one leaks rather than
reporting one number nobody can act on.

  identifier  the tokens of the vector's own name. This is where the largest leak
              in this repository lives and it is not subtle: identifiers carry an
              `ok-`/`bad-` prefix, so the name alone is very nearly the label.
  file        byte length and line count, bucketed. Reading a file's size is not
              reading the file.
  shape       node count, maximum depth, member count, and whether the file
              decodes at all.
  paths       the set of member paths present, with array positions collapsed.
              A vector that drops a required member is visible here.
  lexicon     member names and short string values. This is where a marker value
              or a giveaway field name would show up.

None of the five requires knowing what the predicate MEANS, which is the whole
point: everything measured here is available to a consumer who has not read the
specification, so a figure well above chance says the specification is optional.

How it is measured, and why this estimator
------------------------------------------

Bernoulli naive Bayes with Laplace smoothing, scored under stratified five-fold
cross-validation, averaged over a fixed list of seeds. Each choice is answering a
way the measurement could lie.

Cross-validated, because an in-sample classifier memorises a few hundred vectors
perfectly and reports a leak that does not exist. Out of fold, a feature seen in
one vector helps with nothing.

Averaged over a list of seeds rather than measured at one, because a single fold
split moves the figure by several hundredths on a corpus this size, which would
put the choice of seed in charge of whether the gate passes. The seeds are
literal constants, and every sum over a feature set is taken in sorted order, so
the estimator is deterministic: same corpus, same number, every run, on every
machine, with no network and nothing to install.

The sorting half of that sentence was missing once, and the paragraph still
claimed determinism while the gate did not have it: scores were summed in
frozenset order, which is hash order, which Python salts per process. See
score_fold for what that cost. Fixed seeds alone do not make a measurement
reproducible if anything downstream of them iterates a set.

Naive Bayes rather than anything fitted iteratively, because it trains by
counting. The whole measurement is a few seconds, and a gate slow enough to be
worth skipping is a gate that gets skipped.

The figure the gate compares is SEPARABILITY, `max(auc, 1 - auc)`, and not the
AUC. A classifier that is reliably wrong is a classifier: invert it and it is
reliably right. Reporting the AUC alone would let a corpus leak in the one
direction the threshold cannot see.

Baseline, null, and why both
----------------------------

`docs/SURFACE-LEAKAGE-BASELINE.json` records, for every surface of every corpus,
what it measures and what its own null is, and the gate refuses on two different
things.

A measurement ABOVE ITS OWN RECORDED FIGURE is a new leak, and it fails whether
or not the surface was already outside its null. This half holds every surface at
the level it has reached, so a change that adds predictability fails on the
change that added it.

A measurement OUTSIDE ITS OWN NULL is a regularity that shuffling the labels does
not reproduce -- judged at the family-wise quantile of 2000 seeded shuffles,
because every surface is asked at once (false alarms per run: about 49% before,
at most 5% after) -- and it must be declared in the baseline with the constraint that
blocks it. A declaration is not a permanent allowance: when a surface comes back
inside its null the declaration is stale and the gate refuses until it is
removed, so the ratchet turns in both directions.

The null is recorded rather than recomputed per run because it costs a couple of
hundred times the measurement it calibrates, and it is pinned to the corpus's
class counts so it cannot be carried across a change that moves its level.

`--sync` re-records what is measured and will LOWER a figure, never raise one. A
sync that adopted whatever it found would be this gate's own bypass. Recording a
rise means editing the file by hand and putting the reason beside it, which
leaves a diff somebody reviews.

Usage:
    python3 scripts/surface-leakage-gate.py
    python3 scripts/surface-leakage-gate.py --report   (every figure, no refusal)
    python3 scripts/surface-leakage-gate.py --sync     (rewrite the baseline)
    python3 scripts/surface-leakage-gate.py --root <tree>   (for its own tests)
Exit 0 when no surface has gained predictability and every over-target surface is
declared; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_REL = "docs/SURFACE-LEAKAGE-BASELINE.json"

CORPORA = ("vectors", "vectors-ai-agent-action", "vectors-scitt-cose")

SURFACES = ("identifier", "file", "shape", "paths", "lexicon", "all")

# The threshold is MEASURED, not chosen, and the first version of this gate got
# that wrong in a way worth recording.
#
# It refused above a flat 0.55, reasoning that chance is 0.5 and a little over
# chance is close enough. But the figure compared against it is SEPARABILITY,
# max(auc, 1 - auc), which is a FOLDED statistic: it cannot go below 0.5 by
# construction, so ordinary sampling spread pushes it above 0.5 even when the
# labels carry nothing at all. Permuting the labels of this repository's larger
# corpus -- destroying every trace of signal -- and running this same estimator
# gives a mean of about 0.536 and exceeds 0.585 one time in twenty. A corpus with
# literally zero leakage would therefore have failed a 0.55 gate more often than
# it passed, and no corpus of this size could ever have satisfied it. That is the
# unsatisfiable gate this repository's own history warns about, and the only
# thing an unsatisfiable gate teaches is the bypass flag.
#
# So the threshold each surface is held to is that surface's OWN null: the same
# estimator, over the same features, with the labels shuffled. A figure inside
# the null is a figure a corpus carrying no information could have produced, and
# refusing on it would be refusing noise. A figure outside it is a regularity
# that shuffling does not explain.
#
# The null is recorded in the baseline rather than recomputed on every run,
# because computing it costs a couple of hundred times the measurement it
# calibrates. It is pinned to a FINGERPRINT of the corpus it was computed over --
# the class counts -- because those are what set the null's level, and a null
# carried across a change in them is a threshold describing a different corpus.
#
# Two corrections, measured on 2026-10-09 (DECISION_LOG.md records the figures).
#
# The null used to be the 95th percentile of TWENTY shuffles -- in practice the
# largest of them -- and that estimate moved by 0.005 to 0.05 when one vector was
# added, more than any margin the gate compared at. It is now taken from
# NULL_DRAWS shuffles drawn from a generator with a literal seed, which the
# vectorised estimator above makes affordable.
#
# And the gate asks the null question of every surface of every corpus at once,
# so a 95th percentile per surface is a five-per-cent false alarm per surface:
# with the surfaces that carry any spread, a corpus with no leak at all was
# refused on some surface on a large share of runs. The quantile is therefore
# the family-wise one, 1 - FAMILY_ALPHA / (number of surfaces judged): the
# margin above the old per-surface 95th percentile is read off each surface's
# own shuffle distribution rather than set once by hand, so a noisy surface
# gets a wide margin and a tight one a narrow margin.
#
# False alarms per run on a corpus that carries no signal, before and after:
#   before -- up to 1 - 0.95**13, about 49%, over the 13 surfaces with spread
#             (identifier-like surfaces have none), on top of a threshold that
#             itself moved with every added vector;
#   after  -- at most FAMILY_ALPHA, 5%, by the union bound.
# Power where it matters is not carried by this threshold: a change that lifts a
# surface by more than TOLERANCE is refused by the ratchet below whatever its
# null says, and the test file proves both a giveaway leak and a rise of about
# 0.03 over the null are still refused.
NULL_DRAWS = 2000
NULL_SEED = 20261009
FAMILY_ALPHA = 0.05
NULL_QUANTILE = 1.0 - FAMILY_ALPHA / (len(CORPORA) * len(SURFACES))

# How far the class counts may drift before the recorded null stops describing
# this corpus. Not zero, and the reason is the difference between a threshold
# that is correct and a gate that is usable. The null's level is a function of
# how many vectors there are and how unbalanced they are, and both move
# CONTINUOUSLY: one more reject vector changes it by far less than the width of
# the tolerance band below it. Pinning the counts exactly would therefore refuse
# the single most common change anybody makes to this repository -- adding a
# vector -- and demand a several-minute recalibration to clear it, which is how
# a gate teaches people to reach for the bypass. A tenth is loose enough that
# ordinary growth passes and tight enough that a corpus which has changed shape
# enough to move its own noise floor has to be re-measured. Nothing is lost by
# allowing the drift: the ratchet still refuses any surface whose figure rises,
# so a leak arriving with a new vector is caught on the change that brought it.
FINGERPRINT_DRIFT = 0.10

# The estimator is deterministic, so this band is not measurement noise: it is
# how much a legitimate corpus edit may move a figure before somebody has to look
# at it. Small enough that adding a family of vectors that all share a giveaway
# is caught; large enough that adding one vector is not a gate failure.
TOLERANCE = 0.02

# Literal constants, which is what makes the whole measurement reproducible.
FOLD_SEEDS = (11, 22, 33, 44, 55, 66, 77, 88, 99, 110)
FOLDS = 5


# --- features --------------------------------------------------------------


def bucket(n: int) -> int:
    return int(math.log2(n)) if n > 0 else -1


class Walked:
    """What one pass over a decoded statement collects.

    Array positions collapse to `[]` deliberately. A path carrying an index
    describes where a member sits in one particular vector, so indexed paths
    would make almost every vector unique and the paths surface would measure
    nothing but its own resolution.
    """

    def __init__(self) -> None:
        self.nodes = 0
        self.depth = 0
        self.names: set[str] = set()
        self.paths: set[str] = set()
        self.strings: set[str] = set()

    def walk(self, value: Any, path: str, depth: int) -> None:
        self.nodes += 1
        self.depth = max(self.depth, depth)
        if isinstance(value, dict):
            for key, child in value.items():
                self.names.add(key)
                self.walk(child, f"{path}/{key}", depth + 1)
        elif isinstance(value, list):
            for child in value:
                self.walk(child, f"{path}/[]", depth + 1)
        else:
            self.paths.add(path)
            # A long string is a payload or a digest: unique to its vector, so it
            # is never seen in training and contributes nothing out of fold.
            if isinstance(value, str) and len(value) <= 64:
                self.strings.add(value)


def tokens_of(text: str) -> set[str]:
    for separator in ("/", "_", ".", " "):
        text = text.replace(separator, "-")
    return {t for t in text.lower().split("-") if t}


def features(rel_path: str, raw: bytes) -> dict[str, set[str]]:
    """Every surface of one vector, as sets of binary feature names.

    The identifier surface is built from the vector's WHOLE manifest-relative
    path and not from its filename, because the directory names the label just
    as loudly as the prefix does. A corpus that content-addressed its filenames
    and left the files in `accept/` and `reject/` would move the leak rather
    than remove it, and a gate reading only the stem would go green on the way
    past. That is not hypothetical: it is the shape the obvious version of the
    fix has, so the measurement has to be able to see it.
    """
    lines = raw.count(b"\n") + 1
    groups: dict[str, set[str]] = {
        "identifier": {f"id.tok={t}" for t in tokens_of(rel_path)},
        "file": {
            f"file.bytes={bucket(len(raw))}",
            f"file.lines={bucket(lines)}",
        },
    }
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        # Not decoding is itself a surface fact, and the only one available.
        groups["shape"] = {"shape.undecodable"}
        groups["paths"] = set()
        groups["lexicon"] = set()
        return groups
    seen = Walked()
    seen.walk(decoded, "", 0)
    groups["shape"] = {
        f"shape.nodes={bucket(seen.nodes)}",
        f"shape.depth={seen.depth}",
        f"shape.names={bucket(len(seen.names))}",
    }
    groups["paths"] = {f"path={p}" for p in seen.paths}
    groups["lexicon"] = {f"name={n}" for n in seen.names} | {
        f"str={s}" for s in seen.strings
    }
    return groups


# --- estimator -------------------------------------------------------------


def _design(rows: list[tuple[int, frozenset[str]]]) -> tuple[Any, Any]:
    """The rows as a binary feature matrix and a label vector.

    Column order is the sorted feature names, so the matrix -- and every product
    taken over it -- is a function of the rows alone and not of the process's
    string-hash salt.
    """
    names = sorted(set().union(*(feats for _, feats in rows))) if rows else []
    column = {name: index for index, name in enumerate(names)}
    matrix = np.zeros((len(rows), len(names)), dtype=np.float64)
    for index, (_, feats) in enumerate(rows):
        for name in feats:
            matrix[index, column[name]] = 1.0
    labels = np.array([label for label, _ in rows], dtype=np.float64)
    return matrix, labels


def _folds(labels: Any, seed: int) -> Any:
    """Stratified fold ids, dealt exactly as the scalar estimator always dealt them.

    One `random.Random(seed)` shuffles the accept rows and then the reject rows,
    each in row order, and deals them round-robin into the folds. Keeping the
    stdlib generator rather than numpy's keeps every recorded separability
    figure byte-for-byte what the per-row implementation measured.
    """
    generator = random.Random(seed)
    fold = np.empty(labels.shape[0], dtype=np.int64)
    for value in (0.0, 1.0):
        members = [int(i) for i in np.flatnonzero(labels == value)]
        generator.shuffle(members)
        for position, row in enumerate(members):
            fold[row] = position % FOLDS
    return fold


def _auc_columns(scores: Any, labels: Any) -> Any:
    """Area under the ROC curve for every column, ties given their average rank."""
    out = np.empty(scores.shape[1], dtype=np.float64)
    for col in range(scores.shape[1]):
        y = labels[:, col]
        positives = float(y.sum())
        negatives = float(y.shape[0]) - positives
        if positives == 0 or negatives == 0:
            out[col] = float("nan")
            continue
        order = np.argsort(scores[:, col], kind="stable")
        ordered = scores[order, col]
        starts = np.flatnonzero(np.r_[True, ordered[1:] != ordered[:-1]])
        ends = np.r_[starts[1:], ordered.shape[0]]
        average = (starts + ends + 1) / 2.0
        ranks = np.repeat(average, ends - starts)
        rank_sum = float((ranks * y[order]).sum())
        out[col] = (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)
    return out


def _cross_validated_auc(matrix: Any, labels: Any, folds: Any) -> Any:
    """Naive-Bayes out-of-fold AUC for every labelling column at once.

    `labels` and `folds` are (rows, draws). Training counts for every fold of
    every draw are matrix products, which is what makes thousands of label
    shuffles affordable: the per-row Python loop this replaced cost about forty
    seconds for twenty shuffles of one corpus. The arithmetic is the same
    Laplace-smoothed log ratio, summed only over features seen in training.
    Scores are rounded to nine places before ranking so that rows with
    identical features tie exactly however the product happened to be summed.
    """
    scores = np.zeros(labels.shape, dtype=np.float64)
    for k in range(FOLDS):
        train = (folds != k).astype(np.float64)
        pos = labels * train
        neg = (1.0 - labels) * train
        tot1 = pos.sum(axis=0)
        tot0 = neg.sum(axis=0)
        c1 = matrix.T @ pos
        c0 = matrix.T @ neg
        weight = np.log((c1 + 1.0) / (tot1 + 2.0)) - np.log((c0 + 1.0) / (tot0 + 2.0))
        weight[(c1 + c0) == 0] = 0.0
        prior = np.log((tot1 + 1.0) / (tot0 + 1.0))
        fold_scores = matrix @ weight + prior
        test = folds == k
        scores[test] = fold_scores[test]
    return _auc_columns(np.round(scores, 9), labels)


def _separability_of(matrix: Any, labels: Any) -> Any:
    """Separability for every labelling column: mean AUC over the fold seeds,
    folded so that a reliably wrong classifier counts as much as a right one."""
    total = np.zeros(labels.shape[1], dtype=np.float64)
    for seed in FOLD_SEEDS:
        folds = np.stack(
            [
                _folds(labels[:, col], seed)
                for col in range(labels.shape[1])
            ],
            axis=1,
        )
        total += _cross_validated_auc(matrix, labels, folds)
    mean = total / len(FOLD_SEEDS)
    return np.maximum(mean, 1.0 - mean)


def null_draws(rows: list[tuple[int, frozenset[str]]]) -> Any:
    """What this estimator reports on these features when the labels mean nothing.

    NULL_DRAWS permutations of the labels, each re-measured exactly as the corpus
    is. The permutations come from one generator with a literal seed, so the
    distribution -- and every quantile taken from it -- is a fixed function of
    the rows.
    """
    matrix, labels = _design(rows)
    generator = np.random.default_rng(NULL_SEED)
    shuffled = np.stack(
        [labels[generator.permutation(labels.shape[0])] for _ in range(NULL_DRAWS)],
        axis=1,
    )
    return _separability_of(matrix, shuffled)


def null_separability(rows: list[tuple[int, frozenset[str]]]) -> float:
    """The NULL_QUANTILE point of the permutation null, to four places."""
    return round(float(np.quantile(null_draws(rows), NULL_QUANTILE)), 4)


def separability(rows: list[tuple[int, frozenset[str]]]) -> float:
    """How far from chance the surface is, in whichever direction it leans.

    A classifier that is reliably wrong is a classifier inverted, so the distance
    from 0.5 is the quantity a consumer could exploit, not the AUC itself.
    """
    matrix, labels = _design(rows)
    return round(float(_separability_of(matrix, labels[:, None])[0]), 4)


# --- corpus ----------------------------------------------------------------


def load(tree: Path, corpus: str) -> list[tuple[int, dict[str, set[str]]]]:
    base = tree / corpus
    manifest = json.loads((base / "MANIFEST.json").read_text(encoding="utf-8"))
    rows: list[tuple[int, dict[str, set[str]]]] = []
    for entry in manifest["vectors"]:
        kind = str(entry.get("kind"))
        if kind not in ("accept", "reject"):
            continue  # an indeterminate vector carries no binary label to predict
        rel = str(entry["file"])
        path = base / rel
        rows.append((1 if kind == "reject" else 0, features(rel, path.read_bytes())))
    return rows


def prepare(
    rows: list[tuple[int, dict[str, set[str]]]], surface: str
) -> list[tuple[int, frozenset[str]]]:
    selected = [s for s in SURFACES if s != "all"] if surface == "all" else [surface]
    return [
        (label, frozenset().union(*(groups[s] for s in selected)))
        for label, groups in rows
    ]


def fingerprint(rows: list[tuple[int, dict[str, set[str]]]]) -> dict[str, int]:
    """What the null level depends on: how many of each class there are.

    The null is a property of the corpus's SHAPE rather than of its content, so
    a recorded null stays valid while the shape holds and stops being a
    description of this corpus the moment it does not.
    """
    return {
        "accept": sum(1 for label, _ in rows if label == 0),
        "reject": sum(1 for label, _ in rows if label == 1),
    }


def measure(tree: Path, with_null: bool) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for corpus in CORPORA:
        rows = load(tree, corpus)
        surfaces: dict[str, dict[str, float]] = {}
        for surface in SURFACES:
            prepared = prepare(rows, surface)
            cell: dict[str, Any] = {"separability": separability(prepared)}
            if with_null:
                cell["null"] = null_separability(prepared)
            # Kept so a judgment can re-derive the null at THESE class counts
            # when the recorded one was calibrated at others. Never serialized.
            cell["rows"] = prepared
            surfaces[surface] = cell
        out[corpus] = {"fingerprint": fingerprint(rows), "surfaces": surfaces}
    return out


def read_baseline(tree: Path) -> dict[str, Any]:
    path = tree / BASELINE_REL
    if not path.is_file():
        return {}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def fingerprint_drift(was: Any, now: dict[str, int]) -> str:
    """Empty when the recorded null still describes this corpus, else why not."""
    if not isinstance(was, dict):
        return "not a recorded shape at all"
    for cls in ("accept", "reject"):
        before = int(was.get(cls, 0))
        after = int(now.get(cls, 0))
        if before == 0:
            if after:
                return f"{cls} went from none to {after}"
            continue
        if abs(after - before) / before > FINGERPRINT_DRIFT:
            return (
                f"{cls} moved from {before} to {after}, more than the "
                f"{FINGERPRINT_DRIFT:.0%} the null tolerates"
            )
    return ""


def judge(measured: dict[str, dict[str, Any]], baseline: dict[str, Any]) -> list[str]:
    recorded_corpora = baseline.get("corpora", {})
    problems: list[str] = []
    for corpus, found in measured.items():
        recorded = recorded_corpora.get(corpus)
        if recorded is None:
            problems.append(
                f"{corpus} has no recorded baseline at all, so nothing holds any "
                "of its surfaces and no increase in any of them can be detected."
            )
            continue
        drifted = fingerprint_drift(recorded.get("fingerprint"), found["fingerprint"])
        if drifted:
            problems.append(
                f"{corpus}: the recorded null was calibrated over "
                f"{recorded.get('fingerprint')} and the corpus now holds "
                f"{found['fingerprint']}, which is {drifted}. The class counts set the "
                "null's level, so the recorded thresholds describe a different corpus. "
                "Re-calibrate with --sync."
            )
            continue
        problems.extend(_judge_surfaces(corpus, found, recorded))
    return problems


def null_in_force(found: dict[str, Any], recorded: dict[str, Any], surface: str) -> float:
    """The null a surface is judged against: the one for the CURRENT class counts.

    A null is a function of the class counts, so a value recorded at one set of
    counts is a stale derived figure once the counts move, even inside the drift
    the ratchet tolerates. Comparing against it judged the corpus with a
    threshold for a different corpus: adding one ordinary reject shifted a
    surface that carries no information by 0.0001 past a null calibrated before
    that reject existed, and the gate called noise a leak. The recorded null is
    used only while the counts it was calibrated at still hold; otherwise it is
    re-derived here, by the same estimator, over the same rows, so the threshold
    keeps its meaning and only stops going stale.
    """
    if dict(recorded.get("fingerprint") or {}) == dict(found["fingerprint"]):
        row = recorded.get("surfaces", {}).get(surface, {})
        return float(row.get("null", 0.0))
    cell = found["surfaces"][surface]
    if "null" not in cell:
        cell["null"] = null_separability(cell["rows"])
    return float(cell["null"])


def _judge_surfaces(
    corpus: str, found: dict[str, Any], recorded: dict[str, Any]
) -> list[str]:
    problems: list[str] = []
    rows = recorded.get("surfaces", {})
    for surface in SURFACES:
        value = float(found["surfaces"][surface]["separability"])
        row = rows.get(surface)
        if row is None:
            problems.append(
                f"{corpus}/{surface} measures {value:.4f} and the baseline records "
                "nothing for it. A surface with no recorded figure is a surface "
                "nothing is holding."
            )
            continue
        was = float(row.get("separability", 0.0))
        null = null_in_force(found, recorded, surface)
        blocked = str(row.get("blockedBy", "")).strip()
        if value > was + TOLERANCE:
            problems.append(
                f"{corpus}/{surface} measures {value:.4f}, up from {was:.4f}. "
                "Something in this change made the label more predictable from the "
                "surface than it was."
            )
        if was > value + TOLERANCE:
            problems.append(
                f"{corpus}/{surface} measures {value:.4f} against a recorded "
                f"{was:.4f}. The baseline is holding slack the corpus no longer "
                "needs; re-record it with --sync so the ratchet keeps its grip."
            )
        if value > null and not blocked:
            problems.append(
                f"{corpus}/{surface} measures {value:.4f}, outside its own null of "
                f"{null:.4f} -- a figure shuffling the labels does not produce, so "
                "it is a real regularity and not sampling noise. Fix the leak, or "
                "record what stops it being fixed."
            )
        if value <= null and blocked:
            problems.append(
                f"{corpus}/{surface} measures {value:.4f}, inside its own null of "
                f"{null:.4f}, while still declaring {blocked!r} as its blocker. The "
                "declaration has outlived its subject; remove it."
            )
    return problems


def render(measured: dict[str, dict[str, Any]], baseline: dict[str, Any]) -> str:
    recorded = baseline.get("corpora", {})
    lines = []
    for corpus, found in measured.items():
        rows = recorded.get(corpus, {}).get("surfaces", {})
        lines.append(f"  {corpus}  {found['fingerprint']}")
        for surface in SURFACES:
            value = float(found["surfaces"][surface]["separability"])
            row = rows.get(surface, {})
            null = (
                null_in_force(found, recorded[corpus], surface)
                if row and corpus in recorded
                else 0.0
            )
            flag = "  OUTSIDE NULL" if null and value > null else ""
            note = f"  blocked by {row['blockedBy']}" if row.get("blockedBy") else ""
            lines.append(
                f"    {surface:12s} {value:.4f}  null {null:.4f}{flag}{note}"
            )
    return "\n".join(lines)


def sync(tree: Path, measured: dict[str, dict[str, Any]]) -> list[str]:
    """Re-record the baseline. It may lower a figure and it may not raise one.

    A sync that adopted whatever it measured would be the gate's own bypass: the
    refusal names the surface, the fix is one command away, and the command
    writes down the leak instead of removing it. So a rise beyond tolerance is
    refused here as well, and the only way to record one is to edit the file by
    hand and write the reason next to it.
    """
    existing = read_baseline(tree)
    kept = existing.get("corpora", {})
    refused: list[str] = []
    corpora: dict[str, Any] = {}
    for corpus, found in measured.items():
        previous_rows = kept.get(corpus, {}).get("surfaces", {})
        surfaces: dict[str, Any] = {}
        for surface in SURFACES:
            cell = found["surfaces"][surface]
            value = float(cell["separability"])
            null = float(cell["null"])
            previous = previous_rows.get(surface, {})
            was = previous.get("separability")
            if was is not None and value > float(was) + TOLERANCE:
                refused.append(
                    f"{corpus}/{surface} measures {value:.4f} against a recorded "
                    f"{float(was):.4f}. --sync will not raise a figure: that would "
                    "be writing the leak down instead of removing it. Fix it, or "
                    "record the rise by hand with the reason beside it."
                )
                continue
            row: dict[str, Any] = {"separability": value, "null": null}
            if value > null and previous.get("blockedBy"):
                row["blockedBy"] = previous["blockedBy"]
                row["reason"] = previous.get("reason", "")
            surfaces[surface] = row
        corpora[corpus] = {"fingerprint": found["fingerprint"], "surfaces": surfaces}
    if refused:
        return refused
    payload = {
        "$comment": existing.get("$comment", ""),
        "nullDraws": NULL_DRAWS,
        "nullQuantile": NULL_QUANTILE,
        "tolerance": TOLERANCE,
        "corpora": corpora,
    }
    (tree / BASELINE_REL).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report", action="store_true", help="print every figure")
    parser.add_argument("--sync", action="store_true", help="rewrite the baseline")
    args = parser.parse_args()

    measured = measure(args.root, with_null=args.sync)
    if args.sync:
        refused = sync(args.root, measured)
        if refused:
            print(
                f"FAIL: --sync will not record {len(refused)} rise(s):", file=sys.stderr
            )
            for problem in refused:
                print(f"  - {problem}", file=sys.stderr)
            return 1
        print("baseline rewritten:")
        print(render(measured, read_baseline(args.root)))
        return 0

    baseline = read_baseline(args.root)
    if args.report:
        print(render(measured, baseline))
        return 0
    if not baseline:
        print(
            f"FAIL: {BASELINE_REL} is absent, so nothing records what any surface "
            "used to measure and no increase can be detected.",
            file=sys.stderr,
        )
        return 1

    problems = judge(measured, baseline)
    if problems:
        print(f"FAIL: the corpus is scoreable from its surface ({len(problems)}):",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(render(measured, baseline), file=sys.stderr)
        return 1

    rows = baseline.get("corpora", {})
    outside = [
        f"{c}/{s}"
        for c, found in measured.items()
        for s in SURFACES
        if c in rows
        and s in rows[c].get("surfaces", {})
        and float(found["surfaces"][s]["separability"]) > null_in_force(found, rows[c], s)
    ]
    print(
        f"OK: {len(CORPORA) * len(SURFACES)} surface measurements, none above its "
        "recorded figure"
        + (
            f"; {len(outside)} declared outside its null: {', '.join(outside)}."
            if outside
            else "; every surface inside the null its own labels shuffled produce."
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
