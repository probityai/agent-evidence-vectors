#!/usr/bin/env python3
"""Forcing gate: the corpus may force more rules over time, never fewer.

What forcing is, and why a vector count is not it
-------------------------------------------------
The suite publishes a vector count. A count is an upper bound on forcing and
never a measurement of it, for a reason visible in the evaluator: a vector
declaring several expected codes is satisfied when ANY of them is observed, and
the per-stage column the runner prints is a display, not a verdict. Deleting the
`result-vocabulary` emission from the rail turns two vectors' gate-0 column FAIL
and the suite still reports every vector passing, exit 0. A rail with no
result-vocabulary check at all clears this corpus. The real bar is
sole-across-the-whole-code-set, and nothing measured where it sat.

Forcing is a property of the PAIR (corpus, rail) and it is measured, not argued:
switch off exactly one rule in the rail, replay the whole corpus, and see whether
the corpus notices. A rule the corpus never notices losing is a rule no third
party is obliged to implement, whatever the vector count says.

What this gate holds
--------------------
A tighten-only ratchet against `docs/FORCING-BASELINE.json`. Every site the
baseline records as KILLED must still be killed. Forcing may improve; it may
never silently regress. An improvement is not a pass either -- it updates the
baseline through `--sync`, because a baseline that lags is a baseline whose
per-push subset is smaller than the thing it claims to protect.

`--sync` is the only way the record moves, and it will not move it in the wrong
direction: it refuses to write a baseline in which a rule has STOPPED being
forced unless that site is named to `--accept-unforced`, one at a time, and it
refuses outright while any annotation in the file is disproved by the
measurement. A ratchet that repairs itself is a log.

The four outcomes are kept apart, and the separation is the point:

  KILLED        some vector goes PASS -> FAIL. The corpus forces this rule.
  SILENT        no vector changes status, but some vector's OBSERVATION changes.
                The corpus sees the rail behave differently and stays green:
                the stage passed on a sibling code. This is the weak case.
  DEAD          byte-identical observations on every vector. Nothing depends on
                this rule at all.
  INCONCLUSIVE  the mutant did not generate, did not build, crashed, or did not
                terminate. Nothing is asserted about it. It is a third state and
                is never folded into either of the other two, because "we could
                not measure it" and "the corpus does not force it" are different
                claims and only one of them is a gap.

Two annotations are carried alongside, in `annotations`, for the sites where
"unforced" would be the wrong word:

  unkillable    a true equivalent mutant. The weakened rail computes what the
                original computes, so NO vector can ever kill it and none should
                be written.
  masked        the rule is real and reachable, but an earlier check fires first
                on every input that could reach it, so no vector can kill it AS
                THE CORPUS AND RAIL STAND. Unmintable, which is a different thing
                from unminted: a gap list that conflates the two sends the next
                person to write vectors that cannot work. Two such vectors were
                built, mutation-checked, and did not kill; they are the evidence
                behind these entries, not a hypothesis about them.

Both annotations are falsifiable and this gate falsifies them: if an annotated
site is ever KILLED, the gate fails and says the annotation was wrong. An
annotation is a claim about the world, not a suppression.

The ground-truth gate comes first, always
-----------------------------------------
Scoring hundreds of corpus replays through `cmd/aee-verify` would cost a quarter
of a million process spawns, so the campaign replays in process through
`cmd/mutrun`. That saving is worth nothing if the fast path answers a different
question, so before a single mutant is scored this gate asserts on the UNMUTATED
tree that:

  1. every vector's observation from `cmd/mutrun` -- verdict, codes, result, both
     tier columns, and the no-key result -- equals what `run_vectors.observe_external`
     returns driving the real `cmd/aee-verify -json`; and
  2. the per-vector status and per-gate column this file computes equal the ones
     `packaging/run_vectors.py` writes running the real CLI over the real corpus.

A disagreement stops the run. It has already earned its place: the first
attempt at this measurement drove the CLI through a shim that passed the pinned
key on both passes, so the no-key tier column was answered with the wrong
answer, and `ok-024` -- the corpus's only statement of GATE 2's no-TOFU rule --
disagreed. The numbers would have been wrong in a direction nothing else could
have shown.

One campaign, one corpus
------------------------
The worker trees symlink the corpus rather than copying it, so every mutant
re-reads the vector files, while the manifest, the per-vector self-check and the
unmutated observations each mutant is diffed against are read once before the
first mutant is built. A corpus written while the campaign is in flight is
therefore read one way by the baseline and another by whichever mutants were
running, and the difference is scored as those mutants killing the vector that
moved. That is not hypothetical: a baseline was published recording one rule as
forced by two vectors that cannot reach its branch, and it read exactly like
every correct row beside it. So the manifest and every vector are digested
before the unmutated replay and again after the last mutant, and a disagreement
refuses the run rather than reporting a number.

Scope, and what a subset costs
------------------------------
`--scope forced` runs exactly the sites the baseline records as KILLED. That is
not an arbitrary sample: those are the only sites where a REGRESSION is possible,
because a regression is by definition a site that used to be killed and is not.
The sites left out can only improve, and an improvement is invisible to a check
that would pass either way. What is dropped is printed, by class and count, on
every run; a subset that does not say what it dropped reads as full coverage.

`--scope all` runs every enumerated site. It is the only scope that can see an
improvement, falsify an annotation, or discover that a rule became reachable, so
it is the only scope `--sync` accepts.

Structural checks run in both scopes and cost nothing, because enumerating sites
is a parse: a site in the baseline that no longer exists, and a site that exists
with no baseline row, both fail. That means any edit to the rail fails the
per-push gate until a full sweep has been run and recorded, which is the
intended reading -- a changed rule is a changed forcing question.

Usage:
    scripts/forcing-gate.py                       # ratchet, forced scope
    scripts/forcing-gate.py --scope all           # full sweep
    scripts/forcing-gate.py --scope all --sync    # rewrite the baseline
    scripts/forcing-gate.py --scope all --report  # the gap tables
Needs a Go toolchain. A missing toolchain is a FAILURE, never a skip.
Exit 0 when the ratchet holds; 1 on any regression, drift, or falsified
annotation; 2 on a broken run.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lockfile import single_instance  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "vectors"
DEFAULT_BASELINE = REPO_ROOT / "docs" / "FORCING-BASELINE.json"
RAIL_PKG = REPO_ROOT / "aee"

# The baseline this run reads or writes. It is a module-level binding rather than a
# parameter threaded through every function because --baseline exists for the
# gate's own tests, which drive a rigged copy; production runs never move it.
BASELINE = DEFAULT_BASELINE

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors as rv  # noqa: E402

# Ordered worst-to-best for reporting only; the ratchet compares classes by name.
CLASSES = ("KILLED", "SILENT", "DEAD", "INCONCLUSIVE")
ANNOTATIONS = ("unkillable", "masked")

# A mutant that does not terminate must not hold the campaign open for minutes,
# and a fixed number would either strangle a slow runner or waste a fast one. The
# bound is therefore derived from the measured unmutated replay: a mutant is
# given TIMEOUT_MULTIPLE times as long as the healthy rail took, floored so a
# very fast machine still leaves room for a slow mutant that does terminate.
TIMEOUT_MULTIPLE = 120.0
TIMEOUT_FLOOR_SECONDS = 30.0

Observation = dict[str, Any]
Row = dict[str, Any]


# ---------------------------------------------------------------------------
# process helpers
# ---------------------------------------------------------------------------


def die(message: str, code: int = 2) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(code)


def go_build(target: str, out: str, work: Path, cover: bool = False) -> None:
    """Build one command, or fail. Never returns without a binary."""
    cmd = ["go", "build"] + (["-cover"] if cover else []) + ["-o", out, target]
    try:
        proc = subprocess.run(cmd, cwd=work, capture_output=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(
            f"{target} could not be built ({exc}). This gate needs a Go toolchain; "
            "it does not skip, because an unmeasured forcing baseline is the state "
            "it exists to end."
        )
    if proc.returncode != 0:
        die(f"{target} does not build:\n{proc.stderr.decode('utf-8', 'replace')}")


def jsonl(text: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# the corpus this campaign is a measurement OF
# ---------------------------------------------------------------------------


def corpus_fingerprint(root: Path) -> str:
    """A digest over every byte a replay reads: the manifest and every vector.

    The campaign snapshots the manifest, the per-vector self-check and the
    unmutated observations ONCE, and then re-reads the vector files from disk on
    every one of several hundred mutant replays -- the worker trees symlink the
    corpus rather than copying it. So a vector written while the campaign is in
    flight is read one way by the baseline and another way by whichever mutants
    were running, and the difference is scored as those mutants killing it.
    """
    hashed = hashlib.sha256()
    paths = [root / "MANIFEST.json"]
    # One directory. A fingerprint that walked a directory per verdict would
    # silently cover nothing once the corpus stopped having them, and a
    # fingerprint over nothing agrees with every corpus.
    paths += sorted((root / "statements").glob("*.json"))
    if len(paths) == 1:
        raise SystemExit(
            f"{root}/statements holds no vectors, so this fingerprint would "
            "cover the manifest alone and agree with any corpus at all."
        )
    for path in paths:
        hashed.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        hashed.update(hashlib.sha256(path.read_bytes()).digest())
    return hashed.hexdigest()


def refuse_moved_corpus(before: str, after: str) -> None:
    """A sweep taken across two corpora is a measurement of neither.

    This is not a conservative precaution: a baseline was published in which one
    rule was recorded as forced by two vectors that cannot reach it, because the
    corpus was regenerated while the campaign ran. The wrong row read exactly
    like every right one -- a class, a snippet, two plausible vector names -- and
    the only reason it was ever questioned is that the same file carried a
    second, equivalent mutation of the same branch with the opposite class. So
    the disagreement is refused where it happens rather than left to be noticed.
    """
    if before == after:
        return
    die(
        "the corpus changed while the campaign was running. The unmutated replay "
        "and the mutants were not taken against the same vectors, so a vector "
        "whose bytes moved mid-sweep goes PASS -> FAIL for whichever mutants were "
        "in flight and is recorded as killing them. Nothing measured here is a "
        "fact about any single corpus. Re-run with nothing else writing to "
        f"{VECTORS}."
    )


# ---------------------------------------------------------------------------
# harness-faithful scoring
# ---------------------------------------------------------------------------


def self_check_cache(index: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Per-vector second-fault findings, for every vector the harness checks.

    Computed from the STATEMENT BYTES rather than from the rail, so it is
    invariant under every mutation and is computed once for the whole campaign.
    The indeterminate bucket is included because the harness includes it, and the
    ground-truth gate compares this scoring with the harness column by column: a
    kind omitted here reads as a fast-path discrepancy on every run.
    """
    out: dict[str, list[str]] = {}
    for vid, entry in index.items():
        if entry.get("kind") not in ("reject", "indeterminate"):
            continue
        raw = (VECTORS / entry["file"]).read_bytes()
        stmt, faithful = rv._load_statement(raw)
        if not faithful:
            continue
        expected = entry.get("expected") or {}
        codes = set(expected.get("codes") or []) | set(expected.get("alsoCarries") or [])
        codes |= {str(v) for v in (expected.get("readings") or {}).values()}
        out[vid] = rv.second_fault_absence(stmt, codes)
    return out


def as_observed(line: dict[str, Any]) -> Observation:
    """Reshape one mutrun line into the dict shape `observe_external` returns.

    The `or None` on each optional field is not cosmetic: the CLI's JSON omits an
    empty result and an empty tier column, so the harness reads None for them, and
    a fast path that reported `[]` would differ from the real rail on a field the
    evaluator branches on.

    `absent` is the same statement made explicitly, and it is derived here by the
    harness's own rule rather than restated: a member the rail did not emit, or
    emitted as null, was never established, and the evaluator fails a comparison
    that has an expectation for it. `errors` is empty because this path runs the
    rail in process and has no invocation to fail, and `ran` is True for the same
    reason: the rail answered this vector. The ground-truth gate compares all three
    fields against the real CLI, so a divergence stops the run rather than being
    scored.
    """
    observed: Observation = {
        "verdict": line["verdict"],
        "verdict_without_key": line.get("verdictWithoutKey") or line["verdict"],
        "codes": line.get("codes") or [],
        "primaryCode": line.get("primaryCode") or None,
        "result": line.get("result") or None,
        "tiers_with_key": line.get("tiers") or None,
        "tiers_without_key": line.get("tiersWithoutKey") or None,
        "result_without_key": line.get("resultWithoutKey") or None,
        "errors": [],
        "ran": True,
    }
    observed["absent"] = sorted(
        name
        for name in ("codes", "primaryCode", "result", "tiers_with_key",
                     "tiers_without_key", "result_without_key")
        if not observed[name]
    )
    return observed


def score(
    lines: list[dict[str, Any]],
    index: dict[str, dict[str, Any]],
    selfchk: dict[str, list[str]],
) -> dict[str, Row]:
    """Score one corpus replay with the harness's OWN evaluator.

    The PASS/FAIL below is `run_vectors.evaluate_vector`'s judgement, not a
    reimplementation of it, so this gate cannot drift from the suite it measures.
    """
    rows: dict[str, Row] = {}
    for line in lines:
        vid = line["id"]
        entry = index.get(vid)
        # The kind comes from the manifest entry, and its absence is refused
        # rather than guessed. This line used to fall back to reading the
        # identifier's prefix, which stopped being information the moment
        # identifiers became digests of their own bytes -- every vector would
        # have been classified "reject", silently, and the gate would have gone
        # on reporting a figure.
        kind = (entry or {}).get("kind")
        if not kind:
            raise SystemExit(
                f"the manifest carries no kind for {vid}, and this gate will not "
                "infer one. The identifier is a digest and says nothing about the "
                "verdict, which is the point of it."
            )
        observed = as_observed(line)
        findings = selfchk.get(vid) if kind in ("reject", "indeterminate") else None
        ok, gates, reasons = rv.evaluate_vector(kind, entry, observed, findings)
        rows[vid] = {
            "status": "PASS" if ok else "FAIL",
            "gates": gates,
            "observed": observed,
            "reasons": reasons,
        }
    # The cross-member half of the indeterminate contract. Left out, a mutation
    # that makes the rail answer two members of one family under two different
    # readings would replay green and be recorded as a rule the corpus does not
    # force -- which is precisely the claim the family exists to refuse.
    _, coherence = rv.family_coherence_failures(
        index, [{"id": vid, "kind": (index.get(vid) or {}).get("kind"), "observed": row["observed"]}
                for vid, row in rows.items()]
    )
    if coherence:
        for vid, row in rows.items():
            if (index.get(vid) or {}).get("kind") == "indeterminate":
                row["status"] = "FAIL"
                row["reasons"] = [*row["reasons"], *coherence]
    return rows


def observation_key(observed: Observation) -> tuple[Any, ...]:
    """Everything the harness can see about one vector, as a comparable value."""
    return (
        observed["verdict"],
        tuple(sorted(observed["codes"])),
        # The condition the rail COMMITS to, which the indeterminate families
        # read and nothing else does. Outside the key the ground-truth gate
        # compares, the fast path and the real CLI could disagree about it while
        # every scored verdict matched, and the families would then be measured
        # against a number this gate never proved.
        observed.get("primaryCode"),
        observed["result"],
        tuple(observed["tiers_with_key"] or ()),
        tuple(observed["tiers_without_key"] or ()),
        observed["result_without_key"],
    )


# ---------------------------------------------------------------------------
# workspace
# ---------------------------------------------------------------------------


class Workspace:
    """Built tooling, the derived key policy, and the enumerated sites."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.mutgen = str(work / "mutgen")
        self.mutrun = str(work / "mutrun")
        self.mutrun_cover = str(work / "mutrun.cover")
        self.verify = str(work / "aee-verify")
        self.gocache = str(work / "gocache")
        self.keys = rv.write_pinned_key_policy(rv.derive_test_keys(), str(work))
        self.sites: list[dict[str, Any]] = []
        self.baseline_lines: list[dict[str, Any]] = []
        self.replay_seconds = 0.0

    def build(self) -> None:
        go_build("./cmd/mutgen", self.mutgen, REPO_ROOT)
        go_build("./cmd/mutrun", self.mutrun, REPO_ROOT)
        go_build("./cmd/aee-verify", self.verify, REPO_ROOT)

    def enumerate_sites(self) -> None:
        proc = subprocess.run(
            [self.mutgen, "-pkg", str(RAIL_PKG), "-list"], capture_output=True, timeout=300
        )
        if proc.returncode != 0:
            die(f"mutgen could not enumerate {RAIL_PKG}:\n{proc.stderr.decode('utf-8', 'replace')}")
        self.sites = jsonl(proc.stdout.decode("utf-8"))
        if not self.sites:
            die(f"mutgen found no mutation sites in {RAIL_PKG}; the rail cannot be measured")

    def replay(self) -> None:
        started = time.monotonic()
        proc = subprocess.run(
            [self.mutrun, str(VECTORS), self.keys], capture_output=True, timeout=900
        )
        self.replay_seconds = time.monotonic() - started
        if proc.returncode != 0:
            die(f"the unmutated rail failed to replay the corpus:\n{proc.stderr.decode()}")
        self.baseline_lines = jsonl(proc.stdout.decode("utf-8"))

    @property
    def timeout(self) -> float:
        return max(TIMEOUT_FLOOR_SECONDS, TIMEOUT_MULTIPLE * self.replay_seconds)


# ---------------------------------------------------------------------------
# ground-truth gate
# ---------------------------------------------------------------------------


def truth_observations(
    verify: str, keys: str, index: dict[str, dict[str, Any]]
) -> dict[str, Observation]:
    """Drive the real CLI over every vector, through the harness's own observer."""
    out: dict[str, Observation] = {}
    for vid, entry in index.items():
        path = str(VECTORS / entry["file"])
        out[vid] = rv.observe_external([verify, "-json"], path, keys)
    return out


def compare_observations(
    fast: dict[str, Observation], truth: dict[str, Observation]
) -> list[str]:
    errors: list[str] = []
    for vid in sorted(set(fast) | set(truth)):
        mine, theirs = fast.get(vid), truth.get(vid)
        if mine is None or theirs is None:
            errors.append(f"{vid}: present in only one of the two replays")
            continue
        for field in sorted(theirs):
            if mine.get(field) != theirs[field]:
                errors.append(
                    f"{vid}.{field}: in-process {mine.get(field)!r} != "
                    f"real CLI {theirs[field]!r}"
                )
    return errors


def compare_report(rows: dict[str, Row], report: dict[str, Any]) -> list[str]:
    """The second half: this file's status and gate columns against the harness's."""
    errors: list[str] = []
    for entry in report.get("vectors", []):
        vid = entry["id"]
        mine = rows.get(vid)
        if mine is None:
            errors.append(f"{vid}: scored by the harness, missing from the in-process replay")
            continue
        if mine["status"] != entry["status"]:
            errors.append(
                f"{vid}.status: in-process {mine['status']} != harness {entry['status']}"
            )
        if mine["gates"] != entry["gates"]:
            errors.append(f"{vid}.gates: in-process {mine['gates']} != harness {entry['gates']}")
        observed = entry.get("observed") or {}
        if sorted(mine["observed"]["codes"]) != sorted(observed.get("codes") or []):
            errors.append(
                f"{vid}.codes: in-process {sorted(mine['observed']['codes'])} != "
                f"harness {sorted(observed.get('codes') or [])}"
            )
    extra = set(rows) - {e["id"] for e in report.get("vectors", [])}
    if extra:
        errors.append(f"replayed but never scored by the harness: {sorted(extra)}")
    return errors


def ground_truth_gate(
    ws: Workspace, index: dict[str, dict[str, Any]], rows: dict[str, Row]
) -> None:
    """Block until the fast path is proven to answer what the real one answers."""
    fast = {line["id"]: as_observed(line) for line in ws.baseline_lines}
    errors = compare_observations(fast, truth_observations(ws.verify, ws.keys, index))

    report_path = ws.work / "ground-truth.json"
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "packaging" / "run_vectors.py"),
            "--verifier",
            f"{ws.verify} -json",
            "--report",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=3600,
    )
    if not report_path.is_file():
        die("the harness wrote no report driving cmd/aee-verify, so nothing below is grounded")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("rail") != "external":
        die(
            "the harness fell back to its reference rail "
            f"({report.get('railNote')!r}), so the ground-truth "
            "comparison tested the harness against itself"
        )
    errors += compare_report(rows, report)

    if errors:
        print(
            f"FAIL: the in-process replay and the real harness disagree on "
            f"{len(errors)} point(s); no mutant was scored.",
            file=sys.stderr,
        )
        for err in errors[:40]:
            print(f"  - {err}", file=sys.stderr)
        raise SystemExit(2)
    print(
        f"ground truth: {len(fast)} vectors, 0 discrepancies against "
        f"cmd/aee-verify -json through packaging/run_vectors.py.",
        flush=True,
    )


# ---------------------------------------------------------------------------
# campaign
# ---------------------------------------------------------------------------


def worker_tree(dst: Path) -> None:
    """A throwaway copy of the repository with the corpus symlinked in.

    The corpus is symlinked rather than copied because it is never mutated and it
    is the largest thing here; the rail is copied because it is the thing that is.
    """
    if dst.is_dir():
        shutil.rmtree(dst)
    shutil.copytree(
        REPO_ROOT,
        dst,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", "vectors"
        ),
        symlinks=True,
    )
    (dst / "vectors").symlink_to(VECTORS)


def run_mutant(tree: Path, site: dict[str, Any], ws: Workspace) -> dict[str, Any]:
    """Apply one mutation, rebuild, replay the corpus, restore the source."""
    rel = site["file"]
    mutated, pristine = tree / "aee" / rel, RAIL_PKG / rel
    shutil.copyfile(pristine, mutated)
    record: dict[str, Any] = {"key": site["key"]}
    try:
        gen = subprocess.run(
            [ws.mutgen, "-pkg", str(tree / "aee"), "-apply", site["key"], "-write"],
            capture_output=True,
            timeout=300,
        )
        if gen.returncode != 0:
            return record | {"outcome": "GENFAIL", "detail": gen.stderr.decode()[:400].strip()}
        # One core per worker. `go build` parallelises across every core by
        # default, so N workers would otherwise put N x cores compile jobs on the
        # scheduler and --workers would not mean what it says. The campaign is
        # worker-bound rather than build-bound, so pinning the build costs little.
        env = dict(os.environ, GOCACHE=ws.gocache, GOFLAGS="", GOMAXPROCS="1")
        binary = str(tree / "mutrun.bin")
        build = subprocess.run(
            ["go", "build", "-p", "1", "-o", binary, "./cmd/mutrun"],
            cwd=tree,
            capture_output=True,
            env=env,
            timeout=900,
        )
        if build.returncode != 0:
            return record | {"outcome": "BUILDFAIL", "detail": build.stderr.decode()[:400].strip()}
        try:
            run = subprocess.run(
                [binary, str(VECTORS), ws.keys], capture_output=True, timeout=ws.timeout
            )
        except subprocess.TimeoutExpired:
            return record | {"outcome": "TIMEOUT", "detail": f"exceeded {ws.timeout:.0f}s"}
        if run.returncode != 0:
            return record | {"outcome": "RUNFAIL", "detail": run.stderr.decode()[-400:].strip()}
        return record | {"outcome": "OK", "lines": jsonl(run.stdout.decode("utf-8"))}
    finally:
        shutil.copyfile(pristine, mutated)


def classify(
    record: dict[str, Any],
    base_rows: dict[str, Row],
    index: dict[str, dict[str, Any]],
    selfchk: dict[str, list[str]],
) -> dict[str, Any]:
    """One mutant's outcome, with INCONCLUSIVE kept as its own state."""
    if record["outcome"] != "OK":
        return {
            "key": record["key"],
            "class": "INCONCLUSIVE",
            "reason": record["outcome"],
            "detail": record.get("detail", ""),
        }
    rows = score(record["lines"], index, selfchk)
    killers, changed = [], []
    for vid, row in rows.items():
        base = base_rows[vid]
        if base["status"] == "PASS" and row["status"] == "FAIL":
            killers.append(vid)
        if observation_key(row["observed"]) != observation_key(base["observed"]):
            changed.append(vid)
    if killers:
        return {"key": record["key"], "class": "KILLED", "killers": sorted(killers)}
    if changed:
        return {"key": record["key"], "class": "SILENT", "changed": sorted(changed)}
    return {"key": record["key"], "class": "DEAD"}


def campaign(
    ws: Workspace,
    sites: list[dict[str, Any]],
    base_rows: dict[str, Row],
    index: dict[str, dict[str, Any]],
    selfchk: dict[str, list[str]],
    workers: int,
) -> dict[str, dict[str, Any]]:
    """Build and replay every requested mutant, in parallel worker trees."""
    root = Path(tempfile.mkdtemp(prefix="forcing-workers-", dir=str(ws.work)))
    trees = [root / f"w{i}" for i in range(workers)]
    for tree in trees:
        worker_tree(tree)
    os.makedirs(ws.gocache, exist_ok=True)
    # Prime the shared build cache once, so a per-mutant build recompiles only
    # the rail and relinks, instead of the whole dependency graph.
    subprocess.run(
        ["go", "build", "-o", str(trees[0] / "mutrun.bin"), "./cmd/mutrun"],
        cwd=trees[0],
        capture_output=True,
        env=dict(os.environ, GOCACHE=ws.gocache),
        timeout=900,
        check=False,
    )

    chunks = [sites[i::workers] for i in range(workers)]

    def work(index_of_worker: int) -> list[dict[str, Any]]:
        return [
            classify(run_mutant(trees[index_of_worker], site, ws), base_rows, index, selfchk)
            for site in chunks[index_of_worker]
        ]

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for future in [pool.submit(work, i) for i in range(workers)]:
            results.extend(future.result())
    shutil.rmtree(root, ignore_errors=True)
    return {r["key"]: r for r in results}


# ---------------------------------------------------------------------------
# coverage evidence: mintable gap or unreachable branch
# ---------------------------------------------------------------------------


def coverage_blocks(ws: Workspace) -> dict[str, list[tuple[int, int, int]]]:
    """Per-file executed-block table from `go build -cover` over the corpus.

    It separates the two reasons a mutant can die unnoticed: the branch was never
    TAKEN by any vector, which is a real and mintable corpus gap, or it was taken
    and its outcome did not matter, which no new vector can fix.
    """
    covdir = ws.work / "covdir"
    covdir.mkdir(exist_ok=True)
    go_build("./cmd/mutrun", ws.mutrun_cover, REPO_ROOT, cover=True)
    subprocess.run(
        [ws.mutrun_cover, str(VECTORS), ws.keys],
        capture_output=True,
        env=dict(os.environ, GOCOVERDIR=str(covdir)),
        timeout=900,
        check=False,
    )
    profile = ws.work / "aee.cov"
    subprocess.run(
        ["go", "tool", "covdata", "textfmt", f"-i={covdir}", f"-o={profile}"],
        capture_output=True,
        timeout=300,
        check=False,
    )
    blocks: dict[str, list[tuple[int, int, int]]] = {}
    if not profile.is_file():
        return blocks
    for line in profile.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("mode:"):
            continue
        location, _statements, count = line.rsplit(" ", 2)
        filepath, span = location.rsplit(":", 1)
        start, end = span.split(",")
        blocks.setdefault(filepath.split("/")[-1], []).append(
            (int(start.split(".")[0]), int(end.split(".")[0]), int(count))
        )
    return blocks


def branch_taken(blocks: dict[str, list[tuple[int, int, int]]], site: dict[str, Any]) -> str:
    """Was the site's guarded BRANCH ever entered by any vector?

    For a guard operator the site line is the condition, which executes whether or
    not the branch is taken, so the body's first line is the honest probe. For a
    body-level operator the site line already is the body.

    `LOOP_FIRST` is a guard for this purpose even though it is not a condition:
    the site line is the `for`, which executes whether or not the collection has
    a single member, so a loop no vector ever enters would read as taken. The
    body's first line is the honest probe there too, and it has to be, because
    the whole question this operator asks is what happens on the SECOND member.
    """
    line = site["line"]
    if site["op"].startswith(("IF_", "CASE_OFF", "CASE_DISJ", "CASE_CONJ", "LOOP_FIRST")):
        line += 1
    hits = [c for (a, b, c) in blocks.get(site["file"], []) if a <= line <= b]
    if not hits:
        return "unknown"
    return "taken" if max(hits) > 0 else "never-taken"


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------


BASELINE_COMMENT = (
    "What the conformance corpus FORCES, measured by mutation rather than counted. "
    "Each row is one single-site weakening of the Go rail in aee/, replayed over the "
    "whole corpus: KILLED means some vector goes PASS->FAIL and the corpus forces the "
    "rule; SILENT means the corpus sees the rail change and stays green; DEAD means "
    "nothing in the corpus depends on the rule; INCONCLUSIVE means the mutant did not "
    "build, crash-free, terminate, and nothing is asserted about it. `annotations` "
    "records the sites where 'unforced' would be the wrong word -- `unkillable` for a "
    "true equivalent mutant no vector can ever kill, `masked` for a real rule an "
    "earlier check reaches first, which is unmintable rather than unminted. Both are "
    "claims this gate falsifies: an annotated site that is ever KILLED fails it. "
    "scripts/forcing-gate.py holds every KILLED row as a tighten-only ratchet and "
    "rewrites this file with --scope all --sync."
)


def site_row(site: dict[str, Any], result: dict[str, Any], taken: str | None) -> Row:
    """One baseline row. Nothing volatile: no line number, no timestamp, no count.

    A line number moves under every unrelated edit above it, and a committed file
    that is wrong the moment something else changes teaches a reader to ignore it.
    The site key already carries file, function, operator and a digest of the
    mutated source, which is exactly the information that identifies the rule.
    """
    row: Row = {"class": result["class"], "snippet": site["snippet"]}
    if result["class"] == "KILLED":
        row["killers"] = result["killers"]
    if result["class"] == "INCONCLUSIVE":
        row["reason"] = result["reason"]
    if result["class"] in ("DEAD", "SILENT") and taken is not None:
        row["branch"] = taken
    return row


def build_baseline(
    sites: list[dict[str, Any]],
    results: dict[str, dict[str, Any]],
    blocks: dict[str, list[tuple[int, int, int]]],
    previous: dict[str, Any],
) -> dict[str, Any]:
    rows: dict[str, Row] = {}
    for site in sites:
        result = results[site["key"]]
        taken = branch_taken(blocks, site) if blocks else None
        rows[site["key"]] = site_row(site, result, taken)
    counts = {cls: sum(1 for r in rows.values() if r["class"] == cls) for cls in CLASSES}
    return {
        "$comment": BASELINE_COMMENT,
        "suite": "adversarial-execution-evidence-conformance",
        "counts": counts,
        "annotations": previous.get("annotations", {}),
        "sites": dict(sorted(rows.items())),
    }


def set_baseline(path: Path) -> None:
    global BASELINE
    BASELINE = path


def baseline_label() -> str:
    """The baseline path as written, relative to the repo when it is inside it."""
    try:
        return str(BASELINE.relative_to(REPO_ROOT))
    except ValueError:
        return str(BASELINE)


def load_baseline(allow_absent: bool) -> dict[str, Any]:
    """Read the committed baseline. Absent is fatal unless it is being created.

    `allow_absent` is true only under --sync, which is the one mode whose job is
    to write the file. Every checking mode treats a missing baseline as a
    failure rather than as an empty ratchet that passes everything.
    """
    if not BASELINE.is_file():
        if allow_absent:
            return {"annotations": {}, "sites": {}}
        die(
            f"no forcing baseline at {baseline_label()}; create it "
            "with --scope all --sync. A missing baseline is not an empty one: a "
            "ratchet with no recorded rows would pass every regression it exists to catch."
        )
    data: dict[str, Any] = json.loads(BASELINE.read_text(encoding="utf-8"))
    for key, note in (data.get("annotations") or {}).items():
        if note.get("status") not in ANNOTATIONS:
            die(
                f"annotation for {key} has status {note.get('status')!r}; "
                f"expected one of {ANNOTATIONS}"
            )
    return data


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------


def structural_errors(baseline: dict[str, Any], sites: list[dict[str, Any]]) -> list[str]:
    """A baseline that does not describe the rail in front of it is not a ratchet."""
    recorded = set(baseline.get("sites", {}))
    present = {site["key"] for site in sites}
    errors: list[str] = []
    for key in sorted(recorded - present):
        row = baseline["sites"][key]
        errors.append(
            f"RETIRED {key} ({row['class']}): the baseline records this rule and the "
            f"rail no longer has it in that form -- {row['snippet'][:90]}"
        )
    for key in sorted(present - recorded):
        errors.append(f"UNRECORDED {key}: a mutation site with no baseline row")
    for key in sorted(set(baseline.get("annotations", {})) - present):
        errors.append(f"STALE ANNOTATION {key}: annotated, but no such site exists")
    return errors


class Verdict:
    """What one measurement says about the committed baseline.

    Three lists, not one, because they are closed differently. A REGRESSION is
    the failure this gate exists for and is never repaired by rewriting the
    record. A FALSIFIED annotation means a claim in the file is wrong and has to
    be edited or deleted by the person who made it. DRIFT is the baseline being
    behind, which --sync fixes and which is often the point of a change.
    """

    def __init__(self) -> None:
        self.regressions: list[str] = []
        self.falsified: list[str] = []
        self.drift: list[str] = []
        self.regressed_keys: set[str] = set()

    def any(self) -> bool:
        return bool(self.regressions or self.falsified or self.drift)


def ratchet_errors(baseline: dict[str, Any], results: dict[str, dict[str, Any]]) -> Verdict:
    """Compare one measurement with the baseline. Only KILLED -> anything else
    is a regression; everything else can only be the record lagging."""
    verdict = Verdict()
    annotations = baseline.get("annotations", {})
    for key, result in sorted(results.items()):
        recorded = baseline["sites"].get(key)
        if recorded is None:
            continue  # already reported structurally
        if recorded["class"] == "KILLED" and result["class"] != "KILLED":
            verdict.regressions.append(
                f"{key}: the corpus used to force this and no longer does "
                f"(now {result['class']}) -- {recorded['snippet'][:90]}"
            )
            verdict.regressed_keys.add(key)
            continue
        if key in annotations and result["class"] == "KILLED":
            note = annotations[key]
            verdict.falsified.append(
                f"{key}: annotated {note['status']!r} and it was KILLED by "
                f"{result['killers']}. The annotation is wrong; correct or remove it."
            )
            continue
        if recorded["class"] != result["class"]:
            verdict.drift.append(f"{key}: recorded {recorded['class']}, measured {result['class']}")
        elif result["class"] == "KILLED" and recorded.get("killers") != result["killers"]:
            verdict.drift.append(
                f"{key}: the vectors that force it changed, "
                f"{recorded.get('killers')} -> {result['killers']}"
            )
    return verdict


def dropped_summary(baseline: dict[str, Any], ran: set[str]) -> str:
    """Say what the subset left out, by class. A silent cap reads as full coverage."""
    left = [row for key, row in baseline["sites"].items() if key not in ran]
    if not left:
        return "scope: every enumerated site was run."
    counts = {cls: sum(1 for r in left if r["class"] == cls) for cls in CLASSES}
    listed = ", ".join(f"{cls} {counts[cls]}" for cls in CLASSES if counts[cls])
    return (
        f"scope: {len(ran)} site(s) run, {len(left)} NOT run ({listed}). "
        "A site the baseline does not record as KILLED cannot regress, only improve, "
        "and an improvement is invisible to a check that would pass either way. "
        "Run --scope all to see one."
    )


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def print_report(baseline: dict[str, Any], sites: list[dict[str, Any]]) -> None:
    """The gap tables, with the four states and the two annotations kept apart."""
    rows = baseline["sites"]
    annotations = baseline.get("annotations", {})
    by_site = {site["key"]: site for site in sites}
    print(f"\nforcing baseline: {baseline['counts']}")
    for cls in ("SILENT", "INCONCLUSIVE"):
        keys = [k for k, r in rows.items() if r["class"] == cls]
        print(f"\n{cls} ({len(keys)})")
        for key in sorted(keys):
            note = f"  [{annotations[key]['status']}]" if key in annotations else ""
            extra = rows[key].get("reason", "")
            print(f"  {key}{note} {extra}\n      {rows[key]['snippet'][:96]}")
    dead = [k for k, r in rows.items() if r["class"] == "DEAD"]
    mintable = [k for k in dead if rows[k].get("branch") == "never-taken" and k not in annotations]
    print(f"\nDEAD ({len(dead)}); of those {len(mintable)} sit on a branch no vector takes:")
    for key in sorted(mintable):
        site = by_site.get(key, {})
        print(f"  {key}  {site.get('file')}:{site.get('line')}\n      {rows[key]['snippet'][:96]}")
    annotated = sorted(annotations)
    print(f"\nannotated as not-forcible ({len(annotated)}); these are not gaps:")
    for key in annotated:
        note = annotations[key]
        print(f"  [{note['status']}] {key}\n      {note['reason']}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def select_sites(
    scope: str, sites: list[dict[str, Any]], baseline: dict[str, Any], only: str
) -> list[dict[str, Any]]:
    """Which sites this run rebuilds and replays.

    `forced` is the sites the baseline records as KILLED. That is the whole set
    where a regression is possible -- a regression is by definition a site that
    used to be killed and is not -- and it is also, by construction, the set of
    sites already known to generate, build, run and terminate, so a subset run
    cannot be held open by a non-terminating mutant.
    """
    chosen = sites if scope == "all" else [
        site for site in sites if baseline["sites"].get(site["key"], {}).get("class") == "KILLED"
    ]
    if not only:
        return chosen
    wanted = {key for key in only.split(",") if key}
    known = {site["key"] for site in sites}
    unknown = wanted - known
    if unknown:
        die(f"--only names {len(unknown)} site(s) the rail does not have: {sorted(unknown)}")
    return [site for site in chosen if site["key"] in wanted]


def require_nonempty(chosen: list[dict[str, Any]], scope: str, only: str) -> None:
    """A run that rebuilds nothing must not report that nothing regressed.

    An empty selection is the shape of every gate this repository has caught
    passing while enforcing nothing, so it is refused rather than reported green.
    """
    if chosen:
        return
    die(
        f"the {scope} scope selected no site to measure"
        + (f" under --only {only}" if only else "")
        + ". A run that rebuilds nothing cannot observe a regression, and reporting "
        "it green would be a gate that passes by measuring nothing."
    )


def measure(ws: Workspace, args: argparse.Namespace, baseline: dict[str, Any]) -> tuple[
    dict[str, dict[str, Any]], dict[str, list[tuple[int, int, int]]]
]:
    index = rv.manifest_index(rv.load_manifest(str(VECTORS)))
    selfchk = self_check_cache(index)
    base_rows = score(ws.baseline_lines, index, selfchk)
    ground_truth_gate(ws, index, base_rows)

    chosen = select_sites(args.scope, ws.sites, baseline, args.only)
    require_nonempty(chosen, args.scope, args.only)
    print(
        f"campaign: {len(chosen)} of {len(ws.sites)} sites, {args.workers} worker(s), "
        f"per-mutant replay timeout {ws.timeout:.0f}s "
        f"({TIMEOUT_MULTIPLE:.0f}x the measured {ws.replay_seconds:.2f}s unmutated replay).",
        flush=True,
    )
    started = time.monotonic()
    results = campaign(ws, chosen, base_rows, index, selfchk, args.workers)
    print(f"campaign: {len(results)} mutants in {time.monotonic() - started:.0f}s.", flush=True)
    blocks = coverage_blocks(ws) if args.scope == "all" else {}
    return results, blocks


def refuse_unrecordable(verdict: Verdict, accepted: str) -> None:
    """What --sync may not write down.

    A ratchet that repairs itself is not a ratchet. A rule the corpus has stopped
    forcing is the failure this gate exists for, so --sync refuses to record it
    unless the site is named on the command line, one at a time -- the same shape
    the citation gate's --accept-reaim uses, and for the same reason: naming it
    records nothing that can later rot, and it cannot be done by accident or in
    bulk. A falsified annotation cannot be accepted at all: the file makes a claim
    that measurement has disproved, and only the person who made it can say what
    it should now say.
    """
    if verdict.falsified:
        print(
            f"FAIL: --sync will not rewrite the baseline while {len(verdict.falsified)} "
            "annotation(s) in it are disproved by this measurement. Correct or delete "
            "the annotation first; a claim that a rule cannot be forced is not a "
            "number a script may adjust.",
            file=sys.stderr,
        )
        for message in verdict.falsified:
            print(f"  - {message}", file=sys.stderr)
        raise SystemExit(1)
    named = {key for key in accepted.split(",") if key}
    unaccepted = sorted(verdict.regressed_keys - named)
    if unaccepted:
        print(
            f"FAIL: --sync will not record {len(unaccepted)} forcing regression(s). "
            "Forcing may improve and the baseline follows it; a rule the corpus has "
            "STOPPED forcing is the failure this gate exists for, and writing it into "
            "the record is how a ratchet becomes a log. Restore what forced it, or "
            "name the site to --accept-unforced if losing it is the intended change.",
            file=sys.stderr,
        )
        for message in verdict.regressions:
            print(f"  - {message}", file=sys.stderr)
        raise SystemExit(1)


def report_failure(verdict: Verdict, structural: list[str]) -> int:
    if verdict.regressions:
        print(
            f"FAIL: the corpus stopped forcing {len(verdict.regressions)} rule(s) it "
            "used to force.",
            file=sys.stderr,
        )
        for message in verdict.regressions:
            print(f"  - {message}", file=sys.stderr)
    if verdict.falsified:
        print(
            f"FAIL: {len(verdict.falsified)} annotation(s) in the baseline claim a rule "
            "cannot be forced, and it was.",
            file=sys.stderr,
        )
        for message in verdict.falsified:
            print(f"  - {message}", file=sys.stderr)
    if structural:
        print(
            f"FAIL: the baseline does not describe the rail in front of it "
            f"({len(structural)} difference(s)). Run --scope all --sync.",
            file=sys.stderr,
        )
        for message in structural[:40]:
            print(f"  - {message}", file=sys.stderr)
    if verdict.drift:
        print(
            f"FAIL: forcing changed in {len(verdict.drift)} place(s) without the baseline "
            "being updated. Run --scope all --sync and commit the result.",
            file=sys.stderr,
        )
        for message in verdict.drift[:40]:
            print(f"  - {message}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("forced", "all"), default="forced")
    parser.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 2)))
    parser.add_argument(
        "--sync", action="store_true", help="rewrite the baseline (needs --scope all)"
    )
    parser.add_argument("--report", action="store_true", help="print the gap tables and exit")
    parser.add_argument(
        "--only",
        default="",
        help="restrict the campaign to these comma-separated site keys (developer loop; "
        "refused with --sync, which may not rewrite rows it did not measure)",
    )
    parser.add_argument(
        "--accept-unforced",
        default="",
        help="with --sync, the comma-separated site keys whose loss of forcing is the "
        "intended change; every other regression refuses the write",
    )
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help="path to the baseline to read or write (the committed one by default)",
    )
    args = parser.parse_args()
    set_baseline(Path(args.baseline).resolve())

    # One campaign at a time. Concurrent campaigns oversubscribe the machine
    # rather than sharing it, and cannot use each other's results.
    with single_instance("aee-forcing-gate"):
        return run(args)


def run(args: argparse.Namespace) -> int:

    baseline = load_baseline(allow_absent=args.sync)
    if args.report and not args.sync:
        with tempfile.TemporaryDirectory(prefix="aee-forcing-") as raw:
            ws = Workspace(Path(raw))
            ws.build()
            ws.enumerate_sites()
            print_report(baseline, ws.sites)
        return 0
    if args.sync and (args.scope != "all" or args.only):
        die(
            "--sync needs --scope all and no --only: a subset cannot rewrite rows "
            "it did not measure",
            2,
        )

    with tempfile.TemporaryDirectory(prefix="aee-forcing-") as raw:
        ws = Workspace(Path(raw))
        ws.build()
        ws.enumerate_sites()
        # Taken before the unmutated replay that every mutant is diffed against,
        # and checked again after the last one, so the whole campaign is held to
        # one corpus rather than to whatever was on disk at each moment.
        corpus_before = corpus_fingerprint(VECTORS)
        ws.replay()
        results, blocks = measure(ws, args, baseline)
        refuse_moved_corpus(corpus_before, corpus_fingerprint(VECTORS))

        structural = structural_errors(baseline, ws.sites)
        if args.sync:
            if structural:
                print("\n".join(f"  sync: {message}" for message in structural))
                # A retired row that was KILLED is a rule the corpus forced and the
                # rail no longer states in that form. It is not a corpus regression --
                # the forcing question changed with the code -- but it is the one thing
                # a sync silently drops, so it is counted out loud rather than left in
                # a list of several hundred.
                retired_forced = sum(
                    1
                    for message in structural
                    if message.startswith("RETIRED") and "(KILLED)" in message
                )
                print(
                    f"  sync: {len(structural)} structural difference(s), of which "
                    f"{retired_forced} retire a rule this corpus was FORCING. Read the "
                    "diff before committing it."
                )
            refuse_unrecordable(ratchet_errors(baseline, results), args.accept_unforced)
            updated = build_baseline(ws.sites, results, blocks, baseline)
            BASELINE.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
            print(f"wrote {baseline_label()}: {updated['counts']}")
            return 0

        verdict = ratchet_errors(baseline, results)
        print(dropped_summary(baseline, set(results)))
        if verdict.any() or structural:
            return report_failure(verdict, structural)

    forced = sum(1 for r in baseline["sites"].values() if r["class"] == "KILLED")
    print(
        f"OK: every one of the {forced} rule(s) this corpus is recorded as forcing is "
        f"still forced ({len(results)} mutant(s) rebuilt and replayed this run)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
