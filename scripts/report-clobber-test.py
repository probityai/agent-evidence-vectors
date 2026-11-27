#!/usr/bin/env python3
"""A harness run never replaces a record the repository commits.

Why this file exists
--------------------
``packaging/conformance-report.json`` is a committed record, and the corpus also
commits observed W3C runs under ``corpora/vectors-w3c-report/observed/``. A run of
the harness is an observation: it writes where its caller looks, and it replaces a
tracked file only when its caller says so with ``--replace-record``. This test
holds that property from 17 sides. Each construction builds a private mini
checkout (a copy of ``packaging/``, the registry, git tracking the record) in a
temporary directory, runs the harness, and compares the record's sha256 before
and after. Nothing in the real tree is written and no log is written under it.

Verdicts: LANDS (the bad outcome happened) or HELD (it did not). The four
positive controls (G01 to G04) must PASS: a harness that cannot run them proves
nothing, so a failing control or a case that raises is inconclusive.

Usage: python3 scripts/report-clobber-test.py [--packaging DIR] [--only CASE ...]
       [--out FILE] [--no-mutation]
Exit 0 when every control passes and every attack is HELD (and each mutant of the
guard turns the test red); 1 when any attack LANDS; 3 when a control fails or a
case errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "vectors"
UNCERTAIN = REPO / "corpora" / "vectors-uncertain-effect"
W3C = REPO / "corpora" / "vectors-w3c-report"
OBSERVED_REL = Path("corpora/vectors-w3c-report/observed/aee-v0.12.0")
NAME = "conformance-report.json"
REPLACE_FLAG = "--replace-record"
W3C_SUITE = json.loads((W3C / "MANIFEST.json").read_text(encoding="utf-8"))["suite"]

Result = tuple[str, bool, str]  # verdict word, outcome flag, evidence


def sha(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


class Ctx:
    """One private mini checkout: the harness under test, the registry, git tracking the record."""

    def __init__(self, work: Path, packaging_src: Path) -> None:
        self.work = work
        self.repo = work / "repo"
        self.packaging = self.repo / "packaging"
        shutil.copytree(packaging_src, self.packaging, ignore=shutil.ignore_patterns("__pycache__"))
        self.harness = self.packaging / "run_vectors.py"
        self.committed = self.packaging / NAME
        self.elsewhere = work / "elsewhere"
        self.elsewhere.mkdir()
        (self.repo / "corpora").mkdir()
        shutil.copy(REPO / "corpora" / "REGISTRY.toml", self.repo / "corpora" / "REGISTRY.toml")
        (self.repo / ".gitignore").write_text("/conformance-report.json\n", encoding="utf-8")
        self.git("init", "-q")
        self.track(self.committed)

    def replace_flag(self) -> list[str]:
        """The flag that asks to replace a record, when this harness has one."""
        text = self.harness.read_text(encoding="utf-8")
        return [REPLACE_FLAG] if f'"{REPLACE_FLAG}"' in text else []

    def git(self, *argv: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=a", "-c", "user.email=a@a", *argv],
            check=True,
            capture_output=True,
        )

    def track(self, path: Path) -> None:
        self.git("add", "-f", str(path.relative_to(self.repo)))
        self.git("commit", "-q", "-m", "record")

    def run(
        self, argv: list[str], cwd: Path, harness: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, str(harness or self.harness), *argv]
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, check=False, timeout=900
        )


def tail(proc: subprocess.CompletedProcess[str]) -> str:
    return (proc.stderr.strip().splitlines() or [""])[-1][:300]


# In-process driver: loads the harness from its path, wraps run_suite, runs main().
INPROC = textwrap.dedent(
    r"""
    import importlib.util, os, subprocess, sys
    harness, mode, extra = sys.argv[1], sys.argv[2], sys.argv[3]
    args = sys.argv[4:]
    sys.path.insert(0, os.path.dirname(harness))
    spec = importlib.util.spec_from_file_location("rv_under_test", harness)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rv_under_test"] = mod
    spec.loader.exec_module(mod)
    original = mod.run_suite
    def wrapped(a):
        if mode == "toctou":
            # Another process creates a symlink at the default path after the
            # guard ran and before the report is written.
            os.symlink(extra, os.path.join(os.getcwd(), "conformance-report.json"))
            return original(a)
        if mode == "shared":
            # A second run shares the default path and finishes while this one
            # is replaying; this one then ends without writing a report.
            subprocess.run([sys.executable, harness, "--vectors", extra], check=False,
                           capture_output=True)
            return 1
        if mode == "dirswap":
            # The destination's parent directory is swapped for a symlink into
            # the checkout after the start-up check and before the publish.
            dest = os.path.dirname(os.path.abspath(args[args.index("--report") + 1]))
            os.rename(dest, dest + ".real")
            os.symlink(extra, dest)
            return original(a)
        return original(a)
    mod.run_suite = wrapped
    sys.argv = [harness, *args]
    sys.exit(mod.main())
    """
)


def inproc(
    ctx: Ctx, mode: str, extra: str, args: list[str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    driver = ctx.work / "inproc.py"
    driver.write_text(INPROC, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(driver), str(ctx.harness), mode, extra, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )


def verdict_of(ok: bool, detail: str) -> Result:
    return ("PASS" if ok else "FAIL", ok, detail)


def landed(
    target: Path, before: str | None, p: subprocess.CompletedProcess[str]
) -> Result:
    hit = sha(target) != before
    return ("LANDS" if hit else "HELD", hit, f"exit={p.returncode} record_changed={hit} "
            f"stderr={tail(p)!r}")


def g01_default_elsewhere(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    p = ctx.run(["--vectors", str(VECTORS)], ctx.elsewhere)
    wrote = (ctx.elsewhere / NAME).is_file()
    same = sha(ctx.committed) == before
    return verdict_of(
        p.returncode == 0 and wrote and same,
        f"exit={p.returncode} wrote_cwd={wrote} committed_same={same}",
    )


def g04_default_at_checkout_root(ctx: Ctx) -> Result:
    p = ctx.run(["--vectors", str(VECTORS)], ctx.repo)
    wrote = (ctx.repo / NAME).is_file()
    return verdict_of(
        p.returncode == 0 and wrote, f"exit={p.returncode} wrote_root={wrote} stderr={tail(p)!r}"
    )


def g02_default_in_packaging_refused(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    p = ctx.run(["--vectors", str(VECTORS)], ctx.packaging)
    same = sha(ctx.committed) == before
    return verdict_of(
        p.returncode == 2 and same,
        f"exit={p.returncode} committed_same={same} stderr={tail(p)!r}",
    )


def g03_explicit_committed_writes(ctx: Ctx) -> Result:
    ctx.committed.write_text('{"stale": 1}\n', encoding="utf-8")
    argv = ["--vectors", str(VECTORS), "--report", str(ctx.committed), *ctx.replace_flag()]
    p = ctx.run(argv, ctx.elsewhere)
    body = json.loads(ctx.committed.read_text(encoding="utf-8"))
    count = body.get("totals", {}).get("vectors", 0)
    return verdict_of(p.returncode == 0 and count > 0, f"exit={p.returncode} vectors={count}")


def g05_report_to_a_device(ctx: Ctx) -> Result:
    """A report sent to /dev/null is discarded, not refused: a device is a sink, never a record."""
    p = ctx.run(["--vectors", str(VECTORS), "--report", os.devnull], ctx.elsewhere)
    ok = p.returncode == 0 and not os.path.isfile(os.devnull)
    return verdict_of(ok, f"exit={p.returncode} stderr={tail(p)!r}")


def a01_empty_report(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    p = ctx.run(["--vectors", str(VECTORS), "--report", ""], ctx.packaging)
    return landed(ctx.committed, before, p)


def a02_empty_report_runtime(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    argv = ["runtime", "--runtime", "true", "--vectors", str(UNCERTAIN), "--report", ""]
    p = ctx.run(argv, ctx.packaging)
    return landed(ctx.committed, before, p)


def a03_hardlink_outside(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    os.link(ctx.committed, ctx.elsewhere / NAME)
    p = ctx.run(["--vectors", str(VECTORS)], ctx.elsewhere)
    return landed(ctx.committed, before, p)


def a04_symlink_in_cwd(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    os.symlink(ctx.committed, ctx.elsewhere / NAME)
    p = ctx.run(["--vectors", str(VECTORS)], ctx.elsewhere)
    return landed(ctx.committed, before, p)


def a05_symlinked_cwd(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    link = ctx.work / "pk-link"
    os.symlink(ctx.packaging, link)
    script = f'cd "{link}" && exec "{sys.executable}" "{link}/run_vectors.py" --vectors "{VECTORS}"'
    p = subprocess.run(
        ["sh", "-c", script], capture_output=True, text=True, check=False, timeout=900
    )
    return landed(ctx.committed, before, p)


def a06_harness_via_file_symlink(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    bindir = ctx.work / "bin"
    bindir.mkdir()
    link = bindir / "run_vectors.py"
    os.symlink(ctx.harness, link)
    p = ctx.run(["--vectors", str(VECTORS)], ctx.packaging, harness=link)
    return landed(ctx.committed, before, p)


def a07_toctou_symlink(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    p = inproc(ctx, "toctou", str(ctx.committed), ["--vectors", str(VECTORS)], ctx.elsewhere)
    return landed(ctx.committed, before, p)


def a08_explicit_bare_name(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    p = ctx.run(["--vectors", str(VECTORS), "--report", NAME], ctx.packaging)
    return landed(ctx.committed, before, p)


def a09_emit_w3c_onto_record(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    argv = [
        "--vectors", str(VECTORS), "--report", str(ctx.elsewhere / "r.json"),
        "--emit-w3c-report", NAME,
    ]
    p = ctx.run(argv, ctx.packaging)
    return landed(ctx.committed, before, p)


def a10_stray_corpora_dir(ctx: Ctx) -> Result:
    before = sha(ctx.committed)
    (ctx.packaging / "corpora").mkdir()
    p = ctx.run(["--vectors", str(VECTORS)], ctx.packaging)
    return landed(ctx.committed, before, p)


def a11_second_committed_record(ctx: Ctx) -> Result:
    observed = ctx.repo / OBSERVED_REL
    shutil.copytree(REPO / OBSERVED_REL, observed)
    target = observed / NAME
    ctx.track(target)
    before = sha(target)
    p = ctx.run(["--vectors", str(VECTORS)], observed)
    return landed(target, before, p)


def a12_shared_default_misattribution(ctx: Ctx) -> Result:
    # Run A (w3c-report corpus) ends without writing; run B (vectors) shared the path.
    p = inproc(ctx, "shared", str(VECTORS), ["--vectors", str(W3C)], ctx.elsewhere)
    path = ctx.elsewhere / NAME
    if not path.is_file():
        return ("HELD", False, f"exit={p.returncode} no report at the shared path")
    body = json.loads(path.read_text(encoding="utf-8"))
    header = body.get("verifierResult", {})
    # The body is run B's; a header naming run A's corpus is a report stamped by
    # a run that did not write it.
    hit = header.get("corpus") == W3C_SUITE
    return (
        "LANDS" if hit else "HELD",
        hit,
        f"exit={p.returncode} body.suite={body.get('suite')!r} "
        f"header.corpus={header.get('corpus')!r}",
    )


def a13_cwd_dependent_test(ctx: Ctx) -> Result:
    # A test that only reads stdout fails when pytest stands in packaging/.
    test = REPO / "corpora/vectors-delegation-lifecycle/tests/test_python_reader.py"
    p = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rA", str(test),
         "-k", "routes_the_corpus"],
        cwd=REPO / "packaging",
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
    )
    (ctx.work / "a13.log").write_text(p.stdout + "\n--- stderr ---\n" + p.stderr, encoding="utf-8")
    hit = p.returncode != 0
    last = (p.stdout.strip().splitlines() or [""])[-1][:120]
    return ("LANDS" if hit else "HELD", hit, f"exit={p.returncode} last={last!r}")


def a14_test_silent_pass_without_git(ctx: Ctx) -> Result:
    tree = ctx.work / "nogit"
    (tree / "scripts").mkdir(parents=True)
    shutil.copy(REPO / "scripts/report-default-test.py", tree / "scripts")
    shutil.copytree(ctx.packaging, tree / "packaging", ignore=shutil.ignore_patterns("__pycache__"))
    os.symlink(VECTORS, tree / "vectors")
    (tree / "packaging" / NAME).write_text('{"tampered": true}\n', encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CEILING_DIRECTORIES"] = str(ctx.work)
    p = subprocess.run(
        [sys.executable, str(tree / "scripts/report-default-test.py")],
        cwd=tree, capture_output=True, text=True, check=False, timeout=1800, env=env,
    )
    line = next((ln for ln in p.stdout.splitlines() if "real_record_is_untouched" in ln), "")
    hit = line.startswith("ok")
    return ("LANDS" if hit else "HELD", hit, f"exit={p.returncode} line={line!r}")


def a15_no_git_fallback(ctx: Ctx) -> Result:
    shutil.rmtree(ctx.repo / ".git")
    before = sha(ctx.committed)
    p = ctx.run(["--vectors", str(VECTORS), "--report", NAME], ctx.packaging)
    return landed(ctx.committed, before, p)


def a16_explicit_other_tracked_file(ctx: Ctx) -> Result:
    other = ctx.packaging / "agent_evidence_vectors" / "__init__.py"
    ctx.track(other)
    before = sha(other)
    p = ctx.run(["--vectors", str(VECTORS), "--report", str(other)], ctx.elsewhere)
    return landed(other, before, p)


def a17_parent_directory_swapped(ctx: Ctx) -> Result:
    # The destination's parent is swapped for a symlink into packaging/ after the
    # start-up check and before the publish: the record must still be unchanged.
    before = sha(ctx.committed)
    out = ctx.elsewhere / "out"
    out.mkdir()
    argv = ["--vectors", str(VECTORS), "--report", str(out / NAME)]
    p = inproc(ctx, "dirswap", str(ctx.packaging), argv, ctx.elsewhere)
    verdict, hit, evidence = landed(ctx.committed, before, p)
    bound = (ctx.elsewhere / "out.real" / NAME).is_file()
    if not hit and not bound and os.rename in os.supports_dir_fd:
        # Unchanged is not enough: the publish must have gone to the directory that
        # was bound and checked, or the case did not exercise the descriptor.
        return ("ERROR", False, f"the report reached no bound directory; {evidence}")
    return (verdict, hit, f"published_to_bound_directory={bound} {evidence}")


CASES: list[Callable[[Ctx], Result]] = [
    g01_default_elsewhere, g04_default_at_checkout_root, g02_default_in_packaging_refused,
    g03_explicit_committed_writes, g05_report_to_a_device, a01_empty_report,
    a02_empty_report_runtime, a03_hardlink_outside, a04_symlink_in_cwd, a05_symlinked_cwd,
    a06_harness_via_file_symlink, a07_toctou_symlink, a08_explicit_bare_name,
    a09_emit_w3c_onto_record, a10_stray_corpora_dir, a11_second_committed_record,
    a12_shared_default_misattribution, a13_cwd_dependent_test, a14_test_silent_pass_without_git,
    a15_no_git_fallback, a16_explicit_other_tracked_file, a17_parent_directory_swapped,
]

# Mutants of the guard: (name, [(old text, new text)], the cases that must turn red).
MUTANTS: list[tuple[str, list[tuple[str, str]], list[str]]] = [
    (
        "compare-by-abspath-instead-of-realpath",
        [
            ("os.path.realpath(__file__)", "os.path.abspath(__file__)"),
            (
                "os.path.join(os.path.realpath(os.path.dirname(absolute)), "
                "os.path.basename(absolute))",
                "os.path.join(os.path.dirname(absolute), os.path.basename(absolute))",
            ),
        ],
        ["a06_harness_via_file_symlink"],
    ),
    (
        "drop-the-explicit-report-record-rule",
        [(
            '    outputs = [(report, "--report")]\n',
            '    outputs = [(report, "--report")] if args.report is None else []\n',
        )],
        ["a08_explicit_bare_name", "a16_explicit_other_tracked_file"],
    ),
    (
        "drop-the-emit-w3c-record-rule",
        [('        outputs.append((w3c, "--emit-w3c-report"))\n', "        pass\n")],
        ["a09_emit_w3c_onto_record"],
    ),
    (
        "publish-by-path-instead-of-the-bound-directory",
        [
            ("HAVE_DIR_FD = os.open in", "HAVE_DIR_FD = False and os.open in"),
            (
                "return same and os.path.realpath(self.directory) == self.directory",
                "return True",
            ),
        ],
        ["a17_parent_directory_swapped"],
    ),
]


def run_cases(packaging: Path, only: list[str] | None, out: str | None) -> int:
    rows = []
    controls_ok = True
    for case in CASES:
        name = case.__name__
        if only and name not in only and not name.startswith("g"):
            continue
        with tempfile.TemporaryDirectory() as tmp:
            try:
                verdict, _flag, evidence = case(Ctx(Path(tmp), packaging))
            except Exception as exc:  # a construction that could not run is inconclusive
                verdict, evidence = "ERROR", f"{type(exc).__name__}: {exc}"
        if name.startswith("g") and verdict != "PASS":
            controls_ok = False
        rows.append({"case": name, "verdict": verdict, "evidence": evidence})
        print(f"{name}: {verdict} | {evidence}", flush=True)
    if out:
        Path(out).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    errors = sum(r["verdict"] == "ERROR" for r in rows)
    lands = sum(r["verdict"] == "LANDS" for r in rows)
    held = sum(r["verdict"] == "HELD" for r in rows)
    print(f"SUMMARY controls_ok={controls_ok} errors={errors} lands={lands} held={held}")
    if not controls_ok or errors:
        return 3
    return 1 if lands else 0


def run_mutants(packaging: Path) -> int:
    """Each mutant of the guard must make this test fail on the cases that watch it."""
    source = (packaging / "run_vectors.py").read_text(encoding="utf-8")
    bad = 0
    for name, swaps, cases in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            mutant = Path(tmp) / "packaging"
            shutil.copytree(packaging, mutant, ignore=shutil.ignore_patterns("__pycache__"))
            text = source
            missing = [old for old, _new in swaps if old not in source]
            if missing:
                print(f"FAIL mutant {name}: the guard text moved; update this test: {missing}")
                bad += 1
                continue
            for old, new in swaps:
                text = text.replace(old, new)
            (mutant / "run_vectors.py").write_text(text, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, __file__, "--packaging", str(mutant), "--no-mutation",
                 "--only", *cases],
                capture_output=True, text=True, check=False, timeout=3600,
            )
        if proc.returncode == 1:
            print(f"ok   mutant {name} turned the test red")
        else:
            print(f"FAIL mutant {name}: exit {proc.returncode}, expected 1\n{proc.stdout[-600:]}")
            bad += 1
    return 3 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packaging", default=str(REPO / "packaging"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", nargs="*", default=None, help="only these cases; controls always")
    ap.add_argument("--no-mutation", action="store_true")
    ns = ap.parse_args()
    packaging = Path(ns.packaging)
    status = run_cases(packaging, ns.only, ns.out)
    if status != 0 or ns.no_mutation:
        return status
    return run_mutants(packaging)


if __name__ == "__main__":
    sys.exit(main())
