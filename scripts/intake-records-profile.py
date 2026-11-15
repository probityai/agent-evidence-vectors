#!/usr/bin/env python3
"""Time every phase of scripts/gen-intake-records.py per corpus, and keep its output.

    uv run --locked --extra generators python scripts/intake-records-profile.py OUTDIR

Runs the generator's build() once with a wall clock around each phase (the
three checker runs, the farm, the consumption baseline, each artifact's repin
and checker run, the refused-by evaluations), writes OUTDIR/phases.json and
OUTDIR/phases.txt, writes every file build() returns under OUTDIR/out/, and
says whether that output is byte for byte the committed release/intake/.
"""

from __future__ import annotations

import collections
import importlib.util
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gir", REPO / "scripts/gen-intake-records.py")
assert spec is not None and spec.loader is not None
gir = importlib.util.module_from_spec(spec)
sys.modules["gir"] = gir
spec.loader.exec_module(gir)

TIMES: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
COUNTS: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
CURRENT = ["-"]


def timed(name: str, fn):  # type: ignore[no-untyped-def]
    def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            TIMES[CURRENT[0]][name] += time.perf_counter() - start
            COUNTS[CURRENT[0]][name] += 1
    return wrapper


def main() -> int:
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    original_corpora = gir.corpora

    def corpora_tracking():  # type: ignore[no-untyped-def]
        for item in original_corpora():
            CURRENT[0] = item[0]
            yield item
    gir.corpora = corpora_tracking
    gir.go_runs = timed("go_runs(3 runs)", gir.go_runs)
    gir.scitt_runs = timed("scitt_runs(3 runs)", gir.scitt_runs)
    gir.Farm.__init__ = timed("farm", gir.Farm.__init__)
    gir.Farm.close = timed("farm close", gir.Farm.close)
    gir.Farm.restore = timed("restore", gir.Farm.restore)
    gir.checker_run = timed("checker_run (baseline+swaps)", gir.checker_run)
    gir.repin = timed("repin", gir.repin)
    gir.tracked = timed("tracked (git ls-files)", gir.tracked)
    gir.corpus_digest_of = timed("corpus_digest_of", gir.corpus_digest_of)
    gir.refused_by = timed("refused_by (total)", gir.refused_by)
    gir.w3cintake.rejections = timed("w3cintake.rejections", gir.w3cintake.rejections)
    gir.record = timed("record", gir.record)
    gir.list_is_signed = timed("list_is_signed", gir.list_is_signed)
    gir.population = timed("population", gir.population)
    start = time.perf_counter()
    fresh = gir.build()
    total = time.perf_counter() - start
    for rel, body in fresh.items():
        path = outdir / "out" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    current = gir.on_disk()
    differ = sorted(r for r in set(fresh) | set(current) if fresh.get(r) != current.get(r))
    per_corpus = {c: {"seconds": dict(TIMES[c]), "calls": dict(COUNTS[c]),
                      "total": sum(v for k, v in TIMES[c].items()
                                   if k not in ("tracked (git ls-files)", "corpus_digest_of",
                                                "w3cintake.rejections", "checker_run (baseline+swaps)",
                                                "restore"))}
                  for c in TIMES}
    report = {"total_seconds": total, "differs_from_tree": differ, "corpora": per_corpus}
    (outdir / "phases.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    phase_totals: collections.Counter[str] = collections.Counter()
    for c in TIMES:
        phase_totals.update(TIMES[c])
    lines = [f"total build() wall: {total:.1f} s; files differing from the tree: {len(differ)}", "",
             "phase totals (nested phases overlap their parents):"]
    lines += [f"  {v:9.1f} s  {k}" for k, v in phase_totals.most_common()]
    lines += ["", "corpora by wall time (seconds, artifacts swapped):"]
    for c, row in sorted(per_corpus.items(), key=lambda kv: -kv[1]["total"]):
        lines.append(f"  {row['total']:9.1f}  {row['calls'].get('repin', 0):4d}  {c}")
    (outdir / "phases.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
