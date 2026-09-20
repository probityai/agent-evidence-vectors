#!/usr/bin/env python3
"""One-time migration: line-number citations -> anchor-and-digest citations.

Reads the previous single-document revision of the specification from git at its
pinned commit, maps every ``spec:<lines>`` citation in the Go and Python source
onto the companion file that now holds that text, inserts an anchor there, writes
``spec/CITATION-ANCHORS.json``, and rewrites the citation in the source.

THE SNAP RULE, which is the only judgment in here and is stated rather than
buried. A line range often starts mid-sentence, because a comment author picked
the lines that carried the clause they meant. A digest over half a paragraph is
not a thing a gate can recompute after a reflow, so each range is SNAPPED OUTWARD
to the smallest whole set of markdown blocks that contains it. Snapping outward
can only widen what a citation covers, never narrow it, so no cited requirement
loses its guard; and a widened unit still fails on a reword of the cited sentence,
which is the property the whole change exists to buy.

TWO ANCHORS ARE PLACED BY HAND and this script only records them: the type URI
and the whole-Statement schema block live on the registry page, which was
rewritten rather than copied, so no line map reaches them, and an anchor cannot go
inside a fenced code block anyway. They are declared in HAND_PLACED below and
their digests are computed from the vendored page exactly like every other anchor.

Usage:
    python3 scripts/gen_spec_anchors.py --check     # report, write nothing
    python3 scripts/gen_spec_anchors.py --apply     # insert, rewrite, record
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_anchors as sa  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
LONGFORM = "spec/predicates/adversarial-execution-evidence"
VENDORED_PAGE = "spec/predicates/adversarial-execution-evidence.md"

# The upstream revision the companions were split from, and the split itself.
UPSTREAM_REPO = Path.home() / "Documents/git-clones/attestation"
UPSTREAM_REV = "25ac858"
UPSTREAM_PATH = "spec/predicates/adversarial-execution-evidence.md"

# (destination stem, first old line, last old line) -- the same table the split used.
PLAN = [
    ("registry", 1, 12), ("rationale", 13, 93), ("wire-profile", 94, 293),
    ("rationale", 294, 308), ("registry", 309, 385), ("verification", 386, 430),
    ("fields", 431, 1864), ("registry", 1865, 1871), ("verification", 1872, 2002),
    ("changelog", 2003, 2377), ("registry", 2378, 2383),
]

# Citations that land on the registry page rather than in a companion. Each maps
# the old line set to an anchor placed by hand in the page (and so in the
# vendored copy of it).
HAND_PLACED = {
    "3": "req-type-uri",
    "313": "req-statement-schema",
    "313,317": "req-statement-schema",
}

STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "is", "are", "for", "that",
        "this", "it", "its", "on", "as", "by", "with", "be", "not", "no", "so",
        "which", "at", "from", "every", "any", "one", "must", "may", "shall"}


def old_document() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(UPSTREAM_REPO), "show", f"{UPSTREAM_REV}:{UPSTREAM_PATH}"],
        capture_output=True, text=True, check=True,
    ).stdout
    lines = out.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) != 2383:
        raise SystemExit(f"upstream {UPSTREAM_REV} has {len(lines)} lines, expected 2383")
    return lines


def dest_stem(n: int) -> str:
    for stem, a, b in PLAN:
        if a <= n <= b:
            return stem
    raise SystemExit(f"old line {n} is in no destination")


def parse_ranges(spec: str) -> list[tuple[int, int]]:
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            out.append((int(a), int(b)))
        else:
            out.append((int(part), int(part)))
    return out


def collect_citations() -> dict[str, list[tuple[Path, int]]]:
    sites: dict[str, list[tuple[Path, int]]] = collections.defaultdict(list)
    for f in sa.source_files(REPO_ROOT):
        for i, line in enumerate(f.read_text(encoding="utf-8").split("\n"), 1):
            for m in sa.LEGACY_CITATION_RE.finditer(line):
                sites[m.group(0)[len("spec:"):]].append((f, i))
    return sites


def locate_verbatim(companion: list[str], old: list[str], a: int, b: int) -> int:
    """0-based index in `companion` where old line `a` sits, via the verbatim block."""
    probe = old[a - 1 : min(b, a + 2)]
    probe = [p for p in probe if p.strip()] or old[a - 1 : a]
    first = probe[0]
    hits = [i for i, l in enumerate(companion) if l == first]
    if not hits:
        raise SystemExit(f"old line {a} not found verbatim in companion: {first[:60]!r}")
    if len(hits) > 1:
        # disambiguate on the following line
        nxt = old[a] if a < len(old) else None
        refined = [i for i in hits if nxt is None or (i + 1 < len(companion) and companion[i + 1] == nxt)]
        hits = refined or hits
    return hits[0]


def block_index_of(lines: list[str], idx: int) -> int:
    """Which block (0-based) contains line index `idx`."""
    b = -1
    in_block = False
    for i, l in enumerate(lines):
        if l.strip():
            if not in_block:
                b += 1
                in_block = True
            if i == idx:
                return b
        else:
            in_block = False
    raise SystemExit(f"line index {idx} is blank or out of range")


def block_bounds(lines: list[str]) -> list[tuple[int, int]]:
    out = []
    start = None
    for i, l in enumerate(lines):
        if l.strip():
            if start is None:
                start = i
        elif start is not None:
            out.append((start, i - 1))
            start = None
    if start is not None:
        out.append((start, len(lines) - 1))
    return out


def slug_for(text: str, stem: str) -> str:
    words = re.findall(r"[A-Za-z][A-Za-z0-9]*", sa.normalize(text))
    keep = [w.lower() for w in words if w.lower() not in STOP][:5]
    base = "-".join(keep) or "req"
    return f"req-{stem.replace('-', '')}-{base}"[:72].rstrip("-")


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    old = old_document()
    sites = collect_citations()
    companions = {
        stem: (REPO_ROOT / LONGFORM / f"{stem}.md").read_text(encoding="utf-8").split("\n")
        for stem in {s for s, _, _ in PLAN if s != "registry"}
    }

    # unit key -> (stem, first block, block count); citation -> [unit keys]
    units: dict[tuple[str, int, int], None] = {}
    per_citation: dict[str, list[tuple[str, int, int] | str]] = {}
    unresolved: list[str] = []

    for spec in sorted(sites, key=lambda s: parse_ranges(s)[0][0]):
        if spec in HAND_PLACED:
            per_citation[spec] = [HAND_PLACED[spec]]
            continue
        keys: list[tuple[str, int, int] | str] = []
        for a, b in parse_ranges(spec):
            stem = dest_stem(a)
            if stem == "registry":
                unresolved.append(spec)
                keys = []
                break
            comp = companions[stem]
            # A range may begin or end on a BLANK line, because a comment author
            # picked whole lines rather than whole sentences. A blank line belongs
            # to no block and a blank probe matches the first blank line in the
            # file, so both ends are walked inward to real text first.
            aa = a
            while aa <= b and not old[aa - 1].strip():
                aa += 1
            bb_ = b
            while bb_ >= aa and not old[bb_ - 1].strip():
                bb_ -= 1
            if aa > bb_:
                raise SystemExit(f"citation spec:{spec} range {a}-{b} is entirely blank")
            ia = locate_verbatim(comp, old, aa, bb_)
            ib = locate_verbatim(comp, old, bb_, bb_)
            ba, bb = block_index_of(comp, ia), block_index_of(comp, ib)
            if bb < ba:
                ba, bb = bb, ba
            keys.append((stem, ba, bb - ba + 1))
        for k in keys:
            if isinstance(k, tuple):
                units[k] = None
        if keys:
            per_citation[spec] = keys

    if unresolved:
        print("FAIL: citations land on the registry page with no hand-placed anchor:", file=sys.stderr)
        for s in sorted(set(unresolved)):
            print(f"  spec:{s}", file=sys.stderr)
        return 1

    print(f"{len(sites)} distinct citations over {sum(len(v) for v in sites.values())} sites")
    print(f"{len(units)} distinct anchored units in companions, "
          f"{len(set(HAND_PLACED.values()))} hand-placed on the page")

    # name each unit, then insert bottom-up so earlier offsets stay valid
    named: dict[tuple[str, int, int], str] = {}
    used: set[str] = set(HAND_PLACED.values())
    for key in sorted(units, key=lambda k: (k[0], k[1])):
        stem, ba, n = key
        comp = companions[stem]
        bounds = block_bounds(comp)
        s, e = bounds[ba]
        end = bounds[min(ba + n - 1, len(bounds) - 1)][1]
        text = "\n".join(comp[s : end + 1])
        cand = slug_for(text, stem)
        aid, k = cand, 2
        while aid in used:
            aid = f"{cand}-{k}"
            k += 1
        used.add(aid)
        named[key] = aid

    if args.check:
        for key in sorted(named, key=lambda k: (k[0], k[1])):
            print(f"  {named[key]:<74} {key[0]}.md block {key[1]} +{key[2]}")
        return 0

    # ---- insert anchors, bottom-up per file ----
    records: dict[str, sa.AnchorRecord] = {}
    for stem in sorted(companions):
        comp = companions[stem]
        mine = [(k, named[k]) for k in named if k[0] == stem]
        for key, aid in sorted(mine, key=lambda kv: kv[0][1], reverse=True):
            bounds = block_bounds(comp)
            s, _ = bounds[key[1]]
            comp.insert(s, f'<a id="{aid}"></a>')
            comp.insert(s + 1, "")
        companions[stem] = comp
        (REPO_ROOT / LONGFORM / f"{stem}.md").write_text("\n".join(comp), encoding="utf-8")

    # ---- digest every anchor from the file as written ----
    for stem in sorted(companions):
        lines = (REPO_ROOT / LONGFORM / f"{stem}.md").read_text(encoding="utf-8").split("\n")
        for key, aid in ((k, named[k]) for k in named if k[0] == stem):
            i = sa.find_anchor(lines, aid)
            if i is None:
                raise SystemExit(f"anchor {aid} vanished from {stem}.md")
            text = sa.anchored_text(lines, i, key[2])
            if text is None:
                raise SystemExit(f"anchor {aid} covers fewer than {key[2]} blocks in {stem}.md")
            records[aid] = sa.AnchorRecord(
                aid, f"{LONGFORM}/{stem}.md", key[2], sa.digest(text), sa.excerpt_of(text)
            )

    # The two page anchors are digested from the UPSTREAM CHECKOUT, which is the
    # authority for the registry entry, and recorded against the VENDORED path,
    # which is where the gate will look. Those are deliberately different files
    # right now: `vendor-spec.py` refuses to pin bytes no reproducer can fetch, so
    # the resized page cannot be re-vendored until its branch is pushed. The gate
    # therefore fails closed on these two until the re-vendor lands, and says so by
    # name. That is the honest state -- a citation whose target is not in this
    # repository yet is unresolved, and unresolved is never a pass.
    page = subprocess.run(
        ["git", "-C", str(UPSTREAM_REPO), "show", f"HEAD:{UPSTREAM_PATH}"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    for aid in sorted(set(HAND_PLACED.values())):
        i = sa.find_anchor(page, aid)
        if i is None:
            print(f"FAIL: hand-placed anchor {aid} is absent from the upstream page at "
                  f"{UPSTREAM_REPO}@HEAD. Place it before running --apply.", file=sys.stderr)
            return 1
        text = sa.anchored_text(page, i, 1)
        if text is None:
            print(f"FAIL: hand-placed anchor {aid} covers no block upstream", file=sys.stderr)
            return 1
        records[aid] = sa.AnchorRecord(aid, VENDORED_PAGE, 1, sa.digest(text), sa.excerpt_of(text))

    sa.write_manifest(
        REPO_ROOT, records,
        f"generated from {UPSTREAM_REPO.name}@{UPSTREAM_REV} by scripts/gen_spec_anchors.py; "
        "every citation in the Go and Python source resolves through this file",
    )

    # ---- rewrite the citations ----
    rewritten = 0
    for f in sa.source_files(REPO_ROOT):
        txt = f.read_text(encoding="utf-8")
        out = txt

        def repl(m: re.Match) -> str:
            nonlocal rewritten
            spec = m.group(0)[len("spec:"):]
            keys = per_citation.get(spec)
            if not keys:
                return m.group(0)
            parts = []
            for k in keys:
                aid = k if isinstance(k, str) else named[k]
                parts.append(f"{aid}@{records[aid].sha256[: sa.INLINE_PREFIX_LEN]}")
            rewritten += 1
            return "spec:" + ",".join(parts)

        out = sa.LEGACY_CITATION_RE.sub(repl, out)
        if out != txt:
            f.write_text(out, encoding="utf-8")
    print(f"rewrote {rewritten} citation site(s); {len(records)} anchors recorded")

    # TWO residual checks, because the first one on its own was blind to the
    # failure it was meant to catch. A damaged citation loses its `spec:` prefix
    # along with its first half, so searching for `spec:` followed by a digit
    # reports clean over `, 1744-1746`.
    bad: list[str] = []
    for f in sa.source_files(REPO_ROOT):
        txt = f.read_text(encoding="utf-8")
        rel = str(f.relative_to(REPO_ROOT))
        for m in sa.LEGACY_CITATION_RE.finditer(txt):
            bad.append(f"{rel}: line-number citation {m.group(0)!r}")
        for m in sa.ORPHAN_TAIL_RE.finditer(txt):
            bad.append(f"{rel}: orphaned line numbers after a migrated citation {m.group(0)[-24:]!r}")
    if bad:
        print("FAIL: the migration left line numbers behind:", file=sys.stderr)
        for b in sorted(set(bad)):
            print("  " + b, file=sys.stderr)
        return 1
    print("no line-number citation and no orphaned tail remains")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
