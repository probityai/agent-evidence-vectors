#!/usr/bin/env python3
"""Vector-distinctness gate: two identifiers may never address one statement.

Why this exists, stated as what actually happened rather than as a principle.

`vea5ff2dabe340db7` and `vc05cf94374f0d0d6` were
BYTE-IDENTICAL, sha256 `80f1d055…` for both, while the manifest credited them to
different conditions -- `aee-c-65` and `aee-c-68`. So `aee-c-68`'s only reject
vector was a copy of another condition's, and the corpus credited a condition
with a discriminator it did not have. The cause was not a stray copy: `_seal_mut`
deliberately appends an unreferenced covering seal, and `bad-713`'s hand-written
builder reconstructed exactly that shape, so a design decision in one builder
retroactively made a different vector redundant. Nothing could see it.

The thing worth noticing is WHICH check failed to notice. `docs/FORCING-HONESTY.md`
is this corpus's own published weakness report and it counts, per condition, how
many vectors force it -- and it counted two for `aee-c-68`, because it counts
DECLARED CONDITIONS and never DISTINCT STATEMENTS. A report that exists to say
where the suite is weak could not see that two of its inputs were one artifact.
That is the gap this gate closes, and it closes it at the only place the question
is cheap: the bytes.

The manifest carries no per-vector digest, so before this gate nothing in the
repository pinned vector content at all. A vector could be silently replaced by a
copy of its neighbour and every count would still add up.

Two ways the first version of this gate was narrower than its own name
----------------------------------------------------------------------

FIRST, it read one manifest. The AI Agent Action corpus ships from this same
repository, replays through its own checker, and was outside the only check that
asks whether its identifiers address distinct statements. It has a byte-identical
pair in it -- the accept vector for the log-line-preimage condition is a copy of
the accept vector for member ordering, statement and record line both -- and that
is the same defect the paragraph above is about, sitting in the corpus this gate
was not pointed at. A gate scoped to one of two corpora reports the other one
clean by never reading it.

SECOND, and this is the sharper one, BYTES ARE NOT THE ONLY WAY TWO IDENTIFIERS
CAN ADDRESS ONE STATEMENT. A rail that decodes before it compares sees the
decoded object, and two files can differ in their bytes while decoding to the
same object. When those two carry DIFFERENT LABELS the corpus is asking a
decoding rail to return two different verdicts for one input, which no
implementation can do: whichever way it answers it is wrong about one of them,
and the only thing that separates the pair for such a rail is the `ok-`/`bad-`
prefix in the identifier. That is a corpus scoring the identifier rather than the
statement, and it is invisible to a digest comparison because the bytes really do
differ.

The decode check is therefore run over BOTH readings a rail can take -- the
decoded object compared with `==`, and the object re-serialized to canonical
JSON and compared as text. They are not quite the same question. Python's decoder
maps `1` and `1.0` to values that compare equal and canonicalize differently, and
`True` compares equal to `1`. Asking both means a pair that collides under either
reading is named, and a pair that collides under one and not the other is named
as exactly that, rather than being resolved silently in whichever direction the
gate happened to be written.

An undecodable vector never collides with anything, including another undecodable
vector. That is deliberate and it is the same trap `aee/duplicate_masking_test.go`
documents for record payloads: two files that both fail to parse hold no common
decoded value, and reporting them as equal would be a finding about this loop
rather than about the corpus.

The declaration ledger
----------------------

Some collisions are the point of the vector rather than a defect in it, so the
gate reads `docs/VECTOR-COLLISIONS.json` and refuses on any collision that ledger
does not name. The ledger is not an exemption list. Every entry pins the exact
identifiers and the exact digest of the colliding statement, so a declaration
stops applying the moment either side moves, and an entry naming a collision that
is no longer there fails just as loudly as an undeclared one. A declaration that
outlives its subject is the shape of a stale allowance, and this repository has
enough of those in its history to check for it.

The ledger carries a disposition per entry, and the two values mean different
things. `inherent` says the collision is what the vector is for -- the statement
that carries a duplicate member has to decode to its own parent, because a
lenient decoder keeping the last member silently IS the defect it forces, and a
version of it that decoded to something else would stop forcing anything.
`open` says the collision is a defect nobody has fixed yet, and the entry carries
the remedy. Neither disposition makes the gate quieter about anything else.

Usage:
    python3 scripts/vector-distinctness-gate.py
    python3 scripts/vector-distinctness-gate.py --root <tree>   (for its own tests)
Exit 0 when every collision present is declared and every declaration is live;
1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_REL = "docs/VECTOR-COLLISIONS.json"

# Every corpus this repository ships, by the directory that roots it. A corpus
# added here and not listed is a corpus nothing asks this question about, which
# is the state the AI Agent Action suite was in.
CORPORA = ("vectors", "vectors-ai-agent-action", "vectors-self-reported-record")

DISPOSITIONS = ("inherent", "open")


class Vector:
    """One vector as both readings a rail can take of it."""

    def __init__(self, vid: str, kind: str, raw: bytes, companion: bytes | None):
        self.id = vid
        self.kind = kind
        joined = raw if companion is None else raw + b"\x00" + companion
        self.raw_digest = hashlib.sha256(joined).hexdigest()
        self.decoded: Any = None
        self.canonical: str | None = None
        try:
            self.decoded = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            self.undecodable = True
            return
        self.undecodable = False
        self.canonical = json.dumps(
            self.decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


def load_corpus(tree: Path, corpus: str, problems: list[str]) -> list[Vector]:
    """Read one corpus's manifest and every file it declares."""
    base = tree / corpus
    manifest_path = base / "MANIFEST.json"
    if not manifest_path.is_file():
        problems.append(f"{corpus}: MANIFEST.json is absent")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        problems.append(f"{corpus}: the manifest lists no vectors")
        return []

    vectors: list[Vector] = []
    for entry in entries:
        vid = str(entry.get("id"))
        rel = entry.get("file")
        if not rel:
            problems.append(f"{corpus}: {vid} declares no file")
            continue
        path = base / str(rel)
        if not path.is_file():
            problems.append(f"{corpus}: {vid} names {rel}, which is not on disk")
            continue
        # A vector whose records ship beside it is that pair, not the statement
        # alone: two statements distinguished only by their record lines are two
        # statements, and hashing the file alone would report them as one.
        companion = None
        rec_rel = entry.get("records")
        if rec_rel:
            rec_path = base / str(rec_rel)
            if not rec_path.is_file():
                problems.append(f"{corpus}: {vid} names {rec_rel}, which is not on disk")
                continue
            companion = rec_path.read_bytes()
        vectors.append(Vector(vid, str(entry.get("kind")), path.read_bytes(), companion))
    return vectors


def loose(value: Any) -> Any:
    """A token equal for exactly the values Python's `==` calls equal.

    `json.load` maps `1` and `1.0` to values that compare equal and canonicalize
    differently, and `True` compares equal to `1`. Grouping on canonical text
    alone would therefore answer the object-equality question with the
    serialization question, and the two are the readings a rail actually chooses
    between. Numbers collapse to one type here so that grouping on this token is
    object equality, exactly.
    """
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, dict):
        return {k: loose(v) for k, v in value.items()}
    if isinstance(value, list):
        return [loose(v) for v in value]
    return value


def collisions_in(corpus: str, vectors: list[Vector]) -> list[dict[str, Any]]:
    """Every group of identifiers that address one statement, under any reading.

    A group is reported once, at the STRONGEST reading it collides under, because
    bytes-equal implies canonical-equal implies decode-equal and three lines
    about one pair would say the same thing three times. The reading named is
    therefore the tightest true statement about the group, and a pair that is
    decode-equal without being canonical-equal is named as exactly that.
    """
    readings: list[tuple[str, dict[str, list[Vector]]]] = []

    by_raw: dict[str, list[Vector]] = defaultdict(list)
    for v in vectors:
        by_raw[v.raw_digest].append(v)
    readings.append(("bytes", by_raw))

    by_canonical: dict[str, list[Vector]] = defaultdict(list)
    by_decoded: dict[str, list[Vector]] = defaultdict(list)
    for v in vectors:
        if v.undecodable:
            continue  # holds no decoded value, so it is equal to nothing
        by_canonical[str(v.canonical)].append(v)
        by_decoded[json.dumps(loose(v.decoded), sort_keys=True)].append(v)
    readings.append(("canonical-json", by_canonical))
    readings.append(("decoded", by_decoded))

    found: list[dict[str, Any]] = []
    seen: set[frozenset[str]] = set()
    for reading, buckets in readings:
        for token, members in sorted(buckets.items()):
            if len(members) < 2:
                continue
            ids = frozenset(v.id for v in members)
            if ids in seen:
                continue
            seen.add(ids)
            found.append(
                {
                    "corpus": corpus,
                    "reading": reading,
                    "ids": sorted(ids),
                    "kinds": sorted({v.kind for v in members}),
                    "digest": (
                        token[:16]
                        if reading == "bytes"
                        # `surrogatepass`, because this corpus deliberately
                        # carries statements holding a lone surrogate and a
                        # digest is not the place to discover that.
                        else hashlib.sha256(
                            token.encode("utf-8", "surrogatepass")
                        ).hexdigest()[:16]
                    ),
                }
            )
    return found


def load_ledger(tree: Path, problems: list[str]) -> list[dict[str, Any]]:
    ledger = tree / LEDGER_REL
    if not ledger.is_file():
        problems.append(f"{LEDGER_REL} is absent, so no collision can be declared")
        return []
    entries = json.loads(ledger.read_text(encoding="utf-8")).get("collisions")
    if not isinstance(entries, list):
        problems.append(f"{LEDGER_REL} carries no `collisions` array")
        return []
    for e in entries:
        if e.get("disposition") not in DISPOSITIONS:
            problems.append(
                f"{LEDGER_REL}: {sorted(e.get('ids', []))} declares disposition "
                f"{e.get('disposition')!r}, which is not one of {DISPOSITIONS}"
            )
        if not str(e.get("reason", "")).strip():
            problems.append(
                f"{LEDGER_REL}: {sorted(e.get('ids', []))} declares no reason"
            )
    return entries


def key_of(entry: dict[str, Any]) -> tuple[str, str, tuple[str, ...], str]:
    return (
        str(entry.get("corpus")),
        str(entry.get("reading")),
        tuple(sorted(str(i) for i in entry.get("ids", []))),
        str(entry.get("digest")),
    )


def describe(c: dict[str, Any]) -> str:
    ids = ", ".join(c["ids"])
    kinds = "/".join(c["kinds"])
    if c["reading"] == "bytes":
        why = (
            "are byte-identical, so every condition they are credited to shares "
            "one discriminator and the coverage figures count a vector that does "
            "not exist separately"
        )
    elif len(c["kinds"]) > 1:
        why = (
            "carry different labels and decode to the same statement, so no rail "
            "that decodes before it compares can be right about both, and the only "
            "thing separating them is the identifier"
        )
    else:
        why = (
            "decode to the same statement, so a rail that decodes before it "
            "compares sees one vector where the corpus counts two"
        )
    return f"[{c['corpus']}] {ids} ({kinds}, {c['reading']}, {c['digest']}…) {why}."


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT,
                        help="the tree to read; its own tests point this at a copy")
    tree = parser.parse_args().root

    problems: list[str] = []
    present: list[dict[str, Any]] = []
    total = 0
    for corpus in CORPORA:
        vectors = load_corpus(tree, corpus, problems)
        total += len(vectors)
        present.extend(collisions_in(corpus, vectors))

    declared = load_ledger(tree, problems)
    present_keys = {key_of(c): c for c in present}
    declared_keys = {key_of(d): d for d in declared}

    undeclared = [c for k, c in present_keys.items() if k not in declared_keys]
    stale = [d for k, d in declared_keys.items() if k not in present_keys]

    if problems or undeclared or stale:
        print(
            "FAIL: the corpus does not address one statement per identifier "
            f"({len(undeclared)} undeclared, {len(stale)} stale declaration(s), "
            f"{len(problems)} unreadable):",
            file=sys.stderr,
        )
        for c in undeclared:
            print(f"  - undeclared: {describe(c)}", file=sys.stderr)
        for d in stale:
            print(
                f"  - stale declaration: {LEDGER_REL} names "
                f"{', '.join(str(i) for i in d.get('ids', []))} "
                f"({d.get('corpus')}, {d.get('reading')}, {d.get('digest')}…), which is "
                "not a collision in the corpus as it now stands. Either side moving "
                "retires the declaration with it.",
                file=sys.stderr,
            )
        for m in problems:
            print(f"  - {m}", file=sys.stderr)
        return 1

    counted = ", ".join(
        f"{d['disposition']}: {', '.join(str(i) for i in d['ids'])}" for d in declared
    )
    print(
        f"OK: {total} vectors across {len(CORPORA)} corpora, "
        f"{len(present)} declared collision(s) and no undeclared one"
        + (f" — {counted}." if counted else ".")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
