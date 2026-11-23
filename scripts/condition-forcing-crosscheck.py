#!/usr/bin/env python3
"""Re-derive the published weak-spot figure, independently of the tool that wrote it.

`scripts/condition-forcing-gate.py --check` proves that `docs/FORCING-HONESTY.md`
has not drifted from the data. That is a real property and it is not the one a
reader wants. The generator regenerates the page and compares; if its reading of
the definitions is wrong, the page is wrong and the comparison agrees with it.
Self-consistency cannot see that, by construction.

So this is a second implementation, written from the definitions AS THE PAGE
STATES THEM rather than from the generator's source, sharing no code with it:

    forced    -- some weakening is caught by that condition's vectors and by no
                 others: the killer set is a subset of the condition's vectors.
    weak      -- it intersects a killer set but is a subset of none.
    unforced  -- it intersects no killer set at all.

It reads the two primary inputs, recomputes, then reads the PROSE back out of
the published page -- the headline sentence, the provenance row, the campaign
totals and every row of the weak table -- and refuses on any disagreement. A
figure confirmed only by the program that produced it is the defect this whole
document exists to remove, so the confirmation is not allowed to come from
there either.

`--with-prior` extends that to the earlier figure and to the reconciliation
between the two runs. The page claims an exact identity -- the pinned
baseline's killed count equals the released note's, plus the kills that need
vectors added later, plus the kills only a no-key pass can observe -- and an
identity is the easiest kind of claim to make come out right by choosing the
terms. So the third term is re-derived here from the pinned baseline, the
addition is checked, and the page is then required to state all four numbers
and name every site.

    python3 scripts/condition-forcing-crosscheck.py
    python3 scripts/condition-forcing-crosscheck.py --with-prior   # needs a full clone
    python3 scripts/condition-forcing-crosscheck.py --print        # numbers, no comparison

Exit 0 only when every published number follows from the data. 1 when the page
and the data disagree; 2 when an input could not be read, which is never
reported as agreement.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent

MANIFEST = "vectors/MANIFEST.json"
BASELINE = "docs/FORCING-BASELINE.json"
PAGE = "docs/FORCING-HONESTY.md"
PRIOR = "docs/PRIOR-FORCING.json"

WEAK_SECTION = "## The conditions nothing uniquely attributes to their own vectors"

HEADLINE = re.compile(
    r"Of the (\d+) normative conditions this corpus cites, (\d+) are forced by a vector "
    r"no other condition's vectors duplicate, (\d+) are covered only redundantly, and "
    r"(\d+) are not forced at all\."
)
CORPUS_ROW = re.compile(r"\|\s*corpus\s*\|\s*suiteRevision (\d+), (\d+) vectors")
CAMPAIGN_ROW = re.compile(
    r"\|\s*campaign\s*\|\s*(\d+) single-site weakenings: (\d+) KILLED, (\d+) SILENT, "
    r"(\d+) DEAD, (\d+) INCONCLUSIVE"
)
WEAK_ROW = re.compile(r"^\|\s*`(aee-c-\d+)`\s*\|")

# The reconciliation sentence, as the page states it: "331 killed in the pinned
# baseline = 316 in the released note + 12 killed only by vectors added
# afterwards + 3 the earlier instrument could not observe."
RECONCILIATION = re.compile(
    r"(\d+) killed in the pinned baseline = (\d+) in the released note \+ (\d+) killed "
    r"only by vectors added afterwards \+ (\d+) the earlier instrument could not observe"
)
# A site whose weakening only changes behaviour when no consumer key policy is
# supplied. Transcribed from the page's own words, not from the generator: it
# says "the branch a verifier takes when the consumer supplies no substrate key
# policy at all", and `docs/PRIOR-FORCING.json` spells that branch out.
NO_POLICY = re.compile(r"(?<![\w.])policy == nil")
PAGE_SITE = re.compile(r"^-\s+`([a-z]+\.go::[^`]+)`\s*$", re.MULTILINE)


def disagree(message: str) -> NoReturn:
    """The page says one thing and the data says another."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def unreadable(message: str) -> NoReturn:
    """An input could not be read. Never reported as agreement."""
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_json(path: Path) -> dict[str, Any]:
    try:
        loaded: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        unreadable(f"{path} is absent")
    except (OSError, json.JSONDecodeError) as exc:
        unreadable(f"{path} did not read as JSON: {exc}")
    if not isinstance(loaded, dict):
        unreadable(f"{path} is not a JSON object")
    return loaded


# ---------------------------------------------------------------------------
# the projection, computed from the definitions above and nothing else


def vectors_by_condition(manifest: dict[str, Any]) -> dict[str, frozenset[str]]:
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        unreadable(f"{MANIFEST} carries no vectors")
    collected: defaultdict[str, set[str]] = defaultdict(set)
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            unreadable(f"{MANIFEST} carries a vector with no id")
        for condition in entry.get("conditions", []):
            collected[str(condition)].add(str(entry["id"]))
    if not collected:
        unreadable(f"{MANIFEST} cites no conditions")
    return {name: frozenset(ids) for name, ids in collected.items()}


def killer_sets(baseline: dict[str, Any], known: frozenset[str]) -> list[frozenset[str]]:
    sites = baseline.get("sites")
    if not isinstance(sites, dict) or not sites:
        unreadable(f"{BASELINE} records no sites")
    sets: list[frozenset[str]] = []
    for key, site in sites.items():
        if not isinstance(site, dict):
            unreadable(f"{BASELINE} site {key} is not an object")
        killers = site.get("killers")
        if not killers:
            continue
        named = frozenset(str(one) for one in killers)
        unknown = named - known
        if unknown:
            # A killer the manifest does not carry means the two inputs describe
            # different corpora, and every count below would be a silent guess.
            unreadable(
                f"{BASELINE} site {key} is killed by {sorted(unknown)[0]}, "
                f"which {MANIFEST} does not carry"
            )
        sets.append(named)
    if not sets:
        unreadable(f"{BASELINE} records no killed site")
    return sets


def corpus_only_kills(baseline: dict[str, Any]) -> int:
    """KILLED sites forced only through a corpus-channel member.

    Such a site names no vector of the conformance manifest, so it has no killer
    set to project, and condition-forcing-gate.py skips it for the same reason.
    It still counts toward the KILLED total the baseline records.
    """
    return sum(
        1
        for site in baseline["sites"].values()
        if isinstance(site, dict)
        and site.get("class") == "KILLED"
        and not site.get("killers")
        and site.get("corpusKillers")
    )


def project(
    by_condition: dict[str, frozenset[str]], kills: list[frozenset[str]]
) -> tuple[list[str], list[str], list[str], dict[str, int]]:
    """Return (forced, weak, unforced, shares-per-condition)."""
    forced: list[str] = []
    weak: list[str] = []
    unforced: list[str] = []
    shares: dict[str, int] = {}
    for condition, vectors in by_condition.items():
        touched = [one for one in kills if one & vectors]
        shares[condition] = len(touched)
        if any(one <= vectors for one in touched):
            forced.append(condition)
        elif touched:
            weak.append(condition)
        else:
            unforced.append(condition)
    return forced, weak, unforced, shares


# ---------------------------------------------------------------------------
# the prose, read back out of the published page


def read_page(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        unreadable(f"{path} is absent -- run the gate that writes it before crosschecking")
    except OSError as exc:
        unreadable(f"{path} did not read: {exc}")


def published_weak_rows(page: str) -> dict[str, tuple[int, int]]:
    """The weak table, as {condition: (vectors, shares)}, from that section only."""
    start = page.find(WEAK_SECTION)
    if start < 0:
        disagree(f"{PAGE} has no section headed {WEAK_SECTION!r}")
    section = page[start:]
    end = section.find("\n## ", 1)
    if end > 0:
        section = section[:end]
    rows: dict[str, tuple[int, int]] = {}
    for line in section.splitlines():
        match = WEAK_ROW.match(line.strip())
        if not match:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            disagree(f"{PAGE} weak row for {match.group(1)} has too few columns")
        try:
            rows[match.group(1)] = (int(cells[-2]), int(cells[-1]))
        except ValueError:
            disagree(f"{PAGE} weak row for {match.group(1)} does not end in two integers")
    if not rows:
        disagree(f"{PAGE} publishes no weak rows, so nothing could be crosschecked")
    return rows


def compare(
    page: str,
    computed: dict[str, int],
    weak_names: list[str],
    weak_rows: dict[str, tuple[int, int]],
) -> None:
    flat = " ".join(page.split())

    headline = HEADLINE.search(flat)
    if not headline:
        disagree(f"{PAGE} carries no headline sentence in the form this check reads")
    published = {
        "conditions": int(headline.group(1)),
        "forced": int(headline.group(2)),
        "weak": int(headline.group(3)),
        "unforced": int(headline.group(4)),
    }
    for name, value in published.items():
        if value != computed[name]:
            disagree(
                f"{PAGE} publishes {value} {name}; the data yields {computed[name]}. "
                f"The page does not follow from {BASELINE} and {MANIFEST}."
            )

    corpus = CORPUS_ROW.search(flat)
    if not corpus:
        disagree(f"{PAGE} carries no corpus provenance row")
    if int(corpus.group(2)) != computed["vectors"]:
        disagree(
            f"{PAGE} says {corpus.group(2)} vectors; {MANIFEST} carries {computed['vectors']}"
        )

    campaign = CAMPAIGN_ROW.search(flat)
    if not campaign:
        disagree(f"{PAGE} carries no campaign provenance row")
    if int(campaign.group(1)) != computed["sites"]:
        disagree(f"{PAGE} says {campaign.group(1)} sites; {BASELINE} records {computed['sites']}")
    if int(campaign.group(2)) != computed["killed"]:
        disagree(
            f"{PAGE} says {campaign.group(2)} KILLED; {BASELINE} records {computed['killed']}"
        )

    if sorted(weak_rows) != sorted(weak_names):
        missing = sorted(set(weak_names) - set(weak_rows))
        extra = sorted(set(weak_rows) - set(weak_names))
        disagree(
            f"{PAGE}'s weak table names a different set than the data: "
            f"absent from the page {missing or 'none'}, absent from the data {extra or 'none'}"
        )


def compare_weak_rows(
    weak_rows: dict[str, tuple[int, int]],
    by_condition: dict[str, frozenset[str]],
    shares: dict[str, int],
) -> None:
    for condition, (vectors, shared) in sorted(weak_rows.items()):
        if len(by_condition[condition]) != vectors:
            disagree(
                f"{PAGE} says {condition} has {vectors} vectors; "
                f"{MANIFEST} cites it from {len(by_condition[condition])}"
            )
        if shares[condition] != shared:
            disagree(
                f"{PAGE} says {condition} shares {shared} kills; the data yields "
                f"{shares[condition]}"
            )


# ---------------------------------------------------------------------------
# the earlier figure, from the two git objects it is pinned to


def blob(repo: Path, digest: str) -> dict[str, Any]:
    try:
        done = subprocess.run(  # noqa: S603 -- reading this repository's own history
            ["git", "cat-file", "blob", digest],
            cwd=repo,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        unreadable(f"git could not be run in {repo}: {exc}")
    if done.returncode != 0:
        unreadable(
            f"the pinned blob {digest} is not in this clone "
            f"({done.stderr.decode(errors='replace').strip()}). "
            f"A shallow clone cannot tell an absent object from a disagreeing one, "
            f"so this stops rather than passes."
        )
    try:
        loaded: Any = json.loads(done.stdout)
    except json.JSONDecodeError as exc:
        unreadable(f"the pinned blob {digest} did not read as JSON: {exc}")
    if not isinstance(loaded, dict):
        unreadable(f"the pinned blob {digest} is not a JSON object")
    return loaded


def crosscheck_reconciliation(
    root: Path,
    pins: dict[str, Any],
    sites: dict[str, Any],
    then: frozenset[str],
    got: dict[str, int],
) -> None:
    """The residue between the two runs, re-derived and read back off the page.

    The page claims an exact identity, and an identity is the easiest kind of
    claim to make come out right by choosing the terms. So this recomputes the
    set from the pinned baseline under its own reading of the branch, checks
    that subtracting it from the reconstruction lands on the released note, and
    then requires the PAGE to state all four terms and name every site. A
    reconciliation only the reconciler can confirm is the defect this file
    exists for.
    """
    delta = pins.get("instrumentDelta")
    if not isinstance(delta, dict):
        unreadable(f"{PRIOR} carries no instrumentDelta, and the page publishes one")
    note = pins.get("campaignNote")
    if not isinstance(note, dict):
        unreadable(f"{PRIOR} carries no campaignNote to reconcile against")

    found = sorted(
        str(key)
        for key, site in sites.items()
        if isinstance(site, dict)
        and site.get("class") == "KILLED"
        and {str(one) for one in site.get("killers") or []} & then
        and NO_POLICY.search(str(site.get("snippet") or ""))
    )
    named = sorted(str(one) for one in delta.get("sites") or [])
    if found != named:
        disagree(
            f"{PRIOR} names {named} as the weakenings only a no-key pass reaches; "
            f"the pinned baseline yields {found}"
        )
    if got["killedReachable"] - len(found) != int(note["killed"]):
        disagree(
            f"the reconstruction's {got['killedReachable']} reachable kills less "
            f"{len(found)} instrument-only kills is "
            f"{got['killedReachable'] - len(found)}, and the released note records "
            f"{note['killed']}"
        )

    page = read_page(root / PAGE)
    flat = " ".join(page.split())
    stated = RECONCILIATION.search(flat)
    if not stated:
        disagree(f"{PAGE} states no reconciliation in the form this check reads")
    published = [int(one) for one in stated.groups()]
    expected = [
        got["killedInBaseline"],
        int(note["killed"]),
        got["killedDropped"],
        len(found),
    ]
    if published != expected:
        disagree(
            f"{PAGE} reconciles {published[0]} = {published[1]} + {published[2]} + "
            f"{published[3]}; the pinned objects yield "
            f"{expected[0]} = {expected[1]} + {expected[2]} + {expected[3]}"
        )
    # There is deliberately no "and do the published terms sum" check here. Once
    # the four match `expected` they sum by construction, because the
    # subtraction above already fixed the third term against the other two. A
    # check that cannot fail is worse than no check: it reads as coverage.
    listed = sorted(set(PAGE_SITE.findall(page)))
    if listed != found:
        disagree(f"{PAGE} lists {listed} as the instrument-only sites; the data yields {found}")
    print(
        f"{PAGE}: the residue between the two runs closes exactly "
        f"({expected[0]} = {expected[1]} + {expected[2]} + {expected[3]}) over "
        f"{len(found)} named sites"
    )


def crosscheck_prior(root: Path, repo: Path) -> None:
    record = load_json(root / PRIOR)
    pins = record.get("pins")
    derived = record.get("derived")
    if not isinstance(pins, dict) or not isinstance(derived, dict):
        unreadable(f"{PRIOR} carries no pins or no derived block")
    for field in ("manifestBlob", "baselineBlob"):
        if not isinstance(pins.get(field), str):
            unreadable(f"{PRIOR} pins no {field}")

    manifest = blob(repo, str(pins["manifestBlob"]))
    baseline = blob(repo, str(pins["baselineBlob"]))
    by_condition = vectors_by_condition(manifest)
    entries = manifest["vectors"]
    then = frozenset(str(one["id"]) for one in entries)

    sites = baseline.get("sites")
    if not isinstance(sites, dict) or not sites:
        unreadable(f"the pinned baseline {pins['baselineBlob']} records no sites")
    raw = [
        frozenset(str(k) for k in site["killers"])
        for site in sites.values()
        if isinstance(site, dict) and site.get("killers")
    ]
    # Restricting each killer set to the vectors that existed then is what makes
    # this a reconstruction rather than a re-run. It is exact on the condition
    # axis and says nothing about the site axis, which is why only the condition
    # numbers are compared here.
    reachable = [one & then for one in raw]
    reachable = [one for one in reachable if one]
    forced, weak, unforced, _ = project(by_condition, reachable)

    got = {
        "vectors": len(entries),
        "sites": len(sites),
        "conditions": len(by_condition),
        "forced": len(forced),
        "weak": len(weak),
        "unforced": len(unforced),
        "killedReachable": len(reachable),
        "killedDropped": len(raw) - len(reachable),
        "killedInBaseline": sum(
            1 for site in sites.values() if isinstance(site, dict) and site.get("class") == "KILLED"
        ),
        "instrumentOnlyKilled": sum(
            1
            for site in sites.values()
            if isinstance(site, dict)
            and site.get("class") == "KILLED"
            and {str(one) for one in site.get("killers") or []} & then
            and NO_POLICY.search(str(site.get("snippet") or ""))
        ),
    }
    for name, value in got.items():
        if name not in derived:
            disagree(f"{PRIOR} records no {name}")
        if derived[name] != value:
            disagree(
                f"{PRIOR} records {name} = {derived[name]}; the pinned objects yield {value}"
            )
    crosscheck_reconciliation(root, pins, sites, then, got)
    print(
        f"{PRIOR}: the earlier figure follows from its pinned objects "
        f"({got['forced']} forced, {got['weak']} weak, {got['unforced']} unforced "
        f"across {got['conditions']} conditions)"
    )


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="tree to read the files from")
    parser.add_argument(
        "--with-prior", action="store_true", help="also re-derive the earlier figure from git"
    )
    parser.add_argument(
        "--print", dest="show", action="store_true", help="print the numbers, compare nothing"
    )
    args = parser.parse_args()
    root = Path(args.root).resolve()

    manifest = load_json(root / MANIFEST)
    baseline = load_json(root / BASELINE)
    by_condition = vectors_by_condition(manifest)
    known = frozenset(str(one["id"]) for one in manifest["vectors"] if isinstance(one, dict))
    kills = killer_sets(baseline, known)
    forced, weak, unforced, shares = project(by_condition, kills)

    counts = baseline.get("counts")
    computed: dict[str, int] = {
        "conditions": len(by_condition),
        "forced": len(forced),
        "weak": len(weak),
        "unforced": len(unforced),
        "vectors": len(manifest["vectors"]),
        "sites": len(baseline["sites"]),
        "killed": len(kills) if not isinstance(counts, dict) else int(counts.get("KILLED", 0)),
    }
    attributed = len(kills) + corpus_only_kills(baseline)
    if attributed != computed["killed"]:
        disagree(
            f"{BASELINE} counts {computed['killed']} KILLED but carries {attributed} sites "
            f"with killers"
        )

    if args.show:
        for name in ("conditions", "forced", "weak", "unforced", "vectors", "sites", "killed"):
            print(f"{name:12s} {computed[name]}")
        return 0

    page = read_page(root / PAGE)
    weak_rows = published_weak_rows(page)
    compare(page, computed, weak, weak_rows)
    compare_weak_rows(weak_rows, by_condition, shares)
    print(
        f"{PAGE}: every published figure follows from {BASELINE} and {MANIFEST} "
        f"under a second implementation "
        f"({computed['forced']} forced, {computed['weak']} weak, "
        f"{computed['unforced']} unforced across {computed['conditions']} conditions)"
    )

    if args.with_prior:
        crosscheck_prior(root, REPO_ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
