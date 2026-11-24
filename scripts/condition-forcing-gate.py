#!/usr/bin/env python3
"""Publish what this suite does NOT force, per normative condition and per code.

Why a second projection of one campaign
---------------------------------------
`docs/FORCING-BASELINE.json` records a mutation campaign over the reference Go
rail: switch one rule off, replay the whole corpus, record whether any vector
notices. The baseline is keyed by MUTATION SITE, and a site is a fact about the
rail's source, not about the specification. A reader asking "which of the rules
in the document does this corpus oblige me to implement" cannot answer it from a
site list, because the document does not have sites -- it has conditions, and the
corpus cites them by `aee-c-NN` id on every vector.

So there are two ways to read one campaign, and both are legitimate:

  the SITE axis        already published: how many single-site weakenings of the
                       rail the corpus catches, tolerates, or does not depend on
  the CONDITION axis   this file: for each normative condition the corpus cites,
                       whether any weakening is caught by the vectors citing that
                       condition and by NO other vector

The second was measured once, over an earlier and smaller corpus, and quoted
afterwards beside the first. Two projections of one campaign taken at two corpus
revisions look exactly like two measurements that disagree, and neither of them
is wrong. This gate ends that by deriving the condition projection from the
published baseline on every run, so the two can never again be quoted from
different dates.

The earlier figure gets the same treatment rather than a footnote. It was seven
integers typed into this file, which is the shape of a number a reader has to
take on trust; `--verify-prior` now re-derives it from two pinned git objects
and refuses anything but a match. See the reconstruction section below for what
the reconstruction is exact about and what it is silent about.

Where the two runs disagreed, they now reconcile by arithmetic rather than by
argument. The reconstruction counts three more killed weakenings than the
released note does over the same sites and the same vectors, and all three sit
on the branch a verifier takes when the consumer supplies no substrate key
policy -- a branch no run without a no-key pass can observe, which the run
behind the note did not make. `--verify-prior` derives that set from the pinned
baseline, checks it against the set the record names, and checks that the
subtraction lands on the note's figure with no slack. What it cannot check is
stated on the page beside the number: the earlier campaign's own per-site table
is not in this repository, so this is an exact closure over a derived set and
not a per-site diff.

What the three classes mean, exactly
------------------------------------
For a condition `c`, let `V(c)` be the vectors that cite it and `K` the sites the
baseline records as KILLED, each with the set of vectors that killed it.

  FORCED    some killed site's killer set is a SUBSET of `V(c)`. Delete those
            vectors and that weakening goes undetected. The condition's vectors
            are load-bearing.
  WEAK      `V(c)` kills something, but every site it kills is also killed by a
            vector outside `V(c)`. The rule is covered, redundantly, and nothing
            in the corpus is uniquely attributable to this condition.
  UNFORCED  `V(c)` kills nothing at all. The corpus cites the rule and does not
            oblige anyone to implement it.

WEAK is therefore a statement about ATTRIBUTION, not about strength, and it is
not monotone: adding a vector that happens to kill a site can enlarge that site's
killer set past `V(c)` and move `c` from FORCED to WEAK while the corpus got
strictly better. A reader who diffs two of these figures across revisions and
reads a rise in WEAK as a regression has read the wrong thing, and the generated
document says so where the number is.

The code axis, and why only one mutation operator is admissible for it
----------------------------------------------------------------------
"Can a conforming rail decline to emit this failure code at all" is a third
question, and the operator that answers it is `CODE_OFF`, which removes exactly
one `appendCode` call and nothing else. `IF_OFF` is inadmissible here even though
its snippet names the same code: it removes the whole enclosing statement, so on
a parse block it deletes the field parse as well and is killed by most of the
corpus for a reason that has nothing to do with the code inside it. Deriving the
code axis from every site that mentions a code reports one of this repository's
own published weak spots as forced. It is measured from `CODE_OFF` alone.

Some emissions pass the code through a variable (`appendCode(codes, c)` inside a
shared helper). Those sites name no code, and the codes reached only that way are
reported as NOT MEASURABLE on this axis rather than folded into either answer,
for the same reason the baseline keeps INCONCLUSIVE apart from DEAD: "we could
not measure it" and "the corpus does not force it" are different claims.

Usage:
    scripts/condition-forcing-gate.py                  # regenerate the document
    scripts/condition-forcing-gate.py --check          # fail on drift, write nothing
    scripts/condition-forcing-gate.py --verify-prior   # re-derive the earlier figure
    scripts/condition-forcing-gate.py --sync-prior     # write it, from its own pins
Exit 0 when the document is current; 1 on drift; 2 when an input cannot be read
or an attribution cannot be resolved. Nothing here needs a Go toolchain: the
campaign has already run and its record is in the repository. The two prior
modes read git, so they need a full clone and they stop rather than pass without
one.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "vectors/MANIFEST.json"
BASELINE = "docs/FORCING-BASELINE.json"
VENDOR_PIN = "spec/VENDOR-PIN.json"
REGISTRY = "vectors/reject/INDEX.md"
CHANGES = "vectors/CHANGES.md"
CODES_GO = "aee/codes.go"
UNVECTORED = "vectors/coverage-unforced.json"
OUTPUT = "docs/FORCING-HONESTY.md"

# The tree under check. `--root` points it at a staged copy, which is how this
# gate's own tests rig one input and assert the refusal without ever editing the
# repository they are testing. Production runs never move it.
ROOT = REPO_ROOT


def p(rel: str) -> Path:
    return ROOT / rel


# Prose is wrapped so a generated paragraph reads like the hand-written files
# beside it and a one-word edit does not reflow a whole section in the diff.
WRAP = 88

# `| aee-c-12 | L554-556 | caught intercepted row refs an interception record |`
REGISTRY_ROW = re.compile(r"^\|\s*(aee-c-\d+)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*\|\s*$", re.MULTILINE)
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
# `CodeResultVocabulary          Code = "result-vocabulary"`
CODE_DECL = re.compile(r"\b(Code[A-Z][A-Za-z0-9]*)\s+Code = \"([a-z0-9-]+)\"")
# An identifier as a recorded snippet spells it. Anchored on the `Code` prefix
# plus an uppercase letter, so `appendCode` and the bare `Code` type are not it.
CODE_TOKEN = re.compile(r"\bCode[A-Z][A-Za-z0-9]*")

# The earlier measurement this document reconciles against. It was seven typed
# constants here until the reconstruction below was written; every one of them
# survived it unchanged, which is the finding and not a vindication, because a
# figure nobody can re-derive reads exactly the same on the day it stops being
# true. It is now derived from git objects pinned in docs/PRIOR-FORCING.json,
# and `--verify-prior` re-derives it.
PRIOR = "docs/PRIOR-FORCING.json"

# The branch a verifier takes when the consumer supplies NO substrate key
# policy. A weakening here is invisible to any run that never makes a no-key
# pass, because on the pinned-key pass the policy is present and removing the
# guard changes nothing. Lowercase `policy` and not preceded by a dot or an
# identifier character, so the environment's own `env.CatchPolicy == nil` -- a
# different object on a branch every run reaches -- is not swept in.
NO_POLICY_BRANCH = re.compile(r"(?<![\w.])policy == nil")


def die(message: str) -> NoReturn:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_json(rel: str) -> dict[str, Any]:
    """One JSON object, or a loud stop. An unreadable input is never an empty one."""
    try:
        loaded: Any = json.loads(p(rel).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        die(f"{rel} could not be read: {exc}")
    if not isinstance(loaded, dict):
        die(f"{rel} is not a JSON object.")
    obj: dict[str, Any] = loaded
    return obj


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# the condition axis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConditionRow:
    """One normative condition, and what the corpus forces through it."""

    cid: str
    anchor: str
    text: str
    vectors: int
    sole: int
    shared: int
    verdict: str


def cited_conditions(manifest: dict[str, Any]) -> dict[str, set[str]]:
    """Condition id -> the vectors citing it. Refuses an empty reading."""
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        die("vectors/MANIFEST.json names no vectors, so no condition has a carrier.")
    cited: dict[str, set[str]] = collections.defaultdict(set)
    for entry in vectors:
        for cid in entry.get("conditions", []):
            cited[str(cid)].add(str(entry["id"]))
    if not cited:
        die("no vector in vectors/MANIFEST.json cites a condition; there is nothing to project.")
    return dict(cited)


def killed_killers(baseline: dict[str, Any], known: set[str]) -> list[frozenset[str]]:
    """The killer set of every KILLED site, checked against the corpus."""
    sites = baseline.get("sites")
    if not isinstance(sites, dict) or not sites:
        die("docs/FORCING-BASELINE.json records no sites, so no campaign has been read.")
    out: list[frozenset[str]] = []
    for key, site in sites.items():
        if site.get("class") != "KILLED":
            continue
        killers = {str(v) for v in site.get("killers") or []}
        if not killers and site.get("corpusKillers"):
            # Forced only through a corpus-channel member, which carries no
            # condition of this manifest: nothing here to project it onto.
            continue
        if not killers:
            die(f"{key} is recorded KILLED with no killer, so nothing attributes it.")
        if stray := sorted(killers - known):
            die(f"{key} names killers absent from vectors/MANIFEST.json: {stray}.")
        out.append(frozenset(killers))
    if not out:
        die("no site in the baseline is KILLED; a projection over an empty set forces nothing.")
    return out


def vectors_no_site_depends_on(manifest: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Corpus vectors that appear in no recorded killer set.

    Two very different things produce this list and the page says so rather than
    picking one: a vector genuinely redundant against this rail, or a vector added
    after the campaign that produced the baseline. It is not a failure either way
    -- but while the list is non-empty every figure derived here is a LOWER bound
    on what the corpus forces, because a weakening some unswept vector would catch
    is recorded as caught by nobody.
    """
    killers = {vid for site in baseline["sites"].values() for vid in (site.get("killers") or [])}
    return [str(v["id"]) for v in manifest["vectors"] if str(v["id"]) not in killers]


def registry_text() -> dict[str, tuple[str, str]]:
    """Condition id -> (spec anchor, condition text), from the one registry."""
    rows: dict[str, tuple[str, str]] = {}
    for match in REGISTRY_ROW.finditer(p(REGISTRY).read_text(encoding="utf-8")):
        rows[match.group(1)] = (match.group(2), match.group(3))
    if not rows:
        die("vectors/reject/INDEX.md yielded no condition rows, so no condition can be named.")
    return rows


def condition_rows(manifest: dict[str, Any], baseline: dict[str, Any]) -> list[ConditionRow]:
    """Every cited condition, classified against the published campaign."""
    cited = cited_conditions(manifest)
    known = {str(v["id"]) for v in manifest["vectors"]}
    killed = killed_killers(baseline, known)
    registry = registry_text()
    if missing := sorted(set(cited) - set(registry)):
        die(f"cited conditions with no registry row, so they cannot be named: {missing}.")
    rows: list[ConditionRow] = []
    for cid in sorted(cited, key=lambda c: int(c.rsplit("-", 1)[1])):
        carriers = cited[cid]
        sole = sum(1 for killers in killed if killers <= carriers)
        touched = sum(1 for killers in killed if killers & carriers)
        verdict = "FORCED" if sole else ("WEAK" if touched else "UNFORCED")
        anchor, text = registry[cid]
        rows.append(ConditionRow(cid, anchor, text, len(carriers), sole, touched - sole, verdict))
    return rows


# ---------------------------------------------------------------------------
# the earlier projection, reconstructed rather than remembered
# ---------------------------------------------------------------------------
#
# The figure quoted in campaign material -- 24 of 78 conditions weak -- came from
# a run over a corpus that no longer exists in the working tree, and the campaign
# that produced it says so itself: `vectors/CHANGES.md` records under
# suiteRevision 15 that the measurement's full tables are held outside this
# repository. A number nobody can re-derive is a number a reader has to take on
# trust, which is the one thing this page exists not to ask for.
#
# What CAN be re-derived is the same projection, over the earliest baseline this
# repository does carry, restricted to the vectors that existed at the revision
# the quoted figure names. It is an approximation and the shape of the
# approximation is stated where the number is: dropping the later vectors from a
# killer set tells us which weakenings the earlier corpus still catches, and
# nothing about whether a weakening it stops catching was tolerated or ignored
# then. The condition projection does not read that distinction, so the
# approximation is exact on the axis it is used for and silent on the other.


def git(*args: str) -> bytes:
    """One read of history, or a loud stop. An unavailable git is never a pass.

    Every failure here is fatal on purpose. A missing object, a shallow clone and
    a git that will not run are indistinguishable from this side, and each of
    them makes the check unable to report a result -- which is a different thing
    from the check reporting that the record is wrong, and a very different thing
    from the record being right.
    """
    try:
        done = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            ["git", "-C", str(REPO_ROOT), *args],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        die(
            f"git could not be run ({exc}), so history could not be read. This check is not "
            "satisfied by a shallow clone and it does not pass by default."
        )
    if done.returncode != 0:
        die(
            f"git {' '.join(args)} failed: {done.stderr.decode('utf-8', 'replace').strip()}. "
            "Run this in a full clone; a history that cannot be read is not a history that "
            "agrees."
        )
    return done.stdout


def load_prior() -> dict[str, Any]:
    """The pinned record, checked for the members every reader of it uses."""
    record = load_json(PRIOR)
    for half in ("pins", "derived"):
        if not isinstance(record.get(half), dict):
            die(f"{PRIOR} carries no `{half}` object, so the earlier figure has no {half}.")
    return record


def prior_inputs(pins: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The two pinned objects, read out of history: (baseline, manifest)."""
    baseline = json.loads(git("show", f"{pins['baselineCommit']}:{BASELINE}"))
    manifest = json.loads(git("show", f"{pins['manifestCommit']}:{MANIFEST}"))
    return baseline, manifest


def instrument_only_kills(baseline: dict[str, Any], present: set[str]) -> list[str]:
    """The reachable-killed sites no run without a no-key pass could observe.

    These are the sites the reconstruction counts and the earlier campaign could
    not have: their weakening only changes behaviour when the consumer supplies
    no substrate key policy, and the run behind the released note never made
    that pass. Derived rather than listed, so the set is a consequence of the
    pinned data; `pins.instrumentDelta.sites` then has to agree with it.

    Both filters below are unfalsified by the pinned objects, and this note is
    here so nobody reads them as tested. Switching either off leaves every case
    in `condition-forcing-gate-test.py` green: on this data no site carries
    killers without being KILLED, and no site on this branch is killed only by
    vectors added later. They are guards for data that could exist, not checks
    the suite exercises -- the same distinction this repository draws between an
    unmintable site and an unminted one, applied to its own tooling.
    """
    found: list[str] = []
    for key, site in baseline["sites"].items():
        if site.get("class") != "KILLED":
            continue
        if not {str(v) for v in site.get("killers") or []} & present:
            continue
        if NO_POLICY_BRANCH.search(str(site.get("snippet") or "")):
            found.append(str(key))
    return sorted(found)


def reconstruct_prior(pins: dict[str, Any]) -> dict[str, int]:
    """Re-derive the earlier projection from the two pinned git objects."""
    baseline, manifest = prior_inputs(pins)
    present = {str(v["id"]) for v in manifest["vectors"]}
    cited: dict[str, set[str]] = collections.defaultdict(set)
    for entry in manifest["vectors"]:
        for cid in entry.get("conditions", []):
            cited[str(cid)].add(str(entry["id"]))
    killed: list[frozenset[str]] = []
    dropped = 0
    for site in baseline["sites"].values():
        if site.get("class") != "KILLED":
            continue
        killers = {str(v) for v in site.get("killers") or []} & present
        if not killers:
            dropped += 1
            continue
        killed.append(frozenset(killers))
    tally: collections.Counter[str] = collections.Counter()
    for carriers in cited.values():
        sole = any(k <= carriers for k in killed)
        touched = any(k & carriers for k in killed)
        tally["forced" if sole else ("weak" if touched else "unforced")] += 1
    return {
        "vectors": len(present),
        "sites": len(baseline["sites"]),
        "conditions": len(cited),
        "forced": tally["forced"],
        "weak": tally["weak"],
        "unforced": tally["unforced"],
        "killedReachable": len(killed),
        "killedDropped": dropped,
        "killedInBaseline": sum(
            1 for site in baseline["sites"].values() if site.get("class") == "KILLED"
        ),
        "instrumentOnlyKilled": len(instrument_only_kills(baseline, present)),
    }


def verify_prior(record: dict[str, Any]) -> int:
    """Re-derive the pinned earlier figure, and refuse anything but a match."""
    pins, claimed = record["pins"], record["derived"]
    for member, path in (("baselineBlob", BASELINE), ("manifestBlob", MANIFEST)):
        commit = str(pins[member.replace("Blob", "Commit")])
        found = git("rev-parse", f"{commit}:{path}").decode().strip()
        if found != str(pins[member]):
            print(
                f"FAIL: {PRIOR} pins {path} at {commit} as {pins[member]}, and history now "
                f"holds {found} there. The bytes the earlier figure was derived from moved.",
                file=sys.stderr,
            )
            return 1
    derived = reconstruct_prior(pins)
    if derived != claimed:
        print(
            f"FAIL: {PRIOR} records {claimed} and its own pinned inputs yield {derived}.",
            file=sys.stderr,
        )
        return 1
    if code := verify_instrument_delta(pins, derived):
        return code
    return verify_campaign_note(pins)


def verify_instrument_delta(pins: dict[str, Any], derived: dict[str, int]) -> int:
    """The reconstruction and the released note must reconcile exactly, not roughly.

    Three separate things are checked and each can fail on its own:

      the SET      the sites named in the record are the sites the predicate
                   derives from the pinned baseline. Naming them and deriving
                   them are two handles on one fact, and a rename that slips the
                   predicate makes them disagree instead of silently changing a
                   published integer.
      the SUM      the reconstruction's reachable kills, less those sites,
                   equal the killed figure the released note carries. This is
                   the whole reconciliation: an arithmetic identity over public
                   objects, not an argument.
      the CENSUS   the note's own four classes account for every site in the
                   pinned baseline. Without it the sum above could close on two
                   errors that cancel.
    """
    delta = pins.get("instrumentDelta")
    if not isinstance(delta, dict):
        # Not "nothing to check". The page publishes this reconciliation, so a
        # record without it is a page whose central claim this gate never read.
        die(f"{PRIOR} carries no `pins.instrumentDelta`, and the page publishes one.")
    named = [str(one) for one in delta.get("sites") or []]
    if not named:
        die(f"{PRIOR} names no `pins.instrumentDelta.sites`, so nothing was reconciled.")
    baseline, manifest = prior_inputs(pins)
    found = instrument_only_kills(baseline, {str(v["id"]) for v in manifest["vectors"]})
    if found != sorted(named):
        print(
            f"FAIL: {PRIOR} names {sorted(named)} as the weakenings only a no-key pass "
            f"can observe, and the pinned baseline yields {found}. The reconciliation is "
            f"not over the sites the record claims it is over.",
            file=sys.stderr,
        )
        return 1
    note = pins.get("campaignNote")
    if not isinstance(note, dict):
        die(f"{PRIOR} carries no `pins.campaignNote`, so nothing reconciles against it.")
    if derived["killedReachable"] - len(found) != int(note["killed"]):
        print(
            f"FAIL: {PRIOR} reconstructs {derived['killedReachable']} reachable kills and "
            f"names {len(found)} the earlier instrument could not see, which leaves "
            f"{derived['killedReachable'] - len(found)}. The released note records "
            f"{note['killed']}. The residue does not close.",
            file=sys.stderr,
        )
        return 1
    inconclusive = sum(
        1 for site in baseline["sites"].values() if site.get("class") == "INCONCLUSIVE"
    )
    census = int(note["killed"]) + int(note["dead"]) + int(note["silent"]) + inconclusive
    if census != derived["sites"]:
        print(
            f"FAIL: the released note's classes total {census} over a baseline of "
            f"{derived['sites']} sites. The two runs did not enumerate the same sites, so "
            f"the difference between them is not the residue this record reconciles.",
            file=sys.stderr,
        )
        return 1
    return 0


def verify_campaign_note(pins: dict[str, Any]) -> int:
    """The site-axis figures the released note carries must still be in it.

    Presence in the named section, not a parse of the sentence: the note is prose
    a later editor may reflow, and a gate that dies on a reflow teaches people to
    delete the gate. What it catches is the case that matters -- the published
    figure being changed to something else while this page still cites it.
    """
    note = pins.get("campaignNote")
    if not isinstance(note, dict):
        # Not "nothing to check". The generated page quotes these figures, so a
        # record without them is a page citing a source this gate never read.
        die(f"{PRIOR} carries no `pins.campaignNote`, and the page cites one.")
    revision = int(note["suiteRevision"])
    text = p(CHANGES).read_text(encoding="utf-8")
    start = text.find(f"## suiteRevision {revision} ")
    if start < 0:
        print(f"FAIL: {CHANGES} carries no suiteRevision {revision} section.", file=sys.stderr)
        return 1
    end = text.find("\n## suiteRevision ", start + 1)
    section = text[start : end if end > 0 else len(text)]
    for member in ("killed", "dead", "silent", "vectors", "sites"):
        # Digit-bounded: a bare `in` would find 316 inside 1316 and report a
        # figure that is no longer there as still there.
        if not re.search(rf"(?<!\d){note[member]}(?!\d)", section):
            print(
                f"FAIL: {CHANGES} suiteRevision {revision} no longer carries {note[member]}, "
                f"which {PRIOR} cites as its `{member}` figure.",
                file=sys.stderr,
            )
            return 1
    return 0


# ---------------------------------------------------------------------------
# the code axis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CodeAxis:
    """What the emission-removal operator says about each declared failure code."""

    omissible: list[tuple[str, str, dict[str, int]]]
    measured: int
    unmeasurable: list[str]
    unattributed: int


def declared_codes() -> dict[str, str]:
    """Constant name -> wire spelling, from the rail's closed set."""
    declared = dict(CODE_DECL.findall(p(CODES_GO).read_text(encoding="utf-8")))
    if not declared:
        die("aee/codes.go declares no failure code, so no code can be attributed.")
    return declared


def code_axis(baseline: dict[str, Any]) -> CodeAxis:
    """Classify each code by the emission-removal sites that name it."""
    declared = declared_codes()
    seen: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    unattributed = 0
    for key, site in baseline["sites"].items():
        parts = key.split("::")
        if len(parts) < 3:
            die(
                f"{key} is not a site key of the form file::function::OPERATOR::hash, so the "
                "operator it was produced by cannot be read. A site whose operator is unknown "
                "is not evidence either way about the code inside it."
            )
        if parts[2] != "CODE_OFF":
            continue
        tokens = set(CODE_TOKEN.findall(site.get("snippet", "")))
        if not tokens:
            unattributed += 1
            continue
        if stray := sorted(tokens - set(declared)):
            die(
                f"{key} names {stray}, which aee/codes.go does not declare. The recorded "
                "snippet is clipped at a fixed width, so a partial identifier lands here; "
                "resolving it by guessing is how a published weak spot becomes a claim of "
                "coverage. Widen the recorded snippet rather than loosening this match."
            )
        for token in tokens:
            seen[token][str(site["class"])] += 1
    omissible = [
        (name, declared[name], dict(counts))
        for name, counts in sorted(seen.items())
        if not counts["KILLED"]
    ]
    return CodeAxis(
        omissible=omissible,
        measured=len(seen),
        unmeasurable=sorted(declared[name] for name in set(declared) - set(seen)),
        unattributed=unattributed,
    )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def para(text: str) -> str:
    """One paragraph, whitespace-collapsed and wrapped, so a diff stays local."""
    # Hyphen and long-word breaking are both off: every identifier on this page is
    # hyphenated, and a wrap inside one turns a code a reader is meant to grep for
    # into two strings that match nothing.
    return textwrap.fill(
        " ".join(text.split()),
        width=WRAP,
        break_on_hyphens=False,
        break_long_words=False,
    )


def suite_revision() -> int:
    headings = [int(m.group(1)) for m in REVISION_HEADING.finditer(p(CHANGES).read_text("utf-8"))]
    if not headings:
        die("vectors/CHANGES.md carries no suiteRevision heading, so the corpus is unversioned.")
    return max(headings)


def provenance_block(manifest: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """The table a reproducer works from.

    It used to say "upstream commit <sha>" and name no repository, next to a
    `tracksUpstream` of `in-toto/attestation#570`, which reads as an
    instruction to fetch the commit from there. It is not there: the pull
    request is opened from a fork branch, and a plain clone of the review venue
    resolves neither the commit nor the bytes. So the row now names the
    repository and ref the commit is actually fetchable from, read from
    ``spec/VENDOR-PIN.json``, which is where that fact is derived, and the
    review venue gets a row of its own instead of being inferred from adjacency.
    """
    counts = manifest["counts"]
    tally = baseline["counts"]
    total = len(manifest["vectors"])
    pin_path = p(VENDOR_PIN)
    if not pin_path.is_file():
        die(
            f"{VENDOR_PIN} is absent, so this table cannot say where the "
            "vendored commit is fetchable from. Refusing rather than raising: "
            "a traceback here exits 1, which is this gate's code for a stale "
            "document, and a caller cannot tell an unreadable tree from a "
            "wrong one."
        )
    pin = json.loads(pin_path.read_text("utf-8"))
    missing = [k for k in ("commitRepo", "ref", "refKind") if not pin.get(k)]
    if missing:
        die(
            f"{VENDOR_PIN} carries no {', '.join(missing)}, so this table "
            "cannot say where the vendored commit is fetchable from. Re-run "
            "scripts/vendor-spec.py, which derives all three."
        )
    return [
        "| what | value |",
        "|---|---|",
        f"| suite | `{manifest['suite']}` |",
        f"| corpus | suiteRevision {suite_revision()}, {total} vectors "
        f"({counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate) |",
        f"| vendored specification | commit `{manifest['specUpstreamCommit']}`, "
        f"fetchable from `{pin['commitRepo']}` at {pin['refKind']} "
        f"`{pin['ref']}` |",
        f"| reviewed at | `{manifest['tracksUpstream']}` |",
        f"| `vectors/MANIFEST.json` | `sha256:{digest(p(MANIFEST))}` |",
        f"| `docs/FORCING-BASELINE.json` | `sha256:{digest(p(BASELINE))}` |",
        f"| campaign | {sum(tally.values())} single-site weakenings: "
        f"{tally['KILLED']} KILLED, {tally['SILENT']} SILENT, "
        f"{tally['DEAD']} DEAD, {tally['INCONCLUSIVE']} INCONCLUSIVE |",
    ]


def condition_table(rows: list[ConditionRow]) -> list[str]:
    out = [
        "| condition | spec anchor | rule | vectors | kills it shares |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        out.append(f"| `{row.cid}` | {row.anchor} | {row.text} | {row.vectors} | {row.shared} |")
    return out


def code_table(axis: CodeAxis) -> list[str]:
    out = ["| code | sites, by outcome |", "|---|---|"]
    for _, wire, counts in axis.omissible:
        spread = ", ".join(f"{n} {cls}" for cls, n in sorted(counts.items()))
        out.append(f"| `{wire}` | {spread} |")
    return out


def lower_bound_note(manifest: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Say, where the number is, when the number is a lower bound.

    A corpus can move without the campaign behind the baseline being re-run, and
    the figures above would then be computed from killer sets that predate part of
    the corpus. That is exactly the drift this page exists to end, so it is stated
    beside the headline rather than in a limits list, and it disappears on its own
    once a full sweep covers every vector.
    """
    orphans = vectors_no_site_depends_on(manifest, baseline)
    if not orphans:
        return [
            para(
                "Every vector in the corpus is depended on by at least one recorded weakening, "
                "so no vector is wholly redundant and the campaign covers the corpus as it "
                "stands."
            ),
            "",
        ]
    return [
        para(
            f"**Read the figures above as a lower bound.** {len(orphans)} of the corpus's "
            "vectors appear in no recorded killer set: "
            + ", ".join(f"`{vid}`" for vid in orphans)
            + ". Either they force nothing this rail's weakenings can express, or the campaign "
            "predates them, and the two input digests above are how a reader tells which. Until "
            "a full sweep covers them, a weakening one of them would catch is recorded here as "
            "caught by nobody."
        ),
        "",
    ]


def anchor_note(axis: CodeAxis) -> list[str]:
    """The one interpretation on this page, derived rather than typed.

    Some of the codes a rail may decline to emit are the consumer-policy anchor
    comparison, which the unforced-coverage register already records as out of a
    self-contained corpus's reach by construction. Which codes those are is read
    off the declared set rather than written down, so the paragraph cannot outlive
    the fact -- and it disappears entirely if the group ever empties.
    """
    anchors = [wire for name, wire, _ in axis.omissible if name.endswith("AnchorMismatch")]
    if not anchors:
        return []
    named = " and ".join(f"`{wire}`" for wire in anchors)
    return [
        "",
        para(
            f"{named} are the consumer-policy anchor comparison, which "
            "`vectors/coverage-unforced.json` cell U5 already records as unreachable by a "
            "self-contained corpus by construction: the anchor is an operand each consumer "
            "supplies, and no vector can carry one. The rest are unminted rather than "
            "unmintable, and each is a vector somebody could write."
        ),
    ]


def requirement_axis() -> list[str]:
    """The third axis, and the only one already published: per-requirement coverage.

    Read from the same register `scripts/coverage-matrix-gate.py` renders, so this
    page carries the count and the matrix carries the rows, and neither restates
    the other by hand.
    """
    cells = load_json(UNVECTORED).get("cells")
    if not isinstance(cells, list) or not cells:
        die("vectors/coverage-unforced.json records no cells, so the requirement axis is empty.")
    tally = collections.Counter(str(cell["classification"]) for cell in cells)
    out = ["| classification | count |", "|---|---|"]
    out += [f"| {label} | {count} |" for label, count in sorted(tally.items())]
    return out


def annotation_table(baseline: dict[str, Any]) -> list[str]:
    out = ["| site | annotation | why no vector can kill it |", "|---|---|---|"]
    for key, note in sorted(baseline.get("annotations", {}).items()):
        reason = " ".join(str(note["reason"]).split())
        out.append(f"| `{key}` | {note['status']} | {reason} |")
    return out


def headline(rows: list[ConditionRow]) -> tuple[int, int, int, int]:
    tally = collections.Counter(row.verdict for row in rows)
    return len(rows), tally["FORCED"], tally["WEAK"], tally["UNFORCED"]


def render(manifest: dict[str, Any], baseline: dict[str, Any]) -> str:
    rows = condition_rows(manifest, baseline)
    axis = code_axis(baseline)
    total, forced, weak, unforced = headline(rows)
    weak_rows = [row for row in rows if row.verdict == "WEAK"]
    unforced_rows = [row for row in rows if row.verdict == "UNFORCED"]
    body = [
        _HEADER,
        "# Where this suite is weak",
        "",
        para(_INTRO),
        "",
        "## The figure, and what it measures",
        "",
        para(
            f"**Of the {total} normative conditions this corpus cites, {forced} are forced by "
            f"a vector no other condition's vectors duplicate, {weak} are covered only "
            f"redundantly, and {unforced} are not forced at all.**"
        ),
        "",
        *provenance_block(manifest, baseline),
        "",
        *lower_bound_note(manifest, baseline),
        _DEFINITIONS,
        "",
        *prior_block(load_prior()),
        "",
        "## The conditions nothing uniquely attributes to their own vectors",
        "",
        para(_WEAK_PREAMBLE),
        "",
        *(condition_table(weak_rows) if weak_rows else ["None."]),
        "",
        "## The conditions the corpus does not force at all",
        "",
        *(condition_table(unforced_rows) if unforced_rows else [para(_NO_UNFORCED)]),
        "",
        "## The failure codes a rail can decline to emit",
        "",
        para(_CODE_PREAMBLE),
        "",
        *(code_table(axis) if axis.omissible else ["None."]),
        *anchor_note(axis),
        "",
        para(
            f"That is measured over the {axis.measured} codes an emission-removal site names "
            f"directly. {len(axis.unmeasurable)} of the rail's declared codes are reached only "
            "through a shared helper that takes the code as an argument, and "
            f"{axis.unattributed} emission-removal sites name no code for the same reason. "
            "Those codes are not measured on this axis, and they are not counted as forced "
            "either: " + ", ".join(f"`{wire}`" for wire in axis.unmeasurable) + "."
        ),
        "",
        "## The requirements no vector pins, which is a separate register",
        "",
        para(_REQUIREMENT_PREAMBLE),
        "",
        *requirement_axis(),
        "",
        "## The sites no vector can ever kill, and why that is not a gap",
        "",
        para(_ANNOTATION_PREAMBLE),
        "",
        *annotation_table(baseline),
        "",
        "## What this measurement does not establish",
        "",
        _LIMITS,
        "",
        "## Regenerating every number above",
        "",
        regenerate_block(load_prior()),
        "",
    ]
    return "\n".join(body)


_HEADER = """\
<!--
GENERATED by scripts/condition-forcing-gate.py from vectors/MANIFEST.json,
docs/FORCING-BASELINE.json, docs/PRIOR-FORCING.json, vectors/reject/INDEX.md,
vectors/CHANGES.md and aee/codes.go. Do not hand-edit; run the gate to
regenerate. CI runs it with --check and fails on drift, and the nightly sweep
runs it with --verify-prior, which re-derives the earlier figure from git.
scripts/condition-forcing-crosscheck.py re-derives every figure below under a
second implementation sharing no code with the generator, because drift and
correctness are different properties and --check only sees the first.
-->"""

_INTRO = """\
A conformance suite that publishes only what it covers is asking to be taken on trust.
This document is the other half: the conditions this corpus cites and does not
uniquely force, the failure codes a conforming verifier can decline to emit
entirely, and the sites no vector can ever reach. Every number here is derived
from the published mutation baseline on every run, by the gate named in the
comment above, so it cannot drift from the data it summarises."""

_DEFINITIONS = """\
The corpus cites the specification's rules by `aee-c-NN` condition id on every
vector. Take the vectors citing one condition, and ask what the mutation campaign
in `docs/FORCING-BASELINE.json` says about them:

-   **forced** -- some rail weakening is caught by those vectors and by no
    others. Delete them and that weakening goes undetected.
-   **weak** -- they catch weakenings, but every one is also caught by a vector
    citing something else. The rule is covered; nothing is uniquely attributable
    to this condition.
-   **not forced** -- they catch no weakening at all.

**Weak is a statement about attribution, not about strength, and it does not move
in one direction.** Adding a vector that happens to catch an already-caught
weakening enlarges that weakening's killer set, which can move a condition from
forced to weak while the corpus got strictly better. Two of these figures from
different revisions are not a trend line, and a rise in the weak count is not a
regression."""


def prior_block(record: dict[str, Any]) -> list[str]:
    """The earlier figure, what it was taken over, and what cannot be re-derived."""
    pins, d = record["pins"], record["derived"]
    note = pins["campaignNote"]
    return [
        para(
            f"**The figure this replaces, and what could not be re-derived about it.** A "
            f"condition projection was quoted before this page existed: {d['weak']} of "
            f"{d['conditions']} conditions weak, over the corpus at suiteRevision "
            f"{pins['suiteRevision']}. Its own campaign put its site-axis half in "
            f"`vectors/CHANGES.md` under suiteRevision {note['suiteRevision']} -- "
            f"{note['sites']} single-site weakenings over {note['vectors']} vectors, "
            f"{note['killed']} killed, {note['dead']} byte-identical, {note['silent']} seen "
            f"and tolerated -- and recorded, in the same entry, that the measurement's full "
            f"tables are held outside this repository. **So the quoted figure could not be "
            f"re-derived from anything this repository published, and the condition half had "
            f"never been published at all.** It circulated beside a site-axis figure from a later "
            f"corpus: one method, two corpora, two dates, and the appearance of a "
            f"disagreement that was never there."
        ),
        "",
        para(
            f"It is reproducible now. `docs/PRIOR-FORCING.json` pins the earliest forcing "
            f"baseline this repository carries (`{pins['baselineCommit'][:12]}`, "
            f"{d['sites']} sites) and the tree the original campaign recorded as the one it "
            f"ran against (`{pins['manifestCommit'][:12]}`, {d['vectors']} vectors), and "
            f"`--verify-prior` re-derives the projection from those two objects: "
            f"**{d['forced']} forced, {d['weak']} weak, {d['unforced']} unforced across "
            f"{d['conditions']} conditions**, which is the quoted figure exactly. Every one of "
            f"the seven numbers this page used to carry as a typed constant survives the "
            f"reconstruction unchanged. **That is the finding, not a vindication: a figure "
            f"nobody could re-derive was indistinguishable from a wrong one until somebody "
            f"re-derived it, and seven typed constants would have read exactly the same on the "
            f"day they stopped being true.**"
        ),
        "",
        para(
            f"**The reconstruction is an approximation, and here is its shape.** Restricting "
            f"the later baseline's killer sets to the {d['vectors']} vectors of the earlier "
            f"corpus says which weakenings that corpus still catches; it says nothing about "
            f"whether a weakening it stops catching was tolerated or ignored then. The "
            f"condition projection never reads that distinction, so the approximation is "
            f"exact on this axis and silent on the other. {d['killedDropped']} recorded "
            f"weakenings are killed only by vectors that did not exist yet and are dropped; "
            f"{d['killedReachable']} survive, which is {d['killedReachable'] - note['killed']} "
            f"more than the released note records for the same corpus."
        ),
        "",
        *instrument_delta_block(record),
        "",
        para(
            "The current figure below is not a constant at all. It is derived from the "
            "committed baseline on every run, so the two can never again be quoted from "
            "different dates."
        ),
    ]


def instrument_delta_block(record: dict[str, Any]) -> list[str]:
    """The residue, closed: which weakenings the earlier instrument could not see.

    This was published as unexplained for as long as it was, which was right at
    the time and is not a place to leave a number. It is an arithmetic identity
    over two git objects now, and the identity is stated where the number is so
    a reader can do the addition without leaving the paragraph.
    """
    pins, d = record["pins"], record["derived"]
    note, delta = pins["campaignNote"], pins["instrumentDelta"]
    residue = d["killedReachable"] - note["killed"]
    sites = "".join(f"\n-   `{one}`" for one in sorted(str(s) for s in delta["sites"]))
    return [
        para(
            f"**That residue is not a mystery, and it is not the obvious explanation "
            f"either.** The reference rail is byte-identical at the two pinned commits, so "
            f"the two runs enumerated the same sites and a moved rail explains nothing. What "
            f"moved is the instrument. Exactly {residue} of the weakenings this "
            f"reconstruction counts sit on the branch a verifier takes when the consumer "
            f"supplies no substrate key policy at all:"
        ),
        sites,
        "",
        para(
            f"Removing any of those {residue} changes nothing on a run that supplies a key "
            "policy, because the branch is not taken. Only a run that also makes a no-key "
            "pass can see them, and the run behind the released note made no such pass: "
            "before the `AEE_SUBSTRATE_KEYS` channel existed the harness recorded "
            "`tiers_without_key: None` for every run and the evaluator skips a tier column "
            "it was handed nothing for. This repository's README and "
            "`packaging/run_vectors.py` both say so, in the section on why each vector is "
            "now run twice."
        ),
        "",
        para(
            f"So the whole difference between the two runs closes, and closes exactly: "
            f"**{d['killedInBaseline']} killed in the pinned baseline = {note['killed']} in "
            f"the released note + {d['killedDropped']} killed only by vectors added "
            f"afterwards + {residue} the earlier instrument could not observe.** "
            f"`--verify-prior` derives that {residue}-site set from the baseline by the "
            f"`{delta['branch']}` branch rather than reading this list, refuses if the "
            f"derived set is not the set named in `docs/PRIOR-FORCING.json`, refuses if the "
            f"subtraction does not land on the note's figure, and refuses if the note's four "
            f"classes do not account for every site in the baseline -- which is what stops "
            f"the sum closing on two errors that cancel."
        ),
        "",
        para(
            f"**What that does not establish, stated because the arithmetic is seductive.** "
            f"The earlier campaign's own per-site table is not in this repository, so nothing "
            f"here checks, site by site, that those {residue} are the ones it scored "
            f"differently. What is checked is that they are the only candidates the mechanism "
            f"admits and that the identity lands on the published figure with no slack. An "
            f"exact closure over a derived set is strong and it is not a per-site diff, and "
            f"the difference between those two is the sort of thing this page exists to keep "
            f"visible."
        ),
    ]


_REQUIREMENT_PREAMBLE = """\
A third register, kept separately because it answers a different question. The condition
axis above asks what a vector forces; `vectors/coverage-unforced.json` asks, requirement by
requirement, whether a self-contained vector could pin it at all, and
`docs/COVERAGE-MATRIX.md` carries the rows. The counts are here so this page is the whole
answer and the matrix stays the detail."""

_WEAK_PREAMBLE = """\
Each of these conditions is cited by live vectors that catch real weakenings of
the rail. What none of them has is a weakening that its vectors alone catch. The
practical reading: a third-party verifier could get the rule in this row wrong in
some way this corpus does not separate from a neighbouring rule, and still pass.
The `kills it shares` column is how many weakenings its vectors catch alongside
somebody else's."""

_NO_UNFORCED = """\
None. Every condition this corpus cites is caught by at least one of its own
vectors. That is the one place this measurement comes out better than the
headline suggests, and it is stated with the same weight as the rest."""

_CODE_PREAMBLE = """\
A separate question, and a harder one: can a conforming verifier decline to emit a
failure code at all? It is measured with the one mutation operator that removes exactly
one emission and nothing else, because the operator that removes the enclosing statement
takes a field parse down with it on a parse block and is then killed for a reason that has
nothing to do with the code inside. In the campaign recorded above, removing any single
emission below left every vector passing, so nothing in this suite obliges an implementer
to produce these codes."""

_ANNOTATION_PREAMBLE = """\
Two kinds of site are recorded in the baseline as unkillable rather than unforced,
because writing a vector for them is wasted work. `unkillable` is a true
equivalent mutant: the weakened rail computes exactly what the original computes,
on every input. `masked` is a real rule that an earlier check reaches first on
every input that could get to it, so it cannot be forced as the corpus and the
rail stand. Both are claims about the world and the forcing gate falsifies them:
an annotated site that is ever killed fails the build."""

_LIMITS = """\
-   **It is a property of a pair.** Forcing is measured against one reference
    rail. A rule this corpus does not force on that rail might still be forced on
    another whose control flow differs, and the reverse.
-   **A weakening operator is not an attacker.** The campaign removes guards,
    disjuncts, conjuncts, emissions and boolean returns one at a time, and
    restricts one collection loop at a time to a single member. A verifier
    wrong in a way no single-site weakening expresses is not measured here.
-   **The quantifier operator asks about the SECOND member, and cuts both
    ways.** `LOOP_FIRST` closes a loop body with a `break`, so a rule the
    specification states over every member of a carried collection is applied
    to one member only. Where the loop is a universal, that is a weakening, and
    a vector that still passes was never forcing the "every": it carried one
    witness, or its defective member was the one the weakened rail still looks
    at. Where the loop is instead a SEARCH for one satisfying member, the same
    edit narrows the search and makes the rail stricter rather than laxer. Both
    are scored the same way, by replaying the corpus, so a row here says the
    corpus notices the loop being cut short; read the direction off the site.
-   **The condition classes cannot be compared across revisions.** See the
    definition above: attribution depends on the rest of the corpus, so the
    classification is only meaningful against the inputs named in the provenance
    table.
-   **Some codes are not measured at all**, and are listed above rather than
    assumed either way.
-   **The unmeasurable sites stay unmeasurable.** The baseline's INCONCLUSIVE
    class is mutants that did not generate, build, terminate or run cleanly.
    Nothing is asserted about them and they are never folded into a gap count."""


def regenerate_block(record: dict[str, Any]) -> str:
    """Every number on the page, and the command that produces it."""
    pins = record["pins"]
    return f"""```sh
# the document, from the committed data; --check fails instead of writing
python3 scripts/condition-forcing-gate.py --check

# the earlier figure, re-derived from the two git objects it is pinned to
python3 scripts/condition-forcing-gate.py --verify-prior   # needs a full clone

# the same figures under a SECOND implementation that shares no code with the
# generator, because a number confirmed by the program that wrote it is not
# confirmed. It recomputes from the two inputs and reads this page's prose back
python3 scripts/condition-forcing-crosscheck.py --with-prior

# the rail at those two commits, which is why a moved rail explains nothing
git diff --stat {pins["manifestCommit"][:12]} {pins["baselineCommit"][:12]} -- aee/

# the data itself: re-run the campaign that produces docs/FORCING-BASELINE.json
python3 scripts/forcing-gate.py --scope all --sync   # needs a Go toolchain

# the input digests in the provenance table
sha256sum vectors/MANIFEST.json docs/FORCING-BASELINE.json
```

The first command reads only files in this repository and needs nothing
installed. It is the one to run when checking a number quoted from here. The
second, third and fourth read history, so a shallow clone makes them stop
rather than pass.

The first command proves only that this page has not drifted from the data,
which is a weaker property than it sounds: the generator regenerates the page
and compares, so a generator that read the definitions wrongly would produce a
wrong page and then agree with it. The crosscheck is the answer to that. It
implements the three definitions above independently, recomputes from
`vectors/MANIFEST.json` and `docs/FORCING-BASELINE.json`, and then reads the
headline sentence, the provenance rows and every weak row back out of this page
and refuses on any disagreement."""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the generated document is not current; write nothing",
    )
    parser.add_argument(
        "--verify-prior",
        action="store_true",
        help="re-derive the pinned earlier figure from git and fail on any disagreement",
    )
    parser.add_argument(
        "--sync-prior",
        action="store_true",
        help="write the derived half of docs/PRIOR-FORCING.json from its own pins",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="the tree to read and write; a staged copy, for this gate's own tests",
    )
    args = parser.parse_args()
    global ROOT  # noqa: PLW0603 -- one binding, set once, before anything reads a path
    ROOT = args.root
    if args.sync_prior:
        record = load_prior()
        record["derived"] = reconstruct_prior(record["pins"])
        p(PRIOR).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {PRIOR}")
        return 0
    if args.verify_prior:
        code = verify_prior(load_prior())
        if code == 0:
            print(f"{PRIOR} is what its pinned git objects yield")
        return code
    rendered = render(load_json(MANIFEST), load_json(BASELINE))
    if not args.check:
        p(OUTPUT).write_text(rendered, encoding="utf-8")
        print(f"wrote {OUTPUT}")
        return 0
    if not p(OUTPUT).exists():
        print(
            f"FAIL: {OUTPUT} does not exist. Run this gate without --check to generate it.",
            file=sys.stderr,
        )
        return 1
    if p(OUTPUT).read_text(encoding="utf-8") != rendered:
        print(
            f"FAIL: {OUTPUT} is not what its sources generate. "
            "The corpus or the forcing baseline moved and the published figure did not. "
            "Run this gate without --check and commit the result.",
            file=sys.stderr,
        )
        return 1
    print(f"{OUTPUT} is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
