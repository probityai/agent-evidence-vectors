#!/usr/bin/env python3
"""Generate MANIFEST.json for the AEE v0.7 conformance vector suite.

Derives the machine-readable expectations from the three human-authored
index tables (accept/INDEX.md, reject/INDEX.md and indeterminate/INDEX.md),
which remain the prose source of truth. The MANIFEST is what the differential
harness (packaging/run_vectors.py) consumes: per-vector expected verdict, the
expected failure-code set for reject vectors, any conditions a reject
vector carries deliberately beyond the one it pins (the two together are
the second-fault self-check's exemption key), the expected recomputed
result for accept vectors, the declared readings of each indeterminate
vector, and the expected per-row evidence tiers where
the index pins them. Regenerate byte-identically: python3 gen_manifest.py

One field here is not an expectation and is deliberately consumed by nothing in
that harness: `alsoEmits` records what the REFERENCE RAIL reports beyond the
codes a vector declares, so that the rail's observable output is pinned somewhere
rather than compared against nothing. It changes no rail's obligations and is
enforced separately, by scripts/observed-code-closure-gate.py. See also_emits_of
below for why it is not folded into alsoCarries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))

# The vendored predicate spec the corpus certifies against. Its content digest
# is recorded in the MANIFEST and re-checked in CI (scripts/spec-drift-gate.py)
# so an edit to the spec without a corpus regeneration fails closed instead of
# drifting silently.
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
SPEC_PATH = os.path.normpath(os.path.join(HERE, "..", SPEC_REL))
# Upstream provenance is read from the vendor pin, never restated here. The pin
# is written by scripts/vendor-spec.py from git at vendor time, so the commit
# the corpus certifies against cannot disagree with the bytes it certifies.
PIN_PATH = os.path.normpath(os.path.join(HERE, "..", "spec", "VENDOR-PIN.json"))
# The corpus revision. It has exactly one home -- the newest heading in the
# changelog beside this file -- and this generator copies it into the MANIFEST so
# a consumer can read it without parsing prose. It used to live in prose ALONE,
# and an independent implementer filing a crosswalk read `manifest["suite"]`
# instead, because that was the only suite-shaped key in the file and there was
# nothing better to read. The number a rail must cite is now a field.
CHANGES_PATH = os.path.join(HERE, "CHANGES.md")

# Tier expectations explicitly pinned by the accept/INDEX.md rows that state a
# tier in prose. Each entry is derivable from the vector's own bytes and the
# tier rule (spec:726-735, spec:1074-1075) without running any rail: a
# basis: substrate row is attested exactly when a covering record's signature
# verifies under a policy-named key, every other row is declared, and no key
# policy promotes a row when none is pinned.
#
# GATE 2 is the one output a vector count cannot stand in for. The harness
# compares a tier column only where the MANIFEST states one, so a column no
# vector states is checked against nothing on every rail but this suite's own,
# and for a long time ok-024 was the only row here -- which left the whole of
# tier.go forced by a single vector, and would have let a retitle of that one
# row retire five rules at once with every gate still green.
#
# This table is deliberately not the whole accept set. A column pinned on every
# vector is a recording of what some rail did rather than a claim anybody made,
# and it goes stale on the next regeneration; a column pinned where the index
# already makes the claim in prose is the same claim, machine-checked. The
# property that holds over every accept vector -- that the column partitions on
# the row's basis -- is asserted as an invariant instead, in the runners.
TIER_EXPECTATIONS = {
    # Substrate row, both covering records verify under the pinned key despite a
    # garbage keyid on one and an absent keyid on the other: keyid is a lookup
    # hint and never the check.
    "ok-019-wrong-keyid-sig-verifies": {
        "tierWithPinnedKey": ["attested"],
        "tierWithoutKey": ["unattested"],
    },
    # Substrate row whose covering record is signed over the raw payload rather
    # than the DSSE PAE, so it verifies under no key: the tier's fail-closed
    # path, and a tier fault rather than a validity fault.
    "ok-020-non-pae-signature": {
        "tierWithPinnedKey": ["unattested"],
        "tierWithoutKey": ["unattested"],
    },
    # The payload embeds a tempting public key. Pinned out of band the row is
    # attested; with nothing pinned it stays unattested, because the substrate
    # root is never inferred from the predicate.
    "ok-023-no-tofu-embedded-key": {
        "tierWithPinnedKey": ["attested"],
        "tierWithoutKey": ["unattested"],
    },
    "ok-024-mixed-basis-rows": {
        "tierWithPinnedKey": ["attested", "unattested", "declared"],
        "tierWithoutKey": ["unattested", "unattested", "declared"],
    },
    # An artifact row with two records and a correct batchRoot sitting right
    # beside it: verifiable material is present and the row is still declared
    # under every policy, because basis and not availability is what decides.
    "ok-029-artifact-with-records": {
        "tierWithPinnedKey": ["declared"],
        "tierWithoutKey": ["declared"],
    },
    # One substrate row covered by verifying records and one artifact row, so
    # the mixed-basis column does not rest on ok-024 alone.
    "ok-045-mixed-clean-rows-indirect": {
        "tierWithPinnedKey": ["attested", "declared"],
        "tierWithoutKey": ["unattested", "declared"],
    },
}


def suite_revision(changes_path: str) -> int:
    """The corpus revision, read from the newest changelog heading.

    ONE source, and it is the file that already cannot be wrong: a revision bump
    IS a changelog entry, so a manifest generated without one would be describing
    a corpus nobody recorded. The refusals below are failures, never findings --
    a missing or unreadable changelog says the generator could not establish the
    revision, which is different from the corpus having none.
    """
    try:
        with open(changes_path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise SystemExit(
            f"cannot read {changes_path}: {exc}. The suite revision lives in "
            "that changelog's newest heading and nowhere else, so the MANIFEST "
            "cannot be generated without it."
        ) from exc
    found = [int(m) for m in re.findall(r"^## suiteRevision (\d+)\b", text, re.M)]
    if not found:
        raise SystemExit(
            f"{changes_path} carries no '## suiteRevision <n>' heading. Add the "
            "entry for this revision before regenerating: the MANIFEST copies the "
            "number from there, and a corpus whose revision was never written down "
            "is one no consumer can cite."
        )
    return max(found)


def corpus_files(root: str) -> list[tuple[str, str]]:
    """Every vector file the published digest covers, in the order it covers them.

    ONE layout, and no fallback. A directory per verdict named the answer in the
    path -- measured over each vector's whole path it predicted accept from
    reject perfectly -- so a reader that still parses it keeps the leaky
    structure alive in code where something can write it again. The retired
    layout is refused by name rather than read.
    """
    flat = os.path.join(root, "statements")
    if not os.path.isdir(flat):
        raise SystemExit(
            f"{root} has no statements/ directory. This reads the flat, "
            "content-addressed corpus at suiteRevision 28 and later. A tree "
            "sorted into a directory per verdict is the retired layout, and "
            "nothing here reads it: the reader that did was deleted once the "
            "default branch published the flat corpus, because a published tree "
            "predating suiteRevision 28 is no longer reachable from any ref a "
            "consumer rail can fetch."
        )
    return sorted(
        (f"statements/{name}", os.path.join(flat, name))
        for name in os.listdir(flat)
        if name.endswith(".json")
    )


def _digest_over(files: list[tuple[str, str]]) -> str:
    """The one hashing routine, so two callers cannot drift on the preimage."""
    h = hashlib.sha256()
    for rel, path in files:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with open(path, "rb") as f:
            h.update(hashlib.sha256(f.read()).hexdigest().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def corpus_digest(root: str) -> str:
    r"""A content digest over a corpus tree: sha256 of the sorted
    ``<kind>/<name>\0<sha256-hex>\n`` lines.

    This is the number a consumer rail cannot compute for itself. A rail recomputes
    this same digest over its own vendored copy and compares it against the stamp
    written beside it, which establishes that nobody edited a vendored vector -- and
    establishes nothing whatever about whether that copy is the corpus this
    repository still publishes, because a lagging copy and its own stamp agree with
    each other perfectly. Publishing the digest in the MANIFEST is what gives a rail
    something to disagree with: one fetch of one file at a stable raw URL, and the
    rail's own build can tell that it is behind.

    The definition is duplicated, deliberately and unavoidably, in each consumer's
    vendoring script -- those repositories cannot import from this one in single-repo
    CI. The duplication is not held together by discipline: a copy of this function
    that drifted would recompute a different digest over its own unchanged files and
    stop matching the stamp this repository's vendoring wrote, so it reddens that
    rail's existing self-check on the next run rather than going quiet.
    """
    return _digest_over(corpus_files(root))


# The identifier shapes this corpus publishes, in ONE place because every reader
# of an index table has to agree about them. `vate-` is the family that is not
# numbered from a single sequence: its ids carry the case number and letter of
# the external conformance case that prompted them.
# A published identifier is a digest of the vector's own bytes. It deliberately
# carries no family, no sequence and no verdict: an identifier that said which
# answer a vector wanted let a rail score the corpus without reading it, and
# measured over the whole path it predicted the verdict perfectly.
# THE definition of a published identifier, imported by every reader rather than
# restated. A commit that found and fixed four silent droppers shipped with
# five: indeterminate_rows carried its own inline `^ind-\d`, so when identifiers
# became digests it stopped matching, skipped both rows without complaint, and
# dropped them from the manifest. It was invisible precisely because it looked
# like the four that were fixed. A duplicated constant is how the next audit
# finds a sixth, so there is one spelling and everything references it.
VECTOR_ID_PATTERN = r"v[0-9a-f]{16}"
VECTOR_ID = re.compile(rf"^{VECTOR_ID_PATTERN}$")


def table_rows(md_path: str) -> list[list[str]]:
    """Every vector row of an index's VECTOR table, refusing on one it cannot read.

    The refusal is the point and it was not here before. This used to keep the
    rows whose first cell matched an identifier and SILENTLY DROP the rest, so a
    row whose id stopped matching -- a renamed family, a new prefix, a typo in a
    backtick -- left the table with one fewer vector in it and no complaint
    anywhere. Every closure check downstream runs over what this function
    returned, so a dropped row is not caught later either: it is a vector the
    manifest never knew about, and the counts still agree with each other
    because they are all derived from this same short list.

    Refusing needs a way to tell a vector row from the other tables an index
    carries, and matching the identifier cannot be it -- that is the very thing
    under test. The table is identified by its HEADER instead: the vector table
    is the one whose first column is called `vector`, and the digest-preimage
    and condition-anchor tables beside it are called something else. Inside that
    table every row is a vector row, so a first cell that does not match
    VECTOR_ID is an error rather than something to skip.
    """
    rows: list[list[str]] = []
    inside = False
    with open(md_path, encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            line = line.strip()
            if not line.startswith("|"):
                inside = False
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if not cells:
                continue
            first = cells[0]
            if first == "vector":
                inside = True
                continue
            if not inside:
                continue
            if set(first) <= {"-", ":"} and first:
                continue  # the header's underline
            if VECTOR_ID.match(first.strip("`")):
                rows.append(cells)
                continue
            raise SystemExit(
                f"{md_path}:{number}: a row of the vector table identifies "
                f"itself as {first}, which is not an identifier shape this "
                "corpus publishes. Skipping it silently would drop the vector "
                "from the manifest, and every count derived from it would still "
                "agree. Fix the row, or teach VECTOR_ID the new shape."
            )
    if not rows:
        raise SystemExit(
            f"{md_path}: no vector rows were read at all. Either the table's "
            "first column stopped being called `vector`, or the file no longer "
            "carries one; both produce an empty corpus that agrees with itself."
        )
    return rows


_IND_FAMILY = re.compile(r"^### Family `([^`]+)`")
_IND_READING = re.compile(r"reading `([a-z0-9-]+)`")


def indeterminate_rows(md_path: str) -> list[tuple[str, list[str], list[str]]]:
    """Return (family, reading names in column order, row cells) per vector.

    The reading names come off each family table's own header row rather than
    from a list in this file. A second copy here could disagree with the table a
    reviewer reads, and the thing an indeterminate vector exists to publish is
    exactly which readings were declared.
    """
    out: list[tuple[str, list[str], list[str]]] = []
    family = ""
    readings: list[str] = []
    with open(md_path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if match := _IND_FAMILY.match(line):
                family, readings = match.group(1), []
                continue
            if not line.startswith("|"):
                continue
            if found := _IND_READING.findall(line):
                readings = found
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if not cells:
                continue
            # VECTOR_ID, not a second pattern written out here. This line
            # carried its own `^ind-\d` regex, which is the same defect the
            # vector-table reader had and which survived the round that fixed
            # that one BECAUSE it was spelled separately: when identifiers
            # became digests both indeterminate rows stopped matching, were
            # skipped in silence, and their vectors left the manifest. The
            # corpus-wide closure check is what noticed. One pattern, one place.
            if not VECTOR_ID.match(cells[0].strip("`")):
                if cells[0].startswith("`") and cells[0].endswith("`"):
                    raise SystemExit(
                        f"{md_path}: a row identifies itself as {cells[0]}, which "
                        "is not an identifier shape this corpus publishes. "
                        "Skipping it silently drops the vector from the manifest."
                    )
                continue
            if not family or not readings:
                raise SystemExit(
                    f"{cells[0]}: a vector row with no '### Family' heading or "
                    "no reading columns above it. The family and the readings "
                    "are the whole of what this row declares."
                )
            out.append((family, readings, cells))
    return out


_ALSO_CARRIES = "(also carries:"
_ALSO_EMITS = "(also emits:"
# Every trailing clause a cell may append after the tokens the cell is named
# for. They are listed together because each one ENDS the one before it: a cell
# spelling both clauses must not fold the second one's codes into the first,
# and it must not fold either into the expectation.
_CLAUSES = (_ALSO_CARRIES, _ALSO_EMITS)


def _before_any_clause(cell: str) -> str:
    """The head of a cell: everything before the first trailing clause."""
    cuts = [cell.index(marker) for marker in _CLAUSES if marker in cell]
    return cell[: min(cuts)] if cuts else cell


def _clause_body(cell: str, marker: str) -> str:
    """The text of one named clause, empty when the cell does not spell it.

    A clause runs to the next clause rather than to the end of the cell, so the
    two are order-independent in the index: a row may write `also carries`
    before `also emits` or the other way round and parse the same either way.
    """
    _head, sep, tail = cell.partition(marker)
    if not sep:
        return ""
    ends = [tail.index(other) for other in _CLAUSES if other in tail]
    return tail[: min(ends)] if ends else tail


def codes_of(cell: str) -> list[str]:
    """The expected-rejection code set: a rail conforms when its code is in it.

    A cell may append an "also carries" clause naming conditions the statement
    carries deliberately but that a conforming rail is not expected to report as
    its primary, and an "also emits" clause recording what the reference rail
    additionally reports. Both are split off below and neither widens the
    expectation, since widening it is exactly what a precedence pin must not do.
    """
    return re.findall(r"`([a-z0-9-]+)`", _before_any_clause(cell))


def also_carries_of(cell: str) -> list[str]:
    """Conditions the vector carries on purpose beyond the one it pins.

    They are the second-fault self-check's exemption key in the differential
    harness, and nothing else: declaring one does not make a rail reporting it
    conformant.
    """
    return re.findall(r"`([a-z0-9-]+)`", _clause_body(cell, _ALSO_CARRIES))


def also_emits_of(cell: str) -> list[str]:
    """Codes the REFERENCE RAIL additionally reports on this vector.

    Not an expectation and not an obligation on anybody. A reject vector's
    comparison surface is its verdict and the codes it declares, and this clause
    is outside it in both directions: a second rail is neither required to emit
    these nor failed for omitting them, and adding one here can never satisfy a
    vector that would otherwise go red.

    What it is for is that the rail's own output was unpinned. `bad-817` emitted
    four codes while declaring two, and when the corpus-wide rewrite of
    suiteRevision 27 moved its declared parent from a caught row to a
    reconstructed one, one of the two undeclared codes changed with it, from
    `caught-row-uncovered` to `reconstructed-row-uncovered`. The change was
    correct. Nothing in the repository could see it, because a reject vector is
    graded by INTERSECTING the emitted set with the declared one and an emitted
    code outside that set was compared against nothing at all.

    Deliberately NOT folded into `alsoCarries`, which would have been the
    smaller edit. That clause is the second-fault self-check's exemption key, so
    a code declared there switches OFF a recompute -- and `payload-not-canonical`,
    which `bad-817` needs to declare, sits in the binding fault family, so the
    smaller edit would have bought this pin by disabling `_sfa_binding` on the
    very vector that motivated it. A declaration that a rail emits something
    must never be spelled as an exemption from a check.

    `scripts/observed-code-closure-gate.py` is what makes the clause load-bearing:
    it replays the reference rail and refuses when an emitted code is declared
    nowhere, and equally when a code declared here is no longer emitted.
    """
    return re.findall(r"`([a-z0-9-]+)`", _clause_body(cell, _ALSO_EMITS))


def conditions_of(cell: str) -> list[str]:
    return re.findall(r"aee-c-\d+", cell)


def indeterminate_entries(md_path: str) -> list[dict[str, Any]]:
    """The manifest entries for the indeterminate bucket.

    Each row's expectation is a DETERMINED verdict plus one condition per
    declared reading. Exactly one condition per column is required rather than a
    set, because a reading that predicted several conditions could not be told
    apart from a widened expectation, which is the thing this bucket exists so
    that nobody has to write.
    """
    entries: list[dict[str, Any]] = []
    for family, readings, cells in indeterminate_rows(md_path):
        vid = cells[0].strip("`")
        # cells: id | parent | mutation | conditions | <one per reading> | spec
        predicted = [codes_of(c) for c in cells[4:4 + len(readings)]]
        if any(len(p) != 1 for p in predicted):
            raise SystemExit(
                f"{vid}: each reading column names exactly one condition; got "
                f"{predicted}"
            )
        expected: dict[str, Any] = {
            "verdict": "invalid",
            "family": family,
            "readings": dict(zip(readings, (p[0] for p in predicted), strict=True)),
        }
        # The "also emits" clause rides the CONDITIONS cell here and the codes
        # cell in the reject table, and the asymmetry is the table's rather than
        # a preference. A reject row has one codes cell; an indeterminate row has
        # one per declared reading, and what the rail emits is a property of the
        # vector and not of any single reading, so there is no reading column it
        # could honestly sit in. The conditions cell is the one per-row cell this
        # table has, and conditions_of reads `aee-c-\d+` only, so a backticked
        # code name there is invisible to it.
        if emits := also_emits_of(cells[3]):
            expected["alsoEmits"] = emits
        entries.append(
            {
                "id": vid,
                "kind": "indeterminate",
                "file": f"statements/{vid}.json",
                "conditions": conditions_of(cells[3]),
                "expected": expected,
            }
        )
    return entries


BUILD_IDS = os.path.join(HERE, os.pardir, ".build", "aee-accept-ids.json")


def accept_slugs() -> dict[str, str]:
    """Published identifier -> authoring slug, read from the accept build map.

    TIER_EXPECTATIONS is written by hand and therefore keyed by the slug a
    person types, while the index this generator reads is keyed by the digest a
    vector ships under. Something has to join the two, and it is this map rather
    than a second copy of the correspondence written down somewhere.

    A missing map is a did-not-run: the accept generator writes it on every run
    and this generator is documented to run after it. Guessing would mean
    dropping every tier pin silently, which is the exact failure the
    reconciliation below exists to make loud.
    """
    if not os.path.isfile(BUILD_IDS):
        raise SystemExit(
            f"the accept identifier map is not at {BUILD_IDS}, so no tier pin "
            "can be matched to the vector it pins. Run "
            "vectors/accept/gen_valid_vectors.py first; it writes the map on "
            "every run."
        )
    with open(BUILD_IDS, encoding="utf-8") as handle:
        forward: dict[str, str] = json.load(handle)
    return {vid: slug for slug, vid in forward.items()}


def check_tier_claims(claimed: set[str]) -> None:
    """Refuse a tier pin keyed to a vector the corpus does not carry.

    TIER_EXPECTATIONS is read with .get, so a key matching no vector pins
    nothing AND SAYS NOTHING: the manifest comes out without those tiers and
    every gate over it passes, because the values it would have compared were
    never written. This is the reconciliation that makes that loud, and it lives
    in its own function so main() stays inside the complexity policy.
    """
    unclaimed = sorted(set(TIER_EXPECTATIONS) - claimed)
    if unclaimed:
        raise SystemExit(
            "TIER_EXPECTATIONS names "
            + ", ".join(unclaimed)
            + ", which no accept vector carries. A tier pin keyed to a vector "
            "that is not there pins nothing, and does it without raising: the "
            "manifest loses the tiers and every check over it still passes."
        )


def main() -> int:
    vectors: list[dict[str, Any]] = []
    # Which accept vectors were actually offered a tier pin. TIER_EXPECTATIONS is
    # keyed by identifier and read with .get, so a key that matches no vector
    # stops pinning anything and says nothing at all -- the manifest simply comes
    # out without the tiers, and every gate over it passes because the tiers it
    # would have compared are not there to disagree. The reconciliation below is
    # what makes that loud.
    tiers_claimed: set[str] = set()
    slugs = accept_slugs()

    for cells in table_rows(os.path.join(HERE, "accept", "INDEX.md")):
        vid = cells[0].strip("`")
        result = cells[1]
        expected: dict[str, Any] = {"verdict": "valid", "result": result}
        slug = slugs.get(vid, vid)
        expected.update(TIER_EXPECTATIONS.get(slug, {}))
        tiers_claimed.add(slug)
        vectors.append(
            {
                "id": vid,
                "kind": "accept",
                "file": f"statements/{vid}.json",
                "conditions": conditions_of(cells[2]),
                "expected": expected,
            }
        )

    check_tier_claims(tiers_claimed)

    for cells in table_rows(os.path.join(HERE, "reject", "INDEX.md")):
        vid = cells[0].strip("`")
        codes = codes_of(cells[5])
        if not codes:
            raise SystemExit(f"no expected codes parsed for {vid}")
        expected_reject: dict[str, Any] = {"verdict": "invalid", "codes": codes}
        if also := also_carries_of(cells[5]):
            expected_reject["alsoCarries"] = also
        if emits := also_emits_of(cells[5]):
            expected_reject["alsoEmits"] = emits
        vectors.append(
            {
                "id": vid,
                "kind": "reject",
                "file": f"statements/{vid}.json",
                "conditions": conditions_of(cells[4]),
                "expected": expected_reject,
            }
        )

    vectors.extend(
        indeterminate_entries(os.path.join(HERE, "indeterminate", "INDEX.md"))
    )

    # Closure check: every vector file must have exactly one INDEX row and vice
    # versa. Without this a malformed INDEX row is silently skipped by table_rows
    # and its vector is omitted from the manifest -- silently untested in
    # MANIFEST-mode replay.
    #
    # Asked over the WHOLE corpus rather than once per verdict, because there is
    # one directory now. That also makes this the only place the question can
    # still be asked: each generator used to count the files beside it, and none
    # of them can do that any more without mistaking another generator's output
    # for a stray. Both directions are checked, and the file-with-no-row
    # direction is the one that matters -- a row table_rows could not read used
    # to be skipped in silence, leaving its vector out of the manifest and
    # untested in replay while every count still agreed.
    files = {
        f[: -len(".json")]
        for f in os.listdir(os.path.join(HERE, "statements"))
        if f.endswith(".json")
    }
    indexed = {v["id"] for v in vectors}
    if missing := files - indexed:
        raise SystemExit(
            "vector file(s) with no INDEX.md row (would be silently untested): "
            f"{sorted(missing)}"
        )
    if extra := indexed - files:
        raise SystemExit(f"INDEX.md row(s) with no vector file: {sorted(extra)}")

    ok = sum(1 for v in vectors if v["kind"] == "accept")
    bad = sum(1 for v in vectors if v["kind"] == "reject")
    undecided = sum(1 for v in vectors if v["kind"] == "indeterminate")
    spec_digest = hashlib.sha256(
        open(SPEC_PATH, "rb").read()  # noqa: SIM115 -- one-shot read
    ).hexdigest()
    with open(PIN_PATH, encoding="utf-8") as f:
        pin = json.load(f)
    if pin["specDigest"] != spec_digest:
        raise SystemExit(
            "spec/VENDOR-PIN.json describes different bytes than the vendored "
            f"spec ({pin['specDigest'][:12]}... vs {spec_digest[:12]}...); "
            "re-vendor with scripts/vendor-spec.py before regenerating"
        )
    manifest = {
        "suite": "adversarial-execution-evidence-conformance",
        "suiteRevision": suite_revision(CHANGES_PATH),
        "predicateType": (
            "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
        ),
        "specPath": SPEC_REL,
        "specDigest": spec_digest,
        "tracksUpstream": f"{pin['upstreamRepo']}#{pin['upstreamPullRequest']}",
        "specUpstreamCommit": pin["commit"],
        "counts": {"accept": ok, "reject": bad, "indeterminate": undecided},
        # WHAT A SECOND IMPLEMENTATION IS SCORED ON, stated because it was
        # promised in public and the promise outran the file. In
        # in-toto/attestation#570 the author of the independent checker was told,
        # while he was building it, that this manifest declares the verdict and
        # each accepted statement's result token to be the normative comparison
        # surface, and the per-vector condition codes informative. It declared
        # nothing of the kind, and a commitment that lives only in a comment
        # thread is one nobody downstream can check.
        #
        # The wording matters, because a flat "codes are informative" is refuted
        # by this file's own data: `expected.codes` is carried on every reject
        # entry. Those are what the reference verifier emits, published so a
        # second rail can MEASURE agreement rather than be failed on it. That is
        # exactly what the independent checker does, reporting full conformance
        # alongside reason parity as a separate figure.
        #
        # Scoring a second rail on this vocabulary would make it re-implement
        # these spellings instead of reading the specification, and would hide
        # the divergences the exercise exists to find: the statements two rails
        # both reject for different reasons.
        "comparisonSurface": {
            "normative": ["verdict", "result"],
            "measured": ["codes"],
            "note": (
                "A rail conforms when its verdict, and for an accepted statement "
                "its result token, match this manifest. The codes on a reject "
                "entry are the reference verifier's own vocabulary, not the "
                "specification's: a rail names a reason from whatever set it "
                "declares, and a differing code is a reason-parity datum rather "
                "than a failure. Report that parity as its own figure. The "
                "divergences worth finding are the statements two rails both "
                "reject for different reasons, and scoring on codes would hide "
                "exactly those."
            ),
        },
        # The one field in this file addressed to a reader outside this repository.
        # Everything else here describes the corpus to a harness that already has it;
        # this describes the corpus to a rail that has a DIFFERENT one and cannot
        # otherwise find out. Fetching this file over https is the whole of a
        # consumer's currency check, so the digest rides the artifact whose freshness
        # is already load-bearing for several other reasons rather than a file of its
        # own, which would be one more thing with a single guardian and a long quiet
        # period between the occasions anyone looks at it.
        "corpusDigest": corpus_digest(HERE),
        "vectors": vectors,
    }
    out = os.path.join(HERE, "MANIFEST.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=False)
        f.write("\n")
    print(f"wrote {out}: {ok} accept + {bad} reject + {undecided} indeterminate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
