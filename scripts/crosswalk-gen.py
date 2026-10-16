#!/usr/bin/env python3
"""Crosswalk generator: crosswalks/aee-to-ave.json is produced from two trees,
never edited by hand.

What went wrong without it
--------------------------
The file said `record_count: 59` and `records_read: 2026-07-28` and named no
upstream commit. A date is not a tree. AVE's corpus grew while the file sat
still, so the counts in it were wrong within days and nothing in either
repository could tell a reader whether they had ever been right: the only way to
find out was to go and count the upstream records by hand, which is what AVE's
maintainer ended up doing on a public thread. A count with no commit beside it is
stale by construction rather than by accident.

The same file was also stale about this repository, naming a revision and a
vector total the suite had left behind many revisions earlier -- and the total
it named was not one this suite ever published, so the figure resolved through
nothing at all -- and stale about the predicate
it maps: it used `basis: intercepted` and `method: examination`, which were the
pre-split field shapes. Under v0.7 `basis` is `substrate | artifact` and `method`
is `intercepted | reconstructed`, and `examination` is an `aeeKind`, not a
method. Every one of those is a number or a name that a reader would have had to
already know was wrong in order to not be misled by it.

How it works
------------
Both sides are derived, and the commit each side was derived from is written
beside the figures along with the command that re-derives them.

The upstream side is counted out of a real checkout of aveproject/ave: the
generator resolves that checkout's HEAD, refuses a dirty or unrecognised one,
and counts records by walking `records/AVE-*.json`. The editorial content of a
mapping row -- which AEE field an AVE value corresponds to, and why -- lives in
ROWS below, because that is a judgement and not a measurement. The record counts
attached to those rows are never written there; they are counted.

The local side is read from `vectors/MANIFEST.json` and `vectors/CHANGES.md`,
the same two files scripts/count-gate.py treats as the corpus source of truth.

The generator refuses when the upstream corpus carries a value of a mapped field
that no row covers. Silence would otherwise read as coverage: a crosswalk that
maps four of five `detection_layer` values looks exactly like one that maps all
of them, and the reader cannot see the difference.

This gate is not registered with scripts/regenerability-gate.py, deliberately.
That gate regenerates in a hermetic copy of this tree with no network and no
second checkout, and this generator needs aveproject/ave. Run it with an
explicit checkout instead:

    git clone https://github.com/aveproject/ave /tmp/ave
    python3 scripts/crosswalk-gen.py --ave-repo /tmp/ave
    python3 scripts/crosswalk-gen.py --ave-repo /tmp/ave --check
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
OUT_REL = "crosswalks/aee-to-ave.json"
MANIFEST_REL = "vectors/MANIFEST.json"
CHANGES_REL = "vectors/CHANGES.md"
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)

AVE_REMOTES = ("github.com/aveproject/ave", "github.com:aveproject/ave")

# The command a reader runs to re-derive each side, recorded in the file beside
# the figures it produces. A number whose recipe is not printed next to it is a
# number the next reader has to trust.
UPSTREAM_DERIVED_BY = (
    "git -C <ave-checkout> rev-parse HEAD && "
    "ls <ave-checkout>/records/AVE-*.json | wc -l"
)
# `suiteRevision` is NOT a key in vectors/MANIFEST.json, and a reader who assumes
# it is finds nothing and concludes the corpus has no revision. The authority is
# the FIRST `## suiteRevision N` heading in vectors/CHANGES.md, because that
# changelog is written newest-first: the first heading is the current revision by
# construction, where a maximum is only accidentally the same number and would
# quietly disagree with the file the day a revision was ever written out of order.
SUITE_DERIVED_BY = (
    "python3 -c \"import json,re,pathlib; "
    "m=json.loads(pathlib.Path('vectors/MANIFEST.json').read_text()); "
    "r=re.search(r'^## suiteRevision (\\d+)\\b', "
    "pathlib.Path('vectors/CHANGES.md').read_text(), re.M).group(1); "
    "print(r, len(m['vectors']), m['counts'])\""
)


@dataclass(frozen=True)
class Row:
    """One mapping row. Everything here is editorial except the count, which is
    measured from the upstream tree by the field and value this row names."""

    ave_field: str
    ave_value: str
    aee_field: str
    aee_value: str
    notes: str
    # True for the one row whose upstream record identifiers are small enough to
    # be worth naming, and stable enough to be worth checking.
    list_ave_ids: bool = False


ROWS: tuple[Row, ...] = (
    Row(
        ave_field="detection_stage",
        ave_value="static_detection",
        aee_field="aeeKind",
        aee_value="examination",
        notes=(
            "The component was read, not run. An examination record is the "
            "substrate's account of artifact-independent state inspected after "
            "the fact, and its aeeMethod is necessarily reconstructed. AEE will "
            "not let such a record be signed as intercepted, which is the "
            "structural version of the distinction AVE draws here."
        ),
    ),
    Row(
        ave_field="detection_stage",
        ave_value="runtime_observed",
        aee_field="aeeKind",
        aee_value="interception, under a run-level arming and sealed pair",
        notes=(
            "The component executed and something watched. An interception "
            "record covers the caught event; an arming record says a live "
            "vantage existed before the corpus was injected, and a sealed "
            "record says it stayed armed to run-end. AVE records the stage; "
            "the arming and sealed pair is what makes a clean result at that "
            "stage mean anything, because absence of a catch is only evidence "
            "if something was watching for it."
        ),
    ),
    Row(
        ave_field="detection_stage",
        ave_value="runtime_drift_detected",
        aee_field="method",
        aee_value="reconstructed",
        notes=(
            "Drift is two states compared, not an event captured as it "
            "occurred, so method is reconstructed and the tolerance is part of "
            "the claim: a reconstruction can miss a transient raised and undone "
            "between the states it compares. AEE makes a producer say that in "
            "the signature rather than in a footnote."
        ),
    ),
    Row(
        ave_field="detection_layer",
        ave_value="content",
        aee_field="observationEnvironment",
        aee_value="absent",
        notes=(
            "No execution environment exists to describe, so the environment is "
            "absent rather than stubbed. AEE refuses to dress an examination up "
            "as an observation."
        ),
    ),
    Row(
        ave_field="detection_layer",
        ave_value="runtime",
        aee_field="observationEnvironment",
        aee_value="substrate + corpus + manifest + catchPolicy + networkPosture",
        notes=(
            "A real environment existed and every part of it is pinnable. "
            "networkPosture in particular (no_network, allowlist, sinkhole) "
            "changes what a runtime finding means and is not currently "
            "recoverable from an AVE record."
        ),
    ),
    Row(
        ave_field="detection_layer",
        ave_value="registry_metadata",
        aee_field="method",
        aee_value="reconstructed",
        notes=(
            "The observation is about a registry response, so the fetch itself "
            "is the thing needing provenance and the claim rests on state read "
            "after the fact."
        ),
    ),
    Row(
        ave_field="detection_layer",
        ave_value="server_card",
        aee_field="method",
        aee_value="reconstructed",
        notes="Same, for a declared capability document.",
    ),
    Row(
        ave_field="detection_layer",
        ave_value="transport",
        aee_field="basis",
        aee_value="substrate",
        notes=(
            "A network boundary is the canonical cooperation-independent "
            "vantage in AEE's basis vocabulary: the observed component cannot "
            "cause the boundary to record an egress without performing one, and "
            "cannot suppress the record either. This is the AVE layer where an "
            "AEE row can carry its strongest basis, and it is the layer with "
            "the fewest AVE records today."
        ),
    ),
    Row(
        ave_field="evidence_basis_engines",
        ave_value="sandbox",
        aee_field="basis",
        aee_value="substrate, with method intercepted",
        notes=(
            "The engine value where a substrate basis is available, because "
            "here the component actually ran and something outside it watched. "
            "Both members are required on every AEE row and both compose by "
            "weakest input, so a sandbox observation fused with the "
            "component's own stdout degrades to artifact rather than "
            "silently keeping the stronger label."
        ),
        list_ave_ids=True,
    ),
    Row(
        ave_field="evidence_basis_engines",
        ave_value="external_authority",
        aee_field="basis",
        aee_value="artifact, with method reconstructed",
        notes=(
            "The engine that asks a third party what is true right now: GitHub's "
            "users API for an owner, a package registry for a name, RDAP for a "
            "domain. The authority is outside the observed component's control, "
            "which is the half of substrate that holds, but nothing was watched "
            "while it ran and the finding is assembled from state afterwards, "
            "which is why method is reconstructed rather than intercepted. An AEE "
            "row for this engine has to carry the authority's own answer, because "
            "a finding that only says the anchor was claimable is a declared "
            "claim and the reader has no way to recheck it. AVE's own detection "
            "methodology for the first record carrying this engine already "
            "requires the degraded case explicitly, a check that could not "
            "complete must produce silence rather than a claim of compromise, "
            "which is AEE result degraded and not a missing row."
        ),
        list_ave_ids=True,
    ),
    Row(
        ave_field="evidence_basis_engines",
        ave_value="llm",
        aee_field="aeeKind",
        aee_value="examination",
        notes=(
            "The case where a signed record helps most: a model's judgement is "
            "exactly the kind of claim a reader has no independent way to "
            "check."
        ),
    ),
)

# Values a mapped field may carry upstream that no row covers, each with the
# reason. The generator refuses on any value that is in neither ROWS nor here,
# so a new upstream value cannot pass as covered by staying quiet.
KNOWN_UNCOVERED: dict[tuple[str, str], str] = {
    ("evidence_basis_engines", "pattern"): (
        "A detection technique, not a vantage. AEE has nothing to say about "
        "how a static rule matched."
    ),
    ("evidence_basis_engines", "yara"): "Same as pattern.",
    ("evidence_basis_engines", "semgrep"): "Same as pattern.",
    ("evidence_basis_engines", "magika"): "Same as pattern.",
}

UNMAPPED: tuple[dict[str, str], ...] = (
    {
        "ave_field": "confidence_baseline",
        "reason": (
            "AEE has no confidence field and will not gain one. It expresses "
            "trust structurally instead: an evidence tier (declared, attested, "
            "unattested) says who stands behind the observation, basis "
            "(substrate, artifact) says whether the claim rests on a vantage "
            "the observed component could not forge or suppress, method "
            "(intercepted, reconstructed) says whether the event was captured "
            "as it happened or reconstructed from state afterwards, and result "
            "carries a degraded value so partial observation stays reportable "
            "as partial. A reader who sees confidence_baseline 0.83 learns what "
            "the author believed; a reader who sees an attested tier with basis "
            "substrate and method intercepted learns something verifiable "
            "without trusting the author. The proposal is to keep "
            "confidence_baseline as the human-facing summary it already is and "
            "let an optional AEE attachment carry the checkable part. Tracked "
            "upstream as aveproject/ave#98."
        ),
    },
)

LIMITS: tuple[str, ...] = (
    "AEE detects nothing and does not compete with AVE's classification work. "
    "It cannot tell you a component is malicious, only whether the account of "
    "how you found out is checkable.",
    "AEE is presently exercised by a first-party implementation set, so "
    "cross-rail agreement is a drift check rather than independent "
    "corroboration.",
    "The predicate is a proposal to in-toto, made in attestation pull request "
    "570, not a ratified standard.",
)

NOTE = (
    "AEE is not a scanner and emits no finding IDs, so a finding-to-record "
    "table would invent a correspondence that does not exist. This maps AVE's "
    "existing evidence-provenance vocabulary onto AEE's evidence structure "
    "instead: for each way AVE already describes how a finding was reached, "
    "what the corresponding signed, offline-verifiable record looks like. "
    "Every count in this file is derived by scripts/crosswalk-gen.py from the "
    "upstream commit named in target.commit and from this repository's own "
    "vectors/MANIFEST.json; the command for each side is recorded beside the "
    "figures it produces. Offered as a basis for collaboration, not as a "
    "competing taxonomy."
)


@dataclass
class Upstream:
    """The AVE tree the counts were taken from."""

    commit: str
    records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        return len(self.records)

    def values_of(self, ave_field: str) -> Counter[str]:
        seen: Counter[str] = Counter()
        for record in self.records:
            value = record.get(ave_field)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        seen[item] += 1
            elif isinstance(value, str):
                seen[value] += 1
        return seen

    def ids_with(self, ave_field: str, ave_value: str) -> list[str]:
        found: list[str] = []
        for record in self.records:
            value = record.get(ave_field)
            hit = ave_value in value if isinstance(value, list) else value == ave_value
            if hit:
                identifier = record.get("ave_id")
                if isinstance(identifier, str):
                    found.append(identifier)
        return sorted(found)


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(
            f"FAIL: git {' '.join(args)} in {repo} exited {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def load_upstream(repo: Path) -> Upstream:
    """Resolve the checkout and read its records.

    A dirty checkout is refused: the commit written into the file would then
    name a tree that is not the tree the counts came from, which is the exact
    defect this generator exists to remove, restated one level down.
    """
    if not (repo / ".git").exists():
        raise SystemExit(f"FAIL: {repo} is not a git checkout")

    remotes = git(repo, "remote", "-v")
    if not any(marker in remotes for marker in AVE_REMOTES):
        raise SystemExit(
            f"FAIL: {repo} has no aveproject/ave remote; its remotes are:\n{remotes}"
        )

    dirty = git(repo, "status", "--porcelain")
    if dirty:
        raise SystemExit(
            f"FAIL: {repo} has uncommitted changes, so its HEAD does not describe "
            f"the tree the counts would be taken from:\n{dirty}"
        )

    commit = git(repo, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(f"FAIL: {repo} HEAD did not resolve to a full sha: {commit!r}")

    record_paths = sorted((repo / "records").glob("AVE-*.json"))
    if not record_paths:
        raise SystemExit(f"FAIL: {repo}/records holds no AVE-*.json files")

    records = [json.loads(path.read_text(encoding="utf-8")) for path in record_paths]
    return Upstream(commit=commit, records=records)


def suite_figures() -> dict[str, Any]:
    """This repository's own corpus, from the two files count-gate.py reads."""
    manifest = json.loads((REPO / MANIFEST_REL).read_text(encoding="utf-8"))
    changes = (REPO / CHANGES_REL).read_text(encoding="utf-8")
    heading = REVISION_HEADING.search(changes)
    if heading is None:
        raise SystemExit(f"FAIL: {CHANGES_REL} carries no '## suiteRevision N' heading")
    counts = manifest["counts"]
    return {
        "revision": int(heading.group(1)),
        "vectors": len(manifest["vectors"]),
        "accept": counts["accept"],
        "reject": counts["reject"],
        "indeterminate": counts["indeterminate"],
        "derived_by": SUITE_DERIVED_BY,
    }


def check_coverage(upstream: Upstream) -> None:
    """Refuse when a mapped field carries an upstream value no row covers."""
    mapped: set[tuple[str, str]] = {(row.ave_field, row.ave_value) for row in ROWS}
    fields = sorted({row.ave_field for row in ROWS})
    missing: list[str] = []
    for ave_field in fields:
        for value, count in sorted(upstream.values_of(ave_field).items()):
            key = (ave_field, value)
            if key not in mapped and key not in KNOWN_UNCOVERED:
                missing.append(f"  {ave_field} = {value} ({count} record(s))")
    if missing:
        raise SystemExit(
            "FAIL: the upstream corpus carries values of a mapped field that no "
            "row in ROWS covers and no entry in KNOWN_UNCOVERED excuses. A "
            "crosswalk silently missing a value reads exactly like one that "
            "covers it. Add a row or an exclusion with a reason:\n"
            + "\n".join(missing)
        )


def build(upstream: Upstream, records_read: str) -> dict[str, Any]:
    mappings: list[dict[str, Any]] = []
    for row in ROWS:
        entry: dict[str, Any] = {
            "ave_field": row.ave_field,
            "ave_value": row.ave_value,
            "record_count": upstream.values_of(row.ave_field)[row.ave_value],
            "aee_field": row.aee_field,
            "aee_value": row.aee_value,
            "notes": row.notes,
        }
        if row.list_ave_ids:
            entry["ave_ids"] = upstream.ids_with(row.ave_field, row.ave_value)
        mappings.append(entry)

    uncovered = [
        {"ave_field": ave_field, "ave_value": value, "reason": reason}
        for (ave_field, value), reason in sorted(KNOWN_UNCOVERED.items())
    ]

    return {
        "$schema": "https://aveproject.org/schema/crosswalk-1.0.0.schema.json",
        "source": {
            "standard": "AEE (Adversarial Execution Evidence)",
            "version": "v0.7",
            "predicateType": (
                "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
            ),
            "url": "https://github.com/probityai/agent-evidence-vectors",
            "upstream": "https://github.com/in-toto/attestation/pull/570",
            "conformance_suite": suite_figures(),
        },
        "target": {
            "standard": "AVE (Agentic Vulnerability Enumeration)",
            "url": "https://aveproject.org",
            "repository": "https://github.com/aveproject/ave",
            "commit": upstream.commit,
            "record_count": upstream.record_count,
            "records_read": records_read,
            "derived_by": UPSTREAM_DERIVED_BY,
        },
        "generated": records_read,
        "generated_by": "scripts/crosswalk-gen.py",
        "crosswalk_kind": "vocabulary-to-structure",
        "note": NOTE,
        "mappings": mappings,
        "coverage": {
            "ave_records_read": upstream.record_count,
            "ave_values_mapped": len(ROWS),
            "ave_values_not_mapped": len(uncovered),
        },
        "values_not_mapped": uncovered,
        "unmapped": [dict(entry) for entry in UNMAPPED],
        "limits": list(LIMITS),
    }


SUITE_FIELDS = ("revision", "vectors", "accept", "reject", "indeterminate")


def check_local() -> int:
    """The half of this file that can be checked with no second checkout.

    The generator needs a clean checkout of aveproject/ave, which is why it ran
    nowhere and why the committed crosswalk drifted three revisions and twenty-two
    vectors behind its own repository while still reading as current. That drift
    is entirely on THIS side of the file: `source.conformance_suite` is derived
    from two files in this tree, so it can be checked on every push, and it is the
    half a reader is most likely to act on because it says what they will find
    when they clone.

    The upstream side is deliberately not checked here. A third-party corpus
    growing is their event and not a fault in the commit being pushed, so it is
    reported weekly, as an issue, by the `crosswalk-upstream` job. A gate that
    goes red for something nobody in this repository did is a gate people learn
    to skip.

    Reads only the working tree. No network, no second checkout, no upstream
    HEAD. Exit 0 when the committed figures are what this corpus yields, 1 on any
    divergence.
    """
    out = REPO / OUT_REL
    if not out.exists():
        raise SystemExit(f"FAIL: {OUT_REL} does not exist, so nothing was compared")
    try:
        committed = json.loads(out.read_text(encoding="utf-8"))
        published = committed["source"]["conformance_suite"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SystemExit(
            f"FAIL: {OUT_REL} does not carry source.conformance_suite ({exc}), so "
            "nothing was compared. That is not the same as it agreeing."
        ) from exc

    derived = suite_figures()
    divergences = [
        f"  {field}: the crosswalk says {published.get(field)!r}, this corpus "
        f"yields {derived[field]!r}"
        for field in SUITE_FIELDS
        if published.get(field) != derived[field]
    ]
    if divergences:
        print(
            f"FAIL: {OUT_REL} publishes figures this repository no longer has.",
            file=sys.stderr,
        )
        for line in divergences:
            print(line, file=sys.stderr)
        print(
            "\nRegenerate it against a checkout of aveproject/ave; do not edit it "
            "by hand:\n"
            "  git clone https://github.com/aveproject/ave /tmp/ave\n"
            "  python3 scripts/crosswalk-gen.py --ave-repo /tmp/ave",
            file=sys.stderr,
        )
        return 1

    print(
        f"ok: {OUT_REL} publishes suiteRevision {derived['revision']}, "
        f"{derived['vectors']} vectors, {derived['accept']}/{derived['reject']}/"
        f"{derived['indeterminate']}, which is what this corpus yields"
    )
    return 0


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ave-repo",
        type=Path,
        help="path to a clean checkout of https://github.com/aveproject/ave; "
        "required for every mode except --check-local",
    )
    parser.add_argument(
        "--records-read",
        default=None,
        help="the date the checkout was read, YYYY-MM-DD; defaults to the "
        "committer date of the upstream HEAD, which is the tree's own date "
        "rather than the machine's",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against the committed file and exit non-zero on a diff, "
        "writing nothing",
    )
    parser.add_argument(
        "--check-local",
        action="store_true",
        help="check only the figures derived from this tree, with no upstream "
        "checkout and no network, and exit non-zero when they have drifted",
    )
    args = parser.parse_args()

    if args.check_local:
        if args.ave_repo is not None:
            raise SystemExit(
                "FAIL: --check-local reads only this tree, so --ave-repo would be "
                "ignored. Drop one of them rather than being told which won."
            )
        return check_local()

    if args.ave_repo is None:
        raise SystemExit(
            "FAIL: --ave-repo is required to generate or fully check the "
            "crosswalk, because the upstream side is counted out of a real "
            "checkout. Use --check-local for the half that needs no checkout."
        )

    upstream = load_upstream(args.ave_repo.resolve())
    check_coverage(upstream)

    records_read = args.records_read or git(
        args.ave_repo.resolve(), "show", "-s", "--format=%cs", "HEAD"
    )
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", records_read):
        raise SystemExit(f"FAIL: --records-read is not a YYYY-MM-DD date: {records_read!r}")

    rendered = render(build(upstream, records_read))
    out = REPO / OUT_REL

    if args.check:
        current = out.read_text(encoding="utf-8") if out.exists() else ""
        if current != rendered:
            print(
                f"FAIL: {OUT_REL} is not what scripts/crosswalk-gen.py produces "
                f"from {upstream.commit}. Regenerate it; do not edit it.",
                file=sys.stderr,
            )
            return 1
        print(f"ok: {OUT_REL} matches the generator at upstream {upstream.commit}")
        return 0

    out.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {OUT_REL} from upstream {upstream.commit} "
        f"({upstream.record_count} records, read {records_read})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
