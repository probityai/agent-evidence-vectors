#!/usr/bin/env python3
"""Each agent-audit-record member names the text it tests, and the label is derived.

An outside verifier written from revision 03 differed from the manifest on 38
members. Every one tested a rule of unpublished text, while the manifest labelled
15 of them revision 01 and 22 an unpublished revision 04. The labels were typed
beside each member group. They are now derived from the published texts vendored
under the corpus, and a member whose rule no published text states is
``proposed``. Revision 04 was published on 19 November 2026 and its Appendix B
prints all 68 members that were proposed for it, so none is proposed for it now;
the 24 members of the evaluated-at proposal are proposed for revision 05. This
test pins that:

- the row identifiers read from each vendored Appendix B are the ones it prints
  (revision 01 prints CS1 to CS9 and no CS10, revision 02 adds CS10 to CS17,
  revision 04 adds CS18 to CS54, PS3 to PS5, PR, DS and X1 to X18);
- the committed manifest labels every member with a published revision: the 38
  members and CS32 with revision 04, and X2, X3 and X8 to X16, which -04 also
  prints, with -03, whose sections first stated their rules;
- the generator refuses a member that is published and proposed at once, a
  section member whose revision has no such section, and a section entry that
  names no revision earlier than the Appendix B that first prints the row;
- the harness refuses a manifest that labels a member with an unpublished
  revision, or whose textCounts disagree with its members.

Usage: uv run --extra generators python scripts/audit-record-text-tier-test.py
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "corpora" / "vectors-agent-audit-record"
sys.path.insert(0, str(REPO / "packaging"))

import run_vectors  # noqa: E402,F401
from agent_evidence_vectors import auditrecord  # noqa: E402


def _gen():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen_under_test", CORPUS / "gen_vectors.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: The members an outside -03 verifier differed on, by the cause of each.
DIFFERED = (
    [f"CS{n}" for n in (18, 19, 20, 21, 22, 26, 27, 28, 29, 30, 31, 34, 38, 39, 40)]
    + [f"CS{n}" for n in (41, 43, 48, 49, 50, 53, 54)]
    + [f"PR{n}" for n in range(4, 12)]
    + [f"DS{n}" for n in range(4, 11)]
    + ["X6", "CS32"]
)


REV04 = "draft-gilda-audit-agent-audit-record-04"
# The text findings the manifest records: members the published text states, and members
# proposed for revision 05 by docs/proposals/audit-record-04-evaluated-at.md.
REV05 = "draft-gilda-audit-agent-audit-record-05"
PUBLISHED_TEXT_FINDINGS = 235
PROPOSED_TEXT_FINDINGS = 24


def _check_rows(gen, failures: list[str]) -> None:
    rows = {
        rev: gen.appendix_b_rows(gen._published_text(rev))
        for rev, _ in gen.PUBLISHED_REVISIONS
    }
    if "CS9" not in rows["01"] or "CS10" in rows["01"]:
        failures.append("revision 01's Appendix B should print CS9 and no CS10")
    if "CS17" not in rows["02"] or "CS18" in rows["03"]:
        failures.append("revision 02 should print CS17, and revision 03 no CS18")
    if len(rows["00"]) != 99:
        failures.append(f"revision 00's Appendix B prints 99 rows, read {len(rows['00'])}")
    if "CS18" not in rows["04"] or "X18" not in rows["04"] or len(rows["04"]) != 218:
        failures.append(f"revision 04 prints 218 rows with CS18 and X18, read {len(rows['04'])}")


def _check_labels(manifest: dict, failures: list[str]) -> None:
    by_id = {e["draftId"]: e for e in manifest["vectors"]}
    if len(DIFFERED) != 39:
        failures.append("the differing list should hold 38 members and CS32")
    for draft_id in DIFFERED:
        if by_id[draft_id].get("draftRevision") != REV04:
            failures.append(f"{draft_id} tests text revision 04 publishes and is not labelled -04")
    labelled04 = sorted(d for d, e in by_id.items() if e.get("draftRevision") == REV04)
    if len(labelled04) != 68:
        failures.append(f"68 members test rules -04 first states, read {len(labelled04)}")
    for draft_id in ("X2", "X3", "X8", "X16"):
        if by_id[draft_id].get("draftRevision") != "draft-gilda-audit-agent-audit-record-03":
            failures.append(
                f"{draft_id}'s rule is stated by a section of -03, which -04 only prints"
            )
    _check_manifest_header(manifest, by_id, failures)


def _check_manifest_header(manifest: dict, by_id: dict, failures: list[str]) -> None:
    if by_id["CS10"].get("draftRevision") != "draft-gilda-audit-agent-audit-record-02":
        failures.append("CS10 is first printed by revision 02")
    counts = manifest.get("textCounts")
    if counts != {"proposed": PROPOSED_TEXT_FINDINGS, "published": PUBLISHED_TEXT_FINDINGS}:
        failures.append(
            f"textCounts should be {PUBLISHED_TEXT_FINDINGS} published and "
            f"{PROPOSED_TEXT_FINDINGS} proposed: {counts}"
        )
    members = [v["proposed"] for v in manifest["vectors"] if "proposed" in v]
    proposed_for = {(m["revision"], m["text"]) for m in members}
    if proposed_for != {(REV05, "docs/proposals/audit-record-04-evaluated-at.md")}:
        failures.append(f"the proposed members should all be the revision 05 proposal: {proposed_for}")
    if manifest.get("draft") != REV04:
        failures.append(f"the manifest should name revision 04, names {manifest.get('draft')}")
    findings = auditrecord._text_findings(manifest)
    if findings:
        failures.append(f"the committed manifest has text findings: {findings}")


def _check_harness(manifest: dict, failures: list[str]) -> None:
    rev05 = REV05
    bad = copy.deepcopy(manifest)
    bad["vectors"][0]["draftRevision"] = rev05
    if not any("not a published revision" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted an unpublished draftRevision")
    bad = copy.deepcopy(manifest)
    bad["textCounts"]["proposed"] += 1
    if not any("textCounts" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted textCounts that disagree with the members")
    bad = copy.deepcopy(manifest)
    bad["vectors"][0]["proposed"] = {"revision": rev05, "text": "x"}
    if not any("exactly one" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted a member both published and proposed")
    bad = copy.deepcopy(manifest)
    del bad["vectors"][0]["draftRevision"]
    bad["vectors"][0]["proposed"] = {"revision": REV04, "text": "x"}
    findings = auditrecord._text_findings(bad)
    if not any("proposed names a published revision" in f for f in findings):
        failures.append(
            "the harness accepted a member proposed for revision 04, which is published"
        )


def _check_generator(gen, failures: list[str]) -> None:
    gen.define()
    gen.text_fields(gen.MEMBERS)
    if gen.PROPOSED_REVISION != "draft-gilda-audit-agent-audit-record-05":
        failures.append(f"the next revision after -04 is -05, read {gen.PROPOSED_REVISION}")

    def refused(note: str) -> None:
        try:
            gen.text_fields(gen.MEMBERS)
            failures.append(note)
        except SystemExit:
            pass

    gen.PROPOSED["CS18"] = "docs/proposals/audit-record-04-consumption-ledger.md"
    refused("the generator accepted CS18 as printed by -04 and proposed")
    del gen.PROPOSED["CS18"]
    gen.SECTION_REVISION["CS1"] = "03"
    refused("the generator accepted a section entry -03 for CS1, which -00 prints")
    del gen.SECTION_REVISION["CS1"]
    gen.SECTION_REVISION["X4"] = "03"
    refused("the generator accepted X4 under a Section 4.8 that -03 lacks")
    del gen.SECTION_REVISION["X4"]
    gen.text_fields(gen.MEMBERS)


def main() -> int:
    failures: list[str] = []
    gen = _gen()
    _check_rows(gen, failures)
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    _check_labels(manifest, failures)
    _check_harness(manifest, failures)
    _check_generator(gen, failures)

    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"audit-record text tiers: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
