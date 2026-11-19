#!/usr/bin/env python3
"""Each agent-audit-record member names the text it tests, and the label is derived.

An outside verifier written from revision 03 differed from the manifest on 38
members. Every one tested a rule of unpublished text, while the manifest labelled
15 of them revision 01 and 22 an unpublished revision 04. The labels were typed
beside each member group. They are now derived from the published texts vendored
under the corpus, and a member whose rule no published text states is
``proposed``. This test pins that:

- the row identifiers read from each vendored Appendix B are the ones it prints
  (revision 01 prints CS1 to CS9 and no CS10, revision 02 adds CS10 to CS17);
- the committed manifest labels every published member with a published revision
  and carries every one of the 38 members and CS32 as proposed;
- the generator refuses a member that is published and proposed at once, and a
  section member whose revision has no such section;
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


def main() -> int:
    failures: list[str] = []
    gen = _gen()
    rows = {rev: gen.appendix_b_rows(gen._published_text(rev)) for rev, _ in gen.PUBLISHED_REVISIONS}
    if "CS9" not in rows["01"] or "CS10" in rows["01"]:
        failures.append("revision 01's Appendix B should print CS9 and no CS10")
    if "CS17" not in rows["02"] or "CS18" in rows["03"]:
        failures.append("revision 02 should print CS17, and revision 03 no CS18")
    if len(rows["00"]) != 99:
        failures.append(f"revision 00's Appendix B prints 99 rows, read {len(rows['00'])}")

    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    by_id = {e["draftId"]: e for e in manifest["vectors"]}
    if len(DIFFERED) != 39:
        failures.append("the differing list should hold 38 members and CS32")
    for draft_id in DIFFERED:
        if auditrecord.text_status(by_id[draft_id]) != "proposed":
            failures.append(f"{draft_id} tests unpublished text and is not proposed")
    if by_id["CS10"].get("draftRevision") != "draft-gilda-audit-agent-audit-record-02":
        failures.append("CS10 is first printed by revision 02")
    if auditrecord._text_findings(manifest):
        failures.append(f"the committed manifest has text findings: {auditrecord._text_findings(manifest)}")

    bad = copy.deepcopy(manifest)
    bad["vectors"][0]["draftRevision"] = "draft-gilda-audit-agent-audit-record-04"
    if not any("not a published revision" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted an unpublished draftRevision")
    bad = copy.deepcopy(manifest)
    bad["textCounts"]["proposed"] += 1
    if not any("textCounts" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted textCounts that disagree with the members")
    bad = copy.deepcopy(manifest)
    bad["vectors"][0]["proposed"] = {"revision": "draft-gilda-audit-agent-audit-record-04", "text": "x"}
    if not any("exactly one" in f for f in auditrecord._text_findings(bad)):
        failures.append("the harness accepted a member both published and proposed")

    gen.define()
    gen.text_fields(gen.MEMBERS)
    gen.SECTION_REVISION["CS18"] = "03"
    try:
        gen.text_fields(gen.MEMBERS)
        failures.append("the generator accepted CS18 as published and proposed")
    except SystemExit:
        pass
    del gen.SECTION_REVISION["CS18"]
    del gen.PROPOSED["X1"]
    gen.SECTION_REVISION["X4"] = "03"
    del gen.PROPOSED["X4"]
    try:
        gen.text_fields(gen.MEMBERS)
        failures.append("the generator accepted X1 with no text, or X4 under a Section 4.8 -03 lacks")
    except SystemExit:
        pass

    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"audit-record text tiers: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
