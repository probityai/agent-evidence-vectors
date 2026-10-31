#!/usr/bin/env python3
"""Publish the open adversarial-mutation findings as a derived, versioned report.

The ledger behind this is a ratchet: a finding it does not list fails its own
gate immediately, and an entry that no longer reproduces fails too, so a landed
fix cannot be quietly reverted and a stale entry cannot linger. That ledger is
not published. What is published is the part a reader of the predicate can act
on: which vector, which mutation family, which invariant axis, and which
soundness class.

WHAT IS PUBLISHED, AND WHAT IS NOT.

Published: the vector id, which is already public in the conformance corpus; the
mutation family name, which is describable from the specification text alone;
the invariant axis; and the soundness class. Eight family names, and naming them
makes the predicate argument stronger, because a specification that names its
own open attacks outranks one that does not.

Not published: the mutator code, and by default the measured transition string.
The transition says what the mutation achieved against a specific rail, which is
one step past naming the attack, so it ships only when the caller asks for it
with --include-transitions and the report records that it was asked for.

The number is never bare. Every count in the rendered document is derived here
and carries the corpus digest and the ledger digest it was derived at.

    scripts/ratchet_report.py --ledger <path to the ratchet ledger>
    scripts/ratchet_report.py --check --ledger <path>
    scripts/ratchet_report.py --check          # self-consistency only

Exit codes:
    0  written, or under --check the report agrees with what was checked
    1  under --check, the report disagrees; what differs is printed
    2  could not check: the ledger is missing or malformed, or the report is
       absent. A missing ledger under --check falls back to the self-consistency
       check and SAYS SO, and never reports the ledger comparison as passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
JSON_OUT = HERE / "docs" / "ADVERSARIAL-RATCHET.json"
MD_OUT = HERE / "docs" / "ADVERSARIAL-RATCHET.md"
REGISTRY = HERE / "registry" / "conditions.json"

FIELDS = ("vector", "mutation", "axis", "class")


def cannot(msg: str) -> None:
    print(f"ratchet_report: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def read_ledger(path: Path, include_transitions: bool) -> dict:
    if not path.is_file():
        cannot(f"missing ledger at {path}")
    raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        cannot(f"{path} is not readable JSON: {exc}")
    findings = doc.get("findings")
    if not isinstance(findings, list) or not findings:
        cannot(
            f"{path} carries no findings. An empty ratchet would render as a clean "
            f"report, which is the one thing this file must never do by accident."
        )
    rows = []
    for i, f in enumerate(findings):
        missing = [k for k in FIELDS if not isinstance(f.get(k), str) or not f[k]]
        if missing:
            cannot(f"{path}: finding {i} is missing {', '.join(missing)}")
        row = {k: f[k] for k in FIELDS}
        if include_transitions:
            row["transition"] = f.get("transition", "")
        rows.append(row)
    return {
        "rows": sorted(rows, key=lambda r: (r["vector"], r["mutation"], r["axis"])),
        "ledgerDigest": hashlib.sha256(raw).hexdigest(),
    }


def counts(rows: list[dict]) -> dict:
    def tally(key: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in rows:
            out[r[key]] = out.get(r[key], 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    return {
        "open_findings": len(rows),
        "distinct_vector_mutation_pairs": len({(r["vector"], r["mutation"]) for r in rows}),
        "distinct_vectors": len({r["vector"] for r in rows}),
        "mutation_families": len({r["mutation"] for r in rows}),
        "by_mutation": tally("mutation"),
        "by_class": tally("class"),
        "by_axis": tally("axis"),
    }


def render_md(payload: dict) -> str:
    c = payload["counts"]
    src = payload["source"]
    lines: list[str] = []
    lines.append("# Adversarial ratchet: the open findings\n")
    lines.append(
        "Every number below is derived by `scripts/ratchet_report.py` from a ratchet "
        "ledger and carries the digest it was derived at. None of them is typed, "
        "because this count has been quoted by hand elsewhere and has been three "
        "different numbers inside six weeks.\n"
    )
    lines.append(
        f"**{c['open_findings']} open findings** over "
        f"{c['distinct_vector_mutation_pairs']} distinct vector and mutation pairs, "
        f"across {c['distinct_vectors']} vectors and "
        f"{c['mutation_families']} mutation families, at corpusDigest "
        f"`{src['corpusDigest'][:12]}` and ledgerDigest `{src['ledgerDigest'][:12]}`.\n"
    )
    lines.append(
        "A finding is one vector, one mutation, and one invariant axis. A mutation "
        "that breaks the verdict and the caught label is recorded twice, once against "
        "each of those axes, because folding it into a single row hides whichever of "
        "the two broke second.\n"
    )
    lines.append("## By mutation family\n")
    lines.append("| family | findings |")
    lines.append("|---|---|")
    for k, v in c["by_mutation"].items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    lines.append("## By soundness class\n")
    lines.append("| class | findings |")
    lines.append("|---|---|")
    for k, v in c["by_class"].items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    lines.append("## By invariant axis\n")
    lines.append("| axis | findings |")
    lines.append("|---|---|")
    for k, v in c["by_axis"].items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    lines.append("## What this does not carry\n")
    lines.append(
        "Two things are withheld. The mutator code is one: a reader can act on the "
        "fact that `artifact-downgrade` defeats a rail without being handed a "
        "generator for it. The measured transition is the other, and it ships only "
        "when whoever runs the script passes `--include-transitions`, which sets "
        "`transitionsIncluded` in the JSON beside this document. That flag reads "
        f"`{str(payload['source']['transitionsIncluded']).lower()}` here.\n"
    )
    lines.append(
        "Everything else is already readable elsewhere. The vector ids are published "
        "in the conformance corpus, the family names can be described from the "
        "specification text, and the classes and axes are semantics the specification "
        "itself defines.\n"
    )
    lines.append("## The findings\n")
    header = "| vector | mutation | axis | class |"
    sep = "|---|---|---|---|"
    if payload["source"]["transitionsIncluded"]:
        header = "| vector | mutation | axis | class | transition |"
        sep = "|---|---|---|---|---|"
    lines.append(header)
    lines.append(sep)
    for r in payload["findings"]:
        row = f"| `{r['vector']}` | `{r['mutation']}` | `{r['axis']}` | `{r['class']}` |"
        if payload["source"]["transitionsIncluded"]:
            row += f" {r.get('transition', '')} |"
        lines.append(row)
    lines.append("")
    lines.append(
        f"Re-derive with `{payload['source']['derived_by']}`. A count in this "
        "document that the script does not reproduce is a defect in the document.\n"
    )
    return "\n".join(lines)


def self_check(payload: dict, md: str) -> list[str]:
    """The report against itself: the rendered counts against the derived ones."""
    problems: list[str] = []
    c = payload["counts"]
    if len(payload["findings"]) != c["open_findings"]:
        problems.append(
            f"the JSON lists {len(payload['findings'])} findings and states "
            f"{c['open_findings']}"
        )
    if f"**{c['open_findings']} open findings**" not in md:
        problems.append(f"the document does not state {c['open_findings']} open findings")
    for key, label in (
        ("distinct_vector_mutation_pairs", "distinct vector and mutation pairs"),
        ("distinct_vectors", "vectors"),
        ("mutation_families", "mutation families"),
    ):
        if f"{c[key]} {label}" not in md:
            problems.append(f"the document does not state {c[key]} {label}")
    for family, n in c["by_mutation"].items():
        if f"| `{family}` | {n} |" not in md:
            problems.append(f"the document's family table does not carry {family} at {n}")
    rows = sum(
        1
        for line in md.splitlines()
        if re.match(r"^\| `[^`]+` \| `[^`]+` \| `[^`]+` \| `[^`]+` \|", line)
    )
    if rows != c["open_findings"]:
        problems.append(
            f"the document's finding table has {rows} rows and the count says "
            f"{c['open_findings']}"
        )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--include-transitions", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.check and args.ledger is None:
        if not JSON_OUT.is_file() or not MD_OUT.is_file():
            cannot("no report to check, and no ledger was given")
        payload = json.loads(JSON_OUT.read_text(encoding="utf-8"))
        problems = self_check(payload, MD_OUT.read_text(encoding="utf-8"))
        print(
            "ratchet_report: SELF-CONSISTENCY ONLY. No ledger was given, so the "
            "report was NOT compared against a ledger and nothing here says the "
            "findings are current."
        )
        if problems:
            for p in problems:
                print(f"  {p}")
            return 1
        print(
            f"self-check: the document and the JSON agree on "
            f"{payload['counts']['open_findings']} open findings"
        )
        return 0

    if args.ledger is None:
        cannot("--ledger is required to write a report")

    if not REGISTRY.is_file():
        cannot(f"missing {REGISTRY}; run scripts/gen_condition_registry.py first")
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))

    ledger = read_ledger(args.ledger, args.include_transitions)
    rows = ledger["rows"]
    payload = {
        "source": {
            "corpusDigest": registry["source"]["corpusDigest"],
            "predicateType": registry["source"]["predicateType"],
            "ledgerDigest": ledger["ledgerDigest"],
            "transitionsIncluded": bool(args.include_transitions),
            "derived_by": (
                "scripts/ratchet_report.py --ledger <ratchet ledger>"
                + (" --include-transitions" if args.include_transitions else "")
            ),
        },
        "counts": counts(rows),
        "findings": rows,
    }
    rendered_json = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    rendered_md = render_md(payload)

    problems = self_check(payload, rendered_md)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        cannot("the renderer disagreed with its own counts, so nothing was written")

    if args.check:
        differs = []
        if not JSON_OUT.is_file() or JSON_OUT.read_text(encoding="utf-8") != rendered_json:
            differs.append(str(JSON_OUT.relative_to(HERE)))
        if not MD_OUT.is_file() or MD_OUT.read_text(encoding="utf-8") != rendered_md:
            differs.append(str(MD_OUT.relative_to(HERE)))
        if differs:
            print("these files disagree with the ledger:")
            for d in differs:
                print(f"  {d}")
            return 1
        print(
            f"check: the report agrees with the ledger at "
            f"{payload['counts']['open_findings']} open findings, ledgerDigest "
            f"{ledger['ledgerDigest'][:12]}"
        )
        return 0

    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(rendered_json, encoding="utf-8")
    MD_OUT.write_text(rendered_md, encoding="utf-8")
    c = payload["counts"]
    print(
        f"wrote {JSON_OUT.relative_to(HERE)} and {MD_OUT.relative_to(HERE)}: "
        f"{c['open_findings']} open findings, "
        f"{c['distinct_vector_mutation_pairs']} distinct vector and mutation pairs, "
        f"{c['distinct_vectors']} vectors, {c['mutation_families']} families"
    )
    for k, v in c["by_mutation"].items():
        print(f"  {k:<20} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
