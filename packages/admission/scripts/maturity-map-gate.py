#!/usr/bin/env python3
"""Refuse a maturity-model page that cites a file, an identifier or a quote that is not there.

`docs/AUTOMATED-GOVERNANCE-MATURITY-MODEL.md` maps the CNCF Automated Governance
Maturity Model onto the rails in this repository, item by item, and names the file
that serves each item. A page like that rots without anyone deciding it should: a
file is renamed, a knob is removed, and the row keeps pointing at it in the same
confident sentence. Nothing reading the page can tell. So this gate reads it.

Four checks.

1. EVERY CITATION RESOLVES. A code span that ends in a known file extension, or in
   a slash, is a path, and the path must be a file this repository tracks (or, with
   a trailing slash, a directory holding one). A path followed by `::` and a string
   also names an identifier, and that string must occur in the file. A citation of
   an untracked file fails, because the page describes the published tree.

2. EVERY ITEM IS ACCOUNTED FOR ONCE. Ids run P1-P21, V1-V17, E1-E11 and A1-A16 in
   the page; each appears exactly once, in a table row with a mark from the closed
   vocabulary or in a fenced block of items not served. A served or partly served
   row cites at least one path.

3. THE COUNTS ARE THE ROWS. The summary table is recomputed from the rows and
   compared, so a changed mark cannot leave a stale total above it.

4. THE QUOTES ARE THE MODEL. Given the model file (`--model`), every section's
   items are parsed out of it and compared with the page's quotes, id by id, after
   the two mechanical changes the page declares: a right single quotation mark
   becomes an apostrophe, and a wrapped item is joined with one space. The commit
   the page names is compared with the commit continuous integration fetches, read
   from `.github/workflows/ci.yml`, so the page and the pin cannot disagree.

Without `--model` the fourth check is skipped and the first line of output says so,
because a pass that did not read the model is not a statement about the quotes.

    scripts/maturity-map-gate.py
    scripts/maturity-map-gate.py --model <path to the model README.md>
    scripts/maturity-map-gate.py --selftest

Exit codes:
    0  every check that ran passed
    1  at least one finding; each is printed
    2  could not check: the page or the workflow is missing, `git ls-files`
       returned nothing, the page parsed to no items, or the model parsed to no
       items. A broken read is never reported as a clean one.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from fnmatch import fnmatchcase
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PAGE = "docs/AUTOMATED-GOVERNANCE-MATURITY-MODEL.md"
WORKFLOW = "../../.github/workflows/package-admission.yml"

# The model's four categories in its own order, each with the id prefix the page
# uses and the number of items the model carries at the pinned commit.
SECTIONS = (
    ("Policy", "P", 21),
    ("Evaluation", "V", 17),
    ("Enforcement", "E", 11),
    ("Audit", "A", 16),
)
MARKS = ("served", "partly served", "not served")

PATH_EXTENSIONS = (
    "md",
    "py",
    "rego",
    "json",
    "yaml",
    "yml",
    "toml",
    "cff",
    "txt",
    "pub",
)
CITATION_RE = re.compile(
    r"^(?P<path>[A-Za-z0-9_.*/-]+(?:\.(?:" + "|".join(PATH_EXTENSIONS) + r")|/))"
    r"(?:::(?P<symbol>.+))?$"
)
CODE_SPAN_RE = re.compile(r"`([^`]+)`")
ROW_RE = re.compile(
    r"^\|\s*(?P<id>[PVEA]\d+)\s*\|\s*\"(?P<quote>.*)\"\s*\|\s*(?P<mark>[a-z ]+?)\s*\|"
    r"(?P<evidence>.*)\|\s*$"
)
FENCED_ITEM_RE = re.compile(r"^(?P<id>[PVEA]\d+)\s{2,}(?P<quote>\S.*)$")
SUMMARY_RE = re.compile(
    r"^\|\s*(?P<name>Policy|Evaluation|Enforcement|Audit|all)\s*\|"
    r"\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$"
)
SOURCE_RE = re.compile(r"^Source: `cncf/tag-security` at commit ([0-9a-f]{40})")
PIN_RE = re.compile(r"^\s*MATURITY_MODEL_COMMIT:\s*([0-9a-f]{40})\s*$", re.MULTILINE)
MODEL_HEADING_RE = re.compile(r"^###\s+(Policy|Evaluation|Enforcement|Audit)\s*$")
MODEL_ITEM_RE = re.compile(r"^- \[ \] (.*)$")
MODEL_CONTINUATION_RE = re.compile(r"^ {6}(\S.*)$")


class CannotCheck(Exception):
    """A read failed. Reported with exit 2, never as a pass or a finding."""


def cannot(msg: str) -> None:
    print(f"maturity-map-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def tracked_files() -> set[str]:
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=HERE, check=True, capture_output=True, text=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CannotCheck(f"git ls-files failed: {exc}") from exc
    # The pins live in the repository-root workflow, which `git ls-files` run
    # from the package lists as ../../.github/workflows/<name>.
    try:
        out += subprocess.run(
            ["git", "ls-files", "--", ":/.github/workflows"],
            cwd=HERE, check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CannotCheck(f"git ls-files failed: {exc}") from exc
    names = {n for n in out.splitlines() if n}
    if not names:
        raise CannotCheck("git ls-files returned nothing, which is a broken read")
    return names


def ascii_form(text: str) -> str:
    """The two mechanical changes the page declares, and nothing else."""
    return text.replace("\u2019", "'")


def parse_page(
    text: str,
) -> tuple[dict[str, tuple[str, str, str]], list[str], dict[str, tuple[int, ...]]]:
    """Items as id -> (quote, mark, evidence), plus duplicate ids and the summary rows."""
    items: dict[str, tuple[str, str, str]] = {}
    seen: Counter[str] = Counter()
    summary: dict[str, tuple[int, ...]] = {}
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            hit = FENCED_ITEM_RE.match(line)
            if hit:
                seen[hit["id"]] += 1
                items[hit["id"]] = (hit["quote"].rstrip(), "not served", "")
            continue
        row = ROW_RE.match(line)
        if row:
            quote = row["quote"]
            if len(quote) > 1 and quote.startswith("`") and quote.endswith("`"):
                quote = quote[1:-1]
            seen[row["id"]] += 1
            items[row["id"]] = (quote, row["mark"], row["evidence"])
            continue
        total = SUMMARY_RE.match(line)
        if total:
            summary[total["name"]] = tuple(int(total.group(i)) for i in range(2, 6))
    duplicates = sorted(i for i, n in seen.items() if n > 1)
    return items, duplicates, summary


def check_citations(
    items: dict[str, tuple[str, str, str]],
    page_text: str,
    tracked: set[str],
    read: Callable[[str], str],
) -> tuple[list[str], int]:
    """Every path-shaped code span on the page resolves. Returns findings and the count checked."""
    findings: list[str] = []
    checked = 0
    for number, line in enumerate(page_text.splitlines(), 1):
        for span in CODE_SPAN_RE.findall(line):
            hit = CITATION_RE.match(span)
            if not hit:
                continue
            checked += 1
            path, symbol = hit["path"], hit["symbol"]
            if "*" in path:
                if not any(fnmatchcase(t, path) for t in tracked):
                    findings.append(f"line {number}: `{path}` matches no tracked file")
                continue
            if path.endswith("/"):
                if not any(t.startswith(path) for t in tracked):
                    findings.append(f"line {number}: `{path}` holds no tracked file")
                continue
            if path not in tracked:
                findings.append(f"line {number}: `{path}` is not a tracked file")
                continue
            if symbol is not None and symbol not in read(path):
                findings.append(f"line {number}: `{symbol}` does not occur in `{path}`")
    for item_id, (_, mark, evidence) in sorted(items.items()):
        if mark in ("served", "partly served"):
            cited = [s for s in CODE_SPAN_RE.findall(evidence) if CITATION_RE.match(s)]
            if not cited:
                findings.append(f"{item_id}: marked {mark} and cites no file")
    return findings, checked


def check_items(
    items: dict[str, tuple[str, str, str]], duplicates: list[str]
) -> list[str]:
    findings = [f"{i}: appears more than once" for i in duplicates]
    for name, prefix, count in SECTIONS:
        expected = {f"{prefix}{n}" for n in range(1, count + 1)}
        present = {i for i in items if i[0] == prefix}
        for missing in sorted(expected - present, key=lambda i: int(i[1:])):
            findings.append(f"{missing}: {name} item missing from the page")
        for extra in sorted(present - expected, key=lambda i: int(i[1:])):
            findings.append(f"{extra}: the model has no such {name} item")
    for item_id, (_, mark, _) in sorted(items.items()):
        if mark not in MARKS:
            findings.append(
                f"{item_id}: mark `{mark}` is not one of {', '.join(MARKS)}"
            )
    return findings


def check_summary(
    items: dict[str, tuple[str, str, str]], summary: dict[str, tuple[int, ...]]
) -> list[str]:
    findings: list[str] = []
    totals = [0, 0, 0, 0]
    for name, prefix, _ in SECTIONS:
        marks = [m for i, (_, m, _) in items.items() if i[0] == prefix]
        row = (len(marks), *(marks.count(m) for m in MARKS))
        totals = [a + b for a, b in zip(totals, row)]
        if summary.get(name) != row:
            findings.append(
                f"summary row {name} reads {summary.get(name)}, the rows give {row}"
            )
    if summary.get("all") != tuple(totals):
        findings.append(
            f"summary row all reads {summary.get('all')}, the rows give {tuple(totals)}"
        )
    return findings


def parse_model(text: str) -> dict[str, list[str]]:
    """The model's checklist items per category, wrapped lines joined with one space."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        heading = MODEL_HEADING_RE.match(line)
        if heading:
            current = sections.setdefault(heading.group(1), [])
            continue
        if line.startswith("#"):
            current = None
            continue
        if current is None:
            continue
        item = MODEL_ITEM_RE.match(line)
        if item:
            current.append(item.group(1).rstrip())
            continue
        more = MODEL_CONTINUATION_RE.match(line)
        if more and current:
            current[-1] = f"{current[-1]} {more.group(1).rstrip()}"
    return sections


def check_model(
    items: dict[str, tuple[str, str, str]],
    page_text: str,
    model_text: str,
    pinned: str | None,
) -> list[str]:
    model = parse_model(model_text)
    if not any(model.values()):
        raise CannotCheck("the model file parsed to no checklist items")
    findings: list[str] = []
    for name, prefix, count in SECTIONS:
        quoted = model.get(name, [])
        if len(quoted) != count:
            findings.append(
                f"the model's {name} section has {len(quoted)} items, the page expects {count}"
            )
        for n, source in enumerate(quoted, 1):
            item_id = f"{prefix}{n}"
            page_quote = items.get(item_id, ("",))[0]
            if page_quote != ascii_form(source):
                findings.append(
                    f"{item_id}: the page quotes {page_quote!r}, the model reads {ascii_form(source)!r}"
                )
    named = None
    for line in page_text.splitlines():
        hit = SOURCE_RE.match(line)
        if hit:
            named = hit.group(1)
            break
    if named is None:
        findings.append("the page names no source commit on a `Source:` line")
    elif pinned is not None and named != pinned:
        findings.append(f"the page names commit {named}, the workflow fetches {pinned}")
    return findings


def run(
    page_text: str,
    tracked: set[str],
    read: Callable[[str], str],
    model_text: str | None,
    pinned: str | None,
) -> tuple[list[str], int]:
    items, duplicates, summary = parse_page(page_text)
    if not items:
        raise CannotCheck("the page parsed to no items, which is a broken read")
    findings = check_items(items, duplicates)
    cited, checked = check_citations(items, page_text, tracked, read)
    findings += cited
    if checked == 0:
        raise CannotCheck("the page parsed to no citations, which is a broken read")
    findings += check_summary(items, summary)
    if model_text is not None:
        findings += check_model(items, page_text, model_text, pinned)
    return findings, checked


def selftest() -> int:
    """Every check fires on a case built to trip it, and stays quiet on a clean one."""
    model = "\n".join(
        ["## Categories"]
        + [
            line
            for name, prefix, count in SECTIONS
            for line in [f"### {name}", ""]
            + [f"- [ ] {name} item {n} the unit\u2019s" for n in range(1, count)]
            + [f"- [ ] {name} item {count} first half", "      second half"]
        ]
    )
    rows = []
    for name, prefix, count in SECTIONS:
        for n in range(1, count + 1):
            text = (
                f"{name} item {n} the unit's"
                if n < count
                else f"{name} item {n} first half second half"
            )
            rows.append(f'| {prefix}{n} | "{text}" | served | `a/b.py::thing` |')
    summary = [f"| {name} | {count} | {count} | 0 | 0 |" for name, _, count in SECTIONS]
    summary.append("| all | 65 | 65 | 0 | 0 |")
    sha = "0" * 40
    clean = "\n".join(
        [f"Source: `cncf/tag-security` at commit {sha}, file", *summary, *rows]
    )
    tracked = {"a/b.py"}
    files = {"a/b.py": "def thing(): pass\n"}

    def outcome(
        page: str, model_text: str | None = model, have: set[str] = tracked
    ) -> list[str]:
        return run(page, have, files.__getitem__, model_text, sha)[0]

    cases = {
        "clean page": (outcome(clean), False),
        "untracked file": (outcome(clean, have={"a/c.py"}), True),
        "missing identifier": (outcome(clean.replace("::thing", "::gone")), True),
        "stale summary": (
            outcome(clean.replace("| all | 65 | 65 |", "| all | 65 | 64 |")),
            True,
        ),
        "changed mark": (
            outcome(clean.replace('" | served |', '" | not served |', 1)),
            True,
        ),
        "unknown mark": (
            outcome(clean.replace('" | served |', '" | mostly |', 1)),
            True,
        ),
        "misquote": (
            outcome(clean.replace("Audit item 3 the unit's", "Audit item 3 the units")),
            True,
        ),
        "dropped item": (outcome(clean.replace('| E4 | "', '| X4 | "')), True),
        "duplicate item": (
            outcome(
                clean
                + '\n| E4 | "Enforcement item 4 the unit\'s" | served | `a/b.py` |'
            ),
            True,
        ),
        "served row citing nothing": (
            outcome(
                clean.replace("| served | `a/b.py::thing` |", "| served | prose |", 1)
            ),
            True,
        ),
        "wrong source commit": (outcome(clean.replace(sha, "1" * 40, 1)), True),
    }
    failed = [
        f"{label}: expected {'a finding' if want else 'no finding'}, got {got}"
        for label, (got, want) in cases.items()
        if bool(got) != want
    ]
    fenced = clean.replace(
        '| E4 | "Enforcement item 4 the unit\'s" | served | `a/b.py::thing` |',
        "```text\nE4   Enforcement item 4 the unit's\n```",
    )
    if outcome(
        fenced.replace(
            "| Enforcement | 11 | 11 | 0 | 0 |", "| Enforcement | 11 | 10 | 0 | 1 |"
        ).replace("| all | 65 | 65 | 0 | 0 |", "| all | 65 | 64 | 0 | 1 |")
    ):
        failed.append("a fenced not-served item was not read as one")
    try:
        run("no items here", tracked, files.__getitem__, None, None)
        failed.append("an empty page did not refuse to check")
    except CannotCheck:
        pass
    try:
        run(clean, tracked, files.__getitem__, "no checklist", sha)
        failed.append("an empty model did not refuse to check")
    except CannotCheck:
        pass
    if failed:
        for line in failed:
            print(f"selftest: FAILED -- {line}", file=sys.stderr)
        return 1
    print(
        f"selftest: all {len(cases) + 3} cases behave, every check fires on its positive control"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--model", type=Path, help="the model's README.md, to check every quote against"
    )
    parser.add_argument(
        "--selftest", action="store_true", help="prove each check fires"
    )
    args = parser.parse_args(argv[1:])
    if args.selftest:
        return selftest()

    page_path = HERE / PAGE
    workflow_path = HERE / WORKFLOW
    try:
        if not page_path.is_file():
            raise CannotCheck(f"{PAGE} is not a file")
        if not workflow_path.is_file():
            raise CannotCheck(f"{WORKFLOW} is not a file")
        pin = PIN_RE.search(workflow_path.read_text(encoding="utf-8"))
        if pin is None:
            raise CannotCheck(f"{WORKFLOW} pins no MATURITY_MODEL_COMMIT")
        model_text = None
        if args.model is not None:
            if not args.model.is_file():
                raise CannotCheck(f"{args.model} is not a file")
            model_text = args.model.read_text(encoding="utf-8")
        else:
            print(
                "maturity-map-gate: no --model given, so the quotes were NOT compared with the model"
            )

        def read(path: str) -> str:
            return (HERE / path).read_text(encoding="utf-8", errors="replace")

        findings, checked = run(
            page_path.read_text(encoding="utf-8"),
            tracked_files(),
            read,
            model_text,
            pin.group(1),
        )
    except CannotCheck as exc:
        cannot(str(exc))
        return 2

    if findings:
        for line in findings:
            print(f"{PAGE}: {line}")
        print(f"maturity-map-gate: {len(findings)} finding(s)")
        return 1
    compared = (
        "and every quote matches the model"
        if model_text is not None
        else "quotes not compared"
    )
    print(
        f"maturity-map-gate: {checked} citations resolve, 65 items accounted for, {compared}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
