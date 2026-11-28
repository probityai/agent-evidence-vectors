#!/usr/bin/env python3
"""Rule-to-spec traceability: every code a corpus expects is named in its specification.

    python3 scripts/rule-trace-lint.py            # every predicate defined here
    python3 scripts/rule-trace-lint.py --table    # also print each code with the file that names it

``spec/predicates/REGISTRY.md`` lists each predicate type this repository defines with its
normative Document and its conformance Corpus. A corpus case states what a conformant
verifier must answer: a reason code, and in some corpora the numbered rule or the condition
id it exercises. A code that the corpus demands and no published text defines is a rule a
second implementer cannot derive from the specification; they can only copy it from our
reader. This lint reads every case of every defined predicate's corpus and fails on each
expected identifier the predicate's Document does not name.

What counts as named:

* the identifier in backticks in the Document, or its stem before ``:`` (a parameterised
  code such as ``gate_missing:<gate>`` is defined once, by its stem);
* a backticked ``:suffix`` after a full code in the same text, the shorthand a table cell
  uses for a second code with the same prefix;
* for a numeric rule id, a numbered list item or a table row with that number, under a
  heading that names rules, checks, requirements or conditions (a numbered install step
  defines no rule);
* for any other rule id (``B3``, ``R-ORDER``), a table row whose first cell is that id;
* when the Document does not name it, the corpus's own README (the corpus contract the
  Document links), reported as such so a reader sees which text carries the definition.

A case whose ``document`` member names another Document is read against that Document's
entry, not this one: several predicates can share one corpus. A case whose ``document``
names a file that no registry entry over the same corpus defines (a profile over several
predicates, say) is traced against that file, the entries' Documents and the corpus README,
and reported under the file's path; a ``document`` that names no file FAILS. Until this
rule, such a case was traced by no entry at all, so a typo in its ``document`` member hid
every code it expects.

A rule is traced to its row, not only to the text. When a case expects a rule id and a
reason, and the rule's table row pins a code (its table has a code or reason column and the
cell names one), the row must name that reason. A case expecting rule 7 with rule 3's code
otherwise passes, because both codes are named somewhere in the Document.

``spec/predicates/TRACE-PENDING.toml`` lists, per predicate, identifiers whose definition is
owed and tracked; they are reported as pending, not failed. That list only shrinks: an
identifier on it that is now named, or that no case expects any more, FAILS until it is
removed, so the list cannot outlive the gap it records.

An entry from whose corpus no identifier at all can be read FAILS, because a lint that
read nothing and a lint that found everything named print the same nothing. Such an entry
says why in ``NO_CODES`` below.

Exit 0 when every expected identifier is named; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "spec" / "predicates" / "REGISTRY.md"
PENDING = ROOT / "spec" / "predicates" / "TRACE-PENDING.toml"
MANIFEST_NAMES = ("MANIFEST.json", "manifest.json")
CASE_LISTS = ("vectors", "cases")

# Defined predicates whose corpus carries no expected reason, rule or condition, and why.
NO_CODES: dict[str, str] = {}

BACKTICKED = re.compile(r"`([^`\s]+)`")
NUMBERED = re.compile(r"^\s*(?:\|\s*)?(\d+)(?:\.\s|\s*\|)")
ROW = re.compile(r"^\s*\|\s*`?([A-Za-z0-9][A-Za-z0-9._-]*)`?\s*\|(.*)$")
ITEM = re.compile(r"^\s*(\d+)\.\s(.*)$")
SEPARATOR = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
CODE_HEADER = re.compile(r"code|reason|refusal")
RULE_HEADING = re.compile(r"rule|check|requirement|condition", re.IGNORECASE)


@dataclass
class Entry:
    """One `Defined here` entry of the registry, or a file a corpus's cases name instead.

    ``also`` holds further texts that may define a code (for a named file, the Documents of
    the entries over its corpus); ``unmarked`` says whether cases with no ``document``
    member belong to it.
    """

    name: str
    document: Path
    corpus: Path
    also: list[Path] = field(default_factory=list)
    unmarked: bool = True


@dataclass
class Trace:
    """Where each expected identifier of one entry is named."""

    entry: Entry
    named_in: dict[str, str] = field(default_factory=dict)
    unnamed: dict[str, list[str]] = field(default_factory=dict)
    mispaired: list[str] = field(default_factory=list)
    missing_document: bool = False


def defined_entries(registry: Path = REGISTRY, root: Path = ROOT) -> list[Entry]:
    """Return every entry under the registry's `Defined here` heading."""
    text = registry.read_text(encoding="utf-8")
    section = text.split("\n## Defined here", 1)[1].split("\n## ", 1)[0]
    entries = []
    for block in section.split("\n### ")[1:]:
        name = block.splitlines()[0].strip().strip("`")
        document = re.search(r"^- Document: `([^`]+)`", block, re.MULTILINE)
        corpus = re.search(r"^- Corpus: `([^`]+)`", block, re.MULTILINE)
        if document is None or corpus is None:
            raise ValueError(f"{name}: the entry names no Document or no Corpus")
        entries.append(Entry(name, root / document.group(1), root / corpus.group(1).rstrip("/")))
    return entries


def _codes(text: str) -> set[str]:
    """Return every backticked identifier of a text, expanding the ``:suffix`` shorthand."""
    names: set[str] = set()
    prefix = ""
    for token in BACKTICKED.findall(text):
        if token.startswith(":") and prefix:
            names.add(prefix + token)
            continue
        names.add(token)
        if ":" in token:
            prefix, parameter = token.split(":", 1)
            if parameter.startswith("<"):
                names.add(prefix)  # `stem:<field>` defines every `stem:<value>`
    return names


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def rule_rows(text: str) -> dict[str, set[str]]:
    """Return each rule id a text defines by a table row or numbered item, with its pinned codes.

    A row's pinned codes are the backticked codes in its table's code or reason column (the
    column whose header says ``code``, ``reason`` or ``refusal``); a numbered item, and a row
    of a table with no such column, defines its rule and pins no code. A numeric id counts
    only under a heading that names rules, checks, requirements or conditions.
    """
    rows: dict[str, set[str]] = {}
    in_rules = False
    lines = text.splitlines()
    column: int | None = None
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            in_rules, column = bool(RULE_HEADING.search(line)), None
            continue
        if not line.lstrip().startswith("|"):
            column = None
            numbered = ITEM.match(line)
            if numbered and in_rules:
                rows.setdefault(f"#{numbered.group(1)}", set())
            continue
        following = lines[index + 1] if index + 1 < len(lines) else ""
        if SEPARATOR.match(following):
            headers = [cell.lower() for cell in _cells(line)]
            column = next((i for i, h in enumerate(headers) if CODE_HEADER.search(h)), None)
            continue
        row = ROW.match(line)
        if row is None:
            continue
        rule = row.group(1)
        if rule.isdigit():
            if not in_rules:
                continue
            rule = f"#{rule}"
        cells = _cells(line)
        pinned = _codes(cells[column]) if column is not None and column < len(cells) else set()
        rows.setdefault(rule, set()).update(pinned)
    return rows


def named(text: str) -> set[str]:
    """Return every identifier a text names: backticked codes and the rule ids it defines."""
    return _codes(text) | set(rule_rows(text))


def _manifest(corpus: Path) -> dict[str, Any]:
    for name in MANIFEST_NAMES:
        if (corpus / name).is_file():
            loaded: dict[str, Any] = json.loads((corpus / name).read_text(encoding="utf-8"))
            return loaded
    raise FileNotFoundError(f"{corpus.relative_to(ROOT)}: no {' or '.join(MANIFEST_NAMES)}")


def _identifiers(case: dict[str, Any]) -> Iterable[str]:
    expected = case.get("expected")
    if isinstance(expected, dict):
        for key in ("reason", "code"):
            if isinstance(expected.get(key), str):
                yield expected[key]
        for key in ("codes", "reasons"):
            for code in expected.get(key) or ():
                yield str(code)
    rule = case.get("rule")
    if isinstance(rule, int) or (isinstance(rule, str) and rule.isdigit()):
        yield f"#{rule}"
    elif isinstance(rule, str) and rule:
        yield rule
    for condition in case.get("conditions") or ():
        yield str(condition)


def corpus_cases(corpus: Path) -> list[dict[str, Any]]:
    """Return the case list of a corpus: its manifest's, else its ``cases.json``."""
    manifest = _manifest(corpus)
    cases: list[dict[str, Any]] = next(
        (
            manifest[key]
            for key in CASE_LISTS
            if isinstance(manifest.get(key), list)
            and all(isinstance(c, dict) for c in manifest[key])
        ),
        [],
    )
    if not cases and (corpus / "cases.json").is_file():
        listed = json.loads((corpus / "cases.json").read_text(encoding="utf-8"))
        cases = listed.get("cases", []) if isinstance(listed, dict) else listed
    return cases


def _own_cases(entry: Entry, root: Path = ROOT) -> list[dict[str, Any]]:
    """Return the cases of the entry's corpus that are judged against the entry's Document."""
    document = entry.document.relative_to(root).as_posix()
    owned = (None, document) if entry.unmarked else (document,)
    return [case for case in corpus_cases(entry.corpus) if case.get("document") in owned]


def named_documents(entries: Sequence[Entry], root: Path = ROOT) -> list[Entry]:
    """Return an entry for each file a corpus's cases name that no entry over it defines."""
    by_corpus: dict[Path, list[Entry]] = {}
    for entry in entries:
        by_corpus.setdefault(entry.corpus, []).append(entry)
    extra: list[Entry] = []
    for corpus, over in by_corpus.items():
        documents = {entry.document.relative_to(root).as_posix() for entry in over}
        foreign = sorted(
            {
                str(case["document"])
                for case in corpus_cases(corpus)
                if case.get("document") is not None and str(case["document"]) not in documents
            }
        )
        extra.extend(
            Entry(name, root / name, corpus, [entry.document for entry in over], False)
            for name in foreign
        )
    return extra


def expected_identifiers(entry: Entry, root: Path = ROOT) -> dict[str, list[str]]:
    """Return each identifier the entry's corpus expects, with the cases that expect it."""
    found: dict[str, list[str]] = {}
    for case in _own_cases(entry, root):
        for identifier in _identifiers(case):
            if (entry.corpus / "rules" / f"{identifier}.json").is_file():
                continue  # the case names the acceptance-rule fixture it is judged under
            found.setdefault(identifier, []).append(str(case.get("id")))
    return found


def _is_named(identifier: str, names: set[str]) -> bool:
    return identifier in names or identifier.split(":", 1)[0] in names


def _pair(case: dict[str, Any]) -> tuple[str, str] | None:
    """Return (rule id, reason) for a case that expects both, else None."""
    rule = case.get("rule")
    expected = case.get("expected")
    if not isinstance(expected, dict) or rule in (None, "") or isinstance(rule, bool):
        return None
    reason = expected.get("reason", expected.get("code"))
    if not isinstance(reason, str):
        return None
    rule_id = f"#{rule}" if isinstance(rule, int) or str(rule).isdigit() else str(rule)
    return rule_id, reason


def trace(entry: Entry, root: Path = ROOT) -> Trace:
    """Trace every identifier of one entry to its texts, and every rule to its row."""
    result = Trace(entry)
    if not entry.document.is_file():
        result.missing_document = True
        return result
    texts = [entry.document, *(path for path in entry.also if path.is_file())]
    readme = entry.corpus / "README.md"
    if not readme.is_file():
        readme = entry.corpus.parent / "README.md"
    if readme.is_file():
        texts.append(readme)
    read = [(path, path.read_text(encoding="utf-8")) for path in texts]
    names = [(path, named(text)) for path, text in read]
    for identifier, cases in sorted(expected_identifiers(entry, root).items()):
        where = next((path for path, found in names if _is_named(identifier, found)), None)
        if where is None:
            result.unnamed[identifier] = cases
        else:
            result.named_in[identifier] = where.relative_to(root).as_posix()
    rows = [(path, rule_rows(text)) for path, text in read]
    for case in _own_cases(entry, root):
        pair = _pair(case)
        if pair is None:
            continue
        rule, reason = pair
        row = next(((path, found[rule]) for path, found in rows if found.get(rule)), None)
        if row is not None and not _is_named(reason, row[1]):
            result.mispaired.append(
                f"{case.get('id')} expects rule `{rule}` with `{reason}`, but the row for "
                f"`{rule}` in {row[0].relative_to(root)} names {', '.join(sorted(row[1]))}"
            )
    return result


def load_pending(path: Path = PENDING) -> dict[str, set[str]]:
    """Return the owed identifiers, by predicate."""
    if not path.is_file():
        return {}
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return {item["predicate"]: set(item["identifiers"]) for item in data.get("pending", [])}


def problems(
    traces: Sequence[Trace], pending: dict[str, set[str]] | None = None, root: Path = ROOT
) -> list[str]:
    """Return each failure: unnamed and not pending, stale pending, or nothing read."""
    owed = pending if pending is not None else {}
    found = []
    for item in traces:
        name = item.entry.name
        if item.missing_document:
            found.append(
                f"{name}: cases of {item.entry.corpus.relative_to(root)} name this document, "
                "and no such file exists"
            )
            continue
        found.extend(f"{name}: {line}" for line in item.mispaired)
        if not item.named_in and not item.unnamed and name not in NO_CODES:
            found.append(f"{name}: no reason, rule or condition could be read from its corpus")
        listed = owed.get(name, set())
        for identifier in sorted(listed & item.named_in.keys()):
            found.append(f"{name}: `{identifier}` is named now; remove it from {PENDING.name}")
        for identifier in sorted(listed - item.named_in.keys() - item.unnamed.keys()):
            found.append(
                f"{name}: `{identifier}` is expected by no case; remove it from {PENDING.name}"
            )
        for identifier, cases in item.unnamed.items():
            if identifier in listed:
                continue
            shown = ", ".join(cases[:3]) + (f" and {len(cases) - 3} more" if len(cases) > 3 else "")
            found.append(
                f"{name}: `{identifier}` (expected by {shown}) is named in neither "
                f"{item.entry.document.relative_to(root)} nor the corpus README"
            )
    for name in sorted(owed.keys() - {item.entry.name for item in traces}):
        found.append(f"{name}: listed in {PENDING.name} but not defined in the registry")
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument(
        "--table", action="store_true", help="print every identifier and where it is named"
    )
    args = parser.parse_args(argv)
    entries = defined_entries()
    traces = [trace(entry) for entry in [*entries, *named_documents(entries)]]
    if args.table:
        for item in traces:
            for identifier, where in item.named_in.items():
                print(f"{item.entry.name}\t{identifier}\t{where}")
    total = sum(len(item.named_in) + len(item.unnamed) for item in traces)
    via_readme = sum(
        1 for item in traces for where in item.named_in.values() if where.endswith("README.md")
    )
    pending = load_pending()
    found = problems(traces, pending)
    owed = sum(len(item.unnamed.keys() & pending.get(item.entry.name, set())) for item in traces)
    named_count = sum(len(item.named_in) for item in traces)
    print(
        f"{len(traces)} predicates, {total} expected identifiers: {named_count} named "
        f"({via_readme} only in a corpus README), {owed} pending in {PENDING.name}, "
        f"{len(found)} problems"
    )
    for problem in found:
        print(f"FAIL {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
