"""Read the Clause 5 and Annex A tables, and the clauses that govern them, out of
the NIST AI 300-1 initial public draft.

Everything this corpus binds to is taken from the PDF's own text layer by this
module, and nothing else. The extraction is deliberately plain so that anyone
can re-derive every digest in MANIFEST.json from the PDF with the same pinned
PyMuPDF release:

* Words come from ``page.get_text("words")`` with ligatures expanded and
  whitespace not preserved, so a word never carries a space or a ligature glyph.
* A table cell is the words whose left edge falls in that column, where a column
  starts at the left edge of its header word. Words on one line of a cell are
  joined with one space; lines are joined with one space, except that a line
  ending in a hyphen or an em dash is joined to the next with nothing between.
* A table row starts at a word in the ID column whose first character is a
  digit. A line in the ID column that starts with ``(`` continues the ID above
  it, which is how ``5.2-`` and ``(*).1`` become ``5.2-(*).1``. Words above the
  first row start on a page continue the last row of the previous page.
* Clause text is every word between two headings on the given pages, minus the
  line-number column at the left margin, in reading order (line by line, top to
  bottom, left to right), with lines joined as table cell lines are.
* All text is Unicode NFC. Nothing else is normalised: curly quotes, em dashes
  and the document's own spelling are kept.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# PyMuPDF ships no py.typed marker and no stubs package exists for it. The ignore
# is scoped to these imports, not set in pyproject.toml, because mypy --strict
# warns about an override that a run over other directories never uses. Every
# value PyMuPDF hands back is converted to a typed one in this module.
import pymupdf  # type: ignore[import-untyped]
from pymupdf.table import find_tables  # type: ignore[import-untyped]

# Words left of this x (in points) are the draft's line numbers.
LINE_NUMBER_MARGIN = 30.0
# Two words whose tops differ by less than this sit on one line.
LINE_TOLERANCE = 2.0
# How far left of a header word a cell's text may start and still be in it.
COLUMN_SLACK = 3.0
# The header band is the ID header line and the one line under it.
HEADER_DEPTH = 16.0

TEXT_FLAGS = pymupdf.TEXT_MEDIABOX_CLIP

COLUMNS = ("id", "name", "description", "designation", "guidance")

# A table caption as the draft prints it: "Table A.2.1: Default AI dataset profile".
# A sentence that merely names a table ("Table A.2.1 provides ...") has no colon.
CAPTION = re.compile(r"Table [A-Z0-9][A-Z0-9.]*: .+")
# A row ID: dotted digits, optionally a "-(*)" family with its own dotted tail.
ROW_ID = re.compile(r"\d+(?:\.\d+)*(?:-\(\*\)(?:\.\d+)*)?")


@dataclass(frozen=True)
class Word:
    """One word of the text layer, with its page and box."""

    page: int
    x0: float
    y0: float
    text: str


@dataclass(frozen=True)
class TableSpec:
    """Where one table lives and what its header row says."""

    key: str
    title: str
    pages: tuple[int, ...]
    header: tuple[str, ...]


@dataclass(frozen=True)
class ClauseSpec:
    """A run of prose between two headings."""

    key: str
    start: tuple[int, str]
    end: tuple[int, str]


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    """Hex SHA-256 of the UTF-8 bytes of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value: Any) -> str:
    """Sorted-key, separator-tight JSON, the form every table digest is taken over."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def nfc(text: str) -> str:
    """Unicode NFC, the only normalisation applied to extracted text."""
    return unicodedata.normalize("NFC", text)


def ruled_tables(doc: pymupdf.Document, page: int) -> list[Any]:
    """The ruled tables PyMuPDF finds on one 1-based page.

    From 1.26.7, find_tables catches any exception inside table detection,
    prints it and returns None. Read as "no tables", that would drop a table
    from the count without failing, so a None is an error here.
    """
    finder = find_tables(doc[page - 1])
    if finder is None:
        raise ValueError(f"page {page}: PyMuPDF table detection failed")
    return list(finder.tables)


def page_words(doc: pymupdf.Document, page: int) -> list[Word]:
    """Every word on a 1-based page, right of the line-number margin."""
    out = []
    for w in doc[page - 1].get_text("words", flags=TEXT_FLAGS):
        x0 = float(w[0])
        if x0 >= LINE_NUMBER_MARGIN:
            out.append(Word(page, x0, float(w[1]), nfc(str(w[4]))))
    return out


def group_lines(words: list[Word]) -> list[list[Word]]:
    """Group words into lines by their top edge, top to bottom, left to right."""
    lines: list[list[Word]] = []
    for word in sorted(words, key=lambda w: (w.page, w.y0, w.x0)):
        last = lines[-1] if lines else None
        if last and last[0].page == word.page and abs(last[0].y0 - word.y0) < LINE_TOLERANCE:
            last.append(word)
        else:
            lines.append([word])
    return [sorted(line, key=lambda w: w.x0) for line in lines]


def line_text(line: list[Word]) -> str:
    """The words of one line joined with one space."""
    return " ".join(w.text for w in line)


def join_lines(lines: list[str]) -> str:
    """Join cell lines with one space, or with nothing after a hyphen or em dash."""
    out = ""
    for text in lines:
        if not out:
            out = text
        elif out.endswith(("-", "—")):
            out += text
        else:
            out += " " + text
    return out


def find_line(lines: list[list[Word]], page: int, text: str) -> list[Word]:
    """The single line on a page whose text is exactly ``text``."""
    hits = [ln for ln in lines if ln[0].page == page and line_text(ln) == text]
    if len(hits) != 1:
        raise ValueError(f"page {page}: expected one line {text!r}, found {len(hits)}")
    return hits[0]


def clause_text(doc: pymupdf.Document, spec: ClauseSpec) -> str:
    """The prose between two headings, heading included, end heading excluded."""
    (first, start_text), (last, end_text) = spec.start, spec.end
    lines = group_lines([w for p in range(first, last + 1) for w in page_words(doc, p)])
    begin = find_line(lines, first, start_text)
    end = find_line(lines, last, end_text)
    i, j = lines.index(begin), lines.index(end)
    return join_lines([line_text(ln) for ln in lines[i:j]])


def header_band(words: list[Word], spec: TableSpec) -> tuple[float, list[float]]:
    """The bottom of the header band and the left edge of each column."""
    ids = [w for w in words if w.text == "ID"]
    if len(ids) != 1:
        raise ValueError(f"page {words[0].page}: {len(ids)} ID header words")
    top = ids[0].y0
    band = [w for w in words if top - LINE_TOLERANCE <= w.y0 < top + HEADER_DEPTH]
    starts = []
    for head in spec.header:
        first = head.split()[0]
        hits = [w.x0 for w in band if w.text == first]
        if not hits:
            raise ValueError(f"page {words[0].page}: header {head!r} not found")
        starts.append(min(hits))
    seen = " ".join(line_text(ln) for ln in group_lines(band))
    for head in spec.header:
        for token in head.split():
            if token not in seen.split():
                raise ValueError(f"page {words[0].page}: header token {token!r} missing")
    return top + HEADER_DEPTH, starts


def column_of(word: Word, starts: list[float]) -> int:
    """The column whose left edge is the last one at or left of the word."""
    col = 0
    for i, start in enumerate(starts):
        if word.x0 + COLUMN_SLACK >= start:
            col = i
    return col


def table_words(doc: pymupdf.Document, spec: TableSpec, page: int) -> list[Word]:
    """The words inside the table on one page, below its title line.

    The table's extent is the bounding box of the ruled table PyMuPDF finds
    whose top-left cell is the title, so prose above or below it is excluded.
    """
    found = [t for t in ruled_tables(doc, page) if _is_titled(t, spec.title)]
    if len(found) != 1:
        raise ValueError(f"page {page}: expected one table titled {spec.title!r}")
    x0, y0, x1, y1 = found[0].bbox
    inside = [w for w in page_words(doc, page) if x0 - 1 <= w.x0 <= x1 and y0 - 1 <= w.y0 <= y1]
    title = find_line(group_lines(inside), page, spec.title)
    return [w for w in inside if w.y0 > title[0].y0 + LINE_TOLERANCE]


def _is_titled(table: Any, title: str) -> bool:
    rows = table.extract()
    return bool(rows) and bool(rows[0]) and (rows[0][0] or "").replace("\n", " ") == title


def page_rows(words: list[Word], starts: list[float]) -> list[list[list[Word]]]:
    """Split one page's data words into rows; row 0 is any carry-over from the page before."""
    id_lines = [ln for ln in group_lines([w for w in words if column_of(w, starts) == 0])]
    tops = [ln[0].y0 for ln in id_lines if ln[0].text[:1].isdigit()]
    rows: list[list[list[Word]]] = [[[] for _ in COLUMNS] for _ in range(len(tops) + 1)]
    for word in words:
        index = sum(1 for t in tops if word.y0 >= t - LINE_TOLERANCE)
        rows[index][column_of(word, starts)].append(word)
    return rows


def cell_text(words: list[Word]) -> str:
    """One cell's words as text, lines joined by join_lines."""
    return join_lines([line_text(ln) for ln in group_lines(words)])


def extract_table(doc: pymupdf.Document, spec: TableSpec) -> list[dict[str, Any]]:
    """Every row of one table, with each cell as printed and the pages it spans."""
    rows: list[dict[str, Any]] = []
    for page in spec.pages:
        words = table_words(doc, spec, page)
        bottom, starts = header_band(words, spec)
        data = [w for w in words if w.y0 >= bottom]
        for index, cells in enumerate(page_rows(data, starts)):
            if index == 0:
                _carry(rows, cells, page)
                continue
            rows.append({"cells": [list(c) for c in cells], "pages": [page]})
    return [_finish(r) for r in rows]


def _carry(rows: list[dict[str, Any]], cells: list[list[Word]], page: int) -> None:
    if not any(cells):
        return
    if not rows:
        raise ValueError(f"page {page}: text above the first row of a table")
    for i, words in enumerate(cells):
        rows[-1]["cells"][i].extend(words)
    rows[-1]["pages"].append(page)


def _finish(row: dict[str, Any]) -> dict[str, Any]:
    cells = {name: cell_text(words) for name, words in zip(COLUMNS, row["cells"], strict=True)}
    return {**cells, "pages": sorted(set(row["pages"]))}


def table_digest(rows: list[dict[str, Any]]) -> str:
    """SHA-256 of the canonical JSON of a table's rows: five cells and the pages, per row."""
    return sha256_text(canonical([{k: r[k] for k in (*COLUMNS, "pages")} for r in rows]))


def open_pdf(path: Path) -> pymupdf.Document:
    """Open the source PDF."""
    return pymupdf.open(path)


def census(doc: pymupdf.Document) -> dict[str, Any]:
    """Every ruled box and every table caption in the PDF, read without extract_table.

    This is the completeness count. extract_table reads only the tables it is
    told about, by title and page, so on its own it cannot notice a table it was
    never told about, a page of a table it was not given, or a row its word
    geometry merged into the row above. The census reads every page instead:
    each ruled box PyMuPDF finds, with the first text in it and the row IDs its
    own cell grid gives, and each caption line in the text layer. Comparing the
    two is what makes "every table, every row" a measured claim.
    """
    ruled: list[dict[str, Any]] = []
    captions: list[dict[str, Any]] = []
    for number in range(1, doc.page_count + 1):
        page = doc[number - 1]
        for line in str(page.get_text("text", flags=TEXT_FLAGS)).splitlines():
            text = nfc(line.strip())
            if CAPTION.fullmatch(text):
                captions.append({"page": number, "title": text})
        for table in ruled_tables(doc, number):
            rows: list[list[str | None]] = table.extract()
            filled = [nfc(c.replace("\n", " ").strip()) for r in rows for c in r if c]
            ids = []
            for row in rows[1:]:
                cells = [c for c in row if c]
                if cells and ROW_ID.fullmatch(nfc(cells[0].replace("\n", ""))):
                    ids.append(nfc(cells[0].replace("\n", "")))
            ruled.append({"page": number, "first": filled[0] if filled else "", "ids": ids})
    return {"pages": doc.page_count, "ruled": ruled, "captions": captions}
