"""The drop-in paper sections parse, cite only list messages that exist, quote
their co-authors word for word, and ship PDF and text built from the current source."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

SECTIONS_DIR = Path(__file__).resolve().parent.parent / "sections"
sys.path.insert(0, str(SECTIONS_DIR.parent))
from sections import build  # noqa: E402

MESSAGES = json.loads((SECTIONS_DIR / "messages.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", build.SECTIONS)
def test_section_parses(name: str) -> None:
    tex = (SECTIONS_DIR / f"{name}.tex").read_text(encoding="ascii")
    body = re.sub(r"(?<!\\)%.*", "", tex)
    depth = 0
    for ch in re.sub(r"\\[{}]", "", body):
        depth += {"{": 1, "}": -1}.get(ch, 0)
        assert depth >= 0, name
    assert depth == 0, name
    stack = []
    for kind, env in re.findall(r"\\(begin|end)\{([a-z*]+)\}", body):
        if kind == "begin":
            stack.append(env)
        else:
            assert stack and stack.pop() == env, (name, env)
    assert not stack, (name, stack)
    assert re.search(r"\\section\{", body), name


@pytest.mark.parametrize("name", build.SECTIONS)
def test_every_message_reference_resolves(name: str) -> None:
    tex = (SECTIONS_DIR / f"{name}.tex").read_text(encoding="ascii")
    refs = re.findall(r"\\aevmsg\{(Sep|Oct|Nov)\}\{(\d{4})\}", tex)
    assert refs, name
    for month, number in refs:
        assert f"2026{month}/{number}" in MESSAGES, (name, month, number)
    assert "\\cite{" not in tex, name


def _words(text: str) -> list[str]:
    return re.sub(r"[`'\"]", "", text).split()


@pytest.mark.parametrize(("quoted", "heading"), [
    ("0163-limitations", "Internal validity"),
    ("0148-reader-side-limits", "Construct validity"),
])
def test_threats_quote_coauthors_verbatim(quoted: str, heading: str) -> None:
    tex = (SECTIONS_DIR / "threats.tex").read_text(encoding="ascii")
    section = tex.split(heading, 1)[1]
    quote = section.split("\\begin{quote}", 1)[1].split("\\end{quote}", 1)[0]
    posted = (SECTIONS_DIR / "quoted" / f"{quoted}.txt").read_text(encoding="utf-8")
    body = posted.split("\n", 1)[1]  # the title line is the subsection heading
    assert _words(build._inline(quote)) == _words(body)


def test_pdf_and_text_are_built_from_current_source() -> None:
    proc = subprocess.run([sys.executable, str(SECTIONS_DIR / "build.py"), "--check"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
