"""Build each drop-in section of the v0.1 paper as PDF and plain text, or check them.

    python build.py            # write <name>.txt and pdf/<name>.pdf for every section
    python build.py --check    # fail when a .txt or a PDF is stale against its .tex

Each section is a LaTeX fragment the paper can \\input. The PDF is built by
wrapping the fragment in a one-page article with pdflatex; a log line naming a
warning, an overfull or an underfull box fails the build. The PDF's subject
field carries the sha256 of the .tex it was built from, which is what --check
compares. The plain text is rendered here, from the same .tex, for editors who
assemble the draft in something other than LaTeX.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
APPENDIX = HERE.parent
SECTIONS = ["reproducibility", "availability", "verification", "threats", "findings", "related", "rows"]

PREAMBLE = r"""\documentclass[10pt]{article}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage[margin=2cm]{geometry}
\usepackage{array,booktabs,longtable}
\usepackage[hidelinks]{hyperref}
\pdfinfo{/AevSource (SUBJECT)}
\pdfobjcompresslevel=0
\emergencystretch=3em
\begin{document}
\input{NAME}
\end{document}
"""

LIST_URL = "https://lists.w3.org/Archives/Public/public-agent-conformance/2026{}/{}.html"


def source_digest(name: str) -> str:
    return hashlib.sha256((HERE / f"{name}.tex").read_bytes()).hexdigest()


def build_pdf(name: str) -> Path:
    """Compile one section; raise on any warning the log records."""
    out = HERE / "pdf" / f"{name}.pdf"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "wrap.tex").write_text(
            PREAMBLE.replace("SUBJECT", source_digest(name)).replace("NAME", name),
            encoding="utf-8")
        for _ in range(2):
            proc = subprocess.run(["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "wrap.tex"],
                                  cwd=work, env=_env(), capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                raise SystemExit(f"{name}: pdflatex failed\n{proc.stdout[-3000:]}")
        log = (work / "wrap.log").read_text(encoding="utf-8", errors="replace")
        bad = [line for line in log.splitlines()
               if re.search(r"Warning|Overfull|Underfull|Missing character", line)]
        if bad:
            raise SystemExit(f"{name}: LaTeX reported warnings:\n" + "\n".join(bad))
        out.parent.mkdir(exist_ok=True)
        shutil.copyfile(work / "wrap.pdf", out)
    return out


def _env() -> dict[str, str]:
    import os  # noqa: PLC0415
    return dict(os.environ) | {"TEXINPUTS": f"{HERE}:{APPENDIX}:"}


# ---- plain text ---------------------------------------------------------

def _arg(text: str, i: int) -> tuple[str, int]:
    """Return the brace group starting at text[i] == '{' and the index after it."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1
    raise ValueError("unbalanced braces")


def _macro(text: str, name: str, nargs: int, fmt) -> str:
    out, i, pat = [], 0, "\\" + name + "{"
    while True:
        k = text.find(pat, i)
        if k < 0:
            return "".join(out) + text[i:]
        out.append(text[i:k])
        args, j = [], k + len(pat) - 1
        for _ in range(nargs):
            a, j = _arg(text, j)
            args.append(a)
        out.append(fmt(*args))
        i = j


def _inline(t: str) -> str:
    t = _macro(t, "aevmsg", 2, lambda m, n: f"{m}/{n}")
    t = _macro(t, "href", 2, lambda u, s: f"{s} <{u}>")
    for name in ("url", "nolinkurl", "texttt", "emph", "textit", "textbf", "path"):
        t = _macro(t, name, 1, lambda s: s)
    t = t.replace("\\aevreadrelease{}", "0.31.1").replace("\\aevreadrelease", "0.31.1")
    t = t.replace("\\ldots", "...").replace("\\'a", "a").replace("\\'e", "e")
    t = t.replace("``", '"').replace("''", '"')
    t = re.sub(r"\\([%&_#$])", r"\1", t).replace("~", " ").replace("\\textbackslash{}", "\\")
    t = re.sub(r"\\label\{[^}]*\}", "", t).replace("\\noindent", "")
    return re.sub(r"[ \t]+", " ", t).strip()


def _table(body: str) -> list[str]:
    body = re.sub(r"\\(toprule|midrule|bottomrule|hline|endhead|endfirsthead|centering|footnotesize|scriptsize|small)\b", "", body)
    body = re.sub(r"\\caption\{.*?\}\s*(\\label\{[^}]*\})?\s*\\\\", "", body, flags=re.S)
    rows = [r for r in (x.strip() for x in body.split("\\\\")) if r]
    lines, seen = [], set()
    for r in rows:
        cells = [_inline(c) for c in r.split("&")]
        key = tuple(cells)
        if key in seen:  # longtable repeats its header for later pages
            continue
        seen.add(key)
        lines.append(" | ".join(cells))
    return lines


def render_text(name: str, base: Path = HERE) -> str:
    tex = (base / f"{name}.tex").read_text(encoding="utf-8")
    tex = "\n".join(l for l in tex.splitlines() if not l.lstrip().startswith("%"))
    tex = re.sub(r"\\providecommand\{[^}]*\}(\[\d\])?\{.*\}\s*\n", "", tex)
    tex = re.sub(r"\\IfFileExists\{[^}]*\}\{\\input\{([^}]*)\}\}\{[^}]*\}",
                 lambda m: "\\input{" + m.group(1) + "}", tex)
    tex = re.sub(r"\\input\{([^}]*)\}",
                 lambda m: _included(m.group(1)), tex)
    out: list[str] = []
    pos = 0
    for m in re.finditer(r"\\begin\{(longtable|tabular)\}(\{[^\n]*\})?(.*?)\\end\{\1\}", tex, re.S):
        out.extend(_prose(tex[pos:m.start()]))
        cap = re.search(r"\\caption\{(.*?)\}\s*(\\label|\\\\|$)", m.group(3), re.S)
        if cap:
            out.append("Table: " + _inline(cap.group(1)))
        out.extend(_table(m.group(3)))
        out.append("")
        pos = m.end()
    out.extend(_prose(tex[pos:]))
    text = "\n".join(out)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def _included(path: str) -> str:
    p = (HERE / (path + ("" if path.endswith(".tex") else ".tex"))).resolve()
    if not p.exists():
        p = (APPENDIX / path.replace("\\aevappendixdir/", "")).with_suffix(".tex")
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _prose(tex: str) -> list[str]:
    tex = re.sub(r"\\begin\{(table|quote|itemize|enumerate|center|flushleft)\}(\[[^]]*\])?|\\end\{(table|quote|itemize|enumerate|center|flushleft)\}", "\n\n", tex)
    tex = re.sub(r"\\section\*?\{(.*?)\}", lambda m: "\n\n" + m.group(1).upper() + "\n\n", tex)
    tex = re.sub(r"\\subsection\*?\{(.*?)\}", lambda m: "\n\n" + m.group(1) + "\n\n", tex)
    tex = re.sub(r"\\paragraph\{(.*?)\}", lambda m: "\n\n" + m.group(1) + ". ", tex)
    tex = tex.replace("\\item", "\n\n- ").replace("{\\footnotesize", "").replace("{\\small", "")
    tex = re.sub(r"\\(caption|label)\{[^}]*\}", "", tex)
    paras = [_inline(p) for p in re.split(r"\n\s*\n", tex)]
    out = []
    for p in paras:
        p = p.strip("{} ")
        if p:
            out.extend([p, ""])
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for name in SECTIONS:
        if not (HERE / f"{name}.tex").exists():
            stale.append(f"{name}.tex missing")
            continue
        txt = render_text(name)
        txt_path = HERE / "txt" / f"{name}.txt"
        pdf_path = HERE / "pdf" / f"{name}.pdf"
        if check:
            if not txt_path.exists() or txt_path.read_text(encoding="utf-8") != txt:
                stale.append(f"txt/{name}.txt is stale; run python build.py")
            if not pdf_path.exists() or source_digest(name).encode() not in pdf_path.read_bytes():
                stale.append(f"pdf/{name}.pdf was not built from the current {name}.tex")
        else:
            txt_path.parent.mkdir(exist_ok=True)
            txt_path.write_text(txt, encoding="utf-8")
            build_pdf(name)
    for s in stale:
        print(s, file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
