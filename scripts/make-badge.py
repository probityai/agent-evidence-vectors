#!/usr/bin/env python3
"""Write a flat-square badge as a self-contained SVG, so a README badge is a file in the
repository and cannot fail to load from a third-party service.

usage: make-badge.py OUT.svg MESSAGE [--label LABEL] [--color HEX] [--logo-png FILE] [--title TEXT]
(an empty MESSAGE with a logo and a title writes an icon-only badge)
"""
from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path
from xml.sax.saxutils import escape

CHAR = 6.7
PAD = 10
LOGO = 14


def text_width(text: str) -> int:
    return round(len(text) * CHAR)


def build(message: str, label: str, color: str, logo: bytes | None, title: str = "") -> str:
    if logo and not message and not label:
        data = base64.b64encode(logo).decode()
        name = escape(title or "badge")
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
            f'width="{LOGO + 10}" height="20" role="img" aria-label="{name}"><title>{name}</title>'
            f'<rect width="{LOGO + 10}" height="20" fill="{color}"/>'
            f'<image x="5" y="3" width="{LOGO}" height="{LOGO}" xlink:href="data:image/png;base64,{data}"/></svg>'
        )
    logo_w = LOGO + 4 if logo else 0
    label_w = (text_width(label) + PAD + logo_w) if label else (logo_w + (4 if logo else 0))
    msg_w = text_width(message) + PAD
    total = label_w + msg_w + (0 if label else logo_w)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{total}" height="20" role="img" aria-label="{escape(label + " " + message).strip()}">',
        f"<title>{escape((label + ' ' + message).strip())}</title>",
    ]
    x = 0
    if label:
        parts.append(f'<rect width="{label_w}" height="20" fill="#555"/>')
        parts.append(f'<rect x="{label_w}" width="{msg_w}" height="20" fill="{color}"/>')
    else:
        parts.append(f'<rect width="{total}" height="20" fill="{color}"/>')
    if logo:
        data = base64.b64encode(logo).decode()
        parts.append(f'<image x="5" y="3" width="{LOGO}" height="{LOGO}" xlink:href="data:image/png;base64,{data}"/>')
    text_x = (label_w + msg_w / 2) if label else ((logo_w + total) / 2)
    if label:
        parts.append(
            f'<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{(label_w + logo_w) / 2 if logo else label_w / 2}" y="14">{escape(label)}</text>'
            f'<text x="{text_x}" y="14">{escape(message)}</text></g>'
        )
    else:
        parts.append(
            f'<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{text_x}" y="14">{escape(message)}</text></g>'
        )
    parts.append("</svg>")
    return "".join(parts)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", type=Path)
    ap.add_argument("message")
    ap.add_argument("--label", default="")
    ap.add_argument("--color", default="#007ec6")
    ap.add_argument("--logo-png", type=Path)
    ap.add_argument("--title", default="")
    args = ap.parse_args(argv)
    logo = args.logo_png.read_bytes() if args.logo_png else None
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(args.message, args.label, args.color, logo, args.title), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
