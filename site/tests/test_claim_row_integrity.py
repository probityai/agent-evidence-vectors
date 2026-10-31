"""Claims must not disappear silently when Markdown stops treating them as rows."""
from pathlib import Path

import pytest

import build


def test_source_claims_need_one_matching_row():
    source = "| C-35 | package |\n| C-36 | footer |\n"
    build.check_rendered_claim_rows(source, ["C-36", "C-35"])


@pytest.mark.parametrize("source, rows", [
    ("| C-35 | package |\n\n| C-36 | footer |\n", ["C-35"]),
    ("| C-35 | package |\n", ["C-35", "C-35"]),
    ("| C-35 | package |\n", ["C-35", "C-99"]),
    ("| C-35 | first |\n| C-35 | repeated |\n", ["C-35", "C-35"]),
    ("", []),
])
def test_missing_repeated_or_invented_rows_refused(source, rows, capsys):
    with pytest.raises(SystemExit) as caught:
        build.check_rendered_claim_rows(source, rows)
    assert caught.value.code == 1
    assert "claim ledger rows did not render exactly once" in capsys.readouterr().err


def test_actual_bad_metadata_html_is_refused_when_rows_are_plain_prose():
    root = Path(__file__).resolve().parents[1]
    html = (root / "docs/claims.html").read_text()
    # Keep a real generated document, but substitute its two selected rows with
    # the same visible text outside the table. A text search alone would pass.
    import re
    altered, count = re.subn(r'<tr[^>]*>\s*<td[^>]*>C-3[56]</td>.*?</tr>',
                             '<p>C-35 C-36</p>', html, flags=re.S)
    if not count:
        # The pre-fix immutable document already has both rows as prose.
        altered = html
    assert "C-35" in altered and "C-36" in altered
    with pytest.raises(SystemExit):
        build.stamp_cadence(altered)
