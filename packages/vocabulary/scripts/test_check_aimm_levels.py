#!/usr/bin/env python3
"""Offline tests for check_aimm_levels.py: the parser reads the real page, and a missing path is named."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_aimm_levels as c

PIN = "<!-- pins: vectors=v9.9.9 admission=" + "a" * 40 + " -->\n"


def test_real_page_parses():
    vref, aref, vpaths, apaths = c.parse(c.PAGE.read_text(encoding="utf-8"))
    assert vref.startswith("v") and len(aref) == 40
    assert "vectors-anchored-chain/cases/t2-tail-removal" in vpaths
    assert "vectors-anchored-chain/cases/t7-rollback-older-record" in vpaths
    assert all(p.endswith(".yaml") for p in apaths)


def test_missing_family_is_named():
    page = PIN + "| L5 | `vectors`, `vectors-gone` | `kyverno/x.yaml` |\n"
    _, _, vpaths, apaths = c.parse(page)
    assert c.missing(vpaths, {"vectors"}) == ["vectors-gone"]
    assert c.missing(apaths, {"kyverno/x.yaml"}) == []


def test_page_without_pins_is_refused():
    try:
        c.parse("| L1 | `vectors` | none |\n")
    except ValueError:
        return
    raise AssertionError("a page with no pins comment was accepted")


def test_malformed_row_is_refused():
    try:
        c.parse(PIN + "| L1 | `vectors` |\n")
    except ValueError:
        return
    raise AssertionError("a two-cell row was accepted")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
