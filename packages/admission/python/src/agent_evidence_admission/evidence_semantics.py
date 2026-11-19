"""Exact evidence semantics for every line the verifier prints.

A report must never read as a clearance when nothing was checked. These helpers are the only way the
verifier's output path writes a denominator, a redaction or a link failure, and
``tests/test_evidence_semantics.py`` holds the rest of the package to them:

* an empty denominator prints ``no records``, never a count of zero out of zero and never a percentage;
* a value left out of an output is named by ``redacted``, so a reader sees that something was withheld;
* every way of failing to obtain a document from a URL is one error, ``link-not-verifiable``, so the
  message does not tell a caller whether a link is expired, forged or unknown;
* a result that was not checked (not assessed, errored, covered elsewhere, not asked) is counted apart
  from a pass and never inside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

NO_RECORDS = "no records"
LINK_ERROR = "link-not-verifiable"


class LinkError(ValueError):
    """A document could not be obtained from a URL; the cause is deliberately not stated."""


def link_error(source: str) -> LinkError:
    """The one error every failed fetch of ``source`` raises, whatever went wrong."""
    return LinkError(f"{LINK_ERROR}: {source}")


def redacted(label: str) -> str:
    """The text that stands where a value was left out; it always says what was left out."""
    return f"[redacted: {label}]"


@dataclass
class Tally:
    """Results counted as passed, failed or not checked, with every redaction stated.

    ``ok`` is true only when something was checked, nothing failed and nothing was left unchecked.
    """

    passed: int = 0
    failed: int = 0
    unchecked: int = 0
    redactions: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.unchecked

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.failed == 0 and self.unchecked == 0

    def word(self) -> str:
        """``FAIL`` when anything failed, ``PASS`` only when everything was checked and passed, else ``UNCHECKED``."""
        if self.failed:
            return "FAIL"
        return "PASS" if self.ok else "UNCHECKED"

    def headline(self, noun: str) -> str:
        """``no records`` for an empty denominator; otherwise passed, failed and not-checked counts, then the redactions."""
        if self.total == 0:
            return NO_RECORDS
        text = f"{self.passed} of {self.total} {noun} passed, {self.failed} failed, {self.unchecked} not checked"
        if self.redactions:
            text += "; withheld: " + ", ".join(self.redactions)
        return text
