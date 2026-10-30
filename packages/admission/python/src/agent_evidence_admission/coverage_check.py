"""Per-class coverage check: does a BOM state something for every class a buyer requires?

A buyer (a tender, a procurement profile) lists the classes it requires: CycloneDX component
types or SPDX software purposes. This module reads a CycloneDX BOM or an SPDX 3 document and
reports, for each required class, exactly one of:

* ``ASSESSED``           the document states the class complete;
* ``INCOMPLETE``         the document states the class assessed but incomplete;
* ``NOT-ASSESSED``       the document says the class was not assessed, and why (``unknown`` or
                         ``withheld``);
* ``COVERED-ELSEWHERE``  the document points at another document that covers the class (a
                         CycloneDX BOM-Link, an SPDX import);
* ``NO-REASON``          failing: the class is not assessed and the document gives neither a
                         reason nor a covering reference;
* ``MISSING``            failing: the document says nothing about the class;
* ``DOUBLE``             failing: two entries select the class and overlap or disagree;
* ``NOT-COMPLETE``       failing, only with ``require_complete``: the class is stated incomplete.

It reads the formats as they are today (CycloneDX 1.6 compositions, SPDX 3.0.1 relationship
completeness) and the fields proposed in CycloneDX/specification#1159 (a composition ``filter``
with ``componentTypes``, ``aggregate: not-assessed``, ``notAssessedReason``) and spdx-3-model#1105
(``software_CoverageRelationship`` with ``software_coveredPurpose`` and
``software_notAssessedReason``) when they are present. Standard library only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

ASSESSED = "ASSESSED"
INCOMPLETE = "INCOMPLETE"
NOT_ASSESSED = "NOT-ASSESSED"
COVERED_ELSEWHERE = "COVERED-ELSEWHERE"
NO_REASON = "NO-REASON"
MISSING = "MISSING"
DOUBLE = "DOUBLE"
NOT_COMPLETE = "NOT-COMPLETE"

FAILING = frozenset({NO_REASON, MISSING, DOUBLE, NOT_COMPLETE})
REASONS = ("unknown", "withheld")

_CDX_INCOMPLETE = (
    "incomplete",
    "incomplete_first_party_only",
    "incomplete_first_party_proprietary_only",
    "incomplete_first_party_opensource_only",
    "incomplete_third_party_only",
    "incomplete_third_party_proprietary_only",
    "incomplete_third_party_opensource_only",
)
_CDX_NOT_ASSESSED = ("unknown", "not_specified", "not-assessed", "not_assessed")
_NO_ASSERTION_TAIL = "NoAssertionElement"


class CoverageInputError(ValueError):
    """The document or the required list could not be understood; the verdict is unknown."""


@dataclass(frozen=True)
class Entry:
    """One statement a document makes about the classes it selects."""

    classes: frozenset[str]
    state: str  # "complete" | "incomplete" | "not-assessed"
    reason: str | None
    elsewhere: bool
    exclusive: bool  # selects its classes by an explicit filter or purpose, not by listing members
    targets: frozenset[str] | None
    source: str


@dataclass
class Normalized:
    """A document reduced to the entries it makes and the member counts per class."""

    fmt: str
    entries: list[Entry] = field(default_factory=list)
    present: dict[str, int] = field(default_factory=dict)
    referenced: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ClassResult:
    name: str
    status: str
    reason: str | None
    detail: str

    def as_dict(self) -> dict[str, str | None]:
        return {"class": self.name, "status": self.status, "reason": self.reason, "detail": self.detail}


@dataclass(frozen=True)
class Report:
    fmt: str
    results: list[ClassResult]
    notes: list[str]

    @property
    def ok(self) -> bool:
        return not any(r.status in FAILING for r in self.results)

    def as_dict(self) -> dict[str, object]:
        return {"format": self.fmt, "ok": self.ok, "classes": [r.as_dict() for r in self.results], "notes": self.notes}


# ---------------------------------------------------------------- required list


def parse_required(text: str, fmt: str | None = None) -> list[str]:
    """Read a required-class list: a JSON array, a JSON object, or lines and commas of names.

    A JSON object may carry ``required`` (every format), ``cyclonedx`` and ``spdx`` (one list per
    format, so one tender profile serves both); the key matching ``fmt`` is added to ``required``.
    """
    stripped = text.strip()
    if stripped.startswith(("[", "{")):
        try:
            value = json.loads(stripped)
        except ValueError as error:
            raise CoverageInputError(f"required list is not valid JSON: {error}") from error
        names = _names_from_json(value, fmt)
    else:
        lines = (line.split("#", 1)[0] for line in stripped.splitlines())
        names = [part.strip() for line in lines for part in line.split(",") if part.strip()]
    if not names:
        raise CoverageInputError("the required list names no class")
    return list(dict.fromkeys(names))


def _names_from_json(value: list | dict, fmt: str | None) -> list[str]:
    if isinstance(value, list):
        return _strings(value)
    names = _strings(value.get("required", []))
    if fmt is not None:
        names += _strings(value.get(fmt, []))
    return names


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise CoverageInputError("a required list holds non-empty strings")
    return list(value)


# ---------------------------------------------------------------- CycloneDX


def detect_format(document: object) -> str:
    """``cyclonedx`` or ``spdx``; anything else is an input error."""
    if isinstance(document, dict):
        if document.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if isinstance(document.get("@graph"), list):
            return "spdx"
    raise CoverageInputError("document is neither a CycloneDX BOM (bomFormat) nor an SPDX 3 graph (@graph)")


def _walk_components(components: object, found: dict[str, str]) -> None:
    for component in components if isinstance(components, list) else []:
        if not isinstance(component, dict):
            continue
        ref, kind = component.get("bom-ref"), component.get("type")
        if isinstance(kind, str):
            found[ref if isinstance(ref, str) else f"\0anon{len(found)}"] = kind
        _walk_components(component.get("components"), found)


def _walk_services(services: object, found: dict[str, str]) -> None:
    for service in services if isinstance(services, list) else []:
        if not isinstance(service, dict):
            continue
        ref = service.get("bom-ref")
        found[ref if isinstance(ref, str) else f"\0anon{len(found)}"] = "service"
        _walk_services(service.get("services"), found)


def _cdx_state(aggregate: object) -> str:
    if aggregate == "complete":
        return "complete"
    if aggregate in _CDX_INCOMPLETE:
        return "incomplete"
    if aggregate in _CDX_NOT_ASSESSED:
        return "not-assessed"
    raise CoverageInputError(f"composition aggregate {aggregate!r} is not one this checker understands")


def _cdx_entry(index: int, composition: dict, classes_by_ref: dict[str, str]) -> tuple[Entry, list[str]]:
    refs = [r for key in ("assemblies", "dependencies") for r in composition.get(key, []) if isinstance(r, str)]
    local = [r for r in refs if r in classes_by_ref]
    linked = any(r.startswith("urn:cdx:") for r in refs)
    selector = composition.get("filter")
    filtered = selector.get("componentTypes") if isinstance(selector, dict) else None
    exclusive = filtered is not None
    classes = frozenset(_strings(filtered)) if exclusive else frozenset(classes_by_ref[r] for r in local)
    state = _cdx_state(composition.get("aggregate"))
    targets = composition.get("targets")
    entry = Entry(
        classes=classes,
        state=state,
        reason=composition.get("notAssessedReason"),
        elsewhere=linked and (state == "not-assessed" or not local),
        exclusive=exclusive,
        targets=frozenset(_strings(targets)) if isinstance(targets, list) else None,
        source=f"compositions[{index}]",
    )
    return entry, local


def normalize_cyclonedx(bom: dict) -> Normalized:
    classes_by_ref: dict[str, str] = {}
    _walk_components(bom.get("components"), classes_by_ref)
    _walk_services(bom.get("services"), classes_by_ref)
    out = Normalized("cyclonedx")
    for kind in classes_by_ref.values():
        out.present[kind] = out.present.get(kind, 0) + 1
    seen: set[str] = set()
    for index, composition in enumerate(bom.get("compositions", [])):
        if not isinstance(composition, dict):
            raise CoverageInputError(f"compositions[{index}] is not an object")
        entry, local = _cdx_entry(index, composition, classes_by_ref)
        out.entries.append(entry)
        seen.update(local)
    for ref in seen:
        kind = classes_by_ref[ref]
        out.referenced[kind] = out.referenced.get(kind, 0) + 1
    return out


# ---------------------------------------------------------------- SPDX 3


def _tail(value: object) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1] if isinstance(value, str) else ""


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _purposes(element: dict) -> set[str]:
    values = _as_list(element.get("software_primaryPurpose")) + _as_list(element.get("software_additionalPurpose"))
    return {_tail(v) for v in values if _tail(v)}


def _spdx_state(completeness: object, source: str) -> str:
    table = {"complete": "complete", "incomplete": "incomplete", "noAssertion": "not-assessed", None: "not-assessed"}
    if completeness not in table:
        raise CoverageInputError(f"{source}: completeness {completeness!r} is not complete, incomplete or noAssertion")
    return table[completeness]


def _spdx_entry(relationship: dict, index: dict[str, dict], imports: set[str]) -> tuple[Entry | None, list[str]]:
    kind = relationship.get("type", "")
    coverage = kind.endswith("CoverageRelationship")
    if not coverage and "completeness" not in relationship:
        return None, []
    source = str(relationship.get("spdxId", kind))
    targets = [t for t in _as_list(relationship.get("to")) if isinstance(t, str) and not t.endswith(_NO_ASSERTION_TAIL)]
    local = [t for t in targets if t in index]
    external = bool(targets) and all(t in imports and t not in index for t in targets)
    state = _spdx_state(relationship.get("completeness"), source)
    if coverage:
        classes = {_tail(v) for v in _as_list(relationship.get("software_coveredPurpose")) if _tail(v)}
    else:
        classes = set().union(*(_purposes(index[t]) for t in local)) if local else set()
    reason = relationship.get("software_notAssessedReason")
    entry = Entry(frozenset(classes), state, _tail(reason) or None, external, coverage, None, source)
    return entry, local


def normalize_spdx(document: dict) -> Normalized:
    index = {e["spdxId"]: e for e in document["@graph"] if isinstance(e, dict) and isinstance(e.get("spdxId"), str)}
    spdx_doc = next((e for e in index.values() if e.get("type") == "SpdxDocument"), {})
    roots = {r for r in _as_list(spdx_doc.get("rootElement")) if isinstance(r, str)}
    imports = {m.get("externalSpdxId") for m in _as_list(spdx_doc.get("import")) if isinstance(m, dict)}
    out = Normalized("spdx")
    for element in index.values():
        if element["spdxId"] not in roots:
            for purpose in _purposes(element):
                out.present[purpose] = out.present.get(purpose, 0) + 1
    seen: set[str] = set()
    for relationship in index.values():
        if not str(relationship.get("type", "")).endswith("Relationship"):
            continue
        if roots and relationship.get("from") not in roots:
            continue
        entry, local = _spdx_entry(relationship, index, {i for i in imports if isinstance(i, str)})
        if entry is not None:
            out.entries.append(entry)
            seen.update(t for t in local if t not in roots)
    for target in seen:
        for purpose in _purposes(index[target]):
            out.referenced[purpose] = out.referenced.get(purpose, 0) + 1
    return out


# ---------------------------------------------------------------- resolution


def _outcome(entry: Entry) -> tuple[str, str | None, str]:
    """The status one entry gives each class it selects: (status, reason, detail)."""
    if entry.state == "incomplete":
        return INCOMPLETE, None, f"{entry.source} states the class incomplete"
    if entry.elsewhere:
        return COVERED_ELSEWHERE, None, f"{entry.source} points at the document that covers it"
    if entry.state == "complete":
        return ASSESSED, None, f"{entry.source} states the class complete"
    if entry.reason in REASONS:
        return NOT_ASSESSED, entry.reason, f"{entry.source} not assessed: {entry.reason}"
    if entry.reason is None:
        return NO_REASON, None, f"{entry.source} is not assessed, with no reason and no covering reference"
    return NO_REASON, None, f"{entry.source} gives reason {entry.reason!r}; the values are unknown and withheld"


def _overlapping(a: Entry, b: Entry) -> bool:
    return a.targets is None or b.targets is None or bool(a.targets & b.targets)


_WEAKEST_FIRST = (NO_REASON, NOT_ASSESSED, INCOMPLETE, COVERED_ELSEWHERE, ASSESSED)


def _double(selecting: list[Entry]) -> str | None:
    """Name the first pair of entries that select one class for the same target and clash."""
    for i, first in enumerate(selecting):
        for second in selecting[i + 1 :]:
            if not _overlapping(first, second):
                continue
            if first.exclusive and second.exclusive:
                return f"{first.source} and {second.source} both select the class"
            if _outcome(first)[:2] != _outcome(second)[:2]:
                return f"{first.source} is {_outcome(first)[0]} but {second.source} is {_outcome(second)[0]}"
    return None


def _resolve_class(name: str, doc: Normalized) -> ClassResult:
    selecting = [e for e in doc.entries if name in e.classes]
    if not selecting:
        present = doc.present.get(name, 0)
        detail = f"{present} member(s) present, no entry states their completeness" if present else "no entry and no member"
        return ClassResult(name, MISSING, None, detail)
    clash = _double(selecting)
    if clash is not None:
        return ClassResult(name, DOUBLE, None, clash)
    status, reason, detail = min((_outcome(e) for e in selecting), key=lambda o: _WEAKEST_FIRST.index(o[0]))
    gap = doc.present.get(name, 0) - doc.referenced.get(name, 0)
    if not any(e.exclusive for e in selecting) and gap > 0 and status != COVERED_ELSEWHERE:
        return ClassResult(name, MISSING, None, f"{gap} member(s) of the class are in no entry")
    return ClassResult(name, status, reason, detail)


def _notes(doc: Normalized, required: set[str]) -> list[str]:
    notes = []
    for entry in doc.entries:
        if entry.classes - required and not (entry.classes & required):
            status, _, detail = _outcome(entry)
            if status in FAILING:
                notes.append(f"outside the required list: {detail}")
        if not entry.classes:
            notes.append(f"{entry.source} selects no class, so it covers none")
    return notes


def check(document: object, required: list[str], *, require_complete: bool = False) -> Report:
    """Report each required class's status. ``require_complete`` fails INCOMPLETE as well."""
    fmt = detect_format(document)
    doc = normalize_cyclonedx(document) if fmt == "cyclonedx" else normalize_spdx(document)  # type: ignore[arg-type]
    results = [_resolve_class(name, doc) for name in required]
    if require_complete:
        results = [
            ClassResult(r.name, NOT_COMPLETE, None, f"{r.detail}; the buyer requires complete") if r.status == INCOMPLETE else r
            for r in results
        ]
    return Report(fmt, results, _notes(doc, set(required)))


def format_report(report: Report) -> str:
    """One line per class, then notes, then the verdict."""
    width = max(len(r.name) for r in report.results)
    lines = []
    for r in report.results:
        label = f"{r.status}({r.reason})" if r.reason else r.status
        lines.append(f"{label:<26} {r.name:<{width}}  {r.detail}")
    lines += [f"NOTE {note}" for note in report.notes]
    missing = sum(r.status in FAILING for r in report.results)
    lines.append(f"{'FAIL' if missing else 'PASS'} {report.fmt}: {len(report.results) - missing} of {len(report.results)} required classes accounted for")
    return "\n".join(lines)
