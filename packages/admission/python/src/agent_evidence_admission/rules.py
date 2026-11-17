"""Rule sets: refuse a record before any verifier judges it.

A rule set is a strict parse followed by an ordered list of checks. Each check either passes or
raises a :class:`~agent_evidence_admission.strict_json.Refusal` naming its code and the JSON
Pointer it applies to. The first refusal decides; the verdict also lists every later refusal, so a
report shows all the ways one record fails. A refusal whose code the caller lists in ``warn`` is
reported as a warning and does not refuse. A warned parse code (``duplicate-member``, say) does not
stop the parse: the record is read again with that check off, the way a lenient decoder reads it,
and every rule still runs on what was read. Three codes say that nothing was read
(``not-parseable``, ``payload-not-base64``, ``shape-unreadable``), so warning one would admit a
record no rule judged; they are not warnable, and naming one in ``warn`` is a ``ValueError``.

Admission decides whether a record is fit to be judged. It does not verify a signature, fetch
anything, or say a record is true: a rule set reads bytes the caller already holds, and where it
needs a key, a vendored file or a reference value, the caller passes it in ``options`` or
``files``. A rule that cannot be evaluated for lack of an input refuses under a ``*-not-evaluated``
code, never passes; a caller that accepts the gap lists that code in ``warn``.

Every check has a name, so a check can be switched off (``enabled``). That is what the ablation
command uses to prove that each check is needed by at least one case of the rule set's vectors and
that the full set reaches every stated verdict.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import strict_json
from .strict_json import Refusal

PARSE_PREFIX = "json:"
#: Codes that mean the record was not read at all; a warning on one would admit what no rule judged.
UNWARNABLE = frozenset({"not-parseable", "payload-not-base64", "shape-unreadable"})


def parse_lifting(data: bytes, profile: str, checks: Iterable[str], warn: frozenset[str]) -> tuple[Any, list[Refusal]]:
    """Parse ``data``; a refusal whose code is in ``warn`` is kept and the parse runs again without
    that check, so a warned code yields the lenient reading instead of no reading. A refusal that
    is not warned (or cannot be switched off) is raised."""
    enabled = set(checks)
    lifted: list[Refusal] = []
    while True:
        try:
            return strict_json.loads(data, profile=profile, checks=enabled), lifted
        except Refusal as refusal:
            if refusal.code in warn and refusal.code in enabled:
                lifted.append(refusal)
                enabled.discard(refusal.code)
                continue
            raise


@dataclass
class Context:
    """What one check sees: the parsed document, the raw bytes, options and vendored files."""

    document: Any
    raw: bytes
    options: Mapping[str, Any]
    files: Mapping[str, bytes]
    enabled: frozenset[str]
    found: list[Refusal] = field(default_factory=list)
    warn: frozenset[str] = frozenset()

    def parse(self, data: bytes, at: str, profile: str = "ijson") -> Any:
        """Parse nested bytes (a DSSE payload) under the same parse checks, and the same warned
        codes, as the document."""
        checks = {name[len(PARSE_PREFIX) :] for name in self.enabled if name.startswith(PARSE_PREFIX)}
        try:
            value, lifted = parse_lifting(data, profile, checks, self.warn)
        except Refusal as refusal:
            raise Refusal(refusal.code, at + refusal.at, refusal.detail) from refusal
        for refusal in lifted:
            relocated = Refusal(refusal.code, at + refusal.at, refusal.detail)
            if all((r.code, r.at) != (relocated.code, relocated.at) for r in self.found):
                self.found.append(relocated)
        return value

    def note(self, refusal: Refusal) -> None:
        """Record a refusal without stopping the check that found it."""
        self.found.append(refusal)


@dataclass(frozen=True)
class Check:
    name: str
    summary: str
    run: Callable[[Context], None]


@dataclass(frozen=True)
class RuleSet:
    name: str
    summary: str
    checks: tuple[Check, ...]
    profile: str = "ijson"
    parse_checks: tuple[str, ...] = strict_json.CHECKS
    #: Options a caller may pass, with what each means.
    option_help: Mapping[str, str] = field(default_factory=dict)

    def check_names(self) -> tuple[str, ...]:
        return tuple(PARSE_PREFIX + code for code in self.parse_checks) + tuple(c.name for c in self.checks)


@dataclass(frozen=True)
class Verdict:
    rule_set: str
    admitted: bool
    refusals: tuple[Refusal, ...]
    warnings: tuple[Refusal, ...]

    @property
    def code(self) -> str | None:
        return self.refusals[0].code if self.refusals else None

    def as_dict(self) -> dict[str, Any]:
        def row(r: Refusal) -> dict[str, str]:
            return {"code": r.code, "at": r.at or "/", "detail": r.detail}

        return {
            "ruleSet": self.rule_set,
            "verdict": "admit" if self.admitted else "refuse",
            "code": self.code,
            "refusals": [row(r) for r in self.refusals],
            "warnings": [row(r) for r in self.warnings],
        }


REGISTRY: dict[str, RuleSet] = {}


def register(rule_set: RuleSet) -> RuleSet:
    if rule_set.name in REGISTRY:
        raise AssertionError(f"rule set {rule_set.name} registered twice")
    names = rule_set.check_names()
    if len(set(names)) != len(names):
        raise AssertionError(f"rule set {rule_set.name} names a check twice")
    REGISTRY[rule_set.name] = rule_set
    return rule_set


def get(name: str) -> RuleSet:
    _load_all()
    try:
        return REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown rule set {name!r}; known: {', '.join(sorted(REGISTRY))}") from None


def all_rule_sets() -> list[RuleSet]:
    _load_all()
    return [REGISTRY[name] for name in sorted(REGISTRY)]


def _load_all() -> None:
    from . import catalog_rules, freshness, ijson_rules, receipt_rules, token_rules  # noqa: F401


def run(
    rule_set: RuleSet,
    raw: bytes,
    options: Mapping[str, Any] | None = None,
    files: Mapping[str, bytes] | None = None,
    enabled: Iterable[str] | None = None,
    warn: Iterable[str] = (),
) -> Verdict:
    """Run ``rule_set`` on ``raw``. ``enabled`` limits the checks that run (all by default).

    An option the rule set does not define is a ``ValueError``, not a silent default: a caller who
    writes ``skwe`` for ``skew`` would otherwise be judged under a tolerance they did not choose."""
    names = frozenset(rule_set.check_names() if enabled is None else enabled)
    unknown = names - set(rule_set.check_names())
    if unknown:
        raise ValueError(f"{rule_set.name} has no checks named {', '.join(sorted(unknown))}")
    stray = set(options or {}) - set(rule_set.option_help)
    if stray:
        known = ", ".join(sorted(rule_set.option_help)) or "none"
        raise ValueError(f"{rule_set.name} has no options named {', '.join(sorted(stray))}; it takes: {known}")
    warn_codes = frozenset(warn)
    if warn_codes & UNWARNABLE:
        raise ValueError(f"{', '.join(sorted(warn_codes & UNWARNABLE))} cannot be a warning: it means the record was not read")
    parse_checks = {n[len(PARSE_PREFIX) :] for n in names if n.startswith(PARSE_PREFIX)}
    try:
        document, lifted = parse_lifting(raw, rule_set.profile, parse_checks, warn_codes)
    except Refusal as refusal:
        return _verdict(rule_set, [refusal], warn_codes)
    context = Context(document, raw, options or {}, files or {}, names, list(lifted), warn_codes)
    for check in rule_set.checks:
        if check.name not in names:
            continue
        try:
            check.run(context)
        except Refusal as refusal:
            context.found.append(refusal)
        except (KeyError, TypeError, AttributeError, IndexError, ValueError) as error:
            context.found.append(Refusal("shape-unreadable", "", f"{check.name}: {error.__class__.__name__}: {error}"))
    return _verdict(rule_set, context.found, warn_codes)


def _verdict(rule_set: RuleSet, found: list[Refusal], warn_codes: frozenset[str]) -> Verdict:
    refusals = tuple(r for r in found if r.code not in warn_codes)
    warnings = tuple(r for r in found if r.code in warn_codes)
    return Verdict(rule_set.name, not refusals, refusals, warnings)


# --------------------------------------------------------------------------
# Helpers the rule sets share.
# --------------------------------------------------------------------------


def statement_of(context: Context) -> tuple[dict[str, Any], str]:
    """The in-toto statement a document carries, bare or as a DSSE payload, and its pointer prefix."""
    document = context.document
    if not isinstance(document, dict):
        raise Refusal("shape-unreadable", "", "the document is not a JSON object")
    if "payload" in document and "payloadType" in document:
        payload = document["payload"]
        if not isinstance(payload, str):
            raise Refusal("shape-unreadable", "/payload", "the DSSE payload is not a string")
        try:
            raw = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as error:
            raise Refusal("payload-not-base64", "/payload", str(error)) from error
        statement = context.parse(raw, "/payload")
        if not isinstance(statement, dict):
            raise Refusal("shape-unreadable", "/payload", "the payload is not a JSON object")
        return statement, "/payload"
    return document, ""


def _bytes(base: Path, held: Mapping[str, Any]) -> bytes:
    """Bytes a manifest row carries as ``text``, ``base64`` or a ``file`` beside the manifest."""
    if "text" in held:
        return str(held["text"]).encode("utf-8")
    if "base64" in held:
        return base64.b64decode(held["base64"], validate=True)
    return (base / held["file"]).read_bytes()


def load_cases(manifest_path: str | Path) -> tuple[RuleSet, list[Case]]:
    """The rule set a vectors manifest names and its cases, with every file read relative to it."""
    path = Path(manifest_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    rule_set = get(manifest["ruleSet"])
    base = path.parent
    cases = []
    for row in manifest["cases"]:
        raw = _bytes(base, row)
        files = {uri: _bytes(base, held) for uri, held in row.get("files", {}).items()}
        expect = row["expect"]
        cases.append(
            Case(
                id=row["id"],
                raw=raw,
                expect_admit=expect["verdict"] == "admit",
                expect_code=expect.get("code"),
                options=row.get("options", manifest.get("options", {})),
                files=files,
                warn=tuple(row.get("warn", ())),
            )
        )
    return rule_set, cases


# --------------------------------------------------------------------------
# Ablation: which checks each rule set needs.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    id: str
    raw: bytes
    expect_admit: bool
    expect_code: str | None
    options: Mapping[str, Any] = field(default_factory=dict)
    files: Mapping[str, bytes] = field(default_factory=dict)
    warn: tuple[str, ...] = ()

    def judged(self, verdict: Verdict) -> bool:
        if verdict.admitted != self.expect_admit:
            return False
        return self.expect_admit or self.expect_code is None or verdict.code == self.expect_code


@dataclass(frozen=True)
class Ablation:
    rule_set: str
    cases: int
    sufficient: bool
    failing_with_all: tuple[str, ...]
    necessary: Mapping[str, tuple[str, ...]]
    unexercised: tuple[str, ...]
    monotone: bool
    minimal_sets: tuple[tuple[str, ...], ...] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleSet": self.rule_set,
            "cases": self.cases,
            "sufficient": self.sufficient,
            "failingWithAllChecks": list(self.failing_with_all),
            "necessary": {k: list(v) for k, v in self.necessary.items()},
            "unexercised": list(self.unexercised),
            "monotone": self.monotone,
            "minimalSufficientSets": None if self.minimal_sets is None else [list(s) for s in self.minimal_sets],
        }


EXHAUSTIVE_LIMIT = 12


def ablate(rule_set: RuleSet, cases: list[Case], exhaustive: bool = False) -> Ablation:
    """Drop each check in turn and record which cases then reach the wrong verdict.

    ``sufficient``: every case reaches its stated verdict with all checks on. ``necessary`` maps
    each check to the cases that reach their verdict with every check on and miss it without this
    one (a case that already fails with every check on proves nothing about any single check, so it
    is reported once, as failing, and never as a need); a check with none is ``unexercised``: either the
    vectors lack the case that needs it, or it is dead. ``monotone``: switching a check on never
    turns a refusal into an admission. With ``exhaustive`` (at most 12 checks the vectors
    exercise), the minimal sets of checks that reach every verdict are listed.
    """
    names = rule_set.check_names()
    # The parse checks are ablated over the rule sets that are the parse alone; a rule set with
    # its own checks reads them as a floor beneath its rules, and its vectors exercise the rules.
    ablated = names if not rule_set.checks else tuple(c.name for c in rule_set.checks)

    def outcomes(enabled: frozenset[str]) -> list[Verdict]:
        return [run(rule_set, c.raw, c.options, c.files, enabled, c.warn) for c in cases]

    full = outcomes(frozenset(names))
    failing = tuple(c.id for c, v in zip(cases, full) if not c.judged(v))
    necessary: dict[str, tuple[str, ...]] = {}
    monotone = True
    for name in ablated:
        without = outcomes(frozenset(names) - {name})
        necessary[name] = tuple(
            c.id for c, v, w in zip(cases, without, full) if c.judged(w) and not c.judged(v)
        )
        for with_all, dropped in zip(full, without):
            if with_all.admitted and not dropped.admitted:
                monotone = False
    unexercised = tuple(n for n in ablated if not necessary[n])
    minimal: tuple[tuple[str, ...], ...] | None = None
    exercised = [n for n in ablated if necessary[n]]
    if exhaustive and len(exercised) <= EXHAUSTIVE_LIMIT and not failing:
        found: list[frozenset[str]] = []
        rest = frozenset(unexercised) | (frozenset(names) - frozenset(ablated))
        for size in range(len(exercised) + 1):
            for combo in itertools.combinations(exercised, size):
                chosen = frozenset(combo)
                if any(prior <= chosen for prior in found):
                    continue
                if all(c.judged(v) for c, v in zip(cases, outcomes(chosen | rest))):
                    found.append(chosen)
        minimal = tuple(tuple(n for n in names if n in s) for s in found)
    return Ablation(rule_set.name, len(cases), not failing, failing, necessary, unexercised, monotone, minimal)
