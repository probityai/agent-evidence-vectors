"""Negative controls: single-field mutants of a v0.1 report, each aimed at one rejection row.

``mutants(report)`` returns every mutant this report admits, in a fixed order.
Each changes exactly one JSON member (sets, adds or removes it) and names the
row of the v0.1 rejection table, or the unnumbered rule, it should be rejected
under. A row the report gives no single member to aim at is skipped with the
reason, so the controls table says which rows a report could not test.

Changing a check also changes its leaf under the check-set root, and changing a
state changes the roll-up counts, so a reader that recomputes those rows names
W3C-R-020 or W3C-R-017 beside the target. That is the reader reading the
mutant correctly; only the target is scored.

One pair is not single-field by construction: a non-ASCII check identity needs
the root recomputed to say anything about the digest encoding. Its first half
is a positive control (root over the RFC 8785 form, which writes the character
as UTF-8), its second half the same identity under a root over the
ASCII-escaped form, aimed at W3C-R-020.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

VERDICT = ("pass", "fail")
NON_VERDICT = ("inconclusive", "not-exercised", "void")
NEVER_EXAMINED = ("not_applicable", "out_of_scope", "withheld")
#: Rows 1 to 14 of the v0.1 rejection table and the identifiers the corpus mints for them.
TABLE_ROW = {f"W3C-R-{n:03d}": n for n in range(1, 13)} | {"W3C-R-025": 13, "W3C-R-026": 14}
SHAPE = "shape"
POSITIVE = "none (positive control)"

Report = dict[str, Any]
Mutant = dict[str, Any]


def table_row(rule: str) -> int | None:
    """The rejection-table row number of a rule identifier, None for an unnumbered rule."""
    return TABLE_ROW.get(rule)


def _checks(report: Report) -> list[dict[str, Any]]:
    return [c for c in report.get("checks", []) if isinstance(c, dict)]


def _first(report: Report, test: Callable[[dict[str, Any]], bool]) -> int | None:
    for i, check in enumerate(report.get("checks", [])):
        if isinstance(check, dict) and test(check):
            return i
    return None


def _evidence(report: Report) -> dict[str, dict[str, Any]]:
    return {e["id"]: e for e in report.get("evidence", []) if isinstance(e, dict) and "id" in e}


def _outcome(observation: Any) -> tuple[str, list[str]] | None:
    body = observation.get("carried") if isinstance(observation, dict) else None
    if not isinstance(body, dict) or not isinstance(body.get("verdict"), str):
        return None
    rules = body.get("rules")
    if not isinstance(rules, list):
        return None
    return body["verdict"], sorted(map(str, rules))


def _readable(item: dict[str, Any]) -> set[str] | None:
    """The slots that moved between two carried observations, None when not both carried."""
    obs = item.get("observations")
    if not isinstance(obs, list) or len(obs) != 2:
        return None
    a, b = _outcome(obs[0]), _outcome(obs[1])
    if a is None or b is None:
        return None
    return ({"verdict"} if a[0] != b[0] else set()) | ({"fired-rule list"} if a[1] != b[1] else set())


# --------------------------------------------------------------------------
# One builder per target. Each returns (path, description, mutated report) or
# a string saying why the report has no member to aim at.
# --------------------------------------------------------------------------

Built = tuple[str, str, Report] | str


def _set(report: Report, path: list[Any], value: Any) -> Report:
    out = copy.deepcopy(report)
    node: Any = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


def _drop(report: Report, path: list[Any]) -> Report:
    out = copy.deepcopy(report)
    node: Any = out
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return out


def _p(path: list[Any]) -> str:
    return "".join(f"[{k}]" if isinstance(k, int) else ("." + k if i else k) for i, k in enumerate(path))


def state_outside(r: Report) -> Built:
    i = _first(r, lambda c: True)
    if i is None:
        return "no check"
    path = ["checks", i, "state"]
    return _p(path), "a state outside the five-value enumeration", _set(r, path, "partial")


def row1(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in NON_VERDICT and "cause" in c)
    if i is not None:
        path = ["checks", i, "cause"]
        return _p(path), "the cause removed from a non-verdict check", _drop(r, path)
    i = _first(r, lambda c: c.get("state") == "pass" and "cause" not in c
               and "other-verdict" not in c and "discrimination" not in c)
    if i is None:
        return "no non-verdict check with a cause and no bare pass check"
    path = ["checks", i, "state"]
    return _p(path), "a bare pass check set to inconclusive, with no cause", _set(r, path, "inconclusive")


def row2(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in NON_VERDICT and isinstance(c.get("cause"), dict)
               and c["cause"].get("code") in NEVER_EXAMINED)
    if i is not None:
        path = ["checks", i, "state"]
        return _p(path), "a never-examined cause under void", _set(r, path, "void")
    i = _first(r, lambda c: c.get("state") == "void" and isinstance(c.get("cause"), dict))
    if i is None:
        return "no void check and no non-verdict check with a never-examined cause"
    path = ["checks", i, "cause", "code"]
    return _p(path), "a void check's cause set to not_applicable", _set(r, path, "not_applicable")


def row3(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in NON_VERDICT and isinstance(c.get("cause"), dict)
               and c["cause"].get("code") == "integrity-failure")
    if i is not None:
        path = ["checks", i, "state"]
        return _p(path), "integrity-failure under not-exercised", _set(r, path, "not-exercised")
    i = _first(r, lambda c: c.get("state") == "not-exercised" and isinstance(c.get("cause"), dict))
    if i is None:
        return "no not-exercised check and no non-verdict check citing integrity-failure"
    path = ["checks", i, "cause", "code"]
    return _p(path), "a not-exercised check's cause set to integrity-failure", _set(r, path, "integrity-failure")


def row4(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in ("inconclusive", "not-exercised")
               and isinstance(c.get("cause"), dict))
    if i is None:
        return "no non-void check carrying a cause"
    path = ["checks", i, "cause", "code"]
    return (_p(path), "confinement-failed-during-check under a state other than void",
            _set(r, path, "confinement-failed-during-check"))


def row5(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") != "not-exercised" and "declared-exclusion" not in c)
    if i is None:
        return "every check is not-exercised or already declares an exclusion"
    path = ["checks", i, "declared-exclusion"]
    return _p(path), "a declared exclusion on an exercised check", _set(r, path, True)


def row6(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in NON_VERDICT and "other-verdict" not in c
               and "discrimination" not in c)
    if i is None:
        return "no non-verdict check without a qualifier"
    path = ["checks", i, "other-verdict"]
    return _p(path), "a qualifier on a non-verdict check", _set(r, path, {"value": "unknown"})


def row7(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in VERDICT and "cause" not in c)
    if i is None:
        return "no verdict check without a cause"
    path = ["checks", i, "cause"]
    return _p(path), "a cause on a verdict check", _set(r, path, {"code": "failed"})


def row8(r: Report) -> Built:
    i = _first(r, lambda c: isinstance(c.get("other-verdict"), dict)
               and c["other-verdict"].get("value") == "foreclosed" and "discrimination" not in c)
    if i is not None:
        path = ["checks", i, "discrimination"]
        return _p(path), "discrimination demonstrated beside foreclosed", _set(r, path, {"value": "demonstrated"})
    i = _first(r, lambda c: isinstance(c.get("discrimination"), dict)
               and c["discrimination"].get("value") == "demonstrated"
               and isinstance(c.get("other-verdict"), dict))
    if i is None:
        return "no check carrying foreclosed or demonstrated discrimination with an other-verdict"
    path = ["checks", i, "other-verdict", "value"]
    return _p(path), "other-verdict set to foreclosed beside demonstrated discrimination", _set(r, path, "foreclosed")


def row9(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in VERDICT and "discrimination" not in c
               and (not isinstance(c.get("other-verdict"), dict)
                    or c["other-verdict"].get("value") in ("unknown", "possible-not-demonstrated")))
    if i is None:
        return "no verdict check whose other-verdict is unknown and that has no discrimination"
    path = ["checks", i, "discrimination"]
    return _p(path), "discrimination demonstrated with other-verdict unknown", _set(r, path, {"value": "demonstrated"})


def row10(r: Report) -> Built:
    i = _first(r, lambda c: isinstance(c.get("other-verdict"), dict)
               and c["other-verdict"].get("value") == "foreclosed" and "constraint-set" in c["other-verdict"])
    if i is not None:
        path = ["checks", i, "other-verdict", "constraint-set"]
        return _p(path), "foreclosed without its constraint set", _drop(r, path)
    i = _first(r, lambda c: isinstance(c.get("other-verdict"), dict) and "constraint-set" not in c["other-verdict"])
    if i is not None:
        path = ["checks", i, "other-verdict", "value"]
        return _p(path), "other-verdict set to foreclosed with no constraint set", _set(r, path, "foreclosed")
    i = _first(r, lambda c: c.get("state") in VERDICT and "other-verdict" not in c and "discrimination" not in c)
    if i is None:
        return "no other-verdict and no bare verdict check to add one to"
    path = ["checks", i, "other-verdict"]
    return _p(path), "other-verdict foreclosed with no constraint set or domain", _set(r, path, {"value": "foreclosed"})


def row11(r: Report) -> Built:
    for slot, values in (("other-verdict", ("demonstrated", "foreclosed")), ("discrimination", ("demonstrated",))):
        i = _first(r, lambda c, s=slot, v=values: isinstance(c.get(s), dict) and c[s].get("value") in v
                   and "ref" in c[s])
        if i is not None:
            path = ["checks", i, slot, "ref"]
            return _p(path), f"the evidence reference removed from an asserted {slot}", _drop(r, path)
    i = _first(r, lambda c: c.get("state") in VERDICT and "other-verdict" not in c)
    if i is None:
        return "no asserted qualifier and no verdict check without an other-verdict"
    path = ["checks", i, "other-verdict"]
    return _p(path), "other-verdict demonstrated with no evidence reference", _set(r, path, {"value": "demonstrated"})


def row12(r: Report) -> Built:
    evidence = _evidence(r)
    for check in _checks(r):
        disc = check.get("discrimination")
        if isinstance(disc, dict) and disc.get("value") == "demonstrated" and disc.get("ref") in evidence:
            index = r["evidence"].index(evidence[disc["ref"]])
            path = ["evidence", index, "changed"]
            return _p(path), "the cited evidence object's changed slot set to the checker", _set(r, path, "checker rule")
    return "no demonstrated discrimination citing an evidence object"


def row13(r: Report) -> Built:
    evidence = _evidence(r)
    for check in _checks(r):
        other = check.get("other-verdict")
        if not (isinstance(other, dict) and other.get("value") == "demonstrated" and other.get("ref") in evidence):
            continue
        item = evidence[other["ref"]]
        moved = _readable(item)
        if moved is not None and "verdict" in moved:
            index = r["evidence"].index(item)
            first = item["observations"][0]["carried"]["verdict"]
            path = ["evidence", index, "observations", 1, "carried", "verdict"]
            return _p(path), "the second observation's verdict set equal to the first", _set(r, path, first)
    return "no demonstrated other-verdict citing two carried observations whose verdict moved"


def row14(r: Report) -> Built:
    for index, item in enumerate(r.get("evidence", [])):
        if not (isinstance(item, dict) and item.get("moved")):
            continue
        for j, obs in enumerate(item.get("observations") or []):
            if isinstance(obs, dict) and isinstance(obs.get("reference"), dict) and "sha256" in obs["reference"]:
                path = ["evidence", index, "observations", j, "reference", "sha256"]
                return _p(path), "a referenced observation's digest removed under an asserted moved", _drop(r, path)
    return "no evidence object asserting moved over a referenced observation"


def r016(r: Report) -> Built:
    for index, item in enumerate(r.get("evidence", [])):
        moved = _readable(item) if isinstance(item, dict) else None
        compared = item.get("compared") if isinstance(item, dict) else None
        if moved and isinstance(compared, list):
            slot = sorted(moved)[0]
            if slot in compared:
                path = ["evidence", index, "compared"]
                return (_p(path), f"'{slot}' removed from compared while it moved",
                        _set(r, path, [s for s in compared if s != slot]))
    return "no evidence object with two carried observations whose outcome moved"


def r021(r: Report) -> Built:
    for index, item in enumerate(r.get("evidence", [])):
        moved = _readable(item) if isinstance(item, dict) else None
        declared = item.get("moved") if isinstance(item, dict) else None
        if moved is not None and isinstance(declared, list):
            if "verdict" in declared:
                value = [s for s in declared if s != "verdict"]
            else:
                value = sorted(set(declared) | {"verdict"})
            path = ["evidence", index, "moved"]
            return _p(path), "declared moved disagreeing with the recomputed value", _set(r, path, value)
    return "no evidence object with two carried observations to recompute moved from"


def root_digest(r: Report) -> Built:
    cs = r.get("check-set")
    if not (isinstance(cs, dict) and isinstance(cs.get("sha256"), str) and cs["sha256"]):
        return "no check-set digest"
    digest = cs["sha256"]
    flipped = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    return "check-set.sha256", "the check-set root no longer the root of its leaves", _set(r, ["check-set", "sha256"], flipped)


def flip_state(r: Report) -> Built:
    i = _first(r, lambda c: c.get("state") in VERDICT)
    if i is None:
        return "no verdict check"
    path = ["checks", i, "state"]
    new = "fail" if r["checks"][i]["state"] == "pass" else "pass"
    return _p(path), "one check's state flipped, the check-set root left as it was", _set(r, path, new)


def leaf_count(r: Report) -> Built:
    cs = r.get("check-set")
    if not (isinstance(cs, dict) and isinstance(cs.get("leaf-count"), int)):
        return "no check-set leaf count"
    return ("check-set.leaf-count", "the declared leaf count one more than the checks",
            _set(r, ["check-set", "leaf-count"], cs["leaf-count"] + 1))


def rollup_count(r: Report) -> Built:
    ru = r.get("roll-up")
    if not isinstance(ru, dict):
        return "no roll-up"
    key = "pass" if isinstance(ru.get("pass"), int) else "declared"
    if not isinstance(ru.get(key), int):
        return "no roll-up count"
    path = ["roll-up", key]
    return _p(path), "a roll-up count that disagrees with the checks", _set(r, path, ru[key] + 1)


def drop_rollup(r: Report) -> Built:
    if "roll-up" not in r:
        return "no roll-up"
    return "roll-up", "the roll-up, a required member, removed", _drop(r, ["roll-up"])


def drop_format(r: Report) -> Built:
    if "format" not in r:
        return "no format member"
    return "format", "the format declaration, a required member, removed", _drop(r, ["format"])


def drop_check_state(r: Report) -> Built:
    i = _first(r, lambda c: "state" in c)
    if i is None:
        return "no check with a state"
    path = ["checks", i, "state"]
    return _p(path), "a check's state, a required member, removed", _drop(r, path)


def counter(r: Report) -> Built:
    ru = r.get("roll-up")
    if not (isinstance(ru, dict) and isinstance(ru.get("carried"), int)):
        return "no carried counter in the roll-up"
    return "roll-up.carried", "the carried counter overstated by one", _set(r, ["roll-up", "carried"], ru["carried"] + 1)


def population(r: Report) -> Built:
    ru = r.get("roll-up")
    comp = ru.get("completeness") if isinstance(ru, dict) else None
    claim = comp.get("accounting") if isinstance(comp, dict) else None
    if not (isinstance(claim, dict) and isinstance(claim.get("population"), int)):
        return "no completeness claim with a population"
    path = ["roll-up", "completeness", "accounting", "population"]
    return _p(path), "a completeness claim's population that is not the declared count", _set(r, path, claim["population"] + 1)


def negative_capable(r: Report) -> Built:
    ru = r.get("roll-up")
    if not (isinstance(ru, dict) and "negative-capable" in ru):
        return "no negative-capable statement in the roll-up"
    return ("roll-up.negative-capable", "the negative-capability statement removed from the roll-up",
            _drop(r, ["roll-up", "negative-capable"]))


# --------------------------------------------------------------------------
# The non-ASCII pair. Leaves under the check-set root are hashed under the
# report's tree shape; the two halves differ only in the bytes of each leaf.
# --------------------------------------------------------------------------

def _escaped(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _flat(leaves: list[bytes]) -> str:
    return hashlib.sha256(b"".join(hashlib.sha256(x).digest() for x in leaves)).hexdigest()


def _mth(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


ROOTS: dict[str, Callable[[list[bytes]], str]] = {
    "flat": _flat, "rfc6962": lambda x: _mth(x).hex(), "RFC9162_SHA256": lambda x: _mth(x).hex()}


def _non_ascii(r: Report, leaf: Callable[[Any], bytes]) -> tuple[str, Report] | str:
    cs = r.get("check-set")
    if not (isinstance(cs, dict) and cs.get("tree-shape") in ROOTS):
        return "no check-set under a known tree shape"
    i = _first(r, lambda c: isinstance(c.get("check"), str))
    if i is None:
        return "no check identity"
    out = _set(r, ["checks", i, "check"], r["checks"][i]["check"] + "-é")
    out["check-set"]["sha256"] = ROOTS[cs["tree-shape"]]([leaf(c) for c in out["checks"]])
    return f"checks[{i}].check, check-set.sha256", out


def non_ascii_utf8(r: Report, jcs: Callable[[Any], bytes]) -> Built:
    built = _non_ascii(r, jcs)
    if isinstance(built, str):
        return built
    return built[0], "a non-ASCII check identity, root recomputed over the RFC 8785 form (UTF-8)", built[1]


def non_ascii_escaped(r: Report) -> Built:
    built = _non_ascii(r, _escaped)
    if isinstance(built, str):
        return built
    return built[0], "a non-ASCII check identity, root recomputed over the ASCII-escaped form", built[1]


#: (mutant name, target, builder). The order is the order of every table.
SINGLE: list[tuple[str, str, Callable[[Report], Built]]] = [
    ("row01-no-cause", "W3C-R-001", row1),
    ("row02-void-never-examined", "W3C-R-002", row2),
    ("row03-not-exercised-integrity", "W3C-R-003", row3),
    ("row04-confinement-not-void", "W3C-R-004", row4),
    ("row05-exclusion-exercised", "W3C-R-005", row5),
    ("row06-qualifier-non-verdict", "W3C-R-006", row6),
    ("row07-cause-on-verdict", "W3C-R-007", row7),
    ("row08-foreclosed-demonstrated", "W3C-R-008", row8),
    ("row09-demonstrated-unknown", "W3C-R-009", row9),
    ("row10-foreclosed-no-constraint", "W3C-R-010", row10),
    ("row11-no-evidence-ref", "W3C-R-011", row11),
    ("row12-checker-changed", "W3C-R-012", row12),
    ("row13-moved-without-verdict", "W3C-R-025", row13),
    ("row14-moved-unbound", "W3C-R-026", row14),
    ("state-outside-enum", "W3C-R-019", state_outside),
    ("moved-outside-compared", "W3C-R-016", r016),
    ("moved-declared-not-recomputed", "W3C-R-021", r021),
    ("root-digest-altered", "W3C-R-020", root_digest),
    ("state-flipped-root-kept", "W3C-R-020", flip_state),
    ("leaf-count-off", "W3C-R-015", leaf_count),
    ("rollup-count-off", "W3C-R-017", rollup_count),
    ("rollup-dropped", "W3C-R-017", drop_rollup),
    ("carried-counter-off", "W3C-R-018", counter),
    ("population-off", "W3C-R-023", population),
    ("negative-capable-dropped", "W3C-R-013", negative_capable),
    ("format-dropped", SHAPE, drop_format),
    ("check-state-dropped", SHAPE, drop_check_state),
]


def mutants(report: Report, jcs: Callable[[Any], bytes], only: tuple[str, ...] | None = None,
            ) -> tuple[list[Mutant], list[dict[str, str]]]:
    """Every mutant the report admits, and every target it admits none for, with why."""
    made: list[Mutant] = []
    skipped: list[dict[str, str]] = []
    builders: list[tuple[str, str, int, Callable[[Report], Built]]] = [
        (name, target, 1, build) for name, target, build in SINGLE]
    builders += [("non-ascii-root-utf8", POSITIVE, 2, lambda r: non_ascii_utf8(r, jcs)),
                 ("non-ascii-root-escaped", "W3C-R-020", 2, non_ascii_escaped)]
    for name, target, fields, build in builders:
        if only is not None and name not in only:
            continue
        built = build(report)
        if isinstance(built, str):
            skipped.append({"mutant": name, "target": target, "why": built})
            continue
        path, what, body = built
        made.append({"mutant": name, "target": target, "table_row": table_row(target),
                     "fields_changed": fields, "path": path, "what": what, "report": body})
    return made, skipped
