"""Verify one evaluation claim record against an acceptance rule pinned outside it.

An evaluation claim says how an implementation fared against a case set. The
record carries every coordinate a relying party needs to read that claim
without filling a gap with "clean":

* ``applicability``: which cases of a pinned case set apply, and which are
  excluded under a reason the profile authorises.
* ``population``: the denominator, and every applicable case as passed, failed
  or not run. A case nobody ran is listed, never dropped.
* ``vantage``: who observed the results, and whether the observed party could
  have shaped them (``substrate`` or ``artifact``, as the agent-evidence
  vocabulary defines ``observation_vantage``).
* ``bytes``: the exact bytes the claim binds (implementation, case set,
  verifier), each by digest.
* ``epoch``: the authority state the run acted under, and every transition
  (revocation, suspension, consumption, root change, restart, re-registration,
  fork) during it.
* ``settlement``: whether each side-effecting action is resolved, on bound
  evidence, or still unresolved.

Every coordinate is present. A coordinate may say ``not_applicable`` only with a
reason token the profile authorises for that coordinate; ``unknown``,
``unresolved`` and ``failed`` are states, never non-applicability, and a record
carrying one is refused. The profile is not chosen by the producer: the
acceptance rule names it by digest, and a record that names any other profile is
refused, so a producer cannot satisfy a rule by picking a weaker profile.

The verifier is stdlib-only and offline: profiles and case sets are resolved by
digest from bytes the caller supplies. It never reads a case's expected answer.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

from ..invocation_axes.reader import MalformedInput, canonical, parse_strict, sha256_tag

__all__ = [
    "CLAIM_TYPE",
    "CODES",
    "COORDINATES",
    "MalformedInput",
    "canonical",
    "digest_of",
    "emit",
    "parse_strict",
    "sha256_tag",
    "summary",
    "verify",
]

#: The identifier a record carries, as ``claim_type`` and as the in-toto
#: ``predicateType`` when the record rides in a Statement. It never moves.
CLAIM_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evaluation-claim"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PROFILE_SCHEMA = "aev-claim-profile/v1"
RULE_SCHEMA = "aev-claim-acceptance-rule/v1"
CASE_SET_SCHEMA = "aev-claim-case-set/v1"

ADMITTED = "ADMITTED"
REFUSED = "REFUSED"

COORDINATES = ("applicability", "population", "vantage", "bytes", "epoch", "settlement")
VALUE = "value"
NOT_APPLICABLE = "not_applicable"
#: States that say the producer does not know. None of them is non-applicability.
UNSETTLED_STATES = ("unknown", "unresolved", "failed")
STATES = (VALUE, NOT_APPLICABLE, *UNSETTLED_STATES)
#: Tokens no profile may authorise as a reason for non-applicability: each one
#: names an absence, and an absence is never "does not apply".
FORBIDDEN_NA_REASONS = frozenset(
    {*UNSETTLED_STATES, "not_run", "not_captured", "unavailable", "missing", "skipped", "timeout"}
)
VERDICTS = ("pass", "fail", "incomplete")
VANTAGES = ("substrate", "artifact")
OUTCOMES = ("committed", "not_run", "unresolved")
TRANSITION_KINDS = (
    "revocation",
    "suspension",
    "consumption",
    "root_change",
    "restart",
    "re_registration",
    "fork",
)

#: Every refusal reason, in the order the verifier reports them.
CODES = (
    "MALFORMED_RECORD",
    "PROFILE_UNRESOLVED",
    "PROFILE_MISMATCH",
    "MISSING_COORDINATE",
    "UNRESOLVED_COORDINATE",
    "UNAUTHORISED_NOT_APPLICABLE",
    "INVALID_REFERENTIAL_PIN",
    "CASE_SET_NOT_ACCEPTED",
    "CASE_SET_UNRESOLVED",
    "APPLICABILITY_MISMATCH",
    "POPULATION_MISMATCH",
    "ABSENCE_READ_AS_CLEAN",
    "VERDICT_CONTRADICTED",
    "VANTAGE_NOT_ACCEPTED",
    "BYTES_MISMATCH",
    "STALE_EPOCH",
    "UNSETTLED_OUTCOME",
    "UNSETTLED_ACROSS_EPOCH",
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REF_KEYS = frozenset({"name", "alias", "uri", "digest"})


def digest_of(value: Any) -> str:
    """The digest of a JSON value: sha256 over its RFC 8785 bytes."""
    return sha256_tag(canonical(value))


class _Ctx:
    """The reasons found so far, and what later checks may rely on."""

    def __init__(self) -> None:
        self.reasons: list[dict[str, str]] = []
        self.broken: set[str] = set()

    def refuse(self, code: str, at: str, detail: str) -> None:
        if code not in CODES:
            raise AssertionError(f"unregistered refusal code {code}")
        self.reasons.append({"code": code, "at": at, "detail": detail})


# --- references ---------------------------------------------------------------


def is_immutable(ref: Any) -> bool:
    """A reference binds bytes only through a well-formed sha256 digest.

    A name, an alias or a URI locates bytes; it never identifies them. A name
    that a later revision superseded still identifies nothing by itself, and a
    digest of an old revision still identifies those old bytes.
    """
    return (
        isinstance(ref, dict)
        and isinstance(ref.get("digest"), str)
        and bool(_DIGEST.fullmatch(ref["digest"]))
    )


def _check_ref_shape(ref: Any, at: str) -> None:
    if not isinstance(ref, dict) or not ref or not set(ref) <= _REF_KEYS:
        raise MalformedInput(f"{at} is not a reference object")
    for key, value in ref.items():
        if not isinstance(value, str) or not value:
            raise MalformedInput(f"{at}.{key} is not a non-empty string")


def _references(values: dict[str, Any]) -> Iterable[tuple[str, str, Any]]:
    """Yield (pattern, location, reference) for every reference in valued coordinates."""
    app = values.get("applicability")
    if isinstance(app, dict) and "case_set" in app:
        yield "applicability.case_set", "applicability.case_set", app["case_set"]
    byt = values.get("bytes")
    if isinstance(byt, dict):
        for key in ("implementation", "case_set", "verifier"):
            if key in byt:
                yield f"bytes.{key}", f"bytes.{key}", byt[key]
        for i, ref in enumerate(byt.get("related", [])):
            yield "bytes.related[]", f"bytes.related[{i}]", ref
    sett = values.get("settlement")
    if isinstance(sett, dict):
        for i, action in enumerate(sett.get("actions", [])):
            if isinstance(action, dict) and "evidence" in action:
                yield (
                    "settlement.actions[].evidence",
                    f"settlement.actions[{i}].evidence",
                    action["evidence"],
                )


def check_references(ctx: _Ctx, profile: dict[str, Any], values: dict[str, Any]) -> None:
    """INVALID_REFERENTIAL_PIN: a reference the profile requires to be immutable is not.

    Narrow by design: only the patterns the profile lists are held to byte
    identity, and only a mutable or insufficient binding is refused. A reference
    outside the profile's list may be a tag or a URL.
    """
    required = set(profile["immutable_references"])
    for pattern, at, ref in _references(values):
        try:
            _check_ref_shape(ref, at)
        except MalformedInput as exc:
            ctx.refuse("MALFORMED_RECORD", at, str(exc))
            ctx.broken.add(at)
            continue
        if pattern in required and not is_immutable(ref):
            ctx.refuse(
                "INVALID_REFERENTIAL_PIN",
                at,
                "the profile requires byte identity here, and this binding is "
                + ("a malformed digest" if "digest" in ref else "a name, alias or URI only"),
            )
            ctx.broken.add(at)


# --- profile and rule ---------------------------------------------------------


def check_profile(profile: Any) -> dict[str, Any]:
    """Refuse a profile that drops a coordinate or authorises an absence as not applicable."""
    if not isinstance(profile, dict) or profile.get("schema") != PROFILE_SCHEMA:
        raise MalformedInput(f"profile is not {PROFILE_SCHEMA}")
    if tuple(profile.get("coordinates", ())) != COORDINATES:
        raise MalformedInput("a profile must list every coordinate, in order")
    na = profile.get("not_applicable")
    if not isinstance(na, dict) or not set(na) <= set(COORDINATES):
        raise MalformedInput("profile not_applicable must map coordinates to reason tokens")
    for coord, tokens in na.items():
        if not isinstance(tokens, list) or not all(isinstance(t, str) and t for t in tokens):
            raise MalformedInput(f"profile not_applicable.{coord} is not a list of tokens")
        bad = FORBIDDEN_NA_REASONS.intersection(tokens)
        if bad:
            raise MalformedInput(
                f"profile authorises an absence as not applicable for {coord}: {sorted(bad)}"
            )
    for key in ("immutable_references", "exclusion_reasons"):
        if not isinstance(profile.get(key), list):
            raise MalformedInput(f"profile {key} is not a list")
    return profile


def check_rule(rule: Any) -> dict[str, Any]:
    if not isinstance(rule, dict) or rule.get("schema") != RULE_SCHEMA:
        raise MalformedInput(f"acceptance rule is not {RULE_SCHEMA}")
    prof = rule.get("profile")
    if not isinstance(prof, dict) or not is_immutable(prof) or not isinstance(prof.get("id"), str):
        raise MalformedInput("an acceptance rule pins its profile by id and sha256 digest")
    sets = rule.get("case_sets")
    if (
        not isinstance(sets, list)
        or not sets
        or not all(isinstance(d, str) and _DIGEST.fullmatch(d) for d in sets)
    ):
        raise MalformedInput("an acceptance rule lists the case-set digests it accepts")
    vant = rule.get("accept_vantage")
    if not isinstance(vant, list) or not vant or not set(vant) <= set(VANTAGES):
        raise MalformedInput("an acceptance rule lists the vantages it accepts")
    return rule


def resolve_profile(
    ctx: _Ctx, profiles: dict[str, Any], pinned: dict[str, Any]
) -> dict[str, Any] | None:
    """PROFILE_UNRESOLVED: the pinned profile's bytes were not supplied, or are unusable.

    Resolution re-hashes what it finds, so a store keyed under the wrong digest
    cannot substitute one profile for another.
    """
    profile = profiles.get(pinned["digest"])
    if profile is None or digest_of(profile) != pinned["digest"]:
        ctx.refuse(
            "PROFILE_UNRESOLVED", "rule.profile", "no supplied profile has the pinned digest"
        )
        return None
    try:
        return check_profile(profile)
    except MalformedInput as exc:
        ctx.refuse("PROFILE_UNRESOLVED", "rule.profile", str(exc))
        return None


def check_profile_pin(ctx: _Ctx, record: dict[str, Any], pinned: dict[str, Any]) -> None:
    """PROFILE_MISMATCH: the record is judged under the rule's profile, and must name it.

    The producer's declaration never selects the profile. A record naming a
    weaker one is refused even when it would pass under the one it names.
    """
    if record["profile"] != {"id": pinned["id"], "digest": pinned["digest"]}:
        ctx.refuse(
            "PROFILE_MISMATCH",
            "profile",
            "the record names a profile other than the one the acceptance rule pins",
        )


# --- coordinates --------------------------------------------------------------


def check_states(
    ctx: _Ctx, profile: dict[str, Any], coords: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Every coordinate present; not_applicable only where authorised; absence never clean."""
    values: dict[str, dict[str, Any]] = {}
    for coord in COORDINATES:
        at = f"coordinates.{coord}"
        if coord not in coords:
            ctx.refuse("MISSING_COORDINATE", at, "every coordinate is present in the envelope")
            continue
        body = coords[coord]
        state = body.get("state") if isinstance(body, dict) else None
        if state not in STATES:
            ctx.refuse("MALFORMED_RECORD", at, f"state must be one of {list(STATES)}")
        elif state in UNSETTLED_STATES:
            ctx.refuse(
                "UNRESOLVED_COORDINATE",
                at,
                f"{state} is not a value and not non-applicability; it cannot be admitted",
            )
        elif state == NOT_APPLICABLE:
            check_not_applicable(ctx, profile, coord, body)
        else:
            values[coord] = body
    return values


def check_not_applicable(
    ctx: _Ctx, profile: dict[str, Any], coord: str, body: dict[str, Any]
) -> None:
    at = f"coordinates.{coord}"
    if set(body) != {"state", "reason"}:
        ctx.refuse("MALFORMED_RECORD", at, "not_applicable carries exactly a state and a reason")
        return
    allowed = profile["not_applicable"].get(coord, [])
    if body["reason"] not in allowed:
        ctx.refuse(
            "UNAUTHORISED_NOT_APPLICABLE",
            at,
            f"the pinned profile authorises {allowed or 'no'} reason here, not {body['reason']!r}",
        )


def _id_list(value: Any, at: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise MalformedInput(f"{at} is not a list of case ids")
    return value


def resolve_case_set(
    ctx: _Ctx, rule: dict[str, Any], case_sets: dict[str, Any], ref: dict[str, Any]
) -> dict[str, Any] | None:
    """The case set is resolved by digest alone; the rule decides which digests it accepts."""
    digest = ref["digest"]
    if digest not in rule["case_sets"]:
        ctx.refuse(
            "CASE_SET_NOT_ACCEPTED",
            "applicability.case_set",
            "the acceptance rule does not accept this case set",
        )
        return None
    held = case_sets.get(digest)
    if held is not None and digest_of(held) != digest:
        held = None  # a store keyed under the wrong digest resolves nothing
    if held is not None:
        held = check_case_set(held)
    if held is None:
        ctx.refuse(
            "CASE_SET_UNRESOLVED",
            "applicability.case_set",
            "no supplied case set hashes to this digest",
        )
        return None
    return held


def partition_ok(whole: list[str], parts: Iterable[list[str]]) -> bool:
    """True when the parts are pairwise disjoint, free of repeats, and cover ``whole`` exactly."""
    seen: list[str] = []
    for part in parts:
        seen.extend(part)
    return len(seen) == len(set(seen)) and set(seen) == set(whole) and len(seen) == len(whole)


def check_applicability(
    ctx: _Ctx,
    profile: dict[str, Any],
    rule: dict[str, Any],
    case_sets: dict[str, Any],
    app: dict[str, Any],
) -> list[str] | None:
    """Applicable plus excluded is the case set exactly; only optional cases are excluded."""
    at = "coordinates.applicability"
    if "case_set" not in app:
        raise MalformedInput(f"{at}.case_set names the case set by reference")
    applicable = _id_list(app.get("applicable"), f"{at}.applicable")
    excluded = app.get("excluded", [])
    if not isinstance(excluded, list) or not all(
        isinstance(e, dict) and set(e) == {"id", "reason"} for e in excluded
    ):
        raise MalformedInput(f"{at}.excluded entries carry exactly an id and a reason")
    if "applicability.case_set" in ctx.broken:
        return None
    held = resolve_case_set(ctx, rule, case_sets, app["case_set"])
    if held is None:
        return None
    cases = {c["id"]: c for c in held["cases"]}
    excluded_ids = [e["id"] for e in excluded]
    if not partition_ok(list(cases), [applicable, excluded_ids]):
        ctx.refuse(
            "APPLICABILITY_MISMATCH",
            at,
            "applicable and excluded together must be the case set's ids, each once",
        )
        return None
    for entry in excluded:
        case = cases[entry["id"]]
        if case["requirement"] != "optional" or entry["reason"] not in profile["exclusion_reasons"]:
            ctx.refuse(
                "APPLICABILITY_MISMATCH",
                f"{at}.excluded",
                f"{entry['id']} is {case['requirement']}; only an optional case may be "
                "excluded, under a reason the profile authorises",
            )
            return None
    return applicable


def verdict_reason(verdict: str, total: int, failed: list[str], not_run: list[str]) -> str | None:
    """The refusal a stated verdict earns against its own population, or None."""
    if verdict == "pass":
        if failed:
            return "VERDICT_CONTRADICTED"
        if not_run or total == 0:
            return "ABSENCE_READ_AS_CLEAN"
        return None
    if verdict == "fail":
        return None if failed else "VERDICT_CONTRADICTED"
    # incomplete: nothing failed, and something was not run or nothing applied.
    if failed or (not not_run and total > 0):
        return "VERDICT_CONTRADICTED"
    return None


def check_population(
    ctx: _Ctx, pop: dict[str, Any], applicable: list[str] | None, verdict: str
) -> None:
    at = "coordinates.population"
    total = pop.get("coverage_denominator")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise MalformedInput(f"{at}.coverage_denominator is not a non-negative integer")
    passed = _id_list(pop.get("passed"), f"{at}.passed")
    failed = _id_list(pop.get("failed"), f"{at}.failed")
    not_run = _id_list(pop.get("not_run"), f"{at}.not_run")
    listed = passed + failed + not_run
    whole = applicable if applicable is not None else sorted(set(listed))
    if total != len(whole) or not partition_ok(whole, [passed, failed, not_run]):
        ctx.refuse(
            "POPULATION_MISMATCH",
            at,
            "every applicable case appears once as passed, failed or not run, "
            "and the denominator counts them",
        )
        return
    code = verdict_reason(verdict, total, failed, not_run)
    if code is not None:
        ctx.refuse(code, "verdict", f"verdict {verdict!r} does not follow from the population")


def check_vantage(ctx: _Ctx, rule: dict[str, Any], vant: dict[str, Any]) -> None:
    at = "coordinates.vantage"
    if vant.get("observation_vantage") not in VANTAGES:
        raise MalformedInput(f"{at}.observation_vantage is one of {list(VANTAGES)}")
    if not isinstance(vant.get("observer"), str) or not vant["observer"]:
        raise MalformedInput(f"{at}.observer names who observed")
    if vant["observation_vantage"] not in rule["accept_vantage"]:
        ctx.refuse(
            "VANTAGE_NOT_ACCEPTED",
            at,
            f"the rule accepts {rule['accept_vantage']}, the record is "
            f"{vant['observation_vantage']}",
        )


def check_bytes(ctx: _Ctx, values: dict[str, Any], subject_digest: str | None) -> None:
    """The bytes coordinate binds the same case set applicability resolved, and the subject."""
    byt = values["bytes"]
    for key in ("implementation", "case_set", "verifier"):
        if key not in byt:
            raise MalformedInput(f"coordinates.bytes.{key} is required")
    app = values.get("applicability")
    if (
        app is not None
        and isinstance(app.get("case_set"), dict)
        and "applicability.case_set" not in ctx.broken
        and "bytes.case_set" not in ctx.broken
        and byt["case_set"].get("digest") != app["case_set"].get("digest")
    ):
        ctx.refuse(
            "BYTES_MISMATCH",
            "coordinates.bytes.case_set",
            "the bytes coordinate binds a different case set from the one applicability resolved",
        )
    if (
        subject_digest is not None
        and "bytes.implementation" not in ctx.broken
        and byt["implementation"].get("digest") != subject_digest
    ):
        ctx.refuse(
            "BYTES_MISMATCH",
            "subject",
            "the Statement subject is not the implementation the bytes coordinate binds",
        )


def live_epochs(epoch: dict[str, Any], action_ids: list[str]) -> dict[str, str]:
    """The epoch live when each action was taken, from the initial epoch and the transitions.

    A transition takes effect after the action it names, so the action it follows
    is still judged under the epoch it ends.
    """
    after: dict[str, list[dict[str, Any]]] = {}
    for t in epoch["transitions"]:
        after.setdefault(t["after_action"], []).append(t)
    live = epoch["initial"]
    out: dict[str, str] = {}
    for aid in action_ids:
        out[aid] = live
        for t in after.get(aid, []):
            if t["from"] != live:
                raise MalformedInput(f"transition after {aid} starts from {t['from']}, not {live}")
            live = t["to"]
    return out


def _check_epoch_shape(epoch: dict[str, Any], action_ids: list[str]) -> None:
    at = "coordinates.epoch"
    if not isinstance(epoch.get("initial"), str) or not epoch["initial"]:
        raise MalformedInput(f"{at}.initial names the epoch the run started under")
    transitions = epoch.get("transitions")
    if not isinstance(transitions, list):
        raise MalformedInput(f"{at}.transitions is a list")
    for t in transitions:
        if not isinstance(t, dict) or set(t) != {"after_action", "from", "to", "kind"}:
            raise MalformedInput(f"{at} transition carries after_action, from, to and kind")
        if t["kind"] not in TRANSITION_KINDS:
            raise MalformedInput(f"{at} transition kind {t['kind']!r} is not one of the kinds")
        if t["after_action"] not in action_ids:
            raise MalformedInput(f"{at} transition follows {t['after_action']!r}, no such action")


def _settlement_actions(sett: dict[str, Any]) -> list[dict[str, Any]]:
    actions = sett.get("actions")
    if not isinstance(actions, list) or not all(
        isinstance(a, dict)
        and {"id", "epoch", "outcome"} <= set(a) <= {"id", "epoch", "outcome", "evidence"}
        for a in actions
    ):
        raise MalformedInput("settlement actions carry id, epoch, outcome and optional evidence")
    ids = [a["id"] for a in actions]
    if len(ids) != len(set(ids)) or not all(isinstance(i, str) and i for i in ids):
        raise MalformedInput("settlement action ids are distinct non-empty strings")
    return actions


def check_epoch_settlement(ctx: _Ctx, values: dict[str, Any], coords: dict[str, Any]) -> None:
    """Every action under the epoch live when it ran; every outcome resolved on bound evidence."""
    sett = values.get("settlement")
    epoch = values.get("epoch")
    if sett is None:
        if epoch is not None and epoch.get("transitions"):
            raise MalformedInput("epoch transitions name actions, and settlement lists none")
        return
    actions = _settlement_actions(sett)
    ids = [a["id"] for a in actions]
    if epoch is None:
        said = coords.get("epoch")
        if actions and isinstance(said, dict) and said.get("state") == NOT_APPLICABLE:
            ctx.refuse(
                "UNAUTHORISED_NOT_APPLICABLE",
                "coordinates.epoch",
                "actions were taken, so authority was exercised and the epoch applies",
            )
        return
    _check_epoch_shape(epoch, ids)
    live = live_epochs(epoch, ids)
    spans = _has_later_transition(epoch, ids)
    for i, action in enumerate(actions):
        judge_action(ctx, f"coordinates.settlement.actions[{i}]", action, live, spans)


def judge_action(
    ctx: _Ctx,
    at: str,
    action: dict[str, Any],
    live: dict[str, str],
    spans: dict[str, bool],
) -> None:
    """One action: taken under the live epoch, and resolved on bound evidence.

    An unresolved action that an authority transition follows is the coupled
    case: the outcome is open and the authority it ran under has changed, so it
    is refused as unsettled across an epoch rather than merely unsettled.
    """
    aid = action["id"]
    if action["outcome"] not in OUTCOMES:
        raise MalformedInput(f"{at}.outcome is one of {list(OUTCOMES)}")
    if action["epoch"] != live[aid]:
        ctx.refuse(
            "STALE_EPOCH", at, f"{aid} acts under {action['epoch']}, and {live[aid]} was live"
        )
    if action["outcome"] == "unresolved":
        code = "UNSETTLED_ACROSS_EPOCH" if spans[aid] else "UNSETTLED_OUTCOME"
        ctx.refuse(code, at, f"{aid} has no settled outcome")
    elif "evidence" not in action:
        ctx.refuse(
            "UNSETTLED_OUTCOME", at, f"{aid} says {action['outcome']} with no evidence bound"
        )


def _has_later_transition(epoch: dict[str, Any], ids: list[str]) -> dict[str, bool]:
    """For each action, whether an authority transition takes effect at or after it."""
    positions = {aid: n for n, aid in enumerate(ids)}
    last = max((positions[t["after_action"]] for t in epoch["transitions"]), default=-1)
    return {aid: positions[aid] <= last for aid in ids}


# --- envelope -----------------------------------------------------------------


def unwrap(doc: Any) -> tuple[Any, str | None]:
    """Accept a bare record, or one riding as the predicate of an in-toto Statement v1."""
    if isinstance(doc, dict) and "_type" in doc:
        if doc["_type"] != STATEMENT_TYPE or doc.get("predicateType") != CLAIM_TYPE:
            raise MalformedInput("a Statement carrying a claim names this claim type")
        subject = doc.get("subject")
        if (
            not isinstance(subject, list)
            or len(subject) != 1
            or not isinstance(subject[0], dict)
            or not isinstance(subject[0].get("digest"), dict)
            or not re.fullmatch(r"[0-9a-f]{64}", str(subject[0]["digest"].get("sha256", "")))
        ):
            raise MalformedInput("the Statement names one subject by sha256")
        return doc.get("predicate"), "sha256:" + subject[0]["digest"]["sha256"]
    return doc, None


def check_envelope(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise MalformedInput("the record is a JSON object")
    if set(record) != {"claim_type", "profile", "verdict", "coordinates"}:
        raise MalformedInput("the record carries claim_type, profile, verdict and coordinates")
    if record["claim_type"] != CLAIM_TYPE:
        raise MalformedInput(f"claim_type is {CLAIM_TYPE}")
    if record["verdict"] not in VERDICTS:
        raise MalformedInput(f"verdict is one of {list(VERDICTS)}")
    if not isinstance(record["coordinates"], dict) or not set(record["coordinates"]) <= set(
        COORDINATES
    ):
        raise MalformedInput("coordinates holds only the defined coordinates")
    prof = record["profile"]
    if not isinstance(prof, dict) or set(prof) != {"id", "digest"}:
        raise MalformedInput("the record names its profile by id and digest")
    return record


def _guard(ctx: _Ctx, at: str, step: Callable[[], Any]) -> Any:
    try:
        return step()
    except MalformedInput as exc:
        ctx.refuse("MALFORMED_RECORD", at, str(exc))
        return None


def verify(
    doc: Any,
    rule: Any,
    profiles: dict[str, Any],
    case_sets: dict[str, Any],
) -> dict[str, Any]:
    """Judge one record (or Statement) under one acceptance rule.

    ``profiles`` and ``case_sets`` map a sha256 digest to the parsed document
    that hashes to it; :func:`index_by_digest` builds them from parsed files.
    The rule is the relying party's, never the producer's.
    """
    rule = check_rule(rule)  # the relying party's own file: unusable, never a refusal
    ctx = _Ctx()
    try:
        record, subject = unwrap(doc)
        record = check_envelope(record)
    except MalformedInput as exc:
        ctx.refuse("MALFORMED_RECORD", "record", str(exc))
        return _outcome(ctx, None)
    pinned = rule["profile"]
    profile = resolve_profile(ctx, profiles, pinned)
    if profile is None:
        return _outcome(ctx, None)
    check_profile_pin(ctx, record, pinned)
    values = check_states(ctx, profile, record["coordinates"])
    check_references(ctx, profile, values)
    applicable = None
    if "applicability" in values:
        applicable = _guard(
            ctx,
            "coordinates.applicability",
            lambda: check_applicability(ctx, profile, rule, case_sets, values["applicability"]),
        )
    if "population" in values:
        _guard(
            ctx,
            "coordinates.population",
            lambda: check_population(ctx, values["population"], applicable, record["verdict"]),
        )
    if "vantage" in values:
        _guard(ctx, "coordinates.vantage", lambda: check_vantage(ctx, rule, values["vantage"]))
    if "bytes" in values:
        _guard(ctx, "coordinates.bytes", lambda: check_bytes(ctx, values, subject))
    _guard(
        ctx,
        "coordinates.settlement",
        lambda: check_epoch_settlement(ctx, values, record["coordinates"]),
    )
    return _outcome(ctx, record["verdict"])


def _outcome(ctx: _Ctx, verdict: str | None) -> dict[str, Any]:
    order = {code: n for n, code in enumerate(CODES)}
    reasons = sorted(ctx.reasons, key=lambda r: (order[r["code"]], r["at"]))
    admitted = not reasons
    return {
        "result": ADMITTED if admitted else REFUSED,
        "verdict": verdict if admitted else None,
        "reasons": reasons,
    }


def summary(outcome: dict[str, Any]) -> dict[str, Any]:
    """The part of an outcome a vector pins: result, verdict and the set of reason codes."""
    return {
        "result": outcome["result"],
        "verdict": outcome["verdict"],
        "reasons": sorted({r["code"] for r in outcome["reasons"]}, key=CODES.index),
    }


def index_by_digest(documents: Iterable[Any]) -> dict[str, Any]:
    """Map each parsed document to the digest of its RFC 8785 bytes."""
    return {digest_of(doc): doc for doc in documents}


def check_case_set(case_set: Any) -> dict[str, Any]:
    if not isinstance(case_set, dict) or case_set.get("schema") != CASE_SET_SCHEMA:
        raise MalformedInput(f"case set is not {CASE_SET_SCHEMA}")
    cases = case_set.get("cases")
    if not isinstance(cases, list) or not all(
        isinstance(c, dict)
        and isinstance(c.get("id"), str)
        and c.get("requirement") in ("required", "optional")
        for c in cases
    ):
        raise MalformedInput("case set cases carry an id and a requirement")
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise MalformedInput("case set ids are distinct")
    return case_set


def emit(
    *,
    case_set: dict[str, Any],
    results: dict[str, Any],
    profile: dict[str, str],
    implementation: dict[str, str],
    verifier: dict[str, str],
    observation_vantage: str,
    observer: str,
) -> dict[str, Any]:
    """Build a conformance-profile record from a run's results.

    A case the results do not mention is listed as not run, never dropped, and
    the verdict follows from the population. Results naming a case the case set
    does not hold are refused.
    """
    check_case_set(case_set)
    ids = [c["id"] for c in case_set["cases"]]
    passed = _id_list(results.get("passed", []), "results.passed")
    failed = _id_list(results.get("failed", []), "results.failed")
    excluded = results.get("excluded", [])
    excluded_ids = [e["id"] for e in excluded]
    named = passed + failed + excluded_ids
    unexpected = sorted(set(named) - set(ids))
    if unexpected:
        raise MalformedInput(f"results name cases the case set does not hold: {unexpected}")
    if len(named) != len(set(named)):
        raise MalformedInput("results name a case more than once")
    applicable = [i for i in ids if i not in excluded_ids]
    not_run = [i for i in applicable if i not in passed and i not in failed]
    verdict = "fail" if failed else ("incomplete" if not_run or not applicable else "pass")
    case_ref = {"name": case_set.get("name", "case-set"), "digest": digest_of(case_set)}
    return {
        "claim_type": CLAIM_TYPE,
        "profile": {"id": profile["id"], "digest": profile["digest"]},
        "verdict": verdict,
        "coordinates": {
            "applicability": {
                "state": VALUE,
                "case_set": case_ref,
                "applicable": applicable,
                "excluded": excluded,
            },
            "population": {
                "state": VALUE,
                "coverage_denominator": len(applicable),
                "passed": [i for i in applicable if i in passed],
                "failed": [i for i in applicable if i in failed],
                "not_run": not_run,
            },
            "vantage": {
                "state": VALUE,
                "observation_vantage": observation_vantage,
                "observer": observer,
            },
            "bytes": {
                "state": VALUE,
                "implementation": implementation,
                "case_set": dict(case_ref),
                "verifier": verifier,
            },
            "epoch": {"state": NOT_APPLICABLE, "reason": "no_authority_exercised"},
            "settlement": {"state": NOT_APPLICABLE, "reason": "no_side_effecting_actions"},
        },
    }
